//! Benchmark experiment: native Rust versions of the public-mix Earn vault and zone portal hot
//! paths, run in place of their bytecode so a benchmark can measure what the interpreter costs.
//!
//! Not for production. The interpreter runner calls [select] before each frame; frames whose
//! callee and selector match a native entry run through [run], every other frame runs its
//! bytecode. Each native entry reads and writes the same storage slots, moves the same TIP-20
//! balances and emits the same logs as the bytecode it replaces, then charges the bytecode's
//! remaining gas, so blocks pack the same transactions. Set TEMPO_NATIVE_BENCH=0 to turn it off.

pub mod portal;
pub mod vault;

use crate::{
    error::{EncodePrecompileResult, Result},
    storage::{
        StorageCtx,
        evm::{EvmPrecompileStorageProvider, EvmStorageExt, Frame},
    },
};
use alloy::primitives::{Address, Bytes};
use evm2::{
    Evm, EvmTypes,
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{PrecompileHalt, PrecompileResult},
};
use std::{rc::Rc, sync::LazyLock};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoBlockExt;

/// Which native entries replace bytecode: TEMPO_NATIVE_BENCH unset or "1" runs both, "0" none,
/// and "vault" or "portal" only that one.
static ENABLED: LazyLock<(bool, bool)> =
    LazyLock::new(|| match std::env::var("TEMPO_NATIVE_BENCH").as_deref() {
        Ok("0") => (false, false),
        Ok("vault") => (true, false),
        Ok("portal") => (false, true),
        _ => (true, true),
    });

/// Whether any native entry replaces bytecode.
pub fn enabled() -> bool {
    ENABLED.0 || ENABLED.1
}

/// A native replacement for one bytecode entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    VaultDeposit,
    VaultRedeem,
    PortalDeposit,
    SettlementSettle,
}

impl Entry {
    /// Gas charged on top of the native entry's own storage and precompile gas, so the frame
    /// costs what the bytecode does: the bytecode's opcode, memory and call overhead, measured
    /// against the native entry on the same workload.
    pub const fn extra_gas(self) -> u64 {
        match self {
            Self::VaultDeposit => vault::DEPOSIT_EXTRA_GAS,
            Self::VaultRedeem => vault::REDEEM_EXTRA_GAS,
            Self::PortalDeposit => portal::DEPOSIT_EXTRA_GAS,
            Self::SettlementSettle => portal::SETTLE_EXTRA_GAS,
        }
    }

    fn run(self, frame: &NativeFrame<'_>) -> Result<Bytes> {
        match self {
            Self::VaultDeposit => vault::deposit(frame),
            Self::VaultRedeem => vault::redeem(frame),
            Self::PortalDeposit => portal::deposit(frame),
            Self::SettlementSettle => portal::settle(frame),
        }
    }
}

/// The call frame a native entry runs in.
#[derive(Debug)]
pub struct NativeFrame<'a> {
    /// The account whose storage the frame runs over (address(this)).
    pub address: Address,
    /// msg.sender.
    pub caller: Address,
    /// Calldata, selector included.
    pub input: &'a [u8],
}

/// Picks the native entry replacing the frame of message, whose calldata is input and bytecode
/// is code, if any.
#[inline]
pub fn select<T: EvmTypes>(
    message: &Message<T>,
    input: &[u8],
    code: &[u8],
    is_static: bool,
) -> Option<Entry> {
    if !enabled() || is_static || message.kind != MessageKind::Call || !message.value.is_zero() {
        return None;
    }
    let selector: [u8; 4] = input.get(..4)?.try_into().ok()?;
    let vault = ENABLED
        .0
        .then(|| vault::select(message.destination, selector))
        .flatten();
    vault.or_else(|| ENABLED.1.then(|| portal::select(selector, code)).flatten())
}

/// Runs entry natively over the frame of message, charging gas to gas.
pub fn run<T>(
    evm: &mut Evm<'_, T>,
    spec: TempoHardfork,
    entry: Entry,
    message: &Message<T>,
    input: &[u8],
    gas: &mut GasTracker,
) -> PrecompileResult
where
    T: EvmTypes<BlockEnvExt = TempoBlockExt>,
    T::EvmExt: EvmStorageExt,
{
    let actions = evm.ext().storage_actions();
    let non_creditable_slots = evm.ext().non_creditable_slots();
    let frame = NativeFrame {
        address: message.destination,
        caller: message.caller,
        input,
    };
    let result = {
        let mut storage = EvmPrecompileStorageProvider::new(evm, gas, spec, false)
            .with_actions(actions)
            .with_non_creditable_slots(non_creditable_slots)
            .with_frame(Frame {
                address: message.destination,
                depth: message.depth,
                nested_calls: Rc::default(),
            });
        StorageCtx::enter(&mut storage, || entry.run(&frame))
    };
    if result.is_ok() && gas.spend(entry.extra_gas()).is_err() {
        return Err(PrecompileHalt::OutOfGas.into());
    }
    result.encode_precompile_result(|output| output)
}
