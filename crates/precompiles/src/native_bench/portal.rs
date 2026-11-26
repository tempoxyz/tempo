//! Native version of the public-mix zone portal deposit and the settlement fixture's settle.
//!
//! [deposit] replaces a portal proxy frame calling the 5-argument `deposit`, and [settle] replaces
//! the frame of `SettlementFixture.settle` (`contrib/bench/txgen/zones/PortalFixture.sol`),
//! including every portal call it makes. Both port the T15 ZonePortal runtime
//! (`crates/zones/contracts/src/runtime/tempo/ZonePortal.sol`) over the portal proxy's storage.
//!
//! Gas: the native code performs every account access, storage read and write, log and
//! precompile call of the bytecode, which charge their own dynamic gas, and charges the bytecode's
//! remaining (opcode, memory, call and ABI) gas as constants, measured per path against the
//! bytecode on the same state. Constants are charged where the bytecode spends them, so the gas
//! left when the fixture calls `processWithdrawals` matches the bytecode's, which decides whether
//! that call runs out of gas (see [fixture]).

mod fixture;
mod zone_portal;

use super::{Entry, NativeFrame};
use crate::{
    error::{Result, TempoPrecompileError},
    input_cost,
    storage::StorageCtx,
    zone_factory::portal::ZONE_PORTAL_PROXY_RUNTIME,
};
use alloy::{
    primitives::{Address, Bytes, U256},
    sol_types::{Panic, SolCall, SolError, SolValue},
};
use tempo_contracts::zones::ZonePortal;

/// Opcode gas of a deposit frame (proxy and implementation) on its common path, charged after
/// it by [super::run].
pub const DEPOSIT_EXTRA_GAS: u64 = 12_492;
/// Opcode gas of a settle frame charged after it by [super::run]: none, since settle charges its
/// opcode gas where the bytecode spends it, to give its `processWithdrawals` call the bytecode's
/// gas (see [fixture]).
pub const SETTLE_EXTRA_GAS: u64 = 0;

pub(super) fn select(selector: [u8; 4], code: &[u8]) -> Option<Entry> {
    match selector {
        ZonePortal::deposit_0Call::SELECTOR if code == ZONE_PORTAL_PROXY_RUNTIME => {
            Some(Entry::PortalDeposit)
        }
        fixture::SETTLE_SELECTOR if fixture::is_fixture(code) => Some(Entry::SettlementSettle),
        _ => None,
    }
}

pub(super) fn deposit(frame: &NativeFrame<'_>) -> Result<Bytes> {
    let call = ZonePortal::deposit_0Call::abi_decode_validate(frame.input)
        .map_err(|_| TempoPrecompileError::RawRevert(Bytes::new()))?;
    let portal = zone_portal::Portal::enter(frame.address)?;
    let hash = portal.deposit(frame.caller, call)?;
    Ok(hash.abi_encode().into())
}

pub(super) fn settle(frame: &NativeFrame<'_>) -> Result<Bytes> {
    fixture::settle(frame)
}

/// Charges `gas` of bytecode execution the native code does not perform.
fn charge(gas: u64) -> Result<()> {
    StorageCtx.deduct_gas(gas)
}

/// Gas left in the frame.
fn remaining() -> u64 {
    StorageCtx.gas_limit() - StorageCtx.gas_used()
}

/// Touches `address` as a call or `EXTCODESIZE` does, charging the warm or cold access.
fn access(address: Address) -> Result<()> {
    StorageCtx.with_account_info(address, |_| Ok(()))
}

/// Charges what the EVM charges before a Tempo precompile runs on `len` bytes of calldata.
fn charge_precompile_input(len: usize) -> Result<()> {
    charge(input_cost(StorageCtx.spec(), len)?)
}

/// A revert with the ABI encoding of `error`, as Solidity's `revert` produces it.
fn revert(error: impl SolError) -> TempoPrecompileError {
    TempoPrecompileError::RawRevert(error.abi_encode().into())
}

/// Solidity's checked-arithmetic panic.
fn overflow() -> TempoPrecompileError {
    revert(Panic {
        code: U256::from(0x11),
    })
}
