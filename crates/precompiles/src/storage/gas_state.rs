use std::sync::LazyLock;

use alloy::primitives::{Address, Log, LogData, U256, keccak256};
use alloy_evm::EvmInternals;
use revm::{
    context::{Block, CfgEnv, journaled_state::JournalCheckpoint},
    context_interface::cfg::{GasParams, gas},
    interpreter::gas::GasTracker,
    primitives::AddressMap,
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles_macros::Storable;

use crate::{
    error::TempoPrecompileError,
    storage::{LayoutCtx, PrecompileStorageProvider, Storable, packing::PackedSlot},
};

/// keccak256("GAS_TOKEN_BALANCE_SLOT")
pub static GAS_TOKEN_BALANCE_SLOT: LazyLock<U256> =
    LazyLock::new(|| keccak256(b"GAS_TOKEN_BALANCE_SLOT").into());

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Storable)]
pub enum GasStateMode {
    RefundTokens,
    PreserveTokens,
    DirectTokens,
}

#[derive(Debug, Clone, Copy, Storable)]
pub struct GasState {
    pub token_balance: u64,
    pub creation_mode: GasStateMode,
}

impl From<U256> for GasState {
    fn from(value: U256) -> Self {
        Self::load(&PackedSlot(value), *GAS_TOKEN_BALANCE_SLOT, LayoutCtx::FULL)
            .expect("decoding is infallible")
    }
}

impl Into<U256> for GasState {
    fn into(self) -> U256 {
        let mut slot = PackedSlot(U256::ZERO);
        self.store(&mut slot, U256::ZERO, LayoutCtx::FULL)
            .expect("encoding is infallible");
        slot.0
    }
}
