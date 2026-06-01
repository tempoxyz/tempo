//! Storage gas token state and precompile (TIP-1060).

pub mod dispatch;

use crate::{
    STORAGE_GAS_TOKENS_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
};
use alloy::primitives::Address;
use tempo_contracts::precompiles::{
    IStorageGasTokens::Mode, StorageGasTokensError, StorageGasTokensEvent,
};
use tempo_precompiles_macros::{Storable, contract};

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub enum GasStateMode {
    #[default]
    RefundTokens,
    PreserveTokens,
    DirectTokens,
}

impl TryFrom<Mode> for GasStateMode {
    type Error = TempoPrecompileError;

    fn try_from(mode: Mode) -> Result<Self> {
        match mode {
            Mode::RefundTokens => Ok(Self::RefundTokens),
            Mode::PreserveTokens => Ok(Self::PreserveTokens),
            Mode::DirectTokens => Ok(Self::DirectTokens),
            _ => Err(StorageGasTokensError::invalid_mode().into()),
        }
    }
}

impl From<GasStateMode> for Mode {
    fn from(mode: GasStateMode) -> Self {
        match mode {
            GasStateMode::RefundTokens => Self::RefundTokens,
            GasStateMode::PreserveTokens => Self::PreserveTokens,
            GasStateMode::DirectTokens => Self::DirectTokens,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Storable)]
pub struct GasState {
    pub balance: u64,
    pub mode: GasStateMode,
}

/// Storage gas tokens precompile.
#[contract(addr = STORAGE_GAS_TOKENS_ADDRESS)]
pub struct GasToken {
    pub(crate) state: Mapping<Address, GasState>,
}

impl GasToken {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn state_of(&self, account: Address) -> Result<GasState> {
        self.state[account].read()
    }

    pub fn set_mode(&mut self, msg_sender: Address, mode: Mode) -> Result<()> {
        self.state[msg_sender]
            .mode
            .write(GasStateMode::try_from(mode)?)?;

        self.emit_event(StorageGasTokensEvent::mode_updated(msg_sender, mode))
    }

    pub fn increase_balance(&mut self, account: Address) -> Result<()> {
        let balance = self.state[account].balance.read()?;
        self.state[account].balance.write(balance.saturating_add(1))
    }

    pub fn decrease_balance(&mut self, account: Address) -> Result<()> {
        let balance = self.state[account].balance.read()?;
        self.state[account].balance.write(balance.saturating_sub(1))
    }
}
