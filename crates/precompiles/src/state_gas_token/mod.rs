//! State gas token precompile (TIP-1060).

pub mod dispatch;

use crate::{
    STORAGE_GAS_TOKENS_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, LayoutCtx, StorableType},
};
use alloy::primitives::{Address, U256};
use tempo_contracts::precompiles::{
    IStorageGasTokens::Mode, StorageGasTokensError, StorageGasTokensEvent,
};
use tempo_precompiles_macros::{Storable, contract};

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub enum StorageGasMode {
    #[default]
    RefundTokens,
    PreserveTokens,
    DirectTokens,
}

impl TryFrom<u8> for StorageGasMode {
    type Error = TempoPrecompileError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::RefundTokens),
            1 => Ok(Self::PreserveTokens),
            2 => Ok(Self::DirectTokens),
            _ => Err(StorageGasTokensError::invalid_mode().into()),
        }
    }
}

impl TryFrom<Mode> for StorageGasMode {
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

impl From<StorageGasMode> for Mode {
    fn from(mode: StorageGasMode) -> Self {
        match mode {
            StorageGasMode::RefundTokens => Self::RefundTokens,
            StorageGasMode::PreserveTokens => Self::PreserveTokens,
            StorageGasMode::DirectTokens => Self::DirectTokens,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct AccountState {
    pub balance: u64,
    pub mode: StorageGasMode,
}

impl AccountState {
    /// Decodes a packed storage gas token state word.
    ///
    /// Layout:
    /// - bits `0..=63`: token balance (`uint64`)
    /// - bits `64..=65`: storage creation mode
    /// - bits `66..=255`: reserved for future hardfork-gated extensions
    #[inline]
    pub fn from_word(value: U256) -> Result<Self> {
        // `U256` limbs are little-endian: limb 0 holds bits 0..=63,
        // limb 1 holds bits 64..=127.
        let limbs = value.as_limbs();
        Ok(Self {
            balance: limbs[0],
            mode: (limbs[1] as u8).try_into()?,
        })
    }

    /// Encodes this state as a packed storage word.
    #[inline]
    pub fn into_word(self) -> U256 {
        U256::from_limbs([self.balance, self.mode as u64, 0, 0])
    }
}

/// TIP-1060 state gas token precompile, which tracks per-account gas token state.
///
/// Unlike the Solidity-compatible `Mapping<Address, GasState>` layout, account state is stored
/// directly at the account-derived slot: the 20-byte address is left-padded to 32 bytes and used
/// as the storage key, avoiding hashing on the SSTORE gas-state hook hot path.
///
/// ```text
/// storage_gas_token_slot = uint256(bytes32(account))
/// solidity_mapping_slot = keccak256(abi.encode(account, base_slot))
/// ```
#[contract(addr = STORAGE_GAS_TOKENS_ADDRESS)]
pub struct StorageGasToken {}

impl StorageGasToken {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn state_of(&self, account: Address) -> Result<AccountState> {
        AccountState::handle(Self::slot(account), LayoutCtx::FULL, self.address).read()
    }

    #[inline]
    fn write_state_of(&mut self, account: Address, state: AccountState) -> Result<()> {
        AccountState::handle(Self::slot(account), LayoutCtx::FULL, self.address).write(state)
    }

    pub fn set_mode(&mut self, msg_sender: Address, mode: Mode) -> Result<()> {
        let mut state = self.state_of(msg_sender)?;
        state.mode = StorageGasMode::try_from(mode)?;
        self.write_state_of(msg_sender, state)?;

        self.emit_event(StorageGasTokensEvent::mode_updated(msg_sender, mode))
    }

    #[inline]
    pub fn slot(account: Address) -> U256 {
        U256::from_be_bytes(account.into_word().0)
    }
}
