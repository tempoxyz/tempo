//! Storage credits precompile (TIP-1060).

pub mod dispatch;
pub mod gas_state;

pub use gas_state::{StorageCreditsBackend, sstore_storage_credits};

use crate::{
    STORAGE_CREDITS_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, LayoutCtx, StorableType},
};
use alloy::primitives::{Address, U256};
use tempo_contracts::precompiles::{
    ITIP1060StorageCredits::Mode, TIP1060StorageCreditsError, TIP1060StorageCreditsEvent,
};
use tempo_precompiles_macros::{Storable, contract};

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub enum CreditMode {
    #[default]
    Refund,
    Preserve,
    Direct,
}

impl TryFrom<u8> for CreditMode {
    type Error = TempoPrecompileError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Refund),
            1 => Ok(Self::Preserve),
            2 => Ok(Self::Direct),
            _ => Err(TIP1060StorageCreditsError::invalid_mode().into()),
        }
    }
}

impl TryFrom<Mode> for CreditMode {
    type Error = TempoPrecompileError;

    fn try_from(mode: Mode) -> Result<Self> {
        match mode {
            Mode::Refund => Ok(Self::Refund),
            Mode::Preserve => Ok(Self::Preserve),
            Mode::Direct => Ok(Self::Direct),
            _ => Err(TIP1060StorageCreditsError::invalid_mode().into()),
        }
    }
}

impl From<CreditMode> for Mode {
    fn from(mode: CreditMode) -> Self {
        match mode {
            CreditMode::Refund => Self::Refund,
            CreditMode::Preserve => Self::Preserve,
            CreditMode::Direct => Self::Direct,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub struct AccountState {
    pub balance: u64,
    pub mode: CreditMode,
}

impl AccountState {
    /// Decodes a packed storage credit state word.
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

/// TIP-1060 storage credits precompile, which tracks per-account storage credit state.
///
/// Unlike the Solidity-compatible `Mapping<Address, GasState>` layout, account state is stored
/// directly at the account-derived slot: the 20-byte address is left-padded to 32 bytes and used
/// as the storage key, avoiding hashing on the SSTORE gas-state hook hot path.
///
/// ```text
/// storage_credit_slot = uint256(bytes32(account))
/// solidity_mapping_slot = keccak256(abi.encode(account, base_slot))
/// ```
#[contract(addr = STORAGE_CREDITS_ADDRESS)]
pub struct TIP1060StorageCredits {}

impl TIP1060StorageCredits {
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
        state.mode = CreditMode::try_from(mode)?;
        self.write_state_of(msg_sender, state)?;

        self.emit_event(TIP1060StorageCreditsEvent::mode_updated(msg_sender, mode))
    }

    #[inline]
    pub fn slot(account: Address) -> U256 {
        U256::from_be_bytes(account.into_word().0)
    }
}
