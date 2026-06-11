//! Storage credits precompile (TIP-1060).

pub mod dispatch;
pub mod gas_state;

pub use gas_state::{STORAGE_CREDIT_VALUE, StorageCreditsBackend, sstore_storage_credits};

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
pub struct TransientState {
    pub budget: u64,
    pub mode: CreditMode,
    pub pending_refunds: u64,
}

impl TransientState {
    /// Decodes a packed transient state word.
    ///
    /// Layout:
    /// - bits `0..=63`: remaining direct-spend budget (`uint64`)
    /// - bits `64..=71`: storage creation mode
    /// - bits `128..=191`: pending refund-eligible creations (`uint64`)
    /// - remaining bits: reserved for future hardfork-gated extensions
    #[inline]
    pub fn from_word(value: U256) -> Result<Self> {
        // `U256` limbs are little-endian: limb 0 holds bits 0..=63,
        // limb 1 holds bits 64..=127.
        let limbs = value.as_limbs();
        Ok(Self {
            budget: limbs[0],
            mode: (limbs[1] as u8).try_into()?,
            pending_refunds: limbs[2],
        })
    }

    #[inline]
    pub fn into_word(self) -> U256 {
        U256::from_limbs([self.budget, self.mode as u64, self.pending_refunds, 0])
    }
}

/// TIP-1060 storage credits precompile, which tracks per-account storage credit state.
///
/// Unlike the Solidity-compatible `Mapping<Address, GasState>` layout, persistent account state is
/// stored directly at the account-derived slot: the 20-byte address is left-padded to 32 bytes and
/// used as the storage key, avoiding hashing on the SSTORE gas-state hook hot path.
///
/// ```text
/// storage_credit_slot = uint256(bytes32(account))
/// solidity_mapping_slot = keccak256(abi.encode(account, base_slot))
/// ```
///
/// Storage creation mode, direct-spend budget, and pending refund counters are transaction-local
/// transient state at the same account-derived slot.
#[contract(addr = STORAGE_CREDITS_ADDRESS)]
pub struct TIP1060StorageCredits {}

impl TIP1060StorageCredits {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn balance_of(&self, account: Address) -> Result<u64> {
        u64::handle(Self::slot(account), LayoutCtx::FULL, self.address).read()
    }

    pub fn mode_of(&self, account: Address) -> Result<CreditMode> {
        self.transient_state_of(account).map(|state| state.mode)
    }

    pub fn credit_budget_of(&self, account: Address) -> Result<u64> {
        self.transient_state_of(account).map(|state| state.budget)
    }

    pub fn set_mode(&mut self, msg_sender: Address, mode: Mode) -> Result<()> {
        let mode = CreditMode::try_from(mode)?;
        let budget = if matches!(mode, CreditMode::Direct) {
            u64::MAX
        } else {
            0
        };

        self.write_mode_with_budget(msg_sender, mode, budget)?;
        self.emit_event(TIP1060StorageCreditsEvent::mode_updated(
            msg_sender,
            mode.into(),
        ))
    }

    pub fn set_budget(&mut self, msg_sender: Address, credit_budget: u64) -> Result<()> {
        self.write_mode_with_budget(msg_sender, CreditMode::Direct, credit_budget)?;
        self.emit_event(TIP1060StorageCreditsEvent::mode_updated(
            msg_sender,
            Mode::Direct,
        ))
    }

    fn write_mode_with_budget(
        &mut self,
        msg_sender: Address,
        mode: CreditMode,
        budget: u64,
    ) -> Result<()> {
        let mut state = self.transient_state_of(msg_sender)?;
        state.mode = mode;
        state.budget = budget;
        self.write_transient_state_of(msg_sender, state)
    }

    #[inline]
    pub fn slot(account: Address) -> U256 {
        U256::from_be_bytes(account.into_word().0)
    }

    #[inline]
    fn transient_state_of(&self, account: Address) -> Result<TransientState> {
        TransientState::handle(Self::slot(account), LayoutCtx::FULL, self.address).t_read()
    }

    #[inline]
    fn write_transient_state_of(&mut self, account: Address, state: TransientState) -> Result<()> {
        TransientState::handle(Self::slot(account), LayoutCtx::FULL, self.address).t_write(state)
    }
}
