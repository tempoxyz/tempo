//! Storage credits precompile (TIP-1060).

pub mod accounting;
pub mod dispatch;

pub use accounting::{StorageCreditsBackend, StorageCreditsErr, sstore_storage_credits};

use crate::{
    STORAGE_CREDITS_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, LayoutCtx, StorableType},
};
use alloy::primitives::{Address, U256};
use tempo_contracts::precompiles::{IStorageCredits::Mode, StorageCreditsError};
use tempo_precompiles_macros::{Storable, contract};

/// Storage space for per-account persistent balance and transaction-local credit state.
pub const ACCOUNT_SPACE: u8 = 0;
/// Storage space for the transaction-local storage slot whose clear must not mint a credit.
pub const NO_CREDIT_SLOT_SPACE: u8 = 1;

// NOTE: Can't leverage `Storable` because `StorageCtx` only exists during precompile execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransientState {
    /// Remaining number of credits that may be spent directly in `Direct` mode.
    pub budget: u64,
    /// Current storage creation mode for this account within the transaction.
    pub mode: CreditMode,
    /// Number of Refund-mode storage creations pending end-of-transaction settlement.
    pub pending_refunds: u64,
    /// Whether this account has a transaction-local slot whose clear must not mint a credit.
    pub has_non_creditable_slot: bool,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub enum CreditMode {
    #[default]
    Refund,
    Preserve,
    Direct,
}

/// TIP-1060 storage credits precompile, tracking each storage owner's credit balance and tx state.
///
/// Unlike the Solidity-compatible `Mapping<K, V>` layout, persistent credit balances are stored
/// directly at a namespaced account-derived slot: the 20-byte address is left-padded to 32 bytes
/// and used as the storage key, avoiding hashing on the SSTORE gas-state hook hot path.
///
/// ```text
/// storage_credit_slot = (uint256(uint8(space)) << 248) | uint160(account)
/// solidity_mapping_slot = keccak256(abi.encode(account, base_slot))
/// ```
///
/// Transaction-local mode, direct-spend budget, pending Refund creations, and whether this account
/// has a slot whose clear must not mint a credit live transiently at the account-space slot.
/// Post-tx fee bookkeeping can also register one storage slot per owner whose clear must not mint
/// storage credits during the transaction.
#[contract(addr = STORAGE_CREDITS_ADDRESS)]
pub struct StorageCredits {}

impl StorageCredits {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn balance_of(&self, account: Address) -> Result<u64> {
        self.handler::<u64>(ACCOUNT_SPACE, account).read()
    }

    pub fn mode_of(&self, account: Address) -> Result<CreditMode> {
        self.credit_state_of(account).map(|state| state.mode)
    }

    pub fn budget_of(&self, account: Address) -> Result<u64> {
        self.credit_state_of(account).map(|state| state.budget)
    }

    pub fn set_mode(&mut self, msg_sender: Address, mode: Mode) -> Result<()> {
        let mode = CreditMode::try_from(mode)?;
        let budget = if matches!(mode, CreditMode::Direct) {
            u64::MAX
        } else {
            0
        };

        self.write_mode_with_budget(msg_sender, mode, budget)
    }

    pub fn set_budget(&mut self, msg_sender: Address, credit_budget: u64) -> Result<()> {
        self.write_mode_with_budget(msg_sender, CreditMode::Direct, credit_budget)
    }

    fn write_mode_with_budget(
        &mut self,
        msg_sender: Address,
        mode: CreditMode,
        budget: u64,
    ) -> Result<()> {
        let mut state = self.credit_state_of(msg_sender)?;
        state.mode = mode;
        state.budget = budget;
        self.write_credit_state_of(msg_sender, state)
    }

    /// Returns the storage key for `account` within a storage-credit namespace.
    #[inline]
    pub fn slot(storage_space: u8, account: Address) -> U256 {
        let mut bytes = account.into_word().0;
        bytes[0] = storage_space;
        U256::from_be_bytes(bytes)
    }

    /// Returns true for storage-credit account-state keys.
    #[inline]
    pub fn is_account_space(key: U256) -> bool {
        let bytes = key.to_be_bytes::<32>();
        bytes[0] == ACCOUNT_SPACE
    }

    /// Returns a full-slot handler in the selected storage-credit namespace.
    #[inline]
    fn handler<T: StorableType>(&self, storage_space: u8, account: Address) -> T::Handler {
        T::handle(
            Self::slot(storage_space, account),
            LayoutCtx::FULL,
            self.address,
        )
    }

    /// Registers the single transaction-local storage slot whose clear must not mint a credit.
    pub fn mark_non_creditable_slot(&mut self, account: Address, slot: U256) -> Result<()> {
        let mut state = self.credit_state_of(account)?;
        if state.has_non_creditable_slot {
            let current = self
                .handler::<U256>(NO_CREDIT_SLOT_SPACE, account)
                .t_read()?;
            if current == slot {
                return Ok(());
            }

            return Err(TempoPrecompileError::Fatal(
                "multiple TIP-1060 non-creditable slots for one account".to_string(),
            ));
        }

        state.has_non_creditable_slot = true;
        self.write_credit_state_of(account, state)?;
        self.handler::<U256>(NO_CREDIT_SLOT_SPACE, account)
            .t_write(slot)
    }

    #[inline]
    fn credit_state_of(&self, account: Address) -> Result<TransientState> {
        self.handler::<U256>(ACCOUNT_SPACE, account)
            .t_read()?
            .try_into()
    }

    #[inline]
    fn write_credit_state_of(&mut self, account: Address, state: TransientState) -> Result<()> {
        self.handler::<U256>(ACCOUNT_SPACE, account)
            .t_write(state.into())
    }
}

impl TryFrom<U256> for TransientState {
    type Error = TempoPrecompileError;

    #[inline]
    fn try_from(value: U256) -> Result<Self> {
        let limbs = value.as_limbs();
        Ok(Self {
            budget: limbs[0],
            mode: (limbs[1] as u8).try_into()?,
            pending_refunds: limbs[2],
            has_non_creditable_slot: limbs[3] != 0,
        })
    }
}

impl From<TransientState> for U256 {
    #[inline]
    fn from(value: TransientState) -> Self {
        Self::from_limbs([
            value.budget,
            value.mode as u64,
            value.pending_refunds,
            u64::from(value.has_non_creditable_slot),
        ])
    }
}

impl TryFrom<u8> for CreditMode {
    type Error = TempoPrecompileError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Refund),
            1 => Ok(Self::Preserve),
            2 => Ok(Self::Direct),
            _ => Err(StorageCreditsError::invalid_mode().into()),
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
            _ => Err(StorageCreditsError::invalid_mode().into()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};

    #[test]
    fn test_set_mode_budget_semantics() -> eyre::Result<()> {
        let account = Address::repeat_byte(0x11);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();

            assert_eq!(credits.mode_of(account)?, CreditMode::Refund);
            assert_eq!(credits.budget_of(account)?, 0);

            credits.set_mode(account, Mode::Direct)?;
            assert_eq!(credits.mode_of(account)?, CreditMode::Direct);
            assert_eq!(credits.budget_of(account)?, u64::MAX);

            credits.set_mode(account, Mode::Preserve)?;
            assert_eq!(credits.mode_of(account)?, CreditMode::Preserve);
            assert_eq!(credits.budget_of(account)?, 0);

            credits.set_mode(account, Mode::Refund)?;
            assert_eq!(credits.mode_of(account)?, CreditMode::Refund);
            assert_eq!(credits.budget_of(account)?, 0);

            Ok(())
        })
    }

    #[test]
    fn test_set_budget_zero_stays_direct_with_zero_budget() -> eyre::Result<()> {
        let account = Address::repeat_byte(0x12);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();

            credits.set_budget(account, 2)?;
            assert_eq!(credits.mode_of(account)?, CreditMode::Direct);
            assert_eq!(credits.budget_of(account)?, 2);

            credits.set_budget(account, 0)?;
            assert_eq!(credits.mode_of(account)?, CreditMode::Direct);
            assert_eq!(credits.budget_of(account)?, 0);

            Ok(())
        })
    }

    #[test]
    fn mark_non_creditable_slot_deduplicates_and_preserves_zero_slot() -> eyre::Result<()> {
        let account = Address::repeat_byte(0x13);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();
            credits.mark_non_creditable_slot(account, U256::ZERO)?;
            credits.mark_non_creditable_slot(account, U256::ZERO)?;

            assert!(credits.credit_state_of(account)?.has_non_creditable_slot);
            assert_eq!(
                credits
                    .handler::<U256>(NO_CREDIT_SLOT_SPACE, account)
                    .t_read()?,
                U256::ZERO
            );
            assert!(
                credits
                    .mark_non_creditable_slot(account, U256::from(1))
                    .is_err()
            );

            Ok(())
        })
    }

    #[test]
    fn mark_non_creditable_slot_preserves_existing_transient_state() -> eyre::Result<()> {
        let account = Address::repeat_byte(0x14);
        let slot = U256::from(0x21);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();
            let mut state = credits.credit_state_of(account)?;
            state.mode = CreditMode::Direct;
            state.budget = 7;
            state.pending_refunds = 3;
            credits.write_credit_state_of(account, state)?;

            credits.mark_non_creditable_slot(account, slot)?;

            let state = credits.credit_state_of(account)?;
            assert_eq!(state.mode, CreditMode::Direct);
            assert_eq!(state.budget, 7);
            assert_eq!(state.pending_refunds, 3);
            assert!(state.has_non_creditable_slot);
            assert_eq!(
                credits
                    .handler::<U256>(NO_CREDIT_SLOT_SPACE, account)
                    .t_read()?,
                slot
            );

            Ok(())
        })
    }
}
