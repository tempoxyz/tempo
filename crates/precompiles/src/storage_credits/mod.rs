//! Storage credits precompile (TIP-1060).

pub mod accounting;
pub mod dispatch;

pub use accounting::{StorageCreditsBackend, StorageCreditsErr, sstore_storage_credits};

use crate::{
    STORAGE_CREDITS_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{FromWord, Handler, LayoutCtx, StorableType},
};
use alloy::primitives::{Address, U256};
use tempo_contracts::precompiles::{IStorageCredits::Mode, StorageCreditsError};
use tempo_precompiles_macros::{Storable, contract};

/// Storage space for per-account persistent balance and transaction-local credit state.
pub const ACCOUNT_SPACE: u8 = 0;
/// Storage space for the transaction-local post-tx-restorable watch status.
pub const DEFERRED_CLEAR_STATUS_SPACE: u8 = 1;
/// Storage space for the transaction-local post-tx-restorable watched slot key.
pub const DEFERRED_CLEAR_SLOT_SPACE: u8 = 2;

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub(crate) enum DeferredClear {
    #[default]
    Unwatched,
    Watched,
    Pending,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub enum CreditMode {
    #[default]
    Refund,
    Preserve,
    Direct,
}

// NOTE: Can't leverage `Storable` because `StorageCtx` only exists during precompile execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransientState {
    /// Remaining number of credits that may be spent directly in `Direct` mode.
    pub budget: u64,
    /// Current storage creation mode for this account within the transaction.
    pub mode: CreditMode,
    /// Number of Refund-mode storage creations pending end-of-transaction settlement.
    pub pending_refunds: u64,
}

impl TryFrom<U256> for TransientState {
    type Error = TempoPrecompileError;

    #[inline]
    fn try_from(value: U256) -> Result<Self> {
        let limbs = value.as_limbs();
        Ok(Self {
            budget: limbs[0],
            mode: (limbs[1] as u8).try_into()?,
            pending_refunds: limbs[3],
        })
    }
}

impl From<TransientState> for U256 {
    #[inline]
    fn from(value: TransientState) -> Self {
        Self::from_limbs([value.budget, value.mode as u64, 0, value.pending_refunds])
    }
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
/// Transaction-local mode, direct-spend budget, and pending Refund creations live transiently at the
/// account-space slot. Post-tx fee bookkeeping can also watch one restorable slot per owner with
/// transient status/slot words; watched clears mint only if finalization sees the slot zero.
#[contract(addr = STORAGE_CREDITS_ADDRESS)]
pub struct StorageCredits {}

impl StorageCredits {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn balance_of(&self, account: Address) -> Result<u64> {
        self.slot_handler::<u64>(ACCOUNT_SPACE, account).read()
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
    pub fn is_deferred_clear_space(key: U256) -> bool {
        let bytes = key.to_be_bytes::<32>();
        bytes[0] != ACCOUNT_SPACE
    }

    /// Returns a full-slot handler in the selected storage-credit namespace.
    #[inline]
    fn slot_handler<T: StorableType>(&self, storage_space: u8, account: Address) -> T::Handler {
        T::handle(
            Self::slot(storage_space, account),
            LayoutCtx::FULL,
            self.address,
        )
    }

    /// Registers a storage slot whose clear credit must be finalized after post-tx fee writes.
    pub fn watch_deferred_clear_slot(&mut self, account: Address, slot: U256) -> Result<()> {
        let status = self
            .slot_handler::<DeferredClear>(DEFERRED_CLEAR_STATUS_SPACE, account)
            .t_read()?;
        if status != DeferredClear::Unwatched {
            let current = self
                .slot_handler::<U256>(DEFERRED_CLEAR_SLOT_SPACE, account)
                .t_read()?;
            if current == slot {
                return Ok(());
            }

            return Err(TempoPrecompileError::Fatal(
                "multiple TIP-1060 post-tx watched slots for one account".to_string(),
            ));
        }

        self.slot_handler::<DeferredClear>(DEFERRED_CLEAR_STATUS_SPACE, account)
            .t_write(DeferredClear::Watched)?;
        self.slot_handler::<U256>(DEFERRED_CLEAR_SLOT_SPACE, account)
            .t_write(slot)
    }

    /// Finalizes the pending watched clear for `account` after post-tx fee writes have run.
    ///
    /// A watched clear mints a storage credit only if its final persistent slot value is zero.
    /// If the slot is recreated post-tx, the pending clear is discarded. Returns the minted credits.
    pub fn finalize_deferred_clears(&mut self, account: Address) -> Result<u64> {
        let status = self
            .slot_handler::<DeferredClear>(DEFERRED_CLEAR_STATUS_SPACE, account)
            .t_read()?;
        if status == DeferredClear::Unwatched {
            return Ok(0);
        }

        let minted = if status == DeferredClear::Pending {
            let watched_slot = self
                .slot_handler::<U256>(DEFERRED_CLEAR_SLOT_SPACE, account)
                .t_read()?;
            let final_value = U256::handle(watched_slot, LayoutCtx::FULL, account).read()?;
            u64::from(final_value.is_zero())
        } else {
            0
        };

        if minted > 0 {
            let mut handler = self.slot_handler::<u64>(ACCOUNT_SPACE, account);
            let balance = handler.read()?;
            handler.write(balance.saturating_add(minted))?;
        }

        self.slot_handler::<DeferredClear>(DEFERRED_CLEAR_STATUS_SPACE, account)
            .t_write(DeferredClear::Unwatched)?;
        Ok(minted)
    }

    #[inline]
    fn credit_state_of(&self, account: Address) -> Result<TransientState> {
        self.slot_handler::<U256>(ACCOUNT_SPACE, account)
            .t_read()?
            .try_into()
    }

    #[inline]
    fn write_credit_state_of(&mut self, account: Address, state: TransientState) -> Result<()> {
        self.slot_handler::<U256>(ACCOUNT_SPACE, account)
            .t_write(state.into())
    }
}

impl TryFrom<u8> for DeferredClear {
    type Error = TempoPrecompileError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Unwatched),
            1 => Ok(Self::Watched),
            2 => Ok(Self::Pending),
            _ => Err(TempoPrecompileError::Fatal(
                "invalid TIP-1060 post-tx watch status".to_string(),
            )),
        }
    }
}

impl TryFrom<U256> for DeferredClear {
    type Error = TempoPrecompileError;

    #[inline]
    fn try_from(value: U256) -> Result<Self> {
        u8::from_word(value)?.try_into()
    }
}

impl From<DeferredClear> for U256 {
    #[inline]
    fn from(status: DeferredClear) -> Self {
        Self::from(status as u8)
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
    fn watch_deferred_clear_slot_deduplicates_and_preserves_zero_slot() -> eyre::Result<()> {
        let account = Address::repeat_byte(0x13);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();
            credits.watch_deferred_clear_slot(account, U256::ZERO)?;
            credits.watch_deferred_clear_slot(account, U256::ZERO)?;

            assert_eq!(
                credits
                    .slot_handler::<DeferredClear>(DEFERRED_CLEAR_STATUS_SPACE, account)
                    .t_read()?,
                DeferredClear::Watched
            );
            assert_eq!(
                credits
                    .slot_handler::<U256>(DEFERRED_CLEAR_SLOT_SPACE, account)
                    .t_read()?,
                U256::ZERO
            );
            assert!(
                credits
                    .watch_deferred_clear_slot(account, U256::from(1))
                    .is_err()
            );

            Ok(())
        })
    }

    #[test]
    fn finalize_deferred_clears_mints_only_when_slot_stays_zero() -> eyre::Result<()> {
        let account = Address::repeat_byte(0x14);
        let cleared_slot = U256::from(0x21);
        let restored_slot = U256::from(0x22);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();
            credits.watch_deferred_clear_slot(account, cleared_slot)?;
            credits
                .slot_handler::<DeferredClear>(DEFERRED_CLEAR_STATUS_SPACE, account)
                .t_write(DeferredClear::Pending)?;
            assert_eq!(credits.finalize_deferred_clears(account)?, 1);
            assert_eq!(credits.balance_of(account)?, 1);

            U256::handle(restored_slot, LayoutCtx::FULL, account).write(U256::ONE)?;
            credits.watch_deferred_clear_slot(account, restored_slot)?;
            credits
                .slot_handler::<DeferredClear>(DEFERRED_CLEAR_STATUS_SPACE, account)
                .t_write(DeferredClear::Pending)?;
            assert_eq!(credits.finalize_deferred_clears(account)?, 0);
            assert_eq!(credits.balance_of(account)?, 1);

            Ok(())
        })
    }
}
