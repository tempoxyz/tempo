//! Storage credits precompile (TIP-1060).

pub mod accounting;
pub mod dispatch;

pub use accounting::{StorageCreditsBackend, StorageCreditsErr, sstore_storage_credits};

use crate::{
    ACCOUNT_KEYCHAIN_ADDRESS, STORAGE_CREDITS_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::{Handler, LayoutCtx, StorableType},
    tip_fee_manager::TipFeeManager,
    tip20::TIP20Token,
};
use alloy::primitives::{Address, U256};
use std::{cell::Cell, rc::Rc};
use tempo_contracts::precompiles::{IStorageCredits::Mode, StorageCreditsError};
use tempo_precompiles_macros::{Storable, contract};

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

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Storable)]
pub enum CreditMode {
    #[default]
    Refund,
    Preserve,
    Direct,
}

/// Concrete transaction-local protocol bookkeeping slots whose clears must not mint storage credits.
pub type NonCreditableSlot = [(Address, U256); 3];

#[inline]
pub fn non_creditable_slots() -> Rc<Cell<NonCreditableSlot>> {
    Rc::new(Cell::new([(Address::ZERO, U256::ZERO); 3]))
}

pub fn set_fee_bookkeeping_slots(
    slots: &Rc<Cell<NonCreditableSlot>>,
    fee_token: Address,
    fee_payer: Address,
    beneficiary: Address,
    validator_token: Address,
) {
    let mut entries = slots.get();
    entries[0] = (
        fee_token,
        TIP20Token::from_address_unchecked(fee_token).balances[fee_payer].slot(),
    );
    entries[1] = (
        TIP_FEE_MANAGER_ADDRESS,
        TipFeeManager::new().collected_fees[beneficiary][validator_token].slot(),
    );
    slots.set(entries);
}

pub fn set_keychain_limit_slot(
    slots: &Rc<Cell<NonCreditableSlot>>,
    fee_payer: Address,
    key_id: Address,
    fee_token: Address,
) {
    let keychain = AccountKeychain::new();
    let limit_key = AccountKeychain::spending_limit_key(fee_payer, key_id);
    let mut entries = slots.get();
    entries[2] = (
        ACCOUNT_KEYCHAIN_ADDRESS,
        keychain.spending_limits[limit_key][fee_token]
            .remaining
            .slot(),
    );
    slots.set(entries);
}

#[inline]
pub fn contains_non_creditable_slot(slots: NonCreditableSlot, owner: Address, slot: U256) -> bool {
    slots
        .into_iter()
        .any(|(entry_owner, entry_slot)| entry_owner == owner && entry_slot == slot)
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
/// Transaction-local mode, direct-spend budget, and pending Refund creations live transiently at
/// the account-space slot.
#[contract(addr = STORAGE_CREDITS_ADDRESS)]
pub struct StorageCredits {}

impl StorageCredits {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn balance_of(&self, account: Address) -> Result<u64> {
        self.handler::<u64>(account).read()
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

    /// Returns the storage credit balance/state key for `account`.
    #[inline]
    pub fn slot(account: Address) -> U256 {
        U256::from_be_bytes(account.into_word().0)
    }

    /// Returns a full-slot handler for the account's storage-credit balance/state.
    #[inline]
    fn handler<T: StorableType>(&self, account: Address) -> T::Handler {
        T::handle(Self::slot(account), LayoutCtx::FULL, self.address)
    }

    #[inline]
    fn credit_state_of(&self, account: Address) -> Result<TransientState> {
        self.handler::<U256>(account).t_read()?.try_into()
    }

    #[inline]
    fn write_credit_state_of(&mut self, account: Address, state: TransientState) -> Result<()> {
        self.handler::<U256>(account).t_write(state.into())
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
        })
    }
}

impl From<TransientState> for U256 {
    #[inline]
    fn from(value: TransientState) -> Self {
        Self::from_limbs([value.budget, value.mode as u64, value.pending_refunds, 0])
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
    fn non_creditable_slots_match_fee_bookkeeping_slots() {
        let fee_token = crate::PATH_USD_ADDRESS;
        let fee_payer = Address::repeat_byte(0x13);
        let beneficiary = Address::repeat_byte(0x14);
        let validator_token = Address::repeat_byte(0x15);
        let slots = non_creditable_slots();
        set_fee_bookkeeping_slots(&slots, fee_token, fee_payer, beneficiary, validator_token);
        let slots = slots.get();

        let fee_balance_slot =
            TIP20Token::from_address_unchecked(fee_token).balances[fee_payer].slot();
        assert!(contains_non_creditable_slot(
            slots,
            fee_token,
            fee_balance_slot
        ));
        assert!(!contains_non_creditable_slot(
            slots,
            fee_token,
            fee_balance_slot + U256::ONE
        ));

        let collected_fees_slot =
            TipFeeManager::new().collected_fees[beneficiary][validator_token].slot();
        assert!(contains_non_creditable_slot(
            slots,
            TIP_FEE_MANAGER_ADDRESS,
            collected_fees_slot
        ));
        assert!(!contains_non_creditable_slot(
            slots,
            TIP_FEE_MANAGER_ADDRESS,
            collected_fees_slot + U256::ONE
        ));
    }

    #[test]
    fn non_creditable_slots_match_keychain_limit_slot() {
        let fee_payer = Address::repeat_byte(0x16);
        let key_id = Address::repeat_byte(0x17);
        let fee_token = crate::PATH_USD_ADDRESS;
        let slots = non_creditable_slots();
        set_keychain_limit_slot(&slots, fee_payer, key_id, fee_token);
        let slots = slots.get();

        let keychain = AccountKeychain::new();
        let limit_key = AccountKeychain::spending_limit_key(fee_payer, key_id);
        let remaining_slot = keychain.spending_limits[limit_key][fee_token]
            .remaining
            .slot();
        assert!(contains_non_creditable_slot(
            slots,
            ACCOUNT_KEYCHAIN_ADDRESS,
            remaining_slot
        ));
        assert!(!contains_non_creditable_slot(
            slots,
            ACCOUNT_KEYCHAIN_ADDRESS,
            remaining_slot + U256::ONE
        ));
    }
}
