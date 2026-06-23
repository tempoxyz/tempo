//! Storage credits precompile (TIP-1060).

pub mod accounting;
pub mod dispatch;

pub use accounting::{StorageCreditsBackend, StorageCreditsErr, sstore_storage_credits};

use crate::{
    ACCOUNT_KEYCHAIN_ADDRESS, STORAGE_CREDITS_ADDRESS,
    account_keychain::AccountKeychain,
    error::{Result, TempoPrecompileError},
    storage::{Handler, LayoutCtx, StorableType, StorageCtx},
    tip20::TIP20Token,
};
use alloy::primitives::{Address, U256};
use std::{cell::OnceCell, collections::BTreeMap};
use tempo_contracts::precompiles::{IStorageCredits::Mode, StorageCreditsError};
use tempo_precompiles_macros::{Storable, contract};

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
    /// Current storage creation mode for this account within the transaction.
    pub mode: CreditMode,
    /// Remaining number of credits that may be spent directly in `Direct` mode.
    pub budget: u64,
    /// Number of Refund-mode storage creations pending end-of-transaction settlement.
    pub pending_refunds: u64,
}

impl TryFrom<U256> for TransientState {
    type Error = TempoPrecompileError;

    #[inline]
    fn try_from(value: U256) -> Result<Self> {
        let limbs = value.as_limbs();
        Ok(Self {
            mode: (limbs[0] as u8).try_into()?,
            budget: limbs[1],
            pending_refunds: limbs[3],
        })
    }
}

impl From<TransientState> for U256 {
    #[inline]
    fn from(value: TransientState) -> Self {
        Self::from_limbs([value.mode as u64, value.budget, 0, value.pending_refunds])
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
pub struct StorageCredits {}

impl StorageCredits {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn balance_of(&self, account: Address) -> Result<u64> {
        self.handler::<u64>(account).read()
    }

    /// Runs `f` and returns its value plus the number of credits minted for `account`.
    ///
    /// A negative delta means the operation consumed credits where the caller expected
    /// a mint-only/no-op operation, so it is treated as a fatal bookkeeping error.
    pub fn track_minted_credits<T>(
        &self,
        account: Address,
        f: impl FnOnce() -> Result<T>,
    ) -> Result<(T, u64)> {
        if !StorageCtx.spec().is_t7() {
            return f().map(|value| (value, 0));
        }

        let before = self.balance_of(account)?;
        let value = f()?;
        let after = self.balance_of(account)?;
        if after < before {
            return Err(TempoPrecompileError::Fatal(format!(
                "storage credit operation for owner {account} consumed credits (before: {before}, after: {after})"
            )));
        }

        Ok((value, after - before))
    }

    pub fn mode_of(&self, account: Address) -> Result<CreditMode> {
        self.credit_state_of(account).map(|state| state.mode)
    }

    pub fn budget_of(&self, account: Address) -> Result<u64> {
        self.credit_state_of(account).map(|state| state.budget)
    }

    /// Sets the transaction-local storage-creation mode for the caller.
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

    /// Runs `f` while allowing at most `limit` synchronous TIP-1060 storage-credit consumptions
    /// from `credit_owner`'s balance, returning the signed persistent credit-balance delta.
    ///
    /// Assumes callers enter with `credit_owner` in `Preserve` mode. Any unspent budget is cleared
    /// before this returns so later storage writes cannot consume the remaining allowance.
    pub fn with_budget<T>(
        &mut self,
        credit_owner: Address,
        limit: u64,
        f: impl FnOnce() -> Result<T>,
    ) -> Result<(T, i128)> {
        if !StorageCtx.spec().is_t7() {
            return f().map(|value| (value, 0));
        }

        if limit == 0 {
            let before = self.balance_of(credit_owner)?;
            let value = f()?;
            let after = self.balance_of(credit_owner)?;
            return Ok((value, i128::from(after) - i128::from(before)));
        }

        self.set_budget(credit_owner, limit)?;

        let before = self.balance_of(credit_owner)?;
        let result = f();
        let after = self.balance_of(credit_owner)?;
        let delta = i128::from(after) - i128::from(before);

        // After `f` has been applied and accounting is done, reset to `Preserve`.
        let current_state = self.credit_state_of(credit_owner)?;
        let state = TransientState {
            budget: 0,
            mode: CreditMode::Preserve,
            pending_refunds: current_state.pending_refunds,
        };
        self.write_credit_state_of(credit_owner, state)?;

        result.map(|value| (value, delta))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageCreditDeltas(BTreeMap<Address, u64>);

impl StorageCreditDeltas {
    pub fn new() -> Self {
        Self(BTreeMap::default())
    }

    /// Adds `slots` reusable-storage credits earned by `user`.
    ///
    /// This intentionally records only a delta. The persisted counter is loaded once during
    /// [`Self::flush`], outside the fill loop and only if the enclosing DEX operation succeeds.
    pub fn credit_slots(&mut self, user: Address, slots: u64) {
        if slots == 0 {
            return;
        }

        self.0
            .entry(user)
            .and_modify(|total| *total = total.saturating_add(slots))
            .or_insert(slots);
    }

    pub fn flush(self, mut apply: impl FnMut(Address, u64) -> Result<()>) -> Result<()> {
        for (user, slots) in self.0 {
            apply(user, slots)?;
        }

        Ok(())
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
        let mut slots = NonCreditableSlots::empty();
        slots.initialize(fee_payer, fee_token, None);

        let fee_balance_slot =
            TIP20Token::from_address_unchecked(fee_token).balances[fee_payer].slot();
        assert!(slots.is_non_creditable_slot(fee_token, fee_balance_slot));
        assert!(!slots.is_non_creditable_slot(fee_token, fee_balance_slot + U256::ONE));
    }

    #[test]
    fn non_creditable_slots_match_keychain_limit_slot() {
        let fee_payer = Address::repeat_byte(0x16);
        let key_id = Address::repeat_byte(0x17);
        let fee_token = crate::PATH_USD_ADDRESS;
        let mut slots = NonCreditableSlots::empty();
        slots.initialize(fee_payer, fee_token, Some(key_id));

        let keychain = AccountKeychain::new();
        let limit_key = AccountKeychain::spending_limit_key(fee_payer, key_id);
        let remaining_slot = keychain.spending_limits[limit_key][fee_token]
            .remaining
            .slot();
        assert!(slots.is_non_creditable_slot(ACCOUNT_KEYCHAIN_ADDRESS, remaining_slot));
        assert!(
            !slots.is_non_creditable_slot(ACCOUNT_KEYCHAIN_ADDRESS, remaining_slot + U256::ONE)
        );
    }

    #[test]
    fn non_creditable_slots_clear_resets_bookkeeping_slots() {
        let fee_payer = Address::repeat_byte(0x20);
        let key_id = Address::repeat_byte(0x21);
        let fee_token = crate::PATH_USD_ADDRESS;
        let mut slots = NonCreditableSlots::empty();
        slots.initialize(fee_payer, fee_token, Some(key_id));

        let fee_balance_slot =
            TIP20Token::from_address_unchecked(fee_token).balances[fee_payer].slot();
        assert!(slots.is_non_creditable_slot(fee_token, fee_balance_slot));

        slots.clear();

        assert!(!slots.is_non_creditable_slot(fee_token, fee_balance_slot));
    }
}
