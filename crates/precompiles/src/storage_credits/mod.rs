//! Storage credits precompile (TIP-1060).

pub mod accounting;
pub mod dispatch;

pub use accounting::{
    StorageCreditsBackend, StorageCreditsErr, sstore_storage_credits, update_deferred_refund_status,
};

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
/// Storage space for the transaction-local slot that post-tx fee reimbursement may recreate.
pub const POST_TX_SPACE: u8 = 1;

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
    /// Whether same-tx refund settlement is deferred until post-tx fee reimbursement either restores
    /// the slot or leaves the clear persistent.
    pub deferred_refund: bool,
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
            deferred_refund: limbs[2] != 0,
            pending_refunds: limbs[3],
        })
    }
}

impl From<TransientState> for U256 {
    #[inline]
    fn from(value: TransientState) -> Self {
        Self::from_limbs([
            value.budget,
            value.mode as u64,
            u64::from(value.deferred_refund),
            value.pending_refunds,
        ])
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

    /// Returns a full-slot handler in the selected storage-credit namespace.
    #[inline]
    fn slot_handler<T: StorableType>(&self, storage_space: u8, account: Address) -> T::Handler {
        T::handle(
            Self::slot(storage_space, account),
            LayoutCtx::FULL,
            self.address,
        )
    }

    /// Returns true for transient candidate-slot keys that are not account credit state.
    #[inline]
    pub fn is_post_tx_space(key: U256) -> bool {
        let bytes = key.to_be_bytes::<32>();
        bytes[0] == POST_TX_SPACE
    }

    /// Registers a slot whose same-tx refund may be deferred for post-tx fee reimbursement.
    pub fn watch_deferred_refund(&mut self, account: Address, slot: U256) -> Result<()> {
        self.slot_handler::<U256>(POST_TX_SPACE, account)
            .t_write(slot)
    }

    /// Cancels a deferred refund when post-tx fee reimbursement recreates the registered slot.
    pub fn cancel_deferred_refund(&mut self, account: Address, slot: U256) -> Result<bool> {
        let candidate = self.slot_handler::<U256>(POST_TX_SPACE, account).t_read()?;
        // No-op unless reimbursement recreates the exact registered slot.
        if candidate != slot {
            return Ok(false);
        }

        let mut state = self.credit_state_of(account)?;
        if !state.deferred_refund {
            return Ok(false);
        }

        let mut handler = self.slot_handler::<u64>(ACCOUNT_SPACE, account);
        let balance = handler.read()?;
        if balance > 0 {
            handler.write(balance - 1)?;
        }

        state.deferred_refund = false;
        self.write_credit_state_of(account, state)?;
        Ok(balance > 0)
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
}
