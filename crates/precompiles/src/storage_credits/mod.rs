//! Storage credits precompile (TIP-1060).

pub mod accounting;
pub mod dispatch;

pub use accounting::{StorageCreditsBackend, StorageCreditsErr, sstore_storage_credits};

use crate::{
    STORAGE_CREDITS_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, LayoutCtx, StorableType},
};
use alloy::primitives::{Address, B256, U256, b256, keccak256};
use tempo_contracts::precompiles::{IStorageCredits::Mode, StorageCreditsError};
use tempo_precompiles_macros::{Storable, contract};

const PENDING_SLOT_NAMESPACE: B256 =
    b256!("0x717645693e3410451934f75ab9e25a4bfe75ccddcb377d95400f6f995d59b83e");

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
    /// Fee-restorable clears pending final-state credit minting after post-tx fee reimbursement.
    pub pending_credits: u64,
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
            pending_credits: limbs[2],
            pending_refunds: limbs[3],
        })
    }
}

impl From<TransientState> for U256 {
    #[inline]
    fn from(value: TransientState) -> Self {
        Self::from_limbs([
            value.budget,
            u64::from(value.mode),
            value.pending_credits,
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
/// transient state at the same account-derived slot. Fee-restorable pending credit watchers use
/// `keccak256(PENDING_SLOT_NAMESPACE || account || slot)` transient marker slots, keeping them
/// visibly separate from spendable credit balances.
#[contract(addr = STORAGE_CREDITS_ADDRESS)]
pub struct StorageCredits {}

impl StorageCredits {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn balance_of(&self, account: Address) -> Result<u64> {
        u64::handle(Self::slot(account), LayoutCtx::FULL, self.address).read()
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

    #[inline]
    pub fn slot(account: Address) -> U256 {
        U256::from_be_bytes(account.into_word().0)
    }

    #[inline]
    pub fn pending_slot(account: Address, slot: U256) -> U256 {
        let mut bytes = [0u8; 84];
        bytes[..32].copy_from_slice(PENDING_SLOT_NAMESPACE.as_slice());
        bytes[32..52].copy_from_slice(account.as_slice());
        bytes[52..].copy_from_slice(&slot.to_be_bytes::<32>());
        U256::from_be_bytes(keccak256(bytes).0)
    }

    pub fn watch_pending_credit_slot(&mut self, account: Address, slot: U256) -> Result<()> {
        U256::handle(
            Self::pending_slot(account, slot),
            LayoutCtx::FULL,
            self.address,
        )
        .t_write(U256::ONE)
    }

    pub fn finalize_pending_credit(&mut self, account: Address, slot: U256) -> Result<u64> {
        let mut state = self.credit_state_of(account)?;
        let pending = state.pending_credits;
        if pending == 0 {
            return Ok(0);
        }

        let final_value = U256::handle(slot, LayoutCtx::FULL, account).read()?;
        let minted = if final_value.is_zero() { pending } else { 0 };

        if minted > 0 {
            let mut balance = u64::handle(Self::slot(account), LayoutCtx::FULL, self.address);
            let new_balance = balance.read()?.saturating_add(minted);
            balance.write(new_balance)?;
        }

        state.pending_credits = 0;
        self.write_credit_state_of(account, state)?;
        Ok(minted)
    }

    #[inline]
    fn credit_state_of(&self, account: Address) -> Result<TransientState> {
        U256::handle(Self::slot(account), LayoutCtx::FULL, self.address)
            .t_read()?
            .try_into()
    }

    #[inline]
    fn write_credit_state_of(&mut self, account: Address, state: TransientState) -> Result<()> {
        U256::handle(Self::slot(account), LayoutCtx::FULL, self.address).t_write(state.into())
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

impl From<CreditMode> for u64 {
    fn from(mode: CreditMode) -> Self {
        match mode {
            CreditMode::Refund => 0,
            CreditMode::Preserve => 1,
            CreditMode::Direct => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Handler, StorageCtx, hashmap::HashMapStorageProvider};

    #[test]
    fn pending_slot_namespace_is_keccak_domain_separator() {
        assert_eq!(PENDING_SLOT_NAMESPACE, keccak256(b"tip1060/pending"));
    }

    #[test]
    fn pending_slot_is_scoped_to_owner_and_storage_key() {
        let account = Address::repeat_byte(0x11);
        let other_account = Address::repeat_byte(0x22);
        let slot = U256::from(0x33);
        let other_slot = U256::from(0x44);
        let pending_slot = StorageCredits::pending_slot(account, slot);

        assert_ne!(StorageCredits::slot(account), pending_slot);
        assert_ne!(
            pending_slot,
            StorageCredits::pending_slot(other_account, slot)
        );
        assert_ne!(
            pending_slot,
            StorageCredits::pending_slot(account, other_slot)
        );
    }

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
    fn finalize_pending_credit_mints_only_when_watched_slot_stays_zero() -> eyre::Result<()> {
        let owner = Address::repeat_byte(0x22);
        let watched_slot = U256::from(0x33);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            let mut credits = StorageCredits::new();
            credits.watch_pending_credit_slot(owner, watched_slot)?;

            let mut state = credits.credit_state_of(owner)?;
            state.pending_credits = 1;
            credits.write_credit_state_of(owner, state)?;

            assert_eq!(credits.finalize_pending_credit(owner, watched_slot)?, 1);
            assert_eq!(credits.balance_of(owner)?, 1);
            assert_eq!(credits.credit_state_of(owner)?.pending_credits, 0);

            Ok(())
        })
    }

    #[test]
    fn finalize_pending_credit_drops_credit_when_watched_slot_is_restored() -> eyre::Result<()> {
        let owner = Address::repeat_byte(0x44);
        let watched_slot = U256::from(0x55);
        let mut storage = HashMapStorageProvider::new(1);

        StorageCtx::enter(&mut storage, || {
            U256::handle(watched_slot, LayoutCtx::FULL, owner).write(U256::ONE)?;

            let mut credits = StorageCredits::new();
            credits.watch_pending_credit_slot(owner, watched_slot)?;

            let mut state = credits.credit_state_of(owner)?;
            state.pending_credits = 1;
            credits.write_credit_state_of(owner, state)?;

            assert_eq!(credits.finalize_pending_credit(owner, watched_slot)?, 0);
            assert_eq!(credits.balance_of(owner)?, 0);
            assert_eq!(credits.credit_state_of(owner)?.pending_credits, 0);
            Ok(())
        })
    }
}
