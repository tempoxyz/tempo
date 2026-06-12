//! Storage credits precompile (TIP-1060).

pub mod dispatch;
pub mod gas_state;

pub use gas_state::{StorageCreditsBackend, StorageCreditsError, sstore_storage_credits};

use crate::{
    STORAGE_CREDITS_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, LayoutCtx, Mapping, StorableType, StorageCtx},
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

/// Per-user reusable storage credit state accumulated by a precompile call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageCreditAccount {
    pub user: Address,
    pub amount: u64,
}

impl StorageCreditAccount {
    pub fn new(user: Address, amount: u64) -> Self {
        Self { user, amount }
    }

    pub fn load(user: Address, credits: &Mapping<Address, u64>) -> Result<Option<Self>> {
        if !StorageCtx.spec().is_t7() {
            return Ok(None);
        }

        Ok(Some(Self::new(user, credits[user].read()?)))
    }

    fn with_budget<T>(
        credit_owner: Address,
        budget: u64,
        f: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut storage_credits = TIP1060StorageCredits::new();
        storage_credits.set_budget(credit_owner, budget)?;

        let result = f();
        let remaining_budget = storage_credits.credit_state_of(credit_owner)?.budget;

        match result {
            Ok(value) if remaining_budget == 0 => Ok(value),
            Ok(_) => Err(TempoPrecompileError::Fatal(
                "TIP-1060 direct budget was not fully consumed".to_string(),
            )),
            Err(err) => Err(err),
        }
    }

    /// Runs `write_storage` while allowing up to `slots.min(self.amount)` TIP-1060 token
    /// consumptions from `credit_owner`'s storage-credit balance.
    ///
    /// If all credits are spent, this clears the counter slot first so the credit embodied by that
    /// nonzero slot becomes available for the storage creation.
    pub fn spend<T>(
        &mut self,
        slots: u64,
        credit_owner: Address,
        credits: &mut Mapping<Address, u64>,
        write_storage: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let budget = self.amount.min(slots);
        if budget == 0 {
            return write_storage();
        }

        let old = *self;
        self.amount -= budget;
        credits[self.user].write(self.amount)?;

        match Self::with_budget(credit_owner, budget, write_storage) {
            Ok(value) => Ok(value),
            Err(err) => {
                *self = old;
                Err(err)
            }
        }
    }

    pub fn add(
        &mut self,
        slots: u64,
        credit_owner: Address,
        credits: &mut Mapping<Address, u64>,
    ) -> Result<()> {
        let was_empty = self.amount == 0;
        self.amount = self.amount.saturating_add(slots);

        if was_empty && self.amount > 0 {
            Self::with_budget(credit_owner, 1, || credits[self.user].write(self.amount))
        } else {
            credits[self.user].write(self.amount)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageCreditDeltas {
    enabled: bool,
    deltas: Vec<(Address, u64)>,
}

impl StorageCreditDeltas {
    pub fn new() -> Self {
        Self {
            enabled: StorageCtx.spec().is_t7(),
            deltas: Vec::new(),
        }
    }

    /// Adds `slots` reusable-storage credits earned by `user`.
    ///
    /// This intentionally records only a delta. The persisted counter is loaded once during
    /// [`Self::flush`], outside the fill loop and only if the enclosing DEX operation succeeds.
    pub fn credit_slots(&mut self, user: Address, slots: u64) {
        if slots == 0 || !self.enabled {
            return;
        }

        self.deltas.push((user, slots));
    }

    pub fn flush(
        mut self,
        credit_owner: Address,
        credits: &mut Mapping<Address, u64>,
    ) -> Result<()> {
        self.deltas.sort_by_key(|(user, _)| *user);

        for group in self.deltas.chunk_by(|a, b| a.0 == b.0) {
            let user = group[0].0;
            let slots = group
                .iter()
                .fold(0u64, |total, (_, slots)| total.saturating_add(*slots));
            StorageCreditAccount::new(user, credits[user].read()?).add(
                slots,
                credit_owner,
                credits,
            )?;
        }

        Ok(())
    }
}
