//! Storage credits precompile (TIP-1060).

pub mod dispatch;
pub mod gas_state;

pub use gas_state::{STORAGE_CREDIT_VALUE, StorageCreditsBackend, sstore_storage_credits};

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransientState {
    /// Remaining direct-spend budget for Direct mode. If applicable.
    pub budget: u64,
    /// Credit Mode.
    pub mode: CreditMode,
    // Pending refund-eligible creations for Refund mode.
    pub pending_refunds: u64,
}

impl TransientState {
    /// Decodes a packed transient state word.
    ///
    /// Layout:
    /// - bits `0..=63`: remaining direct-spend budget (`uint64`)
    /// - bits `64..=71`: storage creation mode
    /// - bits `128..=191`: pending refund-eligible creations (`uint64`)
    /// - all other bits: reserved for future hardfork-gated extensions
    #[inline]
    pub fn from_word(value: U256) -> Result<Self> {
        // `U256` limbs are little-endian: limb 0 holds bits 0..=63,
        // limb 1 holds bits 64..=127, limb 2 holds bits 128..=191.
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

    /// Sets the transaction-local storage-creation mode for the caller.
    pub fn set_mode(&mut self, msg_sender: Address, mode: Mode) -> Result<()> {
        let mode = CreditMode::try_from(mode)?;
        let budget = if matches!(mode, CreditMode::Direct) {
            u64::MAX
        } else {
            0
        };
        if self.write_mode_with_budget(msg_sender, mode, budget)? {
            self.emit_event(TIP1060StorageCreditsEvent::mode_updated(
                msg_sender,
                mode.into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Sets a transaction-local Direct budget for the caller.
    ///
    /// A positive budget switches to `Direct` and allows at most `credits` credit-backed storage
    /// creates. A zero budget switches to `Preserve`, matching the post-exhaustion behavior.
    pub fn set_budget(&mut self, msg_sender: Address, credits: u64) -> Result<()> {
        let mode = if credits == 0 {
            CreditMode::Preserve
        } else {
            CreditMode::Direct
        };

        if self.write_mode_with_budget(msg_sender, mode, credits)? {
            self.emit_event(TIP1060StorageCreditsEvent::mode_updated(
                msg_sender,
                mode.into(),
            ))?;
        }
        Ok(())
    }

    fn write_mode_with_budget(
        &mut self,
        account: Address,
        mode: CreditMode,
        budget: u64,
    ) -> Result<bool> {
        let (mode, budget) = match (mode, budget) {
            (CreditMode::Direct, 0) => (CreditMode::Preserve, 0),
            (CreditMode::Direct, budget) => (CreditMode::Direct, budget),
            (mode, _) => (mode, 0),
        };

        let mut state = self.transient_state_of(account)?;
        if state.mode == mode && state.budget == budget {
            return Ok(false);
        }

        state.mode = mode;
        state.budget = budget;
        self.write_transient_state_of(account, state)?;
        Ok(true)
    }

    #[inline]
    pub fn slot(account: Address) -> U256 {
        U256::from_be_bytes(account.into_word().0)
    }

    #[inline]
    fn transient_state_of(&self, account: Address) -> Result<TransientState> {
        TransientState::from_word(self.storage.tload(self.address, Self::slot(account))?)
    }

    #[inline]
    fn write_transient_state_of(&mut self, account: Address, state: TransientState) -> Result<()> {
        self.storage
            .tstore(self.address, Self::slot(account), state.into_word())
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

    pub fn load(
        user: Address,
        read_credit: impl FnOnce(Address) -> Result<u64>,
    ) -> Result<Option<Self>> {
        if !StorageCtx.spec().is_t7() {
            return Ok(None);
        }

        Ok(Some(Self::new(user, read_credit(user)?)))
    }

    fn with_budget<T>(
        credit_owner: Address,
        budget: u64,
        f: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut storage_credits = TIP1060StorageCredits::new();
        storage_credits.set_budget(credit_owner, budget)?;

        let result = f();
        let remaining_budget = storage_credits.transient_state_of(credit_owner)?.budget;

        match result {
            Ok(value) if remaining_budget == 0 => Ok(value),
            Ok(_) => Err(TempoPrecompileError::Fatal(
                "TIP-1060 direct budget was not fully consumed".to_string(),
            )),
            Err(err) => Err(err),
        }
    }

    /// Runs `write_storage` while allowing up to `slots.min(budget)` TIP-1060 token consumptions
    /// from `credit_owner`'s storage-credit balance.
    ///
    /// If spending all credits, the `dex_storage_credits[user]` counter is cleared first so the
    /// credit embodied by that nonzero counter slot becomes available for the storage creation.
    pub fn spend<T>(
        &mut self,
        slots: u64,
        credit_owner: Address,
        mut write_credit: impl FnMut(Address, u64) -> Result<()>,
        write_storage: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let budget = self.amount.min(slots);
        if budget == 0 {
            return write_storage();
        }

        let old = *self;
        if budget == self.amount {
            write_credit(self.user, 0)?;
            self.amount = 0;
        }

        match Self::with_budget(credit_owner, budget, write_storage) {
            Ok(value) => {
                if budget < old.amount {
                    self.amount -= budget;
                    write_credit(self.user, self.amount)?;
                }
                Ok(value)
            }
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
        write_credit: impl FnOnce(Address, u64) -> Result<()>,
    ) -> Result<()> {
        let was_empty = self.amount == 0;
        self.amount = self.amount.saturating_add(slots);

        if was_empty && self.amount > 0 {
            Self::with_budget(credit_owner, 1, || write_credit(self.user, self.amount))
        } else {
            write_credit(self.user, self.amount)
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
                |user, value| credits[user].write(value),
            )?;
        }

        Ok(())
    }
}
