//! Storage credits precompile (TIP-1060).

pub mod dispatch;
pub mod gas_state;

pub use gas_state::{StorageCreditsBackend, sstore_storage_credits};

use crate::{
    STORAGE_CREDITS_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, LayoutCtx, StorableType, StorageCtx},
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
    pub fn set_state_of(&mut self, account: Address, state: AccountState) -> Result<()> {
        AccountState::handle(Self::slot(account), LayoutCtx::FULL, self.address).write(state)
    }

    pub fn set_mode(&mut self, msg_sender: Address, mode: Mode) -> Result<()> {
        let mut state = self.state_of(msg_sender)?;
        state.mode = CreditMode::try_from(mode)?;
        self.set_state_of(msg_sender, state)?;

        self.emit_event(TIP1060StorageCreditsEvent::mode_updated(msg_sender, mode))
    }

    /// Runs `f` with an internal direct TIP-1060 budget for `account`.
    pub fn with_budget<T>(
        &mut self,
        account: Address,
        budget: u64,
        f: impl FnOnce() -> Result<T>,
    ) -> Result<(T, u64)> {
        let mut storage = StorageCtx;

        // Install this scope's budget, and run `f`.
        let previous = storage.set_storage_credit_budget(account, Some(budget))?;
        debug_assert!(previous.is_none());
        let result = f();

        // Clear this scope and use the remaining budget to compute actual consumption.
        let consumed = budget.saturating_sub(
            storage
                .set_storage_credit_budget(account, None)?
                .unwrap_or_default(),
        );
        result.map(|value| (value, consumed))
    }

    #[inline]
    pub fn slot(account: Address) -> U256 {
        U256::from_be_bytes(account.into_word().0)
    }
}

/// Per-user reusable storage credit state accumulated by a precompile call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageCreditAccount {
    pub user: Address,
    pub initial: u64,
    pub persisted: u64,
    pub current: u64,
}

impl StorageCreditAccount {
    pub fn load(
        user: Address,
        read_credit: impl FnOnce(Address) -> Result<u64>,
    ) -> Result<Option<Self>> {
        if !StorageCtx.spec().is_t7() {
            return Ok(None);
        }

        let initial = read_credit(user)?;
        Ok(Some(Self {
            user,
            initial,
            persisted: initial,
            current: initial,
        }))
    }

    fn counter_backed(&self) -> bool {
        self.persisted > 0 && self.current > 0
    }

    fn free_backed_credits(&self) -> u64 {
        self.current
            .saturating_sub(u64::from(self.counter_backed()))
    }

    pub fn credit_slots(&mut self, slots: u64) {
        self.current = self.current.saturating_add(slots);
    }

    /// Runs `write_storage` while allowing up to `slots.min(current)` TIP-1060 token consumptions.
    ///
    /// If spending all remaining credits, the persisted `dex_storage_credits[user]` counter is
    /// cleared first so the credit embodied by that nonzero counter slot becomes an available
    /// TIP-1060 token for the storage creation.
    pub fn spend_storage_credits_for_create<T>(
        &mut self,
        slots: u64,
        credit_owner: Address,
        write_credit: impl FnOnce(Address, u64) -> Result<()>,
        write_storage: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let budget = self.current.min(slots);
        if budget == 0 {
            return write_storage();
        }

        let old = *self;
        if budget > self.free_backed_credits() {
            write_credit(self.user, 0)?;
            self.persisted = 0;
        }

        match TIP1060StorageCredits::new().with_budget(credit_owner, budget, write_storage) {
            Ok((value, consumed)) if consumed == budget => {
                self.current -= budget;
                Ok(value)
            }
            Ok((_value, _consumed)) => {
                *self = old;
                Err(TempoPrecompileError::Fatal(
                    "TIP-1060 direct budget was not fully consumed".to_string(),
                ))
            }
            Err(err) => {
                *self = old;
                Err(err)
            }
        }
    }

    pub fn has_changed(&self) -> bool {
        self.current != self.persisted
    }

    /// Flushes this user-level storage credit counter if it changed.
    pub fn flush(
        self,
        credit_owner: Address,
        write_credit: impl FnOnce(Address, u64) -> Result<()>,
    ) -> Result<()> {
        if !self.has_changed() {
            return Ok(());
        }

        if self.persisted == 0 && self.current > 0 {
            let ((), consumed) =
                TIP1060StorageCredits::new()
                    .with_budget(credit_owner, 1, || write_credit(self.user, self.current))?;
            if consumed != 1 {
                return Err(TempoPrecompileError::Fatal(
                    "TIP-1060 direct budget was not fully consumed".to_string(),
                ));
            }
            return Ok(());
        }

        write_credit(self.user, self.current)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageCreditAccounts(Vec<StorageCreditAccount>);

impl StorageCreditAccounts {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn account(
        &mut self,
        user: Address,
        read_credit: impl FnOnce(Address) -> Result<u64>,
    ) -> Result<Option<&mut StorageCreditAccount>> {
        if let Some(index) = self.0.iter().position(|account| account.user == user) {
            return Ok(Some(&mut self.0[index]));
        }
        let Some(account) = StorageCreditAccount::load(user, read_credit)? else {
            return Ok(None);
        };
        self.0.push(account);
        Ok(self.0.last_mut())
    }

    /// Adds `slots` reusable-storage credits to `user`, saturating at `u64::MAX`.
    pub fn credit_slots(
        &mut self,
        user: Address,
        slots: u64,
        read_credit: impl FnOnce(Address) -> Result<u64>,
    ) -> Result<()> {
        if let Some(account) = self.account(user, read_credit)? {
            account.credit_slots(slots);
        }
        Ok(())
    }

    pub fn flush(
        mut self,
        credit_owner: Address,
        mut write_credit: impl FnMut(Address, u64) -> Result<()>,
    ) -> Result<()> {
        self.0.sort_by_key(|account| account.user);

        for account in self.0 {
            if !account.has_changed() {
                continue;
            }

            if account.persisted == 0 && account.current > 0 {
                let ((), consumed) =
                    TIP1060StorageCredits::new().with_budget(credit_owner, 1, || {
                        write_credit(account.user, account.current)
                    })?;
                if consumed != 1 {
                    return Err(TempoPrecompileError::Fatal(
                        "TIP-1060 direct budget was not fully consumed".to_string(),
                    ));
                }
            } else {
                write_credit(account.user, account.current)?;
            }
        }

        Ok(())
    }

    pub fn into_inner(self) -> Vec<StorageCreditAccount> {
        self.0
    }
}
