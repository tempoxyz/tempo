//! Anchor coordination and packed-storage compatibility shared by the zone EVM database adapter
//! and the L1-backed `TempoState` precompile.

use alloc::{
    rc::Rc,
    string::{String, ToString},
};
use core::{
    cell::{Cell, RefCell},
    fmt,
};

use alloy_primitives::{Address, B256, U256, map::HashSet};
use revm::{
    context::result::AnyError,
    interpreter::gas::{COLD_SLOAD_COST, WARM_STORAGE_READ_COST},
    precompile::PrecompileError,
};
use tempo_precompiles::{
    error::TempoPrecompileError, storage::vec::VecHandler,
    zone_factory::ZonePortalStorage as ZonePortal,
};
use thiserror::Error;

use crate::tempo_state::TempoState;

pub(crate) use tempo_precompiles::storage::*;

/// Raw L1 storage access needed by the anchored Zone database and L1-backed precompiles.
pub trait L1StorageReader: Clone + Send + Sync + 'static {
    /// Reads `account[slot]` at `block_number` on Tempo L1 without gas accounting.
    ///
    /// **IMPORTANT:** Implementations are raw provider hooks. Callers are responsible for dealing
    /// with the execution anchor and charging the appropriate execution gas costs.
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> core::result::Result<B256, L1StateError>;
}

/// Execution-local access to Tempo L1 storage at a single finalized block number.
///
/// The **anchor** is the Tempo L1 block number against which every external storage read in the
/// current transaction attempt must be resolved. It corresponds to the checkpoint maintained in
/// Zone state by the L1-backed `TempoState` precompile. The anchor starts unset and is selected
/// in one of two ways:
///
/// - For an ordinary transaction, the first L1 read selects the `tempoBlockNumber` loaded from the
///   chosen Zone state.
/// - During `advanceTempo`, the `TempoState` precompile governs advancement: it first
///   validates that the submitted header is the direct child of the stored checkpoint, then
///   advances the anchor to that child before any reads at the new checkpoint.
///
/// Once selected, the anchor is immutable for the transaction attempt. Reads at another block,
/// advancement after a parent-anchor read, and duplicate or non-contiguous advancement are
/// rejected. The Zone EVM resets the anchor after every transaction attempt, including failed and
/// noncommitting simulations.
///
/// Clones share the selected anchor and provider handle so the Zone database adapter, `TempoState`,
/// and other L1-backed precompiles enforce one view of L1 state. A new `L1State` must be created
/// for each EVM execution context; it must not be shared across independent EVMs.
#[derive(Clone)]
pub struct L1State<P> {
    /// Tempo block number selected for the current transaction attempt.
    anchor: Rc<Cell<Option<u64>>>,
    /// `(account, slot)` keys successfully accessed during the current transaction attempt.
    ///
    /// Used for cold/warm gas accounting. Unlike REVM's journal, this access set is not rolled back
    /// when a subcall reverts, preserving charges for potentially incurred L1 fetch work and
    /// simplifying the accounting model.
    access_set: Rc<RefCell<HashSet<(Address, B256)>>>,
    /// Underlying cache/RPC-backed reader for storage at an explicit Tempo block number.
    provider: P,
    /// ZonePortal read through the L1 provider by explicit storage operations.
    portal_address: Address,
}

impl<P> L1State<P> {
    /// Creates execution-local L1 state backed by `provider` for `portal_address`.
    pub fn new(provider: P, portal_address: Address) -> Self {
        Self {
            anchor: Rc::new(Cell::new(None)),
            access_set: Rc::new(RefCell::new(HashSet::default())),
            provider,
            portal_address,
        }
    }

    /// Clears bookkeeping after the current transaction attempt completes.
    pub fn reset_transaction_state(&self) {
        self.anchor.set(None);
        self.access_set.borrow_mut().clear();
    }

    /// Returns the anchor selected for the current transaction, if any.
    pub fn get_anchor(&self) -> Option<u64> {
        self.anchor.get()
    }

    /// Returns the configured ZonePortal address.
    pub const fn portal(&self) -> Address {
        self.portal_address
    }

    fn set_anchor(&self, new: u64) -> Result<(), L1StateError> {
        match self.get_anchor() {
            None => {
                self.anchor.set(Some(new));
                Ok(())
            }
            Some(current) if current == new => Ok(()),
            Some(current) => Err(L1StateError::AnchorConflict { current, new }),
        }
    }

    /// Selects the final anchor after `TempoState.finalizeTempo` validates a contiguous range.
    ///
    /// Advancement is valid only before any L1 read has selected an anchor and only from a parent
    /// to a later checkpoint.
    pub fn advance_anchor(&self, from: u64, to: u64) -> Result<(), L1StateError> {
        if to <= from {
            return Err(L1StateError::AdvanceTempoConflict { from, to });
        } else if let Some(current) = self.get_anchor() {
            return Err(L1StateError::AnchorConflict { current, new: to });
        }

        self.anchor.set(Some(to));
        Ok(())
    }
}

impl<P: L1StorageReader> L1State<P> {
    /// Reads L1 storage through the provider without gas metering, after selecting or validating
    /// `block_number` as this transaction's anchor.
    ///
    /// The EVM database overlay uses this path because revm already charges TIP-403 SLOADs.
    /// Other L1-backed precompile reads use [`Self::read_l1`] for cold/warm accounting.
    pub fn read_l1_storage_unmetered(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        self.set_anchor(block_number)?;
        self.provider.read_l1_storage(account, slot, block_number)
    }

    /// Reads L1 storage, with gas metering, after selecting or validating `block_number` as this
    /// transaction's anchor.
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> tempo_precompiles::Result<B256> {
        let key = (account, slot);
        let gas_cost = if self.access_set.borrow().contains(&key) {
            WARM_STORAGE_READ_COST
        } else {
            COLD_SLOAD_COST
        };
        StorageCtx.deduct_gas(gas_cost)?;
        let value = self
            .read_l1_storage_unmetered(account, slot, block_number)
            .map_err(|err| TempoPrecompileError::Fatal(err.to_string()))?;
        self.access_set.borrow_mut().insert(key);
        Ok(value)
    }

    /// Reads, with gas metering, and decodes a typed slot from an L1 account at the active anchor.
    pub fn read_l1<T: Storable>(&self, slot: &Slot<T>) -> tempo_precompiles::Result<T> {
        let storage = L1Storage {
            l1: self,
            account: slot.address(),
        };
        T::load(&storage, slot.slot(), slot.ctx())
    }

    /// Selects and reads a typed slot from the configured `ZonePortal` at the active anchor.
    ///
    /// The callback only exposes the portal for selecting a handler; the selected value is always
    /// resolved through [`Self::read_l1`] rather than the local EVM journal.
    pub fn read_portal<T: Storable>(
        &self,
        select_slot: impl for<'a> FnOnce(&'a ZonePortal) -> &'a Slot<T>,
    ) -> tempo_precompiles::Result<T> {
        let portal = ZonePortal::new(self.portal_address);
        self.read_l1(select_slot(&portal))
    }

    /// Selects and reads a [`VecHandler`] length slot from the configured `ZonePortal` at the active anchor.
    pub fn read_portal_vec_len<T: Storable>(
        &self,
        select: impl for<'a> FnOnce(&'a ZonePortal) -> &'a VecHandler<T>,
    ) -> tempo_precompiles::Result<usize> {
        let portal = ZonePortal::new(self.portal_address);
        let vec = select(&portal);
        let len_slot = Slot::<U256>::new(vec.len_slot(), self.portal_address);

        usize::try_from(self.read_l1(&len_slot)?)
            .map_err(|_| TempoPrecompileError::under_overflow())
    }

    /// Returns whether `account` has `expected` in the configured ZonePortal's role mapping.
    pub fn has_portal_role(
        &self,
        account: Address,
        expected: tempo_zone_contracts::ZonePortal::Role,
    ) -> tempo_precompiles::Result<bool> {
        Ok(self.read_portal(|portal| &portal.role[account])? == u8::from(expected))
    }
}

impl<P> fmt::Debug for L1State<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L1State")
            .field("anchor", &self.get_anchor())
            .field("warm_l1_slots", &self.access_set.borrow().len())
            .field("portal_address", &self.portal_address)
            .finish_non_exhaustive()
    }
}

/// Failure to read or advance execution-local Tempo L1 state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum L1StateError {
    /// The underlying L1 provider could not resolve storage at the requested block.
    #[error(
        "Tempo L1 storage unavailable account={account} slot={slot} block={block_number}: {reason}"
    )]
    StorageUnavailable {
        /// Tempo account whose storage was requested.
        account: Address,
        /// Requested storage slot.
        slot: B256,
        /// Tempo block number at which storage was requested.
        block_number: u64,
        /// Provider failure diagnostic.
        reason: String,
    },
    /// An L1 read disagreed with the anchor already selected for this transaction.
    #[error("Tempo L1 read at anchor {new} conflicts with currently selected anchor {current}")]
    AnchorConflict {
        /// Anchor already selected for this transaction.
        current: u64,
        /// Anchor requested by the new read.
        new: u64,
    },
    /// Tempo advancement was non-contiguous or happened after an anchor was selected.
    #[error("cannot advance Tempo L1 anchor from {from} to {to}")]
    AdvanceTempoConflict {
        /// Parent Tempo block number.
        from: u64,
        /// Requested child Tempo block number.
        to: u64,
    },
}

impl L1StateError {
    /// Returns whether this is an underlying storage-provider failure.
    pub const fn is_storage_unavailable(&self) -> bool {
        matches!(self, Self::StorageUnavailable { .. })
    }
}

impl From<L1StateError> for PrecompileError {
    fn from(error: L1StateError) -> Self {
        Self::FatalAny(AnyError::new(error))
    }
}

/// Read-only [`StorageOps`] adapter for one L1 account.
///
/// This lets typed L1-backed precompile storage handlers read, meter, and decode slots without
/// inserting fetched values into the EVM journal. Reads use the transaction's selected anchor,
/// falling back to the checkpoint stored in [`TempoState`] on the first read.
struct L1Storage<'a, P> {
    /// Execution-local provider and anchor coordination shared by all L1 reads.
    l1: &'a L1State<P>,
    /// L1 account whose storage slots are exposed through [`StorageOps`].
    account: Address,
}

impl<P: L1StorageReader> StorageOps for L1Storage<'_, P> {
    fn load(&self, slot: U256) -> tempo_precompiles::Result<U256> {
        let anchor = match self.l1.get_anchor() {
            Some(anchor) => anchor,
            None => TempoState::new().tempo_block_number.read()?,
        };
        self.l1
            .read_l1_storage(self.account, slot.into(), anchor)
            .map(Into::into)
    }

    fn store(&mut self, _slot: U256, _value: U256) -> tempo_precompiles::Result<()> {
        Err(TempoPrecompileError::Fatal(
            "L1 storage is read-only".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{MockL1Reader, test_context, test_storage_provider};

    fn read(l1: &L1State<MockL1Reader>, anchor: u64) -> Result<B256, L1StateError> {
        l1.read_l1_storage_unmetered(Address::ZERO, B256::ZERO, anchor)
    }

    #[test]
    fn raw_l1_read_is_unmetered() -> eyre::Result<()> {
        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        let gas_before = storage.gas_used();

        StorageCtx::enter(&mut storage, || {
            l1.read_l1_storage_unmetered(Address::ZERO, B256::ZERO, 10)
        })?;

        assert_eq!(storage.gas_used() - gas_before, 0);
        Ok(())
    }

    #[test]
    fn metered_l1_reads_are_cold_once_per_account_slot() -> eyre::Result<()> {
        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        let clone = l1.clone();
        l1.advance_anchor(9, 10).unwrap();
        let first = Slot::<B256>::new(U256::ZERO, Address::ZERO);
        let second = Slot::<B256>::new(U256::ZERO, Address::repeat_byte(1));
        let gas_before = storage.gas_used();

        StorageCtx::enter(&mut storage, || {
            l1.read_l1(&first)?;
            clone.read_l1(&first)?;
            l1.read_l1(&second)
        })?;

        assert_eq!(
            storage.gas_used() - gas_before,
            COLD_SLOAD_COST + WARM_STORAGE_READ_COST + COLD_SLOAD_COST
        );
        Ok(())
    }

    #[test]
    fn metered_l1_reads_charge_before_provider_fetch() -> eyre::Result<()> {
        let mut ctx = test_context();

        let cold_reader = MockL1Reader::default();
        let cold_l1 = L1State::new(cold_reader.clone(), Address::ZERO);
        let mut cold_storage = test_storage_provider(&mut ctx, COLD_SLOAD_COST - 1, false);
        let cold_slot = Slot::<B256>::new(U256::ZERO, Address::ZERO);
        assert!(matches!(
            StorageCtx::enter(&mut cold_storage, || cold_l1.read_l1(&cold_slot)),
            Err(TempoPrecompileError::OutOfGas)
        ));
        assert!(cold_reader.storage_requests().is_empty());
        drop(cold_storage);

        let warm_reader = MockL1Reader::default();
        let warm_l1 = L1State::new(warm_reader.clone(), Address::ZERO);
        warm_l1.advance_anchor(9, 10).unwrap();
        let mut warm_storage = test_storage_provider(
            &mut ctx,
            COLD_SLOAD_COST + WARM_STORAGE_READ_COST - 1,
            false,
        );
        let warm_slot = Slot::<B256>::new(U256::ZERO, Address::ZERO);
        let result = StorageCtx::enter(&mut warm_storage, || {
            warm_l1.read_l1(&warm_slot)?;
            warm_l1.read_l1(&warm_slot)
        });
        assert!(matches!(result, Err(TempoPrecompileError::OutOfGas)));
        assert_eq!(warm_reader.storage_requests().len(), 1);
        Ok(())
    }

    #[test]
    fn l1_state_rejects_advance_after_parent_read() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        read(&l1, 10).unwrap();
        assert!(l1.advance_anchor(10, 11).is_err());
    }

    #[test]
    fn l1_state_accepts_reads_at_advanced_anchor() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        l1.advance_anchor(10, 11).unwrap();
        read(&l1, 11).unwrap();
        assert_eq!(l1.get_anchor(), Some(11));
    }

    #[test]
    fn l1_state_clones_reject_reads_at_different_anchors() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        let clone = l1.clone();
        read(&l1, 10).unwrap();
        assert!(read(&clone, 11).is_err());
    }

    #[test]
    fn l1_state_rejects_duplicate_advance() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        l1.advance_anchor(10, 11).unwrap();
        assert!(l1.advance_anchor(11, 12).is_err());
    }

    #[test]
    fn l1_state_accepts_forward_range_and_rejects_non_forward_advance() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        l1.advance_anchor(10, 12).unwrap();
        assert_eq!(l1.get_anchor(), Some(12));

        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        assert!(l1.advance_anchor(10, 10).is_err());
        assert!(l1.advance_anchor(10, 9).is_err());
        assert_eq!(l1.get_anchor(), None);
    }

    #[test]
    fn l1_state_reset_allows_a_new_anchor() {
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        read(&l1, 10).unwrap();
        l1.reset_transaction_state();
        l1.advance_anchor(10, 11).unwrap();
        assert_eq!(l1.get_anchor(), Some(11));
    }

    #[test]
    fn tx_reset_makes_l1_slots_cold_again() -> eyre::Result<()> {
        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
        let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
        l1.advance_anchor(9, 10).unwrap();
        let slot = Slot::<B256>::new(U256::ZERO, Address::ZERO);
        let gas_before = storage.gas_used();

        StorageCtx::enter(&mut storage, || l1.read_l1(&slot))?;
        l1.reset_transaction_state();
        l1.advance_anchor(10, 11).unwrap();
        StorageCtx::enter(&mut storage, || l1.read_l1(&slot))?;

        assert_eq!(storage.gas_used() - gas_before, 2 * COLD_SLOAD_COST);
        Ok(())
    }
}
