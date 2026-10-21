//! Execution-local database adapter that overlays finalized Tempo L1 reads while preserving
//! the caller-provided Zone database as the sole canonical state backend.

use std::fmt;

use alloy_primitives::{Address, B256, U256};
use evm2::{
    DatabaseError, PendingState,
    bytecode::Bytecode,
    evm::{
        AccountChangeRef, AccountInfo, DynDatabase, StateChangeSink, StateChangeSource,
        StorageChange,
    },
};
use thiserror::Error;
use zone_precompiles::{
    TIP403_REGISTRY_ADDRESS,
    storage::{L1State, L1StorageReader},
};

/// Resolves mirrored L1 reads at the active Tempo anchor and forwards all other database
/// operations to the caller-provided Zone database.
pub struct L1OverlayDB<DB, L1> {
    inner: DB,
    l1: L1State<L1>,
}

impl<DB, L1> L1OverlayDB<DB, L1> {
    /// Creates an adapter around the caller-provided database.
    pub fn new(inner: DB, l1: L1, portal_address: Address) -> Self {
        Self {
            inner,
            l1: L1State::new(l1, portal_address),
        }
    }

    /// Returns the original caller-provided database.
    pub const fn inner(&self) -> &DB {
        &self.inner
    }

    /// Returns the original caller-provided database mutably.
    pub const fn inner_mut(&mut self) -> &mut DB {
        &mut self.inner
    }

    /// Recovers the original caller-provided database.
    pub fn into_inner(self) -> DB {
        self.inner
    }

    /// Returns the execution-local L1 state shared with L1-backed precompiles.
    pub const fn l1_state(&self) -> &L1State<L1> {
        &self.l1
    }
}

impl<DB: fmt::Debug, L1> fmt::Debug for L1OverlayDB<DB, L1> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("L1OverlayDB")
            .field("inner", &self.inner)
            .field("l1", &self.l1)
            .finish_non_exhaustive()
    }
}

impl<DB: DynDatabase, L1: L1StorageReader> L1OverlayDB<DB, L1> {
    fn anchor(&mut self) -> Result<u64, DatabaseError> {
        if let Some(anchor) = self.l1.get_anchor() {
            return Ok(anchor);
        }
        let value = self
            .l1
            .initial_anchor()
            .ok_or_else(|| DatabaseError::new(ZoneDbError::MissingAnchor, true))?;
        u64::try_from(value)
            .map_err(|_| DatabaseError::new(ZoneDbError::AnchorOverflow(value), true))
    }
}

pub(crate) fn validate_pending_state(state: &PendingState) -> Result<(), ZoneDbError> {
    state.visit(&mut L1WriteGuard)
}

struct L1WriteGuard;

impl StateChangeSink for L1WriteGuard {
    type Error = ZoneDbError;

    fn account(&mut self, change: AccountChangeRef<'_>) -> Result<(), Self::Error> {
        if change.address == TIP403_REGISTRY_ADDRESS {
            return Err(ZoneDbError::L1Write {
                address: change.address,
                slot: U256::ZERO,
            });
        }
        Ok(())
    }

    fn storage_wipe(&mut self, address: Address) -> Result<(), Self::Error> {
        if address == TIP403_REGISTRY_ADDRESS {
            return Err(ZoneDbError::L1Write {
                address,
                slot: U256::ZERO,
            });
        }
        Ok(())
    }

    fn storage(&mut self, change: StorageChange) -> Result<(), Self::Error> {
        if change.address == TIP403_REGISTRY_ADDRESS {
            return Err(ZoneDbError::L1Write {
                address: change.address,
                slot: change.key,
            });
        }
        Ok(())
    }
}

impl<DB: DynDatabase, L1: L1StorageReader> DynDatabase for L1OverlayDB<DB, L1> {
    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, DatabaseError> {
        self.inner.get_account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, DatabaseError> {
        self.inner.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, slot: &U256) -> Result<U256, DatabaseError> {
        if *address != TIP403_REGISTRY_ADDRESS {
            return self.inner.get_storage(address, slot);
        }

        let anchor = self.anchor()?;
        // The EVM already charges this TIP-403 SLOAD; the host-side L1 fetch must not be charged
        // again.
        self.l1
            .read_l1_storage_unmetered(*address, B256::from(*slot), anchor)
            .map(Into::into)
            .map_err(|error| DatabaseError::new(error, true))
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<B256, DatabaseError> {
        self.inner.get_block_hash(number)
    }
}

/// Database error produced by [`L1OverlayDB`].
#[derive(Debug, Error)]
pub enum ZoneDbError {
    /// Mirrored storage was accessed without an initialized transaction context.
    #[error("Tempo anchor was not initialized for this transaction")]
    MissingAnchor,
    /// The selected Zone state contains an invalid Tempo anchor.
    #[error("invalid Tempo anchor (does not fit in u64): {0}")]
    AnchorOverflow(U256),
    /// A transaction attempted to persist mirrored Tempo-owned state.
    #[error("write to mirrored Tempo storage address={address} slot={slot}")]
    L1Write { address: Address, slot: U256 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use evm2::evm::InMemoryDB;
    use reth_execution_types::{BlockState, BundleSource, TransactionChanges};
    use zone_precompiles::{
        storage::L1StateError, tempo_state::TEMPO_BLOCK_NUMBER_SLOT,
        test_utils::MockL1Reader as TestL1,
    };
    use zone_primitives::constants::TEMPO_STATE_ADDRESS;

    fn test_db(anchor: u64) -> InMemoryDB {
        let mut db = InMemoryDB::default();
        db.insert_account_storage(
            &TEMPO_STATE_ADDRESS,
            &TEMPO_BLOCK_NUMBER_SLOT,
            &U256::from(anchor),
        );
        db
    }

    fn test_overlay(anchor: u64, reader: TestL1) -> L1OverlayDB<InMemoryDB, TestL1> {
        // The backing database can lag the checkpoint already committed in the EVM overlay.
        let db = L1OverlayDB::new(test_db(anchor.saturating_sub(1)), reader, Address::ZERO);
        db.l1_state().begin_transaction(U256::from(anchor));
        db
    }

    #[test]
    fn overlays_registry_at_selected_state_anchor() {
        let anchor = 42;
        let slot = U256::from(7);
        let expected = U256::from(99);
        let l1 = TestL1::default();
        l1.insert(TIP403_REGISTRY_ADDRESS, slot, anchor - 1, U256::from(98));
        l1.insert(TIP403_REGISTRY_ADDRESS, slot, anchor, expected);
        let mut db = test_overlay(anchor, l1);

        assert_eq!(
            DynDatabase::get_storage(&mut db, &TIP403_REGISTRY_ADDRESS, &slot).unwrap(),
            expected
        );
        assert_eq!(db.l1_state().get_anchor(), Some(anchor));
    }

    #[test]
    fn l1_failures_and_read_before_advance_fail_closed() {
        let anchor = 42;
        let slot = U256::from(7);
        let mut failing = test_overlay(anchor, TestL1::failing_storage());
        let code =
            DynDatabase::get_storage(&mut failing, &TIP403_REGISTRY_ADDRESS, &slot).unwrap_err();
        assert!(matches!(
            code.downcast_ref::<L1StateError>(),
            Some(L1StateError::StorageUnavailable {
                block_number: 42,
                ..
            })
        ));

        let reader = TestL1::default();
        reader.insert(TIP403_REGISTRY_ADDRESS, slot, anchor, U256::ONE);
        let mut db = test_overlay(anchor, reader.clone());
        let l1 = db.l1_state().clone();
        assert_eq!(
            DynDatabase::get_storage(&mut db, &TIP403_REGISTRY_ADDRESS, &slot).unwrap(),
            U256::ONE
        );
        assert!(l1.advance_anchor(anchor, anchor + 1).is_err());
        assert_eq!(reader.storage_requests().len(), 1);
    }

    #[test]
    fn registry_overlay_is_removed_from_canonical_transition() {
        let (anchor, slot) = (42, U256::from(7));
        let (local, l1_value) = (U256::from(5), U256::from(99));
        let l1 = TestL1::default();
        l1.insert(TIP403_REGISTRY_ADDRESS, slot, anchor, l1_value);
        let mut inner = test_db(anchor);
        inner.insert_account_info(&TIP403_REGISTRY_ADDRESS, Default::default());
        inner.insert_account_storage(&TIP403_REGISTRY_ADDRESS, &slot, &local);
        let mut db = L1OverlayDB::new(inner, l1, Address::ZERO);
        db.l1_state().begin_transaction(U256::from(anchor));
        let observed = DynDatabase::get_storage(&mut db, &TIP403_REGISTRY_ADDRESS, &slot).unwrap();
        assert_eq!(observed, l1_value);

        let account = db.get_account(&TIP403_REGISTRY_ADDRESS).unwrap();
        let mut state = PendingState::default();
        state.insert_account(TIP403_REGISTRY_ADDRESS, account.clone(), account);
        state.insert_storage(TIP403_REGISTRY_ADDRESS, slot, observed, observed);
        validate_pending_state(&state).unwrap();

        // Consume the transition through the same bundle stream used by block execution.
        let mut block = BlockState::new();
        let mut changes = TransactionChanges::default();
        state.visit(&mut changes).unwrap();
        block.commit(&changes);
        let state = block.into_bundle();
        assert!(!state.state().contains_key(&TIP403_REGISTRY_ADDRESS));
        let mut inner = db.into_inner();
        inner.commit_source(&BundleSource(&state));
        assert_eq!(
            DynDatabase::get_storage(&mut inner, &TIP403_REGISTRY_ADDRESS, &slot).unwrap(),
            local
        );
    }

    #[test]
    fn transaction_reset_clears_anchor() {
        let (anchor, slot) = (42, U256::from(7));
        let l1 = TestL1::default();
        l1.insert(TIP403_REGISTRY_ADDRESS, slot, anchor, U256::from(7));
        let mut db = test_overlay(anchor, l1);

        DynDatabase::get_storage(&mut db, &TIP403_REGISTRY_ADDRESS, &slot).unwrap();
        assert_eq!(db.l1_state().get_anchor(), Some(anchor));

        db.l1_state().reset_transaction_state();

        assert_eq!(db.l1_state().get_anchor(), None);
        assert_eq!(db.l1_state().initial_anchor(), None);
        let code = db.get_storage(&TIP403_REGISTRY_ADDRESS, &slot).unwrap_err();
        assert!(matches!(
            code.downcast_ref::<ZoneDbError>(),
            Some(ZoneDbError::MissingAnchor)
        ));
    }

    #[test]
    fn ordinary_storage_is_local_and_inner_database_is_recoverable() {
        let address = Address::repeat_byte(0x11);
        let slot = U256::from(3);
        let value = U256::from(5);
        let mut inner = test_db(1);
        inner.insert_account_storage(&address, &slot, &value);
        let mut db = L1OverlayDB::new(inner, TestL1::default(), Address::ZERO);

        assert_eq!(
            DynDatabase::get_storage(&mut db, &address, &slot).unwrap(),
            value
        );
        let mut inner: InMemoryDB = db.into_inner();
        assert_eq!(
            DynDatabase::get_storage(&mut inner, &address, &slot).unwrap(),
            value
        );
    }
}
