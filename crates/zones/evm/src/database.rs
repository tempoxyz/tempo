//! Execution-local database adapter that overlays finalized Tempo L1 reads while preserving
//! the caller-provided Zone database as the sole canonical state backend.

use std::fmt;

use alloy_evm::Database;
use alloy_primitives::{Address, B256, U256};
use revm::{
    context::{
        DBErrorMarker,
        result::{AnyError, EVMError},
    },
    database_interface::Database as RevmDatabase,
    primitives::{AddressMap, StorageKey, StorageValue},
    state::{Account, AccountInfo, Bytecode},
};
use thiserror::Error;
use zone_precompiles::{
    TIP403_REGISTRY_ADDRESS,
    storage::{L1State, L1StateError, L1StorageReader},
    tempo_state::TEMPO_BLOCK_NUMBER_SLOT,
};
use zone_primitives::constants::TEMPO_STATE_ADDRESS;

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

    /// Clears bookkeeping that is valid only for the current transaction attempt.
    pub(crate) fn reset_transaction_state(&mut self) {
        self.l1.reset_transaction_state();
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

impl<DB: Database, L1: L1StorageReader> L1OverlayDB<DB, L1> {
    fn anchor(&mut self) -> Result<u64, ZoneDbError<DB::Error>> {
        if let Some(anchor) = self.l1.get_anchor() {
            return Ok(anchor);
        }

        let value = self
            .inner
            .storage(TEMPO_STATE_ADDRESS, TEMPO_BLOCK_NUMBER_SLOT)
            .map_err(ZoneDbError::Inner)?;
        let anchor = u64::try_from(value).map_err(|_| ZoneDbError::AnchorOverflow(value))?;
        Ok(anchor)
    }

    /// Rejects writes to the L1-mirrored TIP-403 registry.
    pub fn sanitize_state(
        &mut self,
        state: &mut AddressMap<Account>,
    ) -> Result<(), ZoneDbError<DB::Error>> {
        if let Some(account) = state.get(&TIP403_REGISTRY_ADDRESS) {
            if account.info != account.original_info() {
                return Err(ZoneDbError::L1Write {
                    address: TIP403_REGISTRY_ADDRESS,
                    slot: U256::ZERO,
                });
            }
            if let Some((&slot, _)) = account.changed_storage_slots().next() {
                return Err(ZoneDbError::L1Write {
                    address: TIP403_REGISTRY_ADDRESS,
                    slot,
                });
            }
            // A read-only overlay has identical original and present values, so it is not changed
            // above, but committing the touched account could still persist that L1 value locally.
            // Since every registry slot is mirrored and writes were rejected, drop the transition.
            state.remove(&TIP403_REGISTRY_ADDRESS);
        }

        Ok(())
    }
}

impl<DB: Database, L1: L1StorageReader> RevmDatabase for L1OverlayDB<DB, L1> {
    type Error = ZoneDbError<DB::Error>;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner.basic(address).map_err(ZoneDbError::Inner)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner
            .code_by_hash(code_hash)
            .map_err(ZoneDbError::Inner)
    }

    fn storage(&mut self, address: Address, slot: StorageKey) -> Result<StorageValue, Self::Error> {
        if address != TIP403_REGISTRY_ADDRESS {
            return self
                .inner
                .storage(address, slot)
                .map_err(ZoneDbError::Inner);
        }

        let anchor = self.anchor()?;
        // REVM already charges this TIP-403 SLOAD; the host-side L1 fetch must not be charged again.
        self.l1
            .read_l1_storage_unmetered(address, B256::from(slot), anchor)
            .map(Into::into)
            .map_err(ZoneDbError::L1State)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash(number).map_err(ZoneDbError::Inner)
    }
}

/// Database error produced by [`L1OverlayDB`].
#[derive(Debug, Error)]
pub enum ZoneDbError<E> {
    /// Error from the caller-provided database.
    #[error("inner database error: {0}")]
    Inner(#[source] E),
    /// The selected Zone state contains an invalid Tempo anchor.
    #[error("invalid Tempo anchor (does not fit in u64): {0}")]
    AnchorOverflow(U256),
    /// Execution-local Tempo L1 state could not be read or advanced consistently.
    #[error(transparent)]
    L1State(#[from] L1StateError),
    /// A transaction attempted to persist mirrored Tempo-owned state.
    #[error("write to mirrored Tempo storage address={address} slot={slot}")]
    L1Write { address: Address, slot: U256 },
}

impl<E: DBErrorMarker> DBErrorMarker for ZoneDbError<E> {}

impl<E: DBErrorMarker> ZoneDbError<E> {
    pub(crate) fn into_evm_error<TxError>(self) -> EVMError<E, TxError> {
        match self {
            Self::Inner(error) => EVMError::Database(error),
            error => EVMError::CustomAny(AnyError::new(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{database::InMemoryDB, database_interface::DatabaseCommit, state::EvmStorageSlot};
    use zone_precompiles::test_utils::MockL1Reader as TestL1;

    fn test_db(anchor: u64) -> InMemoryDB {
        let mut db = InMemoryDB::default();
        db.insert_account_storage(
            TEMPO_STATE_ADDRESS,
            TEMPO_BLOCK_NUMBER_SLOT,
            U256::from(anchor),
        )
        .unwrap();
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
        let mut db = L1OverlayDB::new(test_db(anchor), l1, Address::ZERO);

        assert_eq!(db.storage(TIP403_REGISTRY_ADDRESS, slot).unwrap(), expected);
        assert_eq!(db.l1_state().get_anchor(), Some(anchor));
    }

    #[test]
    fn l1_failures_and_read_before_advance_fail_closed() {
        let anchor = 42;
        let slot = U256::from(7);
        let mut failing =
            L1OverlayDB::new(test_db(anchor), TestL1::failing_storage(), Address::ZERO);
        assert!(matches!(
            failing.storage(TIP403_REGISTRY_ADDRESS, slot),
            Err(ZoneDbError::L1State(L1StateError::StorageUnavailable {
                block_number: 42,
                ..
            }))
        ));

        let reader = TestL1::default();
        reader.insert(TIP403_REGISTRY_ADDRESS, slot, anchor, U256::ONE);
        let mut db = L1OverlayDB::new(test_db(anchor), reader.clone(), Address::ZERO);
        let l1 = db.l1_state().clone();
        assert_eq!(
            db.storage(TIP403_REGISTRY_ADDRESS, slot).unwrap(),
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
        inner
            .insert_account_storage(TIP403_REGISTRY_ADDRESS, slot, local)
            .unwrap();
        let mut db = L1OverlayDB::new(inner, l1, Address::ZERO);
        let observed = db.storage(TIP403_REGISTRY_ADDRESS, slot).unwrap();
        assert_eq!(observed, l1_value);

        let mut account = Account::default();
        account.mark_touch();
        account.storage.insert(
            slot,
            EvmStorageSlot {
                original_value: observed,
                present_value: observed,
                ..Default::default()
            },
        );
        let mut state = AddressMap::from_iter([(TIP403_REGISTRY_ADDRESS, account)]);

        db.sanitize_state(&mut state).unwrap();
        assert!(!state.contains_key(&TIP403_REGISTRY_ADDRESS));

        let mut inner = db.into_inner();
        inner.commit(state);
        assert_eq!(inner.storage(TIP403_REGISTRY_ADDRESS, slot).unwrap(), local);
    }

    #[test]
    fn transaction_reset_clears_anchor() {
        let (anchor, slot) = (42, U256::from(7));
        let l1 = TestL1::default();
        l1.insert(TIP403_REGISTRY_ADDRESS, slot, anchor, U256::from(7));
        let mut db = L1OverlayDB::new(test_db(anchor), l1, Address::ZERO);

        db.storage(TIP403_REGISTRY_ADDRESS, slot).unwrap();
        assert_eq!(db.l1_state().get_anchor(), Some(anchor));

        db.reset_transaction_state();

        assert_eq!(db.l1_state().get_anchor(), None);
    }

    #[test]
    fn ordinary_storage_is_local_and_inner_database_is_recoverable() {
        let address = Address::repeat_byte(0x11);
        let slot = U256::from(3);
        let value = U256::from(5);
        let mut inner = test_db(1);
        inner.insert_account_storage(address, slot, value).unwrap();
        let mut db = L1OverlayDB::new(inner, TestL1::default(), Address::ZERO);

        assert_eq!(db.storage(address, slot).unwrap(), value);
        let mut inner: InMemoryDB = db.into_inner();
        assert_eq!(inner.storage(address, slot).unwrap(), value);
    }
}
