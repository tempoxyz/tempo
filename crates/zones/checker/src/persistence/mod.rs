//! Row-oriented MDBX persistence for the current verified state.

mod codec;
mod model;
mod schema;
#[cfg(test)]
mod tests;

use std::{fs, path::Path, sync::Arc};

use reth_db::{
    Database, DatabaseEnv, DatabaseEnvKind,
    cursor::DbCursorRO,
    is_database_empty,
    mdbx::{DatabaseArguments, init_db_for},
    transaction::{DbTx, DbTxMut},
};

use crate::accounting::{AccountingError, ChangedRows, Effect, State};

pub(crate) use model::{AppliedStatus, BlockRef, Checkpoint, Finding, Identity, Metadata, Status};
use schema::{AccountValue, Accounts, Meta, MetaKey, MetaValue, Tables, TokenValue, Tokens};

const SCHEMA_VERSION: u32 = 1;

/// Loaded durable accounting state and its exact coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) metadata: Metadata,
    pub(crate) state: Arc<State>,
}

/// Verified post-block state and the rows changed by its transition.
pub(crate) struct CandidateTransition {
    state: State,
    zone: BlockRef,
    parent: BlockRef,
    imported_tempo: BlockRef,
    imported_tempo_parent: BlockRef,
    changes: ChangedRows,
}

impl CandidateTransition {
    /// Consume the current snapshot and derive its next verified state.
    pub(crate) fn derive(
        prior: Snapshot,
        zone: BlockRef,
        parent: BlockRef,
        imported_tempo: BlockRef,
        effects: &[Effect],
    ) -> Result<Self, AccountingError> {
        let Snapshot { metadata, state } = prior;
        let mut state = Arc::unwrap_or_clone(state);
        let changes = state.apply(effects)?;
        Ok(Self {
            state,
            zone,
            parent,
            imported_tempo,
            imported_tempo_parent: metadata.imported_tempo,
            changes,
        })
    }

    /// Return the derived post-block accounting state.
    pub(crate) const fn state(&self) -> &State {
        &self.state
    }
}

/// Sole-writer checker database.
pub(crate) struct Store {
    db: Arc<DatabaseEnv>,
    identity: Identity,
}

impl Store {
    /// Read the identity bound to an existing checker database.
    pub(crate) fn inspect_identity(path: &Path) -> Result<Identity, PersistenceError> {
        let db = DatabaseEnv::open(path, DatabaseEnvKind::RO, DatabaseArguments::default())?;
        let tx = db.tx()?;
        validate_schema(&tx)?;
        let identity = read_metadata(&tx)?.identity;
        tx.commit()?;
        Ok(identity)
    }

    /// Open an existing database or atomically create it from an authenticated checkpoint.
    pub(crate) fn open_or_create(
        path: &Path,
        checkpoint: &Checkpoint,
    ) -> Result<(Self, Snapshot), PersistenceError> {
        if path.exists() {
            return Self::open(path, checkpoint.identity);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| PersistenceError::Invalid(error.to_string()))?;
        }
        Self::create_atomic(path, checkpoint)?;
        Self::open(path, checkpoint.identity)
    }

    /// Create, verify, and atomically publish a genesis checkpoint.
    pub(crate) fn create_atomic(
        target: &Path,
        checkpoint: &Checkpoint,
    ) -> Result<Snapshot, PersistenceError> {
        if target.exists() {
            return Err(PersistenceError::Invalid("database already exists".into()));
        }
        let parent = target
            .parent()
            .ok_or_else(|| PersistenceError::Invalid("database has no parent directory".into()))?;
        let staging = tempfile::Builder::new()
            .prefix(".checker-staging-")
            .tempdir_in(parent)
            .map_err(|error| PersistenceError::Invalid(error.to_string()))?;
        let snapshot = {
            let (store, snapshot) = Self::create(staging.path(), checkpoint)?;
            drop(store);
            let (store, reopened) = Self::open(staging.path(), checkpoint.identity)?;
            drop(store);
            if reopened != snapshot {
                return Err(PersistenceError::Invalid(
                    "genesis state changed after reopen".into(),
                ));
            }
            snapshot
        };
        fs::rename(staging.path(), target)
            .map_err(|error| PersistenceError::Invalid(error.to_string()))?;
        Ok(snapshot)
    }

    fn create(path: &Path, checkpoint: &Checkpoint) -> Result<(Self, Snapshot), PersistenceError> {
        if !is_database_empty(path) {
            return Err(PersistenceError::Invalid(
                "fresh database is not empty".into(),
            ));
        }
        let db = init_db_for::<_, Tables>(path, DatabaseArguments::default())
            .map_err(PersistenceError::Open)?;
        let store = Self {
            db: Arc::new(db),
            identity: checkpoint.identity,
        };
        let metadata = Metadata {
            identity: checkpoint.identity,
            verified_zone: checkpoint.zone,
            imported_tempo: checkpoint.tempo,
            observed_zone: checkpoint.zone,
            status: Status::Verifying,
        };
        let tx = store.db.tx_mut()?;
        tx.put::<Meta>(MetaKey::Version, MetaValue::Version(SCHEMA_VERSION))?;
        write_metadata(&tx, &metadata)?;
        for (key, value) in checkpoint.state.accounts() {
            tx.put::<Accounts>(key, AccountValue(value))?;
        }
        for (token, value) in checkpoint.state.tokens() {
            tx.put::<Tokens>(token, TokenValue(value))?;
        }
        tx.commit()?;
        Ok((
            store,
            Snapshot {
                metadata,
                state: Arc::new(checkpoint.state.clone()),
            },
        ))
    }

    /// Open and validate an existing checker database.
    pub(crate) fn open(
        path: &Path,
        identity: Identity,
    ) -> Result<(Self, Snapshot), PersistenceError> {
        let db = DatabaseEnv::open(path, DatabaseEnvKind::RW, DatabaseArguments::default())?;
        let store = Self {
            db: Arc::new(db),
            identity,
        };
        let snapshot = store.load()?;
        Ok((store, snapshot))
    }

    /// Load the active row state directly without replaying retained deltas.
    pub(crate) fn load(&self) -> Result<Snapshot, PersistenceError> {
        let tx = self.db.tx()?;
        validate_schema(&tx)?;
        let metadata = read_metadata(&tx)?;
        if metadata.identity != self.identity {
            return Err(PersistenceError::Identity);
        }

        let mut accounts = Vec::new();
        let mut cursor = tx.cursor_read::<Accounts>()?;
        let mut row = cursor.first()?;
        while let Some((key, AccountValue(value))) = row {
            accounts.push((key, value));
            row = cursor.next()?;
        }
        let mut tokens = Vec::new();
        let mut cursor = tx.cursor_read::<Tokens>()?;
        let mut row = cursor.first()?;
        while let Some((token, TokenValue(value))) = row {
            tokens.push((token, value));
            row = cursor.next()?;
        }
        let state = State::from_rows(accounts, tokens)?;
        tx.commit()?;
        Ok(Snapshot {
            metadata,
            state: Arc::new(state),
        })
    }

    /// Atomically apply one contiguous verified block.
    ///
    /// Requires the candidate's parent coordinates to still be current and verifying.
    pub(crate) fn apply(
        &self,
        candidate: CandidateTransition,
    ) -> Result<Snapshot, PersistenceError> {
        let CandidateTransition {
            state,
            zone,
            parent,
            imported_tempo,
            imported_tempo_parent,
            changes,
        } = candidate;

        let tx = self.db.tx_mut()?;
        let mut metadata = read_metadata(&tx)?;
        if metadata.status != Status::Verifying {
            return Err(PersistenceError::Invalid("checker is not verifying".into()));
        }
        if parent != metadata.verified_zone
            || imported_tempo_parent != metadata.imported_tempo
            || zone.number != parent.number.saturating_add(1)
        {
            return Err(PersistenceError::StaleSnapshot);
        }
        write_changed_rows(&tx, &state, &changes)?;
        metadata.verified_zone = zone;
        metadata.imported_tempo = imported_tempo;
        if metadata.observed_zone.number < zone.number {
            metadata.observed_zone = zone;
        }
        write_metadata(&tx, &metadata)?;
        tx.commit()?;
        Ok(Snapshot {
            metadata,
            state: Arc::new(state),
        })
    }

    /// Atomically discard derived rows and restart from authenticated genesis.
    pub(crate) fn reset(&self, checkpoint: &Checkpoint) -> Result<Snapshot, PersistenceError> {
        if checkpoint.identity != self.identity {
            return Err(PersistenceError::Identity);
        }
        let metadata = Metadata {
            identity: self.identity,
            verified_zone: checkpoint.zone,
            imported_tempo: checkpoint.tempo,
            observed_zone: checkpoint.zone,
            status: Status::Verifying,
        };
        let tx = self.db.tx_mut()?;
        tx.clear::<Accounts>()?;
        tx.clear::<Tokens>()?;
        for (key, value) in checkpoint.state.accounts() {
            tx.put::<Accounts>(key, AccountValue(value))?;
        }
        for (token, value) in checkpoint.state.tokens() {
            tx.put::<Tokens>(token, TokenValue(value))?;
        }
        write_metadata(&tx, &metadata)?;
        tx.commit()?;
        Ok(Snapshot {
            metadata,
            state: Arc::new(checkpoint.state.clone()),
        })
    }

    /// Persist a terminal finding without advancing verified accounting state.
    pub(crate) fn record_finding(
        &self,
        prior: &Snapshot,
        finding: Finding,
    ) -> Result<Snapshot, PersistenceError> {
        let tx = self.db.tx_mut()?;
        ensure_current(&tx, &prior.metadata)?;
        let mut metadata = prior.metadata.clone();
        if metadata.observed_zone.number < finding.zone.number {
            metadata.observed_zone = finding.zone;
        }
        metadata.status = Status::Diverged { finding };
        write_metadata(&tx, &metadata)?;
        tx.commit()?;
        Ok(Snapshot {
            metadata,
            state: Arc::clone(&prior.state),
        })
    }

    /// Persist the latest delivered canonical tip, whether verifying or diverged.
    pub(crate) fn observe(
        &self,
        prior: &Snapshot,
        observed: BlockRef,
    ) -> Result<Snapshot, PersistenceError> {
        let mut metadata = prior.metadata.clone();
        metadata.observed_zone = observed;
        let tx = self.db.tx_mut()?;
        ensure_current(&tx, &prior.metadata)?;
        write_metadata(&tx, &metadata)?;
        tx.commit()?;
        Ok(Snapshot {
            metadata,
            state: Arc::clone(&prior.state),
        })
    }
}

fn validate_schema<T: DbTx>(tx: &T) -> Result<(), PersistenceError> {
    let version = match tx.get::<Meta>(MetaKey::Version)? {
        Some(MetaValue::Version(version)) => version,
        _ => {
            return Err(PersistenceError::Invalid(
                "schema version is missing".into(),
            ));
        }
    };
    if version != SCHEMA_VERSION {
        return Err(PersistenceError::Schema {
            expected: SCHEMA_VERSION,
            actual: version,
        });
    }
    Ok(())
}

fn read_metadata<T: DbTx>(tx: &T) -> Result<Metadata, PersistenceError> {
    match tx.get::<Meta>(MetaKey::Metadata)? {
        Some(MetaValue::Metadata(metadata)) => Ok(*metadata),
        _ => Err(PersistenceError::Invalid("metadata is missing".into())),
    }
}

fn write_metadata<T: DbTxMut>(tx: &T, metadata: &Metadata) -> Result<(), PersistenceError> {
    let value = MetaValue::Metadata(Box::new(metadata.clone()));
    codec::validate(&value).map_err(PersistenceError::Invalid)?;
    tx.put::<Meta>(MetaKey::Metadata, value)?;
    Ok(())
}

fn ensure_current<T: DbTx>(tx: &T, prior: &Metadata) -> Result<(), PersistenceError> {
    if read_metadata(tx)? != *prior {
        return Err(PersistenceError::StaleSnapshot);
    }
    Ok(())
}

fn write_changed_rows<T: DbTxMut>(
    tx: &T,
    state: &State,
    changes: &ChangedRows,
) -> Result<(), PersistenceError> {
    for key in &changes.accounts {
        match state.account(*key) {
            Some(value) => tx.put::<Accounts>(*key, AccountValue(value))?,
            None => {
                tx.delete::<Accounts>(*key, None)?;
            }
        }
    }
    for token in &changes.tokens {
        match state.token(*token) {
            Some(value) => tx.put::<Tokens>(*token, TokenValue(value))?,
            None => {
                tx.delete::<Tokens>(*token, None)?;
            }
        }
    }
    Ok(())
}

/// Durable checker database failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PersistenceError {
    #[error("database open failed: {0}")]
    Open(eyre::Report),
    #[error("database error: {0}")]
    Database(#[from] reth_db::DatabaseError),
    #[error("accounting error: {0}")]
    Accounting(#[from] crate::accounting::AccountingError),
    #[error("checker identity does not match the database")]
    Identity,
    #[error("checker schema mismatch: expected {expected}, found {actual}")]
    Schema { expected: u32, actual: u32 },
    #[error("stale checker snapshot")]
    StaleSnapshot,
    #[error("invalid checker database: {0}")]
    Invalid(String),
}
