use std::path::Path;
use thiserror::Error;

use redb::{Database, TableDefinition};

const DECIDED_VALUES_TABLE: redb::TableDefinition<HeightKey, Vec<u8>> =
    TableDefinition::new("decided_values");

const UNDECIDED_PROPOSALS_TABLE: redb::TableDefinition<UndecidedValueKey, Vec<u8>> =
    TableDefinition::new("undecided_values");

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(#[from] redb::DatabaseError),
}
pub struct Store {
    db: redb::Database,
}

impl Store {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self {
            db: Database::create(path).map_err(StoreError::Database)?,
        })
    }
}