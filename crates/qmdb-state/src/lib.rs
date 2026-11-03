//! QMDB state commitment for Tempo.
//!
//! Tempo's state root becomes the root of one ordered `current` QMDB that holds every account and
//! storage slot as a fixed 32-byte key and a fixed 104-byte value (see [`layout`]). Ordered keys
//! give exclusion proofs, which zones need to authenticate reads of unset slots.
//!
//! The QMDB root depends on the operation history, not only on the final key-value set, so every
//! node must produce the same batches:
//!
//! - [`import`] builds the state at the snapshot block from the hashed state tables, in key order
//!   and in chunks of [`import::CHUNK_KEYS`] keys.
//! - [`diff::block_writes`] turns each later block's execution output into one batch of only the
//!   keys whose value changed, sorted by key.
//!
//! [`Store`] holds the database on a dedicated commonware runtime thread. It builds each executed
//! block's batch on its parent's unapplied batch, and applies batches to disk only when the node
//! finalizes them, so the on-disk database never runs ahead of a block that could reorg.

pub mod diff;
pub mod import;
pub mod layout;
mod store;

pub use store::{BlockRef, Config, Error, QmdbBatch, Status, Store};
