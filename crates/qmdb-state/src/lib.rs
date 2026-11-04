//! QMDB state commitment for Tempo.
//!
//! Tempo's state root commits to two ordered `current` QMDBs, one holding accounts as 104-byte
//! values and one holding storage slots as 32-byte values, each under a 32-byte key (see
//! [`layout`]). Ordered keys give exclusion proofs, which zones need to authenticate reads of unset
//! slots. Splitting the databases keeps slots at their own size instead of padding them to the
//! account size, and merkleizes both in parallel.
//!
//! The QMDB roots depend on the operation history, not only on the final key-value set, so every
//! node must produce the same batches:
//!
//! - [`import`] builds the state at the snapshot block from the hashed state tables, in key order
//!   and in chunks of [`import::CHUNK_KEYS`] keys per database.
//! - [`diff::block_writes`] turns each later block's execution output into one batch per database
//!   of only the keys whose value changed, sorted by key.
//!
//! [`Store`] holds both databases on a dedicated commonware runtime thread. It builds each executed
//! block's batches on its parent's unapplied batches, and applies them to disk only when the node
//! persists the block, so the on-disk state never runs ahead of the database.

pub mod diff;
pub mod import;
pub mod layout;
mod store;

pub use store::{BlockRef, Config, Error, QmdbBatch, Status, Store};
