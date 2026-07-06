//! Page-state commitment primitives for Tempo page accounts.
//!
//! Plain storage remains the source of truth. This crate maintains a derived BLAKE3 page tree and
//! provides the sentinel transform that feeds page roots into reth's normal state-root machinery.

use tempo_primitives as _;

pub mod db;
pub mod manager;
pub mod metrics;
pub mod page;
pub mod recovery;
pub mod sentinel;
pub mod smt;
pub mod store;
pub mod updates;

pub use db::{MdbxPageStore, Watermark};
pub use manager::{PageBlockOutput, PageStateError, PageStateManager};
pub use page::{PAGE_DOMAIN, PAGE_INDEX_BITS, PAGE_SIZE_BYTES, PAGE_SIZE_WORDS, Page, PageIndex};
pub use recovery::{
    PageStateRecoverySource, RecoveryPageKey, RecoveryReport, recover_from_plain_state,
};
pub use smt::{EMPTY_PAGE_ROOT, NodePath, PageProof, PageSmt, PageTreeNode, empty_page_root};
pub use store::{MemoryPageStore, OverlayPageStore, PageStoreError, PageStoreRead, PageStoreScan};
pub use updates::{AccountPageUpdates, PageStateUpdates};
