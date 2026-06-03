//! Ordered commit helpers for production Block-STM execution.

use crate::blockstm::{overlay::BlockStmOverlay, rw_set::BlockStmWriteSet};

/// Commits one validated write set in builder-selected order.
pub fn commit_validated_writes(
    overlay: &mut BlockStmOverlay,
    tx_index: usize,
    writes: &BlockStmWriteSet,
) {
    overlay.commit(tx_index, writes);
}
