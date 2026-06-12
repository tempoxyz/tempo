//! Block gas invariants.

use crate::{block::BlockView, invariant};

invariant! {
    id: "TEMPO-BLOCK-GAS-LIMIT",
    severity: P1,
    description: "block gasUsed must not exceed gasLimit",
    fn gas_used_within_limit(block: &BlockView, out: &mut Report<'_>) {
        if block.gas_used > block.gas_limit {
            out.fail(format!("gasUsed ({}) > gasLimit ({})", block.gas_used, block.gas_limit));
        }
    }
}
