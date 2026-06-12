//! Block-level invariants. Block state is pure data (no storage reads), so
//! [`BlockView`] *is* the snapshot — there's no `read` step and the runner uses
//! it directly. Use this scope for checks over per-block header / receipt
//! fields.

use crate::{Check, Scope, ScopeKind};

mod gas;

/// Block entity / snapshot. Extend with header / receipt fields as checks need
/// them. Doubles as both the enumeration entity and the snapshot because no
/// storage read is involved.
#[derive(Debug, Clone, Copy)]
pub struct BlockView {
    pub number: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
}

impl Scope for BlockView {
    const KIND: ScopeKind = ScopeKind::Block;
}
crate::inventory::collect!(Check<BlockView>);
