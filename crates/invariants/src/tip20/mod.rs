//! TIP20 invariants, grouped by concern (one file can hold several related
//! checks). State is read **once** per token into [`Tip20Snapshot`] by `read`;
//! checks are pure functions of that snapshot.

use crate::{Check, EvalError, Scope, ScopeKind};
use alloy_primitives::{Address, U256};
use tempo_precompiles::tip20::TIP20Token;

mod supply;

impl Scope for Tip20Snapshot {
    const KIND: ScopeKind = ScopeKind::Tip20Token;
}
crate::inventory::collect!(Check<Tip20Snapshot>);

/// Pre-read scalar state for one TIP20 token. This is the scope's **read set**:
/// every field a TIP20 check may use is read once here. A new scalar invariant
/// reuses these fields; only one needing a *new* scalar extends this struct and
/// `read` (a small, central, type-checked change). Unbounded keyed data
/// (per-holder balances/allowances) is not put here — that needs enumeration.
#[derive(Debug, Clone, Copy)]
pub struct Tip20Snapshot {
    pub token: Address,
    pub total_supply: U256,
    pub supply_cap: U256,
    pub opted_in_supply: U256,
}

/// Read a token's scalar state once through the real `TIP20Token` accessors
/// (the layout source of truth). This is the single I/O point for the scope and
/// the natural home for a future batched multi-slot read.
pub(crate) fn read(address: Address) -> Result<Tip20Snapshot, EvalError> {
    let token = TIP20Token::from_address_unchecked(address);
    Ok(Tip20Snapshot {
        token: address,
        total_supply: token.total_supply()?,
        supply_cap: token.supply_cap()?,
        opted_in_supply: U256::from(token.get_opted_in_supply()?),
    })
}
