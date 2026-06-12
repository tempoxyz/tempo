//! Supply-integrity invariants for TIP20 tokens.
//!
//! Each check is a pure function of [`Tip20Snapshot`] — no storage reads, no
//! `?`. Add another as a single `invariant!` block; reuse fields already in the
//! snapshot so it doesn't touch `read`. The public TIP20 API can't produce a
//! violating state (the precompile guards reject it), so tests inject state
//! directly at the authoritative slots.

use crate::{invariant, tip20::Tip20Snapshot};

invariant! {
    id: "TEMPO-TIP20-SUPPLY-CAP",
    severity: P1,
    description: "totalSupply must not exceed supplyCap when a cap is set",
    fn supply_cap(t: &Tip20Snapshot, out: &mut Report<'_>) {
        if !t.supply_cap.is_zero() && t.total_supply > t.supply_cap {
            out.fail(format!("totalSupply ({}) > supplyCap ({})", t.total_supply, t.supply_cap));
        }
    }
}

invariant! {
    id: "TEMPO-TIP20-OPTIN-SUPPLY",
    severity: P1,
    description: "rewards optedInSupply must not exceed totalSupply",
    fn opted_in_supply(t: &Tip20Snapshot, out: &mut Report<'_>) {
        if t.opted_in_supply > t.total_supply {
            out.fail(format!(
                "optedInSupply ({}) > totalSupply ({})",
                t.opted_in_supply, t.total_supply
            ));
        }
    }
}
