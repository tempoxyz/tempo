use super::{context::InvariantContext, result::InvariantResult};

pub(crate) struct Invariant {
    pub(crate) name: &'static str,
    #[allow(dead_code)]
    pub(crate) description: &'static str,
    pub(crate) check: fn(&InvariantContext<'_>) -> eyre::Result<InvariantResult>,
}

pub(crate) fn all_invariants() -> Vec<Invariant> {
    use crate::invariant_tests::invariants::*;

    vec![
        Invariant {
            name: "linked_list_integrity",
            description: "Doubly-linked list pointers consistent at every tick level",
            check: linked_list::check_linked_list,
        },
        Invariant {
            name: "liquidity_consistency",
            description: "total_liquidity == sum of order.remaining() at each tick",
            check: liquidity::check_liquidity,
        },
        Invariant {
            name: "balance_conservation",
            description: "DEX external balance >= internal balances + escrow (TEMPO-DEX10)",
            check: balance::check_balances,
        },
    ]
}
