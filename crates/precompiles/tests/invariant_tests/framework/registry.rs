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
        Invariant {
            name: "best_tick_accuracy",
            description: "best_bid/ask is the actual best tick with liquidity (TEMPO-DEX12/13)",
            check: best_tick::check_best_ticks,
        },
        Invariant {
            name: "bitmap_consistency",
            description: "Bitmap bit set iff tick has liquidity > 0 (TEMPO-DEX15)",
            check: bitmap::check_bitmap,
        },
        Invariant {
            name: "rounding_favors_protocol",
            description: "round_up >= round_down and escrow(remaining) <= escrow(amount)",
            check: rounding::check_rounding,
        },
        Invariant {
            name: "flip_order_correctness",
            description: "Flip tick constraints and remaining <= amount for all orders",
            check: flip_order::check_flip_orders,
        },
        Invariant {
            name: "cross_pair_isolation",
            description: "Control pair remains untouched by operations on active pair",
            check: cross_pair::check_cross_pair,
        },
    ]
}
