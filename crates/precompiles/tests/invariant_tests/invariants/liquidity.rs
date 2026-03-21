use tempo_precompiles::{
    stablecoin_dex::{
        TICK_SPACING,
        orderbook::{MAX_TICK, MIN_TICK},
    },
    storage::Handler,
};

use crate::invariant_tests::framework::{context::InvariantContext, result::InvariantResult};

/// Verifies that total_liquidity matches the sum of order.remaining() at each tick
pub(crate) fn check_liquidity(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
    for is_bid in [true, false] {
        let side = if is_bid { "bid" } else { "ask" };
        let mut tick = MIN_TICK;

        while tick <= MAX_TICK {
            if !ctx.exchange.books[ctx.book_key].is_tick_initialized(tick, is_bid)? {
                tick += TICK_SPACING;
                continue;
            }

            let level = ctx.exchange.books[ctx.book_key]
                .tick_level_handler(tick, is_bid)
                .read()?;

            if level.head == 0 {
                tick += TICK_SPACING;
                continue;
            }

            // Sum remaining across all orders in the linked list
            let mut sum_remaining: u128 = 0;
            let mut current_id = level.head;

            while current_id != 0 {
                let order = ctx.exchange.orders[current_id].read()?;
                sum_remaining = sum_remaining
                    .checked_add(order.remaining())
                    .ok_or_else(|| eyre::eyre!("overflow summing remaining"))?;
                current_id = order.next();
            }

            if sum_remaining != level.total_liquidity {
                return Ok(InvariantResult::Violated {
                    message: format!(
                        "{side} tick={tick}: total_liquidity={}, sum(remaining)={sum_remaining}",
                        level.total_liquidity
                    ),
                });
            }

            tick += TICK_SPACING;
        }
    }

    Ok(InvariantResult::Passed)
}
