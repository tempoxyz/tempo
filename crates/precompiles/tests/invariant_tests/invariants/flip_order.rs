use tempo_precompiles::{
    stablecoin_dex::{
        TICK_SPACING,
        orderbook::{MAX_TICK, MIN_TICK},
    },
    storage::Handler,
};

use crate::invariant_tests::framework::{context::InvariantContext, result::InvariantResult};

/// Verifies flip order constraints for all active flip orders.
///
/// Checks:
/// - Bid flip: flip_tick > tick (buy low, sell high)
/// - Ask flip: flip_tick < tick (sell high, buy low)
/// - flip_tick is within bounds [MIN_TICK, MAX_TICK]
/// - flip_tick is aligned to TICK_SPACING
/// - remaining <= amount
pub(crate) fn check_flip_orders(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
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

            let mut current_id = level.head;
            while current_id != 0 {
                let order = ctx.exchange.orders[current_id].read()?;

                if order.is_flip() {
                    if is_bid && order.flip_tick() <= order.tick() {
                        return Ok(InvariantResult::Violated {
                            message: format!(
                                "{side} order={current_id}: bid flip_tick={} <= tick={}",
                                order.flip_tick(),
                                order.tick()
                            ),
                        });
                    }
                    if !is_bid && order.flip_tick() >= order.tick() {
                        return Ok(InvariantResult::Violated {
                            message: format!(
                                "{side} order={current_id}: ask flip_tick={} >= tick={}",
                                order.flip_tick(),
                                order.tick()
                            ),
                        });
                    }

                    if !(MIN_TICK..=MAX_TICK).contains(&order.flip_tick()) {
                        return Ok(InvariantResult::Violated {
                            message: format!(
                                "{side} order={current_id}: flip_tick={} out of bounds",
                                order.flip_tick()
                            ),
                        });
                    }

                    if order.flip_tick() % TICK_SPACING != 0 {
                        return Ok(InvariantResult::Violated {
                            message: format!(
                                "{side} order={current_id}: flip_tick={} not aligned to TICK_SPACING",
                                order.flip_tick()
                            ),
                        });
                    }
                }

                if order.remaining() > order.amount() {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "{side} order={current_id}: remaining={} > amount={}",
                            order.remaining(),
                            order.amount()
                        ),
                    });
                }

                current_id = order.next();
            }

            tick += TICK_SPACING;
        }
    }

    Ok(InvariantResult::Passed)
}
