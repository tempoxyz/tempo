use tempo_precompiles::{
    stablecoin_dex::{
        TICK_SPACING,
        orderbook::{MAX_TICK, MIN_TICK},
    },
    storage::Handler,
};

use crate::invariant_tests::framework::{context::InvariantContext, result::InvariantResult};

const MAX_TRAVERSAL: usize = 10_000;

/// Verifies doubly-linked list consistency at every initialized tick level
pub(crate) fn check_linked_list(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
    for is_bid in [true, false] {
        let side = if is_bid { "bid" } else { "ask" };
        let mut tick = MIN_TICK;

        while tick <= MAX_TICK {
            let initialized = ctx.exchange.books[ctx.book_key].is_tick_initialized(tick, is_bid)?;

            let level = ctx.exchange.books[ctx.book_key]
                .tick_level_handler(tick, is_bid)
                .read()?;

            if initialized && level.head == 0 {
                return Ok(InvariantResult::Violated {
                    message: format!("{side} tick={tick}: bitmap set but head=0"),
                });
            }

            if !initialized && level.head != 0 {
                return Ok(InvariantResult::Violated {
                    message: format!("{side} tick={tick}: bitmap clear but head={}", level.head),
                });
            }

            if (level.head == 0) != (level.tail == 0) {
                return Ok(InvariantResult::Violated {
                    message: format!(
                        "{side} tick={tick}: head={}, tail={} (must both be 0 or both non-zero)",
                        level.head, level.tail
                    ),
                });
            }

            if level.head == 0 {
                if level.total_liquidity != 0 {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "{side} tick={tick}: empty tick but total_liquidity={}",
                            level.total_liquidity
                        ),
                    });
                }
                tick += TICK_SPACING;
                continue;
            }

            let mut current_id = level.head;
            let mut prev_id: u128 = 0;
            let mut count: usize = 0;

            while current_id != 0 {
                if count >= MAX_TRAVERSAL {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "{side} tick={tick}: traversed {MAX_TRAVERSAL} orders without reaching tail (cycle?)"
                        ),
                    });
                }

                let order = ctx.exchange.orders[current_id].read()?;

                if order.prev() != prev_id {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "{side} tick={tick}: order {} prev={}, expected {prev_id}",
                            current_id,
                            order.prev()
                        ),
                    });
                }

                if order.is_bid() != is_bid {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "{side} tick={tick}: order {} has is_bid={}, expected {is_bid}",
                            current_id,
                            order.is_bid()
                        ),
                    });
                }

                if order.tick() != tick {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "{side} tick={tick}: order {} has tick={}",
                            current_id,
                            order.tick()
                        ),
                    });
                }

                if order.remaining() == 0 {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "{side} tick={tick}: order {current_id} has remaining=0 but is still in list"
                        ),
                    });
                }

                prev_id = current_id;
                current_id = order.next();
                count += 1;
            }

            if prev_id != level.tail {
                return Ok(InvariantResult::Violated {
                    message: format!(
                        "{side} tick={tick}: last order={prev_id}, level.tail={}",
                        level.tail
                    ),
                });
            }

            if count == 0 {
                return Ok(InvariantResult::Violated {
                    message: format!(
                        "{side} tick={tick}: head={} but traversal found 0 orders",
                        level.head
                    ),
                });
            }

            tick += TICK_SPACING;
        }
    }

    Ok(InvariantResult::Passed)
}
