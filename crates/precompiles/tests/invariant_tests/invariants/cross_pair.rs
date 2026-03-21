use tempo_precompiles::{
    stablecoin_dex::{
        TICK_SPACING,
        orderbook::{MAX_TICK, MIN_TICK},
    },
    storage::Handler,
};

use crate::invariant_tests::framework::{context::InvariantContext, result::InvariantResult};

/// Verifies that operations on the active pair do not corrupt an untouched control pair.
pub(crate) fn check_cross_pair(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
    let book = ctx.exchange.books[ctx.control_book_key].read()?;

    if book.best_bid_tick != i16::MIN {
        return Ok(InvariantResult::Violated {
            message: format!(
                "control pair: best_bid_tick={}, expected i16::MIN",
                book.best_bid_tick
            ),
        });
    }
    if book.best_ask_tick != i16::MAX {
        return Ok(InvariantResult::Violated {
            message: format!(
                "control pair: best_ask_tick={}, expected i16::MAX",
                book.best_ask_tick
            ),
        });
    }

    for is_bid in [true, false] {
        let side = if is_bid { "bid" } else { "ask" };
        let mut tick = MIN_TICK;

        while tick <= MAX_TICK {
            if ctx.exchange.books[ctx.control_book_key].is_tick_initialized(tick, is_bid)? {
                return Ok(InvariantResult::Violated {
                    message: format!("control pair: {side} tick={tick} is initialized"),
                });
            }
            tick += TICK_SPACING;
        }
    }

    for &order_id in ctx.created_order_ids {
        let order = ctx.exchange.orders[order_id].read()?;
        if !order.maker().is_zero() && order.book_key() == ctx.control_book_key {
            return Ok(InvariantResult::Violated {
                message: format!("control pair: order {order_id} has control book_key"),
            });
        }
    }

    Ok(InvariantResult::Passed)
}
