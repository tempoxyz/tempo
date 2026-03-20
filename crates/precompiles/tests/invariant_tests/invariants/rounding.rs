use tempo_precompiles::{
    stablecoin_dex::{
        TICK_SPACING,
        orderbook::{MAX_TICK, MIN_TICK, RoundingDirection, base_to_quote},
    },
    storage::Handler,
};

use crate::invariant_tests::framework::{context::InvariantContext, result::InvariantResult};

/// Verifies rounding always favors the protocol.
///
/// For every active order, checks:
/// - base_to_quote(remaining, tick, Up) >= base_to_quote(remaining, tick, Down)
/// - The difference is at most 1
/// - Escrow for remaining <= escrow for original amount
pub(crate) fn check_rounding(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
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

                let quote_up = base_to_quote(order.remaining(), tick, RoundingDirection::Up);
                let quote_down = base_to_quote(order.remaining(), tick, RoundingDirection::Down);

                match (quote_up, quote_down) {
                    (Some(up), Some(down)) => {
                        if up < down {
                            return Ok(InvariantResult::Violated {
                                message: format!(
                                    "{side} tick={tick} order={current_id}: \
                                     round_up({})={up} < round_down={down}",
                                    order.remaining()
                                ),
                            });
                        }
                        if up - down > 1 {
                            return Ok(InvariantResult::Violated {
                                message: format!(
                                    "{side} tick={tick} order={current_id}: \
                                     rounding gap={} (up={up}, down={down})",
                                    up - down
                                ),
                            });
                        }
                    }
                    (None, _) | (_, None) => {
                        return Ok(InvariantResult::Violated {
                            message: format!(
                                "{side} tick={tick} order={current_id}: \
                                 base_to_quote overflow for remaining={}",
                                order.remaining()
                            ),
                        });
                    }
                }

                if let (Some(remaining_escrow), Some(original_escrow)) = (
                    base_to_quote(order.remaining(), tick, RoundingDirection::Up),
                    base_to_quote(order.amount(), tick, RoundingDirection::Up),
                ) && remaining_escrow > original_escrow
                {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "{side} tick={tick} order={current_id}: \
                             escrow(remaining)={remaining_escrow} > escrow(amount)={original_escrow}"
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
