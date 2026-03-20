use tempo_precompiles::{
    stablecoin_dex::{
        TICK_SPACING,
        orderbook::{MAX_TICK, MIN_TICK},
    },
    storage::Handler,
};

use crate::invariant_tests::framework::{context::InvariantContext, result::InvariantResult};

/// Verifies bitmap consistency: bit set <=> tick has liquidity > 0 (TEMPO-DEX15).
///
/// Detects ghost bits and invisible orders.
pub(crate) fn check_bitmap(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
    for is_bid in [true, false] {
        let side = if is_bid { "bid" } else { "ask" };
        let mut tick = MIN_TICK;

        while tick <= MAX_TICK {
            let initialized = ctx.exchange.books[ctx.book_key].is_tick_initialized(tick, is_bid)?;
            let level = ctx.exchange.books[ctx.book_key]
                .tick_level_handler(tick, is_bid)
                .read()?;
            let has_liquidity = level.total_liquidity > 0;

            if initialized && !has_liquidity {
                return Ok(InvariantResult::Violated {
                    message: format!(
                        "{side} tick={tick}: bitmap set but total_liquidity=0 (ghost bit)"
                    ),
                });
            }

            if !initialized && has_liquidity {
                return Ok(InvariantResult::Violated {
                    message: format!(
                        "{side} tick={tick}: bitmap clear but total_liquidity={} (invisible orders)",
                        level.total_liquidity
                    ),
                });
            }

            tick += TICK_SPACING;
        }
    }

    Ok(InvariantResult::Passed)
}
