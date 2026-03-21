use tempo_precompiles::{
    stablecoin_dex::{
        TICK_SPACING,
        orderbook::{MAX_TICK, MIN_TICK},
    },
    storage::Handler,
};

use crate::invariant_tests::framework::{context::InvariantContext, result::InvariantResult};

/// Verifies best_bid_tick and best_ask_tick accuracy (TEMPO-DEX12, TEMPO-DEX13).
///
/// Checks:
/// - If best tick is not sentinel, it must have liquidity
/// - No tick with liquidity exists at a better price than best tick
pub(crate) fn check_best_ticks(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
    let book = ctx.exchange.books[ctx.book_key].read()?;

    // Bid side
    if book.best_bid_tick != i16::MIN {
        // TEMPO-DEX12: best bid tick must have liquidity
        let level = ctx.exchange.books[ctx.book_key]
            .tick_level_handler(book.best_bid_tick, true)
            .read()?;
        if level.total_liquidity == 0 {
            return Ok(InvariantResult::Violated {
                message: format!("best_bid_tick={} has total_liquidity=0", book.best_bid_tick),
            });
        }

        let mut tick = book.best_bid_tick + TICK_SPACING;
        while tick <= MAX_TICK {
            if ctx.exchange.books[ctx.book_key].is_tick_initialized(tick, true)? {
                let above = ctx.exchange.books[ctx.book_key]
                    .tick_level_handler(tick, true)
                    .read()?;
                if above.total_liquidity > 0 {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "bid tick={tick} has liquidity={} but best_bid_tick={}",
                            above.total_liquidity, book.best_bid_tick
                        ),
                    });
                }
            }
            tick += TICK_SPACING;
        }
    } else {
        let mut tick = MIN_TICK;
        while tick <= MAX_TICK {
            if ctx.exchange.books[ctx.book_key].is_tick_initialized(tick, true)? {
                let level = ctx.exchange.books[ctx.book_key]
                    .tick_level_handler(tick, true)
                    .read()?;
                if level.total_liquidity > 0 {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "best_bid_tick=MIN but bid tick={tick} has liquidity={}",
                            level.total_liquidity
                        ),
                    });
                }
            }
            tick += TICK_SPACING;
        }
    }

    // Ask side
    if book.best_ask_tick != i16::MAX {
        // TEMPO-DEX13: best ask tick must have liquidity
        let level = ctx.exchange.books[ctx.book_key]
            .tick_level_handler(book.best_ask_tick, false)
            .read()?;
        if level.total_liquidity == 0 {
            return Ok(InvariantResult::Violated {
                message: format!("best_ask_tick={} has total_liquidity=0", book.best_ask_tick),
            });
        }

        let mut tick = MIN_TICK;
        while tick < book.best_ask_tick {
            if ctx.exchange.books[ctx.book_key].is_tick_initialized(tick, false)? {
                let below = ctx.exchange.books[ctx.book_key]
                    .tick_level_handler(tick, false)
                    .read()?;
                if below.total_liquidity > 0 {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "ask tick={tick} has liquidity={} but best_ask_tick={}",
                            below.total_liquidity, book.best_ask_tick
                        ),
                    });
                }
            }
            tick += TICK_SPACING;
        }
    } else {
        let mut tick = MIN_TICK;
        while tick <= MAX_TICK {
            if ctx.exchange.books[ctx.book_key].is_tick_initialized(tick, false)? {
                let level = ctx.exchange.books[ctx.book_key]
                    .tick_level_handler(tick, false)
                    .read()?;
                if level.total_liquidity > 0 {
                    return Ok(InvariantResult::Violated {
                        message: format!(
                            "best_ask_tick=MAX but ask tick={tick} has liquidity={}",
                            level.total_liquidity
                        ),
                    });
                }
            }
            tick += TICK_SPACING;
        }
    }

    Ok(InvariantResult::Passed)
}
