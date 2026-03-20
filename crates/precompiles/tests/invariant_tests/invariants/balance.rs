use tempo_precompiles::{
    stablecoin_dex::{
        TICK_SPACING,
        orderbook::{MAX_TICK, MIN_TICK, RoundingDirection, base_to_quote},
    },
    storage::Handler,
    tip20::{ITIP20, TIP20Token},
};

use crate::invariant_tests::framework::{context::InvariantContext, result::InvariantResult};

/// Verifies DEX solvency (TEMPO-DEX10).
///
/// DEX external balance must equal internal balances + escrow, within dust tolerance from fills.
pub(crate) fn check_balances(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
    for (token, is_quote) in [(ctx.base_token, false), (ctx.quote_token, true)] {
        let token_name = if is_quote { "quote" } else { "base" };

        let tip20 = TIP20Token::from_address(token)?;
        let dex_external: u128 = tip20
            .balance_of(ITIP20::balanceOfCall {
                account: ctx.exchange.address(),
            })?
            .try_into()
            .map_err(|_| eyre::eyre!("dex external balance exceeds u128"))?;

        let mut total_internal: u128 = 0;
        for &user in ctx.users {
            let balance = ctx.exchange.balance_of(user, token)?;
            total_internal = total_internal
                .checked_add(balance)
                .ok_or_else(|| eyre::eyre!("internal balance sum overflow"))?;
        }

        let mut total_escrow: u128 = 0;
        let mut order_count: u128 = 0;

        for is_bid in [true, false] {
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
                    order_count += 1;

                    let escrow_for_token = if is_bid && is_quote {
                        base_to_quote(order.remaining(), tick, RoundingDirection::Up)
                            .ok_or_else(|| eyre::eyre!("escrow overflow"))?
                    } else if !is_bid && !is_quote {
                        order.remaining()
                    } else {
                        0
                    };

                    total_escrow = total_escrow
                        .checked_add(escrow_for_token)
                        .ok_or_else(|| eyre::eyre!("escrow sum overflow"))?;

                    current_id = order.next();
                }

                tick += TICK_SPACING;
            }
        }

        // TEMPO-DEX10: DEX external balance ≈ internal balances + escrow.
        // TEMPO-DEX8: each swap produces up to (ordersFilled + hops) units of dust.
        let total_owed = total_internal.saturating_add(total_escrow);
        let diff = dex_external.abs_diff(total_owed);

        let max_dust = (ctx.swap_count as u128)
            .saturating_mul(50)
            .saturating_add(order_count.saturating_mul(2));

        if diff > max_dust {
            return Ok(InvariantResult::Violated {
                message: format!(
                    "{token_name}: |external ({dex_external}) - owed ({total_owed})| = {diff} > tolerance ({max_dust})"
                ),
            });
        }
    }

    Ok(InvariantResult::Passed)
}
