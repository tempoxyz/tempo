//! Frozen pre-T12 swap execution for historical block compatibility.
//!
//! Keep settlement-derived outputs and the ordering of arithmetic, storage access,
//! and errors from before TIP-1088. In particular, the route side selects input
//! arithmetic, but the stored order side selects the output returned by settlement.
//! T12+ execution and quoting use the shared per-order walker instead.

use super::*;

impl StablecoinDEX {
    /// Partially fill an order with the specified amount. Fill amount is denominated in base token.
    pub(super) fn partial_fill_order_legacy(
        &mut self,
        order: &mut Order,
        level: &mut TickLevel,
        fill_amount: u128,
        taker: Address,
    ) -> Result<u128> {
        let orderbook = self.books[order.book_key()].read()?;

        // Update order remaining amount
        let new_remaining = order.remaining() - fill_amount;
        self.orders[order.order_id()]
            .remaining()?
            .write(new_remaining)?;
        order.remaining = new_remaining;

        // Calculate quote amount for this fill (used by both maker settlement and taker output)
        let quote_amount = base_to_quote(
            fill_amount,
            order.tick(),
            if order.is_bid() {
                RoundingDirection::Down // Bid: taker receives quote, round DOWN
            } else {
                RoundingDirection::Up // Ask: maker receives quote, round UP to favor maker
            },
        )
        .ok_or(TempoPrecompileError::under_overflow())?;

        if order.is_bid() {
            // Bid order maker receives base tokens (exact amount)
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
        } else {
            // Ask order maker receives quote tokens
            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;
        }

        // Taker output: bid→quote, ask→base (zero-sum with maker)
        let amount_out = if order.is_bid() {
            quote_amount
        } else {
            fill_amount
        };

        // Update price level total liquidity
        let new_liquidity = level
            .total_liquidity
            .checked_sub(fill_amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        level.total_liquidity = new_liquidity;

        self.books[order.book_key()]
            .tick_level_handler_mut(order.tick(), order.is_bid())
            .write(*level)?;

        // Emit OrderFilled event for partial fill
        self.emit_order_filled(order.order_id(), order.maker(), taker, fill_amount, true)?;

        Ok(amount_out)
    }

    /// Fill an order and delete from storage. Returns the next best order and price level.
    ///
    /// NOTE: Maker transfer policy is not enforced here to not block swaps on the pair.
    /// Note that TIP403 checks on order placement and withdraws are enforced.
    /// [`cancel_stale_order`](Self::cancel_stale_order) can be used to remove orders.
    pub(super) fn fill_order_legacy(
        &mut self,
        storage_credits: &mut StorageCreditDeltas,
        book_key: B256,
        order: &mut Order,
        mut level: TickLevel,
        taker: Address,
    ) -> Result<(u128, Option<(TickLevel, Order)>)> {
        debug_assert_eq!(order.book_key(), book_key);

        let orderbook = self.books[book_key].read()?;
        let fill_amount = order.remaining();

        // Settlement: bid rounds DOWN (taker receives less), ask rounds UP (maker receives more)
        let amount_out = if order.is_bid() {
            // Bid maker receives base tokens (exact amount)
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
            // Taker receives quote tokens - round DOWN
            base_to_quote(fill_amount, order.tick(), RoundingDirection::Down)
                .ok_or(TempoPrecompileError::under_overflow())?
        } else {
            // Ask maker receives quote tokens - round UP to favor maker
            let quote_amount = base_to_quote(fill_amount, order.tick(), RoundingDirection::Up)
                .ok_or(TempoPrecompileError::under_overflow())?;

            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;

            // Taker receives base tokens (exact amount)
            fill_amount
        };

        // Emit OrderFilled event for complete fill
        self.emit_order_filled(order.order_id(), order.maker(), taker, fill_amount, false)?;

        if order.is_flip() {
            // Create a new flip order with flipped side and swapped ticks.
            // Bid becomes Ask, Ask becomes Bid.
            // The current tick becomes the new flip_tick, and flip_tick becomes the new tick.
            // Uses internal balance only, does not transfer from wallet.
            let res = if self.storage.spec().is_t5() {
                // Post T5: flip the order in place, without creating a new one.
                self.flip_in_place(order, orderbook.base, orderbook.quote)
            } else {
                self.place_flip(
                    order.maker(),
                    orderbook.base,
                    order.amount(),
                    !order.is_bid(),
                    order.flip_tick(),
                    order.tick(),
                    true,
                )
                .map(|_| ())
            };

            // Business logic errors are ignored so that flip failure does not block the swap.
            // System errors (OOG, DB errors, panics) propagate because state may be inconsistent.
            if let Err(err) = &res {
                if err.is_system_error() && self.storage.spec().is_t1a() {
                    return Err(res.unwrap_err());
                }

                if self.storage.spec().is_t5() {
                    self.emit_event(StablecoinDEXEvents::flip_failed(
                        order.order_id(),
                        order.maker(),
                        err.selector(),
                    ))?;
                }
            }

            // T5+: a successful `flip_in_place` already rewrote the order
            // record under the same `orderId` (TIP-1056). In every other case
            // (pre-T5, or T5 with a swallowed flip failure) the filled order
            // record must be deleted to avoid leaving an orphan in storage.
            let keep_record = self.storage.spec().is_t5() && res.is_ok();
            if !keep_record {
                self.delete_order_and_track_deltas(storage_credits, order)?;
            }
        } else {
            // Non-flip filled order: always delete.
            self.delete_order_and_track_deltas(storage_credits, order)?;
        }

        // Advance tick if liquidity is exhausted
        let next_tick_info = if order.next() == 0 {
            self.books[book_key]
                .tick_level_handler_mut(order.tick(), order.is_bid())
                .delete()?;
            self.books[book_key].delete_tick_bit(order.tick(), order.is_bid())?;

            let (tick, has_liquidity) =
                self.books[book_key].next_initialized_tick(order.tick(), order.is_bid())?;

            // Update best_tick when tick is exhausted
            if order.is_bid() {
                let new_best = if has_liquidity { tick } else { i16::MIN };
                self.books[book_key].best_bid_tick.write(new_best)?;
            } else {
                let new_best = if has_liquidity { tick } else { i16::MAX };
                self.books[book_key].best_ask_tick.write(new_best)?;
            }

            if !has_liquidity {
                // No more liquidity at better prices - return None to signal completion
                None
            } else {
                let new_level = self.books[book_key]
                    .tick_level_handler(tick, order.is_bid())
                    .read()?;
                let new_order = self.orders[new_level.links.head].read_in_book(book_key)?;

                Some((new_level, new_order))
            }
        } else {
            // If there are subsequent orders at tick, advance to next order
            level.links.head = order.next();
            let (_, credits) = StorageCredits::new().track_minted_credits(self.address, || {
                self.orders[order.next()].prev()?.delete()
            })?;

            let new_liquidity = level
                .total_liquidity
                .checked_sub(fill_amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            level.total_liquidity = new_liquidity;

            self.books[book_key]
                .tick_level_handler_mut(order.tick(), order.is_bid())
                .write(level)?;

            let new_order = self.orders[order.next()].read_in_book(book_key)?;
            storage_credits.credit_slots(new_order.maker(), credits);

            Some((level, new_order))
        };

        Ok((amount_out, next_tick_info))
    }

    /// Fill orders for exact output amount
    pub(super) fn fill_orders_exact_out_legacy(
        &mut self,
        storage_credits: &mut StorageCreditDeltas,
        book_key: B256,
        bid: bool,
        mut amount_out: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = self.orders[level.links.head].read_in_book(book_key)?;

        let mut total_amount_in: u128 = 0;

        while amount_out > 0 {
            let tick = order.tick();

            let (fill_amount, amount_in) = if bid {
                // For bids: amount_out is quote, amount_in is base
                // Round UP baseNeeded to ensure we collect enough base to cover exact output
                let base_needed = quote_to_base(amount_out, tick, RoundingDirection::Up)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                let fill_amount = base_needed.min(order.remaining());
                (fill_amount, fill_amount)
            } else {
                // For asks: amount_out is base, amount_in is quote
                // Taker pays quote, maker receives quote - round UP (zero-sum with maker)
                let fill_amount = amount_out.min(order.remaining());
                let amount_in = base_to_quote(fill_amount, tick, RoundingDirection::Up)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                (fill_amount, amount_in)
            };

            if fill_amount < order.remaining() {
                self.partial_fill_order_legacy(&mut order, &mut level, fill_amount, taker)?;
                total_amount_in = total_amount_in
                    .checked_add(amount_in)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                break;
            } else {
                let (amount_out_received, next_order_info) =
                    self.fill_order_legacy(storage_credits, book_key, &mut order, level, taker)?;
                total_amount_in = total_amount_in
                    .checked_add(amount_in)
                    .ok_or(TempoPrecompileError::under_overflow())?;

                // Update remaining amount_out
                if bid {
                    // Round UP baseNeeded to match the initial calculation
                    let base_needed = quote_to_base(amount_out, tick, RoundingDirection::Up)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                    if base_needed > order.remaining() {
                        amount_out = amount_out
                            .checked_sub(amount_out_received)
                            .ok_or(TempoPrecompileError::under_overflow())?;
                    } else {
                        amount_out = 0;
                    }
                } else if amount_out > order.remaining() {
                    amount_out = amount_out
                        .checked_sub(amount_out_received)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                } else {
                    amount_out = 0;
                }

                if let Some((new_level, new_order)) = next_order_info {
                    level = new_level;
                    order = new_order;
                } else {
                    if amount_out > 0 {
                        return Err(StablecoinDEXError::insufficient_liquidity().into());
                    }
                    break;
                }
            }
        }

        Ok(total_amount_in)
    }

    /// Fill orders with exact amount in
    pub(super) fn fill_orders_exact_in_legacy(
        &mut self,
        storage_credits: &mut StorageCreditDeltas,
        book_key: B256,
        bid: bool,
        mut amount_in: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = self.orders[level.links.head].read_in_book(book_key)?;

        let mut total_amount_out: u128 = 0;

        while amount_in > 0 {
            let tick = order.tick();

            let fill_amount = if bid {
                // For bids: amount_in is base, fill in base
                amount_in.min(order.remaining())
            } else {
                // For asks: amount_in is quote, convert to base
                // Round down base_out (user receives less base, favors protocol)
                let base_out = quote_to_base(amount_in, tick, RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                base_out.min(order.remaining())
            };

            if fill_amount < order.remaining() {
                let amount_out =
                    self.partial_fill_order_legacy(&mut order, &mut level, fill_amount, taker)?;
                total_amount_out = total_amount_out
                    .checked_add(amount_out)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                break;
            } else {
                let (amount_out, next_order_info) =
                    self.fill_order_legacy(storage_credits, book_key, &mut order, level, taker)?;
                total_amount_out = total_amount_out
                    .checked_add(amount_out)
                    .ok_or(TempoPrecompileError::under_overflow())?;

                // Set to 0 to avoid rounding errors
                if bid {
                    if amount_in > order.remaining() {
                        amount_in = amount_in
                            .checked_sub(order.remaining())
                            .ok_or(TempoPrecompileError::under_overflow())?;
                    } else {
                        amount_in = 0;
                    }
                } else {
                    // For asks: taker pays quote, maker receives quote
                    let base_out = quote_to_base(amount_in, tick, RoundingDirection::Down)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                    if base_out > order.remaining() {
                        // Quote consumed = what maker receives - round UP (zero-sum with maker)
                        let quote_needed =
                            base_to_quote(order.remaining(), tick, RoundingDirection::Up)
                                .ok_or(TempoPrecompileError::under_overflow())?;
                        amount_in = amount_in
                            .checked_sub(quote_needed)
                            .ok_or(TempoPrecompileError::under_overflow())?;
                    } else {
                        amount_in = 0;
                    }
                }

                if let Some((new_level, new_order)) = next_order_info {
                    level = new_level;
                    order = new_order;
                } else {
                    if amount_in > 0 {
                        return Err(StablecoinDEXError::insufficient_liquidity().into());
                    }
                    break;
                }
            }
        }

        Ok(total_amount_out)
    }
}
