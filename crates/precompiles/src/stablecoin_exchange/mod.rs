//! Stablecoin DEX types and utilities.
pub mod dispatch;
pub mod error;
pub mod order;
pub mod orderbook;

pub use order::Order;
pub use orderbook::{
    MAX_TICK, MIN_TICK, Orderbook, PRICE_SCALE, RoundingDirection, TickLevel, base_to_quote,
    quote_to_base, tick_to_price,
};
use tempo_contracts::precompiles::PATH_USD_ADDRESS;
pub use tempo_contracts::precompiles::{
    IStablecoinExchange, StablecoinExchangeError, StablecoinExchangeEvents,
};

use crate::{
    STABLECOIN_EXCHANGE_ADDRESS,
    error::{Result, TempoPrecompileError},
    stablecoin_exchange::orderbook::{MAX_PRICE, MIN_PRICE, compute_book_key},
    storage::{Handler, Mapping},
    tip20::{ITIP20, TIP20Token, is_tip20_prefix, validate_usd_currency},
    tip20_factory::TIP20Factory,
};
use alloy::primitives::{Address, B256, U256};
use tempo_precompiles_macros::contract;

/// Minimum order size of $10 USD
pub const MIN_ORDER_AMOUNT: u128 = 10_000_000;

/// Allowed tick spacing for order placement
pub const TICK_SPACING: i16 = 10;

#[contract(addr = STABLECOIN_EXCHANGE_ADDRESS)]
pub struct StablecoinExchange {
    books: Mapping<B256, Orderbook>,
    orders: Mapping<u128, Order>,
    balances: Mapping<Address, Mapping<Address, u128>>,
    next_order_id: u128,
    book_keys: Vec<B256>,
}

impl StablecoinExchange {
    /// Stablecoin exchange address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Initializes the contract
    ///
    /// This ensures the [`StablecoinExchange`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.__initialize()
    }

    /// Read next order ID (always at least 1)
    fn next_order_id(&self) -> Result<u128> {
        Ok(self.next_order_id.read()?.max(1))
    }

    /// Increment next order ID
    fn increment_next_order_id(&mut self) -> Result<()> {
        let next_order_id = self.next_order_id()?;
        self.next_order_id.write(next_order_id + 1)
    }

    /// Get user's balance for a specific token
    pub fn balance_of(&self, user: Address, token: Address) -> Result<u128> {
        self.balances.at(user).at(token).read()
    }

    /// Get MIN_PRICE value
    pub fn min_price(&self) -> u32 {
        MIN_PRICE
    }

    /// Get MAX_PRICE value
    pub fn max_price(&self) -> u32 {
        MAX_PRICE
    }

    /// Validates that a trading pair exists or creates the pair
    fn validate_or_create_pair(&mut self, book: &Orderbook, token: Address) -> Result<()> {
        if book.base.is_zero() {
            self.create_pair(token)?;
        }
        Ok(())
    }

    /// Fetch order from storage. If the order is currently pending or filled, this function returns
    /// `StablecoinExchangeError::OrderDoesNotExist`
    pub fn get_order(&self, order_id: u128) -> Result<Order> {
        let order = self.orders.at(order_id).read()?;

        // If the order is not filled and currently active
        if !order.maker().is_zero() && order.order_id() < self.next_order_id()? {
            Ok(order)
        } else {
            Err(StablecoinExchangeError::order_does_not_exist().into())
        }
    }

    /// Set user's balance for a specific token
    fn set_balance(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        self.balances.at(user).at(token).write(amount)
    }

    /// Add to user's balance
    fn increment_balance(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        let current = self.balance_of(user, token)?;
        self.set_balance(
            user,
            token,
            current
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )
    }

    /// Subtract from user's balance
    fn sub_balance(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        let current = self.balance_of(user, token)?;
        self.set_balance(user, token, current.saturating_sub(amount))
    }

    /// Emit the appropriate OrderFilled event
    fn emit_order_filled(
        &mut self,
        order_id: u128,
        maker: Address,
        taker: Address,
        amount_filled: u128,
        partial_fill: bool,
    ) -> Result<()> {
        self.emit_event(StablecoinExchangeEvents::OrderFilled_1(
            IStablecoinExchange::OrderFilled_1 {
                orderId: order_id,
                maker,
                taker,
                amountFilled: amount_filled,
                partialFill: partial_fill,
            },
        ))?;

        Ok(())
    }

    /// Transfer tokens, accounting for pathUSD
    fn transfer(&mut self, token: Address, to: Address, amount: u128) -> Result<()> {
        TIP20Token::from_address(token)?.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: U256::from(amount),
            },
        )?;
        Ok(())
    }

    /// Transfer tokens from user, accounting for pathUSD
    fn transfer_from(&mut self, token: Address, from: Address, amount: u128) -> Result<()> {
        TIP20Token::from_address(token)?.transfer_from(
            self.address,
            ITIP20::transferFromCall {
                from,
                to: self.address,
                amount: U256::from(amount),
            },
        )?;
        Ok(())
    }

    /// Decrement user's internal balance or transfer from external wallet
    fn decrement_balance_or_transfer_from(
        &mut self,
        user: Address,
        token: Address,
        amount: u128,
    ) -> Result<()> {
        TIP20Token::from_address(token)?.ensure_transfer_authorized(user, self.address)?;

        let user_balance = self.balance_of(user, token)?;
        if user_balance >= amount {
            self.sub_balance(user, token, amount)
        } else {
            let remaining = amount
                .checked_sub(user_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;

            self.transfer_from(token, user, remaining)?;
            self.set_balance(user, token, 0)
        }
    }

    pub fn quote_swap_exact_amount_out(
        &self,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
    ) -> Result<u128> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Execute quotes backwards from output to input
        let mut current_amount = amount_out;
        for (book_key, base_for_quote) in route.iter().rev() {
            current_amount = self.quote_exact_out(*book_key, current_amount, *base_for_quote)?;
        }

        Ok(current_amount)
    }

    pub fn quote_swap_exact_amount_in(
        &self,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
    ) -> Result<u128> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Execute quotes for each hop using precomputed book keys and directions
        let mut current_amount = amount_in;
        for (book_key, base_for_quote) in route {
            current_amount = self.quote_exact_in(book_key, current_amount, base_for_quote)?;
        }

        Ok(current_amount)
    }

    pub fn swap_exact_amount_in(
        &mut self,
        sender: Address,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<u128> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Deduct input tokens from sender (only once, at the start)
        self.decrement_balance_or_transfer_from(sender, token_in, amount_in)?;

        // Execute swaps for each hop - intermediate balances are transitory
        let mut amount = amount_in;
        for (book_key, base_for_quote) in route {
            // Fill orders for this hop - no min check on intermediate hops
            amount = self.fill_orders_exact_in(book_key, base_for_quote, amount, sender)?;
        }

        // Check final output meets minimum requirement
        if amount < min_amount_out {
            return Err(StablecoinExchangeError::insufficient_output().into());
        }

        self.transfer(token_out, sender, amount)?;

        Ok(amount)
    }

    pub fn swap_exact_amount_out(
        &mut self,
        sender: Address,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
        max_amount_in: u128,
    ) -> Result<u128> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Work backwards from output to calculate input needed - intermediate amounts are TRANSITORY
        let mut amount = amount_out;
        for (book_key, base_for_quote) in route.iter().rev() {
            amount = self.fill_orders_exact_out(*book_key, *base_for_quote, amount, sender)?;
        }

        if amount > max_amount_in {
            return Err(StablecoinExchangeError::max_input_exceeded().into());
        }

        // Deduct input tokens ONCE at end
        self.decrement_balance_or_transfer_from(sender, token_in, amount)?;

        // Transfer only final output ONCE at end
        self.transfer(token_out, sender, amount_out)?;

        Ok(amount)
    }

    /// Generate deterministic key for token pair
    pub fn pair_key(&self, token_a: Address, token_b: Address) -> B256 {
        compute_book_key(token_a, token_b)
    }

    /// Get price level information
    pub fn get_price_level(&self, base: Address, tick: i16, is_bid: bool) -> Result<TickLevel> {
        let quote = TIP20Token::from_address(base)?.quote_token()?;
        let book_key = compute_book_key(base, quote);
        self.books
            .at(book_key)
            .get_tick_level_handler(tick, is_bid)
            .read()
    }

    /// Get orderbook by pair key
    pub fn books(&self, pair_key: B256) -> Result<Orderbook> {
        self.books.at(pair_key).read()
    }

    /// Get all book keys
    pub fn get_book_keys(&self) -> Result<Vec<B256>> {
        self.book_keys.read()
    }

    /// Convert scaled price to relative tick
    pub fn price_to_tick(&self, price: u32) -> Result<i16> {
        orderbook::price_to_tick(price)
    }

    pub fn create_pair(&mut self, base: Address) -> Result<B256> {
        // Validate that base is a TIP20 token
        if !TIP20Factory::new().is_tip20(base)? {
            return Err(StablecoinExchangeError::invalid_base_token().into());
        }

        let quote = TIP20Token::from_address(base)?.quote_token()?;
        validate_usd_currency(base)?;
        validate_usd_currency(quote)?;

        let book_key = compute_book_key(base, quote);

        if self.books.at(book_key).read()?.is_initialized() {
            return Err(StablecoinExchangeError::pair_already_exists().into());
        }

        let book = Orderbook::new(base, quote);
        self.books.at(book_key).write(book)?;
        self.book_keys.push(book_key)?;

        // Emit PairCreated event
        self.emit_event(StablecoinExchangeEvents::PairCreated(
            IStablecoinExchange::PairCreated {
                key: book_key,
                base,
                quote,
            },
        ))?;

        Ok(book_key)
    }

    /// Place a limit order on the orderbook
    ///
    /// Only supports placing an order on a pair between a token and its quote token.
    /// The order is queued in the pending queue and will be processed at end of block.
    ///
    /// # Arguments
    /// * `token` - The token to trade (not the quote token)
    /// * `amount` - Order amount in the token
    /// * `is_bid` - True for buy orders (using quote token to buy token), false for sell orders
    /// * `tick` - Price tick: (price - 1) * 1000, where price is denominated in the quote token
    ///
    /// # Returns
    /// The assigned order ID
    pub fn place(
        &mut self,
        sender: Address,
        token: Address,
        amount: u128,
        is_bid: bool,
        tick: i16,
    ) -> Result<u128> {
        let quote_token = TIP20Token::from_address(token)?.quote_token()?;

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);

        let book = self.books.at(book_key).read()?;
        self.validate_or_create_pair(&book, token)?;

        // Validate tick is within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(tick).into());
        }

        // Enforce that the tick adheres to tick spacing
        if tick % TICK_SPACING != 0 {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        // Validate order amount meets minimum requirement
        if amount < MIN_ORDER_AMOUNT {
            return Err(StablecoinExchangeError::below_minimum_order_size(amount).into());
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount) = if is_bid {
            // For bids, escrow quote tokens based on price
            let quote_amount = base_to_quote(amount, tick, RoundingDirection::Up)
                .ok_or(StablecoinExchangeError::insufficient_balance())?;
            (quote_token, quote_amount)
        } else {
            // For asks, escrow base tokens
            (token, amount)
        };

        // Debit from user's balance or transfer from wallet
        self.decrement_balance_or_transfer_from(sender, escrow_token, escrow_amount)?;

        // Create the order
        let order_id = self.next_order_id()?;
        self.increment_next_order_id()?;
        let order = if is_bid {
            Order::new_bid(order_id, sender, book_key, amount, tick)
        } else {
            Order::new_ask(order_id, sender, book_key, amount, tick)
        };
        self.commit_order_to_book(order)?;

        // Emit OrderPlaced event
        self.emit_event(StablecoinExchangeEvents::OrderPlaced(
            IStablecoinExchange::OrderPlaced {
                orderId: order_id,
                maker: sender,
                token,
                amount,
                isBid: is_bid,
                tick,
            },
        ))?;

        Ok(order_id)
    }

    /// Commits an order to the specified orderbook, updating tick bits, best bid/ask, and total liquidity
    fn commit_order_to_book(&mut self, mut order: Order) -> Result<()> {
        let mut book_handler = self.books.at(order.book_key());
        let mut level_handler = book_handler.get_tick_level_handler(order.tick(), order.is_bid());
        let orderbook = book_handler.read()?;
        let mut level = level_handler.read()?;

        let prev_tail = level.tail;
        if prev_tail == 0 {
            level.head = order.order_id();
            level.tail = order.order_id();

            book_handler.set_tick_bit(order.tick(), order.is_bid())?;

            if order.is_bid() {
                if order.tick() > orderbook.best_bid_tick {
                    self.books
                        .at(order.book_key())
                        .best_bid_tick
                        .write(order.tick())?;
                }
            } else if order.tick() < orderbook.best_ask_tick {
                self.books
                    .at(order.book_key())
                    .best_ask_tick
                    .write(order.tick())?;
            }
        } else {
            // Update previous tail's next pointer
            let mut prev_order = self.orders.at(prev_tail).read()?;
            prev_order.next = order.order_id();
            self.orders.at(prev_tail).write(prev_order)?;

            // Set current order's prev pointer
            order.prev = prev_tail;
            level.tail = order.order_id();
        }

        let new_liquidity = level
            .total_liquidity
            .checked_add(order.remaining())
            .ok_or(TempoPrecompileError::under_overflow())?;
        level.total_liquidity = new_liquidity;

        level_handler.write(level)?;

        self.orders.at(order.order_id()).write(order)
    }

    /// Place a flip order that auto-flips when filled
    ///
    /// Flip orders automatically create a new order on the opposite side when completely filled.
    /// For bids: flip_tick must be > tick
    /// For asks: flip_tick must be < tick
    pub fn place_flip(
        &mut self,
        sender: Address,
        token: Address,
        amount: u128,
        is_bid: bool,
        tick: i16,
        flip_tick: i16,
    ) -> Result<u128> {
        let quote_token = TIP20Token::from_address(token)?.quote_token()?;

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);

        // Check book existence
        let book = self.books.at(book_key).read()?;
        self.validate_or_create_pair(&book, token)?;

        // Validate tick and flip_tick are within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(tick).into());
        }

        // Enforce that the tick adheres to tick spacing
        if tick % TICK_SPACING != 0 {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        if !(MIN_TICK..=MAX_TICK).contains(&flip_tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(flip_tick).into());
        }

        // Enforce that the tick adheres to tick spacing
        if flip_tick % TICK_SPACING != 0 {
            return Err(StablecoinExchangeError::invalid_flip_tick().into());
        }

        // Validate flip_tick relationship to tick based on order side
        if (is_bid && flip_tick <= tick) || (!is_bid && flip_tick >= tick) {
            return Err(StablecoinExchangeError::invalid_flip_tick().into());
        }

        // Validate order amount meets minimum requirement
        if amount < MIN_ORDER_AMOUNT {
            return Err(StablecoinExchangeError::below_minimum_order_size(amount).into());
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount) = if is_bid {
            // For bids, escrow quote tokens based on price
            let quote_amount = base_to_quote(amount, tick, RoundingDirection::Up)
                .ok_or(StablecoinExchangeError::insufficient_balance())?;
            (quote_token, quote_amount)
        } else {
            // For asks, escrow base tokens
            (token, amount)
        };

        // Debit from user's balance or transfer from wallet
        self.decrement_balance_or_transfer_from(sender, escrow_token, escrow_amount)?;

        // Create the flip order
        let order_id = self.next_order_id()?;
        self.increment_next_order_id()?;
        let order = Order::new_flip(order_id, sender, book_key, amount, tick, is_bid, flip_tick)
            .map_err(|_| StablecoinExchangeError::invalid_flip_tick())?;

        self.commit_order_to_book(order)?;

        // Emit FlipOrderPlaced event
        self.emit_event(StablecoinExchangeEvents::FlipOrderPlaced(
            IStablecoinExchange::FlipOrderPlaced {
                orderId: order_id,
                maker: sender,
                token,
                amount,
                isBid: is_bid,
                tick,
                flipTick: flip_tick,
            },
        ))?;

        Ok(order_id)
    }

    /// Partially fill an order with the specified amount.
    /// Fill amount is denominated in base token
    fn partial_fill_order(
        &mut self,
        order: &mut Order,
        level: &mut TickLevel,
        fill_amount: u128,
        taker: Address,
    ) -> Result<u128> {
        let book_handler = self.books.at(order.book_key());
        let orderbook = book_handler.read()?;

        // Update order remaining amount
        let new_remaining = order.remaining() - fill_amount;
        self.orders
            .at(order.order_id())
            .remaining
            .write(new_remaining)?;

        if order.is_bid() {
            // Bid order maker receives base tokens (exact amount)
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
        } else {
            // Ask order maker receives quote tokens - round DOWN to favor protocol
            let quote_amount = base_to_quote(fill_amount, order.tick(), RoundingDirection::Down)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;
        }

        // Calculate amount out for taker - round DOWN to favor protocol
        let amount_out = if order.is_bid() {
            base_to_quote(fill_amount, order.tick(), RoundingDirection::Down)
                .ok_or(TempoPrecompileError::under_overflow())?
        } else {
            fill_amount
        };

        // Update price level total liquidity
        let new_liquidity = level
            .total_liquidity
            .checked_sub(fill_amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        level.total_liquidity = new_liquidity;

        book_handler
            .get_tick_level_handler(order.tick(), order.is_bid())
            .write(*level)?;

        // Emit OrderFilled event for partial fill
        self.emit_order_filled(order.order_id(), order.maker(), taker, fill_amount, true)?;

        Ok(amount_out)
    }

    /// Fill an order and delete from storage. Returns the next best order and price level.
    fn fill_order(
        &mut self,
        book_key: B256,
        order: &mut Order,
        mut level: TickLevel,
        taker: Address,
    ) -> Result<(u128, Option<(TickLevel, Order)>)> {
        let book_handler = self.books.at(book_key);
        debug_assert_eq!(order.book_key(), book_key);
        let mut book_handler_order = book_handler.clone();

        let orderbook = book_handler_order.read()?;
        let fill_amount = order.remaining();

        // Settlement: round DOWN for both maker and taker to favor protocol
        let amount_out = if order.is_bid() {
            // Bid maker receives base tokens (exact amount)
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
            // Taker receives quote tokens - round DOWN
            base_to_quote(fill_amount, order.tick(), RoundingDirection::Down)
                .ok_or(TempoPrecompileError::under_overflow())?
        } else {
            // Ask maker receives quote tokens - round DOWN
            let quote_amount = base_to_quote(fill_amount, order.tick(), RoundingDirection::Down)
                .ok_or(TempoPrecompileError::under_overflow())?;

            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;

            // Taker receives base tokens (exact amount)
            fill_amount
        };

        // Emit OrderFilled event for complete fill
        self.emit_order_filled(order.order_id(), order.maker(), taker, fill_amount, false)?;

        if order.is_flip() {
            // Create a new flip order with flipped side and swapped ticks
            // Bid becomes Ask, Ask becomes Bid
            // The current tick becomes the new flip_tick, and flip_tick becomes the new tick
            let _ = self.place_flip(
                order.maker(),
                orderbook.base,
                order.amount(),
                !order.is_bid(),
                order.flip_tick(),
                order.tick(),
            );
        }

        // Delete the filled order
        self.orders.at(order.order_id()).delete()?;

        // Advance tick if liquidity is exhausted
        let next_tick_info = if order.next() == 0 {
            book_handler
                .get_tick_level_handler(order.tick(), order.is_bid())
                .delete()?;
            book_handler_order.delete_tick_bit(order.tick(), order.is_bid())?;

            let (tick, has_liquidity) =
                book_handler.next_initialized_tick(order.tick(), order.is_bid());

            // Update best_tick when tick is exhausted
            if order.is_bid() {
                let new_best = if has_liquidity { tick } else { i16::MIN };
                self.books.at(book_key).best_bid_tick.write(new_best)?;
            } else {
                let new_best = if has_liquidity { tick } else { i16::MAX };
                self.books.at(book_key).best_ask_tick.write(new_best)?;
            }

            if !has_liquidity {
                // No more liquidity at better prices - return None to signal completion
                None
            } else {
                let new_level = book_handler
                    .get_tick_level_handler(tick, order.is_bid())
                    .read()?;
                let new_order = self.orders.at(new_level.head).read()?;

                Some((new_level, new_order))
            }
        } else {
            // If there are subsequent orders at tick, advance to next order
            level.head = order.next();
            self.orders.at(order.next()).prev.delete()?;

            let new_liquidity = level
                .total_liquidity
                .checked_sub(fill_amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            level.total_liquidity = new_liquidity;

            book_handler_order
                .get_tick_level_handler(order.tick(), order.is_bid())
                .write(level)?;

            let new_order = self.orders.at(order.next()).read()?;
            Some((level, new_order))
        };

        Ok((amount_out, next_tick_info))
    }

    /// Fill orders for exact output amount
    fn fill_orders_exact_out(
        &mut self,
        book_key: B256,
        bid: bool,
        mut amount_out: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = self.orders.at(level.head).read()?;

        let mut total_amount_in: u128 = 0;

        while amount_out > 0 {
            let tick = order.tick();

            let (fill_amount, amount_in) = if bid {
                // For bids: amount_out is quote, amount_in is base
                // Round down base_needed (user provides less base, favors protocol)
                let base_needed = quote_to_base(amount_out, tick, RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                let fill_amount = base_needed.min(order.remaining());
                (fill_amount, fill_amount)
            } else {
                // For asks: amount_out is base, amount_in is quote
                let fill_amount = amount_out.min(order.remaining());
                // Round down amount_in (taker pays less, but this is balanced by settlement rounding)
                let amount_in = base_to_quote(fill_amount, tick, RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                (fill_amount, amount_in)
            };

            if fill_amount < order.remaining() {
                self.partial_fill_order(&mut order, &mut level, fill_amount, taker)?;
                total_amount_in = total_amount_in
                    .checked_add(amount_in)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                break;
            } else {
                let (amount_out_received, next_order_info) =
                    self.fill_order(book_key, &mut order, level, taker)?;
                total_amount_in = total_amount_in
                    .checked_add(amount_in)
                    .ok_or(TempoPrecompileError::under_overflow())?;

                // Set to 0 to avoid rounding errors
                if bid {
                    // Round down base_needed (user provides less base, favors protocol)
                    let base_needed = quote_to_base(amount_out, tick, RoundingDirection::Down)
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
                        return Err(StablecoinExchangeError::insufficient_liquidity().into());
                    }
                    break;
                }
            }
        }

        Ok(total_amount_in)
    }

    /// Fill orders with exact amount in
    fn fill_orders_exact_in(
        &mut self,
        book_key: B256,
        bid: bool,
        mut amount_in: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = self.orders.at(level.head).read()?;

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
                    self.partial_fill_order(&mut order, &mut level, fill_amount, taker)?;
                total_amount_out = total_amount_out
                    .checked_add(amount_out)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                break;
            } else {
                let (amount_out, next_order_info) =
                    self.fill_order(book_key, &mut order, level, taker)?;
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
                    // Round down base_out (user receives less base, favors protocol)
                    let base_out = quote_to_base(amount_in, tick, RoundingDirection::Down)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                    if base_out > order.remaining() {
                        // Round down quote_needed (user pays less quote, but order is fully consumed)
                        let quote_needed =
                            base_to_quote(order.remaining(), tick, RoundingDirection::Down)
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
                        return Err(StablecoinExchangeError::insufficient_liquidity().into());
                    }
                    break;
                }
            }
        }

        Ok(total_amount_out)
    }

    /// Helper function to get best tick from orderbook
    fn get_best_price_level(&mut self, book_key: B256, is_bid: bool) -> Result<TickLevel> {
        let book_handler = self.books.at(book_key);
        let orderbook = book_handler.read()?;

        let current_tick = if is_bid {
            if orderbook.best_bid_tick == i16::MIN {
                return Err(StablecoinExchangeError::insufficient_liquidity().into());
            }
            orderbook.best_bid_tick
        } else {
            if orderbook.best_ask_tick == i16::MAX {
                return Err(StablecoinExchangeError::insufficient_liquidity().into());
            }
            orderbook.best_ask_tick
        };

        book_handler
            .get_tick_level_handler(current_tick, is_bid)
            .read()
    }

    /// Cancel an order and refund tokens to maker
    /// Only the order maker can cancel their own order
    pub fn cancel(&mut self, sender: Address, order_id: u128) -> Result<()> {
        let order = self.orders.at(order_id).read()?;

        if order.maker().is_zero() {
            return Err(StablecoinExchangeError::order_does_not_exist().into());
        }

        if order.maker() != sender {
            return Err(StablecoinExchangeError::unauthorized().into());
        }

        if order.remaining() == 0 {
            return Err(StablecoinExchangeError::order_does_not_exist().into());
        }

        // All orders are immediately active in the orderbook
        self.cancel_active_order(order)?;

        Ok(())
    }

    /// Cancel an active order (already in the orderbook)
    fn cancel_active_order(&mut self, order: Order) -> Result<()> {
        let mut book_handler = self.books.at(order.book_key());
        let mut level_handler = book_handler.get_tick_level_handler(order.tick(), order.is_bid());
        let mut level = level_handler.read()?;

        // Update linked list
        if order.prev() != 0 {
            self.orders.at(order.prev()).next.write(order.next())?;
        } else {
            level.head = order.next();
        }

        if order.next() != 0 {
            self.orders.at(order.next()).prev.write(order.prev())?;
        } else {
            level.tail = order.prev();
        }

        // Update level liquidity
        let new_liquidity = level
            .total_liquidity
            .checked_sub(order.remaining())
            .ok_or(TempoPrecompileError::under_overflow())?;
        level.total_liquidity = new_liquidity;

        // If this was the last order at this tick, clear the bitmap bit
        if level.head == 0 {
            book_handler.delete_tick_bit(order.tick(), order.is_bid())?;

            // If this was the best tick, update it
            let orderbook = self.books.at(order.book_key()).read()?;
            let best_tick = if order.is_bid() {
                orderbook.best_bid_tick
            } else {
                orderbook.best_ask_tick
            };

            if best_tick == order.tick() {
                let (next_tick, has_liquidity) =
                    book_handler.next_initialized_tick(order.tick(), order.is_bid());

                if order.is_bid() {
                    let new_best = if has_liquidity { next_tick } else { i16::MIN };
                    self.books
                        .at(order.book_key())
                        .best_bid_tick
                        .write(new_best)?;
                } else {
                    let new_best = if has_liquidity { next_tick } else { i16::MAX };
                    self.books
                        .at(order.book_key())
                        .best_ask_tick
                        .write(new_best)?;
                }
            }
        }

        level_handler.write(level)?;

        // Refund tokens to maker - round DOWN to favor protocol
        let orderbook = self.books.at(order.book_key()).read()?;
        if order.is_bid() {
            // Bid orders are in quote token, refund quote amount - round DOWN
            let quote_amount =
                base_to_quote(order.remaining(), order.tick(), RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?;

            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;
        } else {
            // Ask orders are in base token, refund base amount (exact)
            self.increment_balance(order.maker(), orderbook.base, order.remaining())?;
        }

        // Clear the order from storage
        self.orders.at(order.order_id()).delete()?;

        // Emit OrderCancelled event
        self.emit_event(StablecoinExchangeEvents::OrderCancelled(
            IStablecoinExchange::OrderCancelled {
                orderId: order.order_id(),
            },
        ))
    }

    /// Withdraw tokens from exchange balance
    pub fn withdraw(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        let current_balance = self.balance_of(user, token)?;
        if current_balance < amount {
            return Err(StablecoinExchangeError::insufficient_balance().into());
        }
        self.sub_balance(user, token, amount)?;
        self.transfer(token, user, amount)?;

        Ok(())
    }

    /// Quote exact output amount without executing trades
    fn quote_exact_out(&self, book_key: B256, amount_out: u128, is_bid: bool) -> Result<u128> {
        let mut remaining_out = amount_out;
        let mut amount_in = 0u128;
        let book_handler = self.books.at(book_key);
        let orderbook = book_handler.read()?;

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };
        // Check for no liquidity: i16::MIN means no bids, i16::MAX means no asks
        if current_tick == i16::MIN || current_tick == i16::MAX {
            return Err(StablecoinExchangeError::insufficient_liquidity().into());
        }

        while remaining_out > 0 {
            let level = book_handler
                .get_tick_level_handler(current_tick, is_bid)
                .read()?;

            // If no liquidity at this level, move to next tick
            if level.total_liquidity == 0 {
                let (next_tick, initialized) =
                    book_handler.next_initialized_tick(current_tick, is_bid);

                if !initialized {
                    return Err(StablecoinExchangeError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
                continue;
            }

            let (fill_amount, amount_in_tick) = if is_bid {
                // For bids: remaining_out is in quote, amount_in is in base
                // Round down base_needed (user provides less base)
                let base_needed =
                    quote_to_base(remaining_out, current_tick, RoundingDirection::Down)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                let fill_amount = if base_needed > level.total_liquidity {
                    level.total_liquidity
                } else {
                    base_needed
                };
                (fill_amount, fill_amount)
            } else {
                // For asks: remaining_out is in base, amount_in is in quote
                let fill_amount = if remaining_out > level.total_liquidity {
                    level.total_liquidity
                } else {
                    remaining_out
                };
                // Round down quote_needed (user pays less quote)
                let quote_needed =
                    base_to_quote(fill_amount, current_tick, RoundingDirection::Down)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                (fill_amount, quote_needed)
            };

            let amount_out_tick = if is_bid {
                // Round down amount_out_tick (user receives less quote)
                base_to_quote(fill_amount, current_tick, RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?
            } else {
                fill_amount
            };

            remaining_out = remaining_out
                .checked_sub(amount_out_tick)
                .ok_or(TempoPrecompileError::under_overflow())?;
            amount_in = amount_in
                .checked_add(amount_in_tick)
                .ok_or(TempoPrecompileError::under_overflow())?;

            // If we exhausted this level or filled our requirement, move to next tick
            if fill_amount == level.total_liquidity {
                let (next_tick, initialized) =
                    book_handler.next_initialized_tick(current_tick, is_bid);

                if !initialized && remaining_out > 0 {
                    return Err(StablecoinExchangeError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
            } else {
                break;
            }
        }

        Ok(amount_in)
    }

    /// Find the trade path between two tokens
    /// Returns a vector of (book_key, base_for_quote) tuples for each hop
    /// Also validates that all pairs exist
    fn find_trade_path(&self, token_in: Address, token_out: Address) -> Result<Vec<(B256, bool)>> {
        // Cannot trade same token
        if token_in == token_out {
            return Err(StablecoinExchangeError::identical_tokens().into());
        }

        // Validate that both tokens are TIP20 tokens
        if !is_tip20_prefix(token_in) || !is_tip20_prefix(token_out) {
            return Err(StablecoinExchangeError::invalid_token().into());
        }

        // Check if direct or reverse pair exists
        let in_quote = TIP20Token::from_address(token_in)?.quote_token()?;
        let out_quote = TIP20Token::from_address(token_out)?.quote_token()?;

        if in_quote == token_out || out_quote == token_in {
            return self.validate_and_build_route(&[token_in, token_out]);
        }

        // Multi-hop: Find LCA and build path
        let path_in = self.find_path_to_root(token_in)?;
        let path_out = self.find_path_to_root(token_out)?;

        // Find the lowest common ancestor (LCA) using O(n+m) algorithm:
        // Build a HashSet from path_out for O(1) lookups, then iterate path_in
        let path_out_set: std::collections::HashSet<Address> = path_out.iter().copied().collect();
        let mut lca = None;
        for token_a in &path_in {
            if path_out_set.contains(token_a) {
                lca = Some(*token_a);
                break;
            }
        }

        let lca = lca.ok_or_else(StablecoinExchangeError::pair_does_not_exist)?;

        // Build the trade path: token_in -> ... -> LCA -> ... -> token_out
        let mut trade_path = Vec::new();

        // Add path from token_in up to and including LCA
        for token in &path_in {
            trade_path.push(*token);
            if *token == lca {
                break;
            }
        }

        // Add path from LCA down to token_out (excluding LCA itself)
        let lca_to_out: Vec<Address> = path_out
            .iter()
            .take_while(|&&t| t != lca)
            .copied()
            .collect();

        // Reverse to get path from LCA to token_out
        trade_path.extend(lca_to_out.iter().rev());

        self.validate_and_build_route(&trade_path)
    }

    /// Validates that all pairs in the path exist and returns book keys with direction info
    fn validate_and_build_route(&self, path: &[Address]) -> Result<Vec<(B256, bool)>> {
        let mut route = Vec::new();

        for i in 0..path.len() - 1 {
            let hop_token_in = path[i];
            let hop_token_out = path[i + 1];

            let book_key = compute_book_key(hop_token_in, hop_token_out);
            let orderbook = self.books.at(book_key).read()?;

            // Validate pair exists
            if orderbook.base.is_zero() {
                return Err(StablecoinExchangeError::pair_does_not_exist().into());
            }

            // Determine direction
            let base_for_quote = hop_token_in == orderbook.base;

            route.push((book_key, base_for_quote));
        }

        Ok(route)
    }

    /// Find the path from a token to the root (PathUSD)
    /// Returns a vector of addresses starting with the token and ending with PathUSD
    fn find_path_to_root(&self, mut token: Address) -> Result<Vec<Address>> {
        let mut path = vec![token];

        while token != PATH_USD_ADDRESS {
            token = TIP20Token::from_address(token)?.quote_token()?;
            path.push(token);
        }

        Ok(path)
    }

    /// Quote exact input amount without executing trades
    fn quote_exact_in(&self, book_key: B256, amount_in: u128, is_bid: bool) -> Result<u128> {
        let mut remaining_in = amount_in;
        let mut amount_out = 0u128;
        let book_handler = self.books.at(book_key);
        let orderbook = book_handler.read()?;

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };

        // Check for no liquidity: i16::MIN means no bids, i16::MAX means no asks
        if current_tick == i16::MIN || current_tick == i16::MAX {
            return Err(StablecoinExchangeError::insufficient_liquidity().into());
        }

        while remaining_in > 0 {
            let level = book_handler
                .get_tick_level_handler(current_tick, is_bid)
                .read()?;

            // If no liquidity at this level, move to next tick
            if level.total_liquidity == 0 {
                let (next_tick, initialized) =
                    book_handler.next_initialized_tick(current_tick, is_bid);

                if !initialized {
                    return Err(StablecoinExchangeError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
                continue;
            }

            // Compute (fill_amount, amount_out_tick, amount_consumed) based on hardfork
            let (fill_amount, amount_out_tick, amount_consumed) = if is_bid {
                // For bids: remaining_in is base, amount_out is quote
                let fill = remaining_in.min(level.total_liquidity);
                // Round down quote_out (user receives less quote)
                let quote_out = base_to_quote(fill, current_tick, RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                (fill, quote_out, fill)
            } else {
                // For asks: remaining_in is quote, amount_out is base
                // Round down base_to_get (user receives less base)
                let base_to_get =
                    quote_to_base(remaining_in, current_tick, RoundingDirection::Down)
                        .ok_or(TempoPrecompileError::under_overflow())?;
                let fill = base_to_get.min(level.total_liquidity);
                // Round down quote_consumed (less quote consumed from remaining)
                let quote_consumed = base_to_quote(fill, current_tick, RoundingDirection::Down)
                    .ok_or(TempoPrecompileError::under_overflow())?;
                (fill, fill, quote_consumed)
            };

            remaining_in = remaining_in
                .checked_sub(amount_consumed)
                .ok_or(TempoPrecompileError::under_overflow())?;
            amount_out = amount_out
                .checked_add(amount_out_tick)
                .ok_or(TempoPrecompileError::under_overflow())?;

            // If we exhausted this level, move to next tick
            if fill_amount == level.total_liquidity {
                let (next_tick, initialized) =
                    book_handler.next_initialized_tick(current_tick, is_bid);

                if !initialized && remaining_in > 0 {
                    return Err(StablecoinExchangeError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
            } else {
                break;
            }
        }

        Ok(amount_out)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::IntoLogData;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::TIP20Error;

    use crate::{
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
    };

    use super::*;

    fn setup_test_tokens(
        admin: Address,
        user: Address,
        exchange_address: Address,
        amount: u128,
    ) -> Result<(Address, Address)> {
        // Configure PathUSD
        let quote = TIP20Setup::path_usd(admin)
            .with_issuer(admin)
            .with_mint(user, U256::from(amount))
            .with_approval(user, exchange_address, U256::from(amount))
            .apply()?;

        // Configure base token (uses PathUSD as quote by default)
        let base = TIP20Setup::create("BASE", "BASE", admin)
            .with_issuer(admin)
            .with_mint(user, U256::from(amount))
            .with_approval(user, exchange_address, U256::from(amount))
            .apply()?;

        Ok((base.address(), quote.address()))
    }

    #[test]
    fn test_tick_to_price() {
        let test_ticks = [-2000i16, -1000, -100, -1, 0, 1, 100, 1000, 2000];
        for tick in test_ticks {
            let price = orderbook::tick_to_price(tick);
            let expected_price = (orderbook::PRICE_SCALE as i32 + tick as i32) as u32;
            assert_eq!(price, expected_price);
        }
    }

    #[test]
    fn test_price_to_tick() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let exchange = StablecoinExchange::new();

            // Valid prices should succeed
            assert_eq!(exchange.price_to_tick(orderbook::PRICE_SCALE)?, 0);
            assert_eq!(exchange.price_to_tick(orderbook::MIN_PRICE)?, MIN_TICK);
            assert_eq!(exchange.price_to_tick(orderbook::MAX_PRICE)?, MAX_TICK);

            // Out of bounds prices should fail
            let result = exchange.price_to_tick(orderbook::MIN_PRICE - 1);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::TickOutOfBounds(
                    _
                ))
            ));

            let result = exchange.price_to_tick(orderbook::MAX_PRICE + 1);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::TickOutOfBounds(
                    _
                ))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_calculate_quote_amount_rounding() -> eyre::Result<()> {
        // Floor division rounds DOWN
        // amount = 100, tick = 1 means price = 100001
        // 100 * 100001 / 100000 = 10000100 / 100000 = 100.001
        // Should round down to 100
        let amount = 100u128;
        let tick = 1i16;
        let result_floor = base_to_quote(amount, tick, RoundingDirection::Down).unwrap();
        assert_eq!(
            result_floor, 100,
            "Expected 100 (rounded down from 100.001)"
        );

        // Ceiling division rounds UP - same inputs should round up to 101
        let result_ceil = base_to_quote(amount, tick, RoundingDirection::Up).unwrap();
        assert_eq!(result_ceil, 101, "Expected 101 (rounded up from 100.001)");

        // Another test case with floor
        let amount2 = 999u128;
        let tick2 = 5i16; // price = 100005
        let result2_floor = base_to_quote(amount2, tick2, RoundingDirection::Down).unwrap();
        // 999 * 100005 / 100000 = 99904995 / 100000 = 999.04995 -> should be 999
        assert_eq!(
            result2_floor, 999,
            "Expected 999 (rounded down from 999.04995)"
        );

        // Same inputs with ceiling should round up to 1000
        let result2_ceil = base_to_quote(amount2, tick2, RoundingDirection::Up).unwrap();
        assert_eq!(
            result2_ceil, 1000,
            "Expected 1000 (rounded up from 999.04995)"
        );

        // Test with no remainder (should work the same for both)
        let amount3 = 100000u128;
        let tick3 = 0i16; // price = 100000
        let result3_floor = base_to_quote(amount3, tick3, RoundingDirection::Down).unwrap();
        let result3_ceil = base_to_quote(amount3, tick3, RoundingDirection::Up).unwrap();
        // 100000 * 100000 / 100000 = 100000 (exact, no rounding)
        assert_eq!(result3_floor, 100000, "Exact division should remain exact");
        assert_eq!(result3_ceil, 100000, "Exact division should remain exact");

        Ok(())
    }

    #[test]
    fn test_settlement_rounding_favors_protocol() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();

            let base_amount = 10_000_003u128;
            let tick = 100i16;

            let price = orderbook::tick_to_price(tick) as u128;
            let expected_quote_floor = (base_amount * price) / orderbook::PRICE_SCALE as u128;
            let expected_quote_ceil =
                (base_amount * price).div_ceil(orderbook::PRICE_SCALE as u128);

            let max_escrow = expected_quote_ceil * 2;

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(base_amount * 2))
                .with_mint(bob, U256::from(base_amount * 2))
                .with_approval(alice, exchange.address, U256::MAX)
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;

            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(max_escrow))
                .with_mint(bob, U256::from(max_escrow))
                .with_approval(alice, exchange.address, U256::MAX)
                .with_approval(bob, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;

            exchange.place(alice, base_token, base_amount, false, tick)?;

            let alice_quote_before = exchange.balance_of(alice, quote_token)?;
            assert_eq!(alice_quote_before, 0);

            exchange.swap_exact_amount_in(bob, quote_token, base_token, expected_quote_ceil, 0)?;

            let alice_quote_after = exchange.balance_of(alice, quote_token)?;

            assert_eq!(
                alice_quote_after, expected_quote_floor,
                "Maker settlement should round DOWN to favor protocol. Got {alice_quote_after}, expected floor {expected_quote_floor}"
            );

            assert!(
                expected_quote_ceil > expected_quote_floor,
                "Test setup error: should have a non-zero remainder"
            );

            Ok(())
        })
    }

    #[test]
    fn test_cancellation_refund_rounding_favors_protocol() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();

            let base_amount = 10_000_003u128;
            let tick = 100i16;

            let price = orderbook::tick_to_price(tick) as u128;
            let escrow_ceil = (base_amount * price).div_ceil(orderbook::PRICE_SCALE as u128);
            let refund_floor = (base_amount * price) / orderbook::PRICE_SCALE as u128;

            let base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;

            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(escrow_ceil))
                .with_approval(alice, exchange.address, U256::MAX)
                .apply()?;

            exchange.create_pair(base_token)?;

            let order_id = exchange.place(alice, base_token, base_amount, true, tick)?;

            exchange.cancel(alice, order_id)?;

            let alice_refund = exchange.balance_of(alice, quote_token)?;

            assert_eq!(
                alice_refund, refund_floor,
                "Cancellation refund should round DOWN to favor protocol. Got {alice_refund}, expected floor {refund_floor}"
            );

            assert!(
                escrow_ceil > refund_floor,
                "Protocol should keep the rounding difference: escrowed {escrow_ceil} but refunded {refund_floor}"
            );

            Ok(())
        })
    }

    #[test]
    fn test_place_order_pair_auto_created() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let tick = 100i16;

            let price = orderbook::tick_to_price(tick);
            let expected_escrow =
                (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

            let (base_token, _quote_token) =
                setup_test_tokens(admin, alice, exchange.address, expected_escrow)?;

            // Pair is auto-created when placing order
            let result = exchange.place(alice, base_token, min_order_amount, true, tick);
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_place_order_below_minimum_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let below_minimum = min_order_amount - 1;
            let tick = 100i16;

            let price = orderbook::tick_to_price(tick);
            let escrow_amount = (below_minimum * price as u128) / orderbook::PRICE_SCALE as u128;

            let (base_token, _quote_token) =
                setup_test_tokens(admin, alice, exchange.address, escrow_amount)?;

            // Create the pair
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            // Try to place an order below minimum amount
            let result = exchange.place(alice, base_token, below_minimum, true, tick);
            assert_eq!(
                result,
                Err(StablecoinExchangeError::below_minimum_order_size(below_minimum).into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_place_bid_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let tick = 100i16;

            let price = orderbook::tick_to_price(tick);
            let expected_escrow =
                (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

            // Setup tokens with enough balance for the escrow
            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, expected_escrow)?;

            // Create the pair before placing orders
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            // Place the bid order
            let order_id = exchange
                .place(alice, base_token, min_order_amount, true, tick)
                .expect("Place bid order should succeed");

            assert_eq!(order_id, 1);
            assert_eq!(exchange.next_order_id()?, 2);

            // Verify the order was stored correctly
            let stored_order = exchange.orders.at(order_id).read()?;
            assert_eq!(stored_order.maker(), alice);
            assert_eq!(stored_order.amount(), min_order_amount);
            assert_eq!(stored_order.remaining(), min_order_amount);
            assert_eq!(stored_order.tick(), tick);
            assert!(stored_order.is_bid());
            assert!(!stored_order.is_flip());

            // Verify the order is in the active orderbook
            let book_key = compute_book_key(base_token, quote_token);
            let book_handler = exchange.books.at(book_key);
            let level = book_handler.get_tick_level_handler(tick, true).read()?;
            assert_eq!(level.head, order_id);
            assert_eq!(level.tail, order_id);
            assert_eq!(level.total_liquidity, min_order_amount);

            // Verify balance was reduced by the escrow amount
            let quote_tip20 = TIP20Token::from_address(quote_token)?;
            let remaining_balance =
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice })?;
            assert_eq!(remaining_balance, U256::ZERO);

            // Verify exchange received the tokens
            let exchange_balance = quote_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            })?;
            assert_eq!(exchange_balance, U256::from(expected_escrow));

            Ok(())
        })
    }

    #[test]
    fn test_place_ask_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let tick = 50i16; // Use positive tick to avoid conversion issues

            // Setup tokens with enough base token balance for the order
            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, min_order_amount)?;
            // Create the pair before placing orders
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            let order_id = exchange
                .place(alice, base_token, min_order_amount, false, tick) // is_bid = false for ask
                .expect("Place ask order should succeed");

            assert_eq!(order_id, 1);
            assert_eq!(exchange.next_order_id()?, 2);

            // Verify the order was stored correctly
            let stored_order = exchange.orders.at(order_id).read()?;
            assert_eq!(stored_order.maker(), alice);
            assert_eq!(stored_order.amount(), min_order_amount);
            assert_eq!(stored_order.remaining(), min_order_amount);
            assert_eq!(stored_order.tick(), tick);
            assert!(!stored_order.is_bid());
            assert!(!stored_order.is_flip());

            // Verify the order is in the active orderbook
            let book_key = compute_book_key(base_token, quote_token);
            let book_handler = exchange.books.at(book_key);
            let level = book_handler.get_tick_level_handler(tick, false).read()?;
            assert_eq!(level.head, order_id);
            assert_eq!(level.tail, order_id);
            assert_eq!(level.total_liquidity, min_order_amount);

            // Verify balance was reduced by the escrow amount
            let base_tip20 = TIP20Token::from_address(base_token)?;
            let remaining_balance =
                base_tip20.balance_of(ITIP20::balanceOfCall { account: alice })?;
            assert_eq!(remaining_balance, U256::ZERO); // All tokens should be escrowed

            // Verify exchange received the base tokens
            let exchange_balance = base_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            })?;
            assert_eq!(exchange_balance, U256::from(min_order_amount));

            Ok(())
        })
    }

    #[test]
    fn test_place_flip_order_below_minimum_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let below_minimum = min_order_amount - 1;
            let tick = 100i16;
            let flip_tick = 200i16;

            let price = orderbook::tick_to_price(tick);
            let escrow_amount = (below_minimum * price as u128) / orderbook::PRICE_SCALE as u128;

            let (base_token, _quote_token) =
                setup_test_tokens(admin, alice, exchange.address, escrow_amount)?;

            // Create the pair
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            // Try to place a flip order below minimum amount
            let result =
                exchange.place_flip(alice, base_token, below_minimum, true, tick, flip_tick);
            assert_eq!(
                result,
                Err(StablecoinExchangeError::below_minimum_order_size(below_minimum).into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_place_flip_auto_creates_pair() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let user = Address::random();

            // Setup tokens
            let (base_token, quote_token) =
                setup_test_tokens(admin, user, exchange.address, 100_000_000)?;

            // Before placing flip order, verify pair doesn't exist
            let book_key = compute_book_key(base_token, quote_token);
            let book_before = exchange.books.at(book_key).read()?;
            assert!(book_before.base.is_zero(),);

            // Transfer tokens to exchange first
            let mut base = TIP20Token::new(1);
            base.transfer(
                user,
                ITIP20::transferCall {
                    to: exchange.address,
                    amount: U256::from(MIN_ORDER_AMOUNT),
                },
            )
            .expect("Base token transfer failed");

            // Place a flip order which should also create the pair
            exchange.place_flip(user, base_token, MIN_ORDER_AMOUNT, true, 0, 10)?;

            let book_after = exchange.books.at(book_key).read()?;
            assert_eq!(book_after.base, base_token);

            // Verify PairCreated event was emitted (along with FlipOrderPlaced)
            let events = exchange.emitted_events();
            assert_eq!(events.len(), 2);
            assert_eq!(
                events[0],
                StablecoinExchangeEvents::PairCreated(IStablecoinExchange::PairCreated {
                    key: book_key,
                    base: base_token,
                    quote: quote_token,
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_place_flip_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let flip_tick = 200i16; // Must be > tick for bid flip orders

            // Calculate escrow amount needed for bid
            let price = orderbook::tick_to_price(tick);
            let expected_escrow =
                (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

            // Setup tokens with enough balance for the escrow
            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, expected_escrow)?;
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            let order_id = exchange
                .place_flip(alice, base_token, min_order_amount, true, tick, flip_tick)
                .expect("Place flip bid order should succeed");

            assert_eq!(order_id, 1);
            assert_eq!(exchange.next_order_id()?, 2);

            // Verify the order was stored correctly
            let stored_order = exchange.orders.at(order_id).read()?;
            assert_eq!(stored_order.maker(), alice);
            assert_eq!(stored_order.amount(), min_order_amount);
            assert_eq!(stored_order.remaining(), min_order_amount);
            assert_eq!(stored_order.tick(), tick);
            assert!(stored_order.is_bid());
            assert!(stored_order.is_flip());
            assert_eq!(stored_order.flip_tick(), flip_tick);

            // Verify the order is in the active orderbook
            let book_key = compute_book_key(base_token, quote_token);
            let book_handler = exchange.books.at(book_key);
            let level = book_handler.get_tick_level_handler(tick, true).read()?;
            assert_eq!(level.head, order_id);
            assert_eq!(level.tail, order_id);
            assert_eq!(level.total_liquidity, min_order_amount);

            // Verify balance was reduced by the escrow amount
            let quote_tip20 = TIP20Token::from_address(quote_token)?;
            let remaining_balance =
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice })?;
            assert_eq!(remaining_balance, U256::ZERO);

            // Verify exchange received the tokens
            let exchange_balance = quote_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            })?;
            assert_eq!(exchange_balance, U256::from(expected_escrow));

            Ok(())
        })
    }

    #[test]
    fn test_withdraw() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let price = orderbook::tick_to_price(tick);
            let expected_escrow =
                (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

            // Setup tokens
            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, expected_escrow)?;
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            // Place the bid order and cancel
            let order_id = exchange
                .place(alice, base_token, min_order_amount, true, tick)
                .expect("Place bid order should succeed");

            exchange
                .cancel(alice, order_id)
                .expect("Cancel pending order should succeed");

            assert_eq!(exchange.balance_of(alice, quote_token)?, expected_escrow);

            // Get balances before withdrawal
            exchange
                .withdraw(alice, quote_token, expected_escrow)
                .expect("Withdraw should succeed");
            assert_eq!(exchange.balance_of(alice, quote_token)?, 0);

            // Verify wallet balances changed correctly
            let quote_tip20 = TIP20Token::from_address(quote_token)?;
            assert_eq!(
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice })?,
                expected_escrow
            );
            assert_eq!(
                quote_tip20.balance_of(ITIP20::balanceOfCall {
                    account: exchange.address
                })?,
                0
            );

            Ok(())
        })
    }

    #[test]
    fn test_withdraw_insufficient_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();

            let min_order_amount = MIN_ORDER_AMOUNT;
            let (_base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, min_order_amount)?;

            // Alice has 0 balance on the exchange
            assert_eq!(exchange.balance_of(alice, quote_token)?, 0);

            // Try to withdraw more than balance
            let result = exchange.withdraw(alice, quote_token, 100u128);

            assert_eq!(
                result,
                Err(StablecoinExchangeError::insufficient_balance().into())
            );

            Ok(())
        })
    }

    #[test]
    fn test_quote_swap_exact_amount_out() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let amount_out = 500_000u128;
            let tick = 10;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, 200_000_000u128)?;
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            let order_amount = min_order_amount;
            exchange
                .place(alice, base_token, order_amount, false, tick)
                .expect("Order should succeed");

            let amount_in = exchange
                .quote_swap_exact_amount_out(quote_token, base_token, amount_out)
                .expect("Swap should succeed");

            let price = orderbook::tick_to_price(tick);
            let expected_amount_in = (amount_out * price as u128) / orderbook::PRICE_SCALE as u128;
            assert_eq!(amount_in, expected_amount_in);

            Ok(())
        })
    }

    #[test]
    fn test_quote_swap_exact_amount_in() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let amount_in = 500_000u128;
            let tick = 10;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, 200_000_000u128)?;
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            let order_amount = min_order_amount;
            exchange
                .place(alice, base_token, order_amount, true, tick)
                .expect("Place bid order should succeed");

            let amount_out = exchange
                .quote_swap_exact_amount_in(base_token, quote_token, amount_in)
                .expect("Swap should succeed");

            // Calculate expected amount_out based on tick price
            let price = orderbook::tick_to_price(tick);
            let expected_amount_out = (amount_in * price as u128) / orderbook::PRICE_SCALE as u128;
            assert_eq!(amount_out, expected_amount_out);

            Ok(())
        })
    }

    #[test]
    fn test_quote_swap_exact_amount_out_base_for_quote() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let amount_out = 500_000u128;
            let tick = 0;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, 200_000_000u128)?;
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            // Alice places a bid: willing to BUY base using quote
            let order_amount = min_order_amount;
            exchange
                .place(alice, base_token, order_amount, true, tick)
                .expect("Place bid order should succeed");

            // Quote: sell base to get quote
            // Should match against Alice's bid (buyer of base)
            let amount_in = exchange
                .quote_swap_exact_amount_out(base_token, quote_token, amount_out)
                .expect("Quote should succeed");

            let price = orderbook::tick_to_price(tick);
            let expected_amount_in = (amount_out * price as u128) / orderbook::PRICE_SCALE as u128;
            assert_eq!(amount_in, expected_amount_in);

            Ok(())
        })
    }

    #[test]
    fn test_swap_exact_amount_out() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let amount_out = 500_000u128;
            let tick = 10;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, 200_000_000u128)?;
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            let order_amount = min_order_amount;
            exchange
                .place(alice, base_token, order_amount, false, tick)
                .expect("Order should succeed");

            exchange
                .set_balance(bob, quote_token, 200_000_000u128)
                .expect("Could not set balance");

            let price = orderbook::tick_to_price(tick);
            let max_amount_in = (amount_out * price as u128) / orderbook::PRICE_SCALE as u128;

            let amount_in = exchange
                .swap_exact_amount_out(bob, quote_token, base_token, amount_out, max_amount_in)
                .expect("Swap should succeed");

            let base_tip20 = TIP20Token::from_address(base_token)?;
            let bob_base_balance = base_tip20.balance_of(ITIP20::balanceOfCall { account: bob })?;
            assert_eq!(bob_base_balance, U256::from(amount_out));

            let alice_quote_exchange_balance = exchange.balance_of(alice, quote_token)?;
            assert_eq!(alice_quote_exchange_balance, amount_in);

            Ok(())
        })
    }

    #[test]
    fn test_swap_exact_amount_in() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let amount_in = 500_000u128;
            let tick = 10;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, 200_000_000u128)?;
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            let order_amount = min_order_amount;
            exchange
                .place(alice, base_token, order_amount, true, tick)
                .expect("Order should succeed");

            exchange
                .set_balance(bob, base_token, 200_000_000u128)
                .expect("Could not set balance");

            let price = orderbook::tick_to_price(tick);
            let min_amount_out = (amount_in * price as u128) / orderbook::PRICE_SCALE as u128;

            let amount_out = exchange
                .swap_exact_amount_in(bob, base_token, quote_token, amount_in, min_amount_out)
                .expect("Swap should succeed");

            let quote_tip20 = TIP20Token::from_address(quote_token)?;
            let bob_quote_balance =
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: bob })?;
            assert_eq!(bob_quote_balance, U256::from(amount_out));

            let alice_base_exchange_balance = exchange.balance_of(alice, base_token)?;
            assert_eq!(alice_base_exchange_balance, amount_in);

            Ok(())
        })
    }

    #[test]
    fn test_flip_order_execution() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let amount = min_order_amount;
            let tick = 100i16;
            let flip_tick = 200i16;

            let price = orderbook::tick_to_price(tick);
            let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, expected_escrow * 2)?;
            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            // Place a flip bid order
            let flip_order_id = exchange
                .place_flip(alice, base_token, amount, true, tick, flip_tick)
                .expect("Place flip order should succeed");

            exchange
                .set_balance(bob, base_token, amount)
                .expect("Could not set balance");

            exchange
                .swap_exact_amount_in(bob, base_token, quote_token, amount, 0)
                .expect("Swap should succeed");

            // Assert that the order has filled (remaining should be 0)
            let filled_order = exchange.orders.at(flip_order_id).read()?;
            assert_eq!(filled_order.remaining(), 0);

            // The flipped order should be created with id = flip_order_id + 1
            let new_order_id = exchange.next_order_id()? - 1;
            assert_eq!(new_order_id, flip_order_id + 1);

            let new_order = exchange.orders.at(new_order_id).read()?;
            assert_eq!(new_order.maker(), alice);
            assert_eq!(new_order.tick(), flip_tick);
            assert_eq!(new_order.flip_tick(), tick);
            assert!(new_order.is_ask());
            assert_eq!(new_order.amount(), amount);
            assert_eq!(new_order.remaining(), amount);

            Ok(())
        })
    }

    #[test]
    fn test_pair_created() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();

            let min_order_amount = MIN_ORDER_AMOUNT;
            // Setup tokens
            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, min_order_amount)?;

            // Create the pair
            let key = exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            // Verify PairCreated event was emitted
            exchange.assert_emitted_events(vec![StablecoinExchangeEvents::PairCreated(
                IStablecoinExchange::PairCreated {
                    key,
                    base: base_token,
                    quote: quote_token,
                },
            )]);

            Ok(())
        })
    }

    #[test]
    fn test_pair_already_created() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();

            let min_order_amount = MIN_ORDER_AMOUNT;
            // Setup tokens
            let (base_token, _) =
                setup_test_tokens(admin, alice, exchange.address, min_order_amount)?;

            exchange
                .create_pair(base_token)
                .expect("Could not create pair");

            let result = exchange.create_pair(base_token);
            assert_eq!(
                result,
                Err(StablecoinExchangeError::pair_already_exists().into())
            );

            Ok(())
        })
    }

    /// Helper to verify a single hop in a route
    fn verify_hop(hop: (B256, bool), token_in: Address, token_out: Address) -> eyre::Result<()> {
        let (book_key, base_for_quote) = hop;
        let expected_book_key = compute_book_key(token_in, token_out);
        assert_eq!(book_key, expected_book_key, "Book key should match");

        let exchange = StablecoinExchange::new();
        let orderbook = exchange.books.at(book_key).read()?;
        let expected_direction = token_in == orderbook.base;
        assert_eq!(
            base_for_quote, expected_direction,
            "Direction should be correct: token_in={}, base={}, base_for_quote={}",
            token_in, orderbook.base, base_for_quote
        );

        Ok(())
    }

    #[test]
    fn test_find_path_to_root() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();

            // Setup: PathUSD <- USDC <- TokenA
            let usdc = TIP20Setup::create("USDC", "USDC", admin).apply()?;
            let token_a = TIP20Setup::create("TokenA", "TKA", admin)
                .quote_token(usdc.address())
                .apply()?;

            // Find path from TokenA to root
            let path = exchange.find_path_to_root(token_a.address())?;

            // Expected: [TokenA, USDC, PathUSD]
            assert_eq!(path.len(), 3);
            assert_eq!(path[0], token_a.address());
            assert_eq!(path[1], usdc.address());
            assert_eq!(path[2], PATH_USD_ADDRESS);

            Ok(())
        })
    }

    #[test]
    fn test_find_trade_path_same_token_errors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let user = Address::random();

            let min_order_amount = MIN_ORDER_AMOUNT;
            let (token, _) = setup_test_tokens(admin, user, exchange.address, min_order_amount)?;

            // Trading same token should error with IdenticalTokens
            let result = exchange.find_trade_path(token, token);
            assert_eq!(
                result,
                Err(StablecoinExchangeError::identical_tokens().into()),
                "Should return IdenticalTokens error when token_in == token_out"
            );

            Ok(())
        })
    }

    #[test]
    fn test_find_trade_path_direct_pair() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let user = Address::random();

            let min_order_amount = MIN_ORDER_AMOUNT;
            // Setup: PathUSD <- Token (direct pair)
            let (token, path_usd) =
                setup_test_tokens(admin, user, exchange.address, min_order_amount)?;

            // Create the pair first
            exchange.create_pair(token).expect("Failed to create pair");

            // Trade token -> path_usd (direct pair)
            let route = exchange
                .find_trade_path(token, path_usd)
                .expect("Should find direct pair");

            // Expected: 1 hop (token -> path_usd)
            assert_eq!(route.len(), 1, "Should have 1 hop for direct pair");
            verify_hop(route[0], token, path_usd)?;

            Ok(())
        })
    }

    #[test]
    fn test_find_trade_path_reverse_pair() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let user = Address::random();

            let min_order_amount = MIN_ORDER_AMOUNT;
            // Setup: PathUSD <- Token
            let (token, path_usd) =
                setup_test_tokens(admin, user, exchange.address, min_order_amount)?;

            // Create the pair first
            exchange.create_pair(token).expect("Failed to create pair");

            // Trade path_usd -> token (reverse direction)
            let route = exchange
                .find_trade_path(path_usd, token)
                .expect("Should find reverse pair");

            // Expected: 1 hop (path_usd -> token)
            assert_eq!(route.len(), 1, "Should have 1 hop for reverse pair");
            verify_hop(route[0], path_usd, token)?;

            Ok(())
        })
    }

    #[test]
    fn test_find_trade_path_two_hop_siblings() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();

            // Setup: PathUSD <- USDC
            //        PathUSD <- EURC
            // (USDC and EURC are siblings, both have PathUSD as quote)
            let usdc = TIP20Setup::create("USDC", "USDC", admin).apply()?;
            let eurc = TIP20Setup::create("EURC", "EURC", admin).apply()?;

            // Create pairs first
            exchange.create_pair(usdc.address())?;
            exchange.create_pair(eurc.address())?;

            // Trade USDC -> EURC should go through PathUSD
            let route = exchange.find_trade_path(usdc.address(), eurc.address())?;

            // Expected: 2 hops (USDC -> PathUSD, PathUSD -> EURC)
            assert_eq!(route.len(), 2, "Should have 2 hops for sibling tokens");
            verify_hop(route[0], usdc.address(), PATH_USD_ADDRESS)?;
            verify_hop(route[1], PATH_USD_ADDRESS, eurc.address())?;

            Ok(())
        })
    }

    #[test]
    fn test_quote_exact_in_multi_hop() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let min_order_amount_x10 = U256::from(MIN_ORDER_AMOUNT * 10);

            // Setup: PathUSD <- USDC
            //        PathUSD <- EURC
            let _path_usd = TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;
            let usdc = TIP20Setup::create("USDC", "USDC", admin)
                .with_issuer(admin)
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;
            let eurc = TIP20Setup::create("EURC", "EURC", admin)
                .with_issuer(admin)
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;

            // Place orders to provide liquidity at 1:1 rate (tick 0)
            // For trade USDC -> PathUSD -> EURC:
            // - First hop needs: bid on USDC (someone buying USDC with PathUSD)
            // - Second hop needs: ask on EURC (someone selling EURC for PathUSD)

            // USDC bid: buy USDC with PathUSD
            exchange.place(alice, usdc.address(), min_order_amount * 5, true, 0)?;

            // EURC ask: sell EURC for PathUSD
            exchange.place(alice, eurc.address(), min_order_amount * 5, false, 0)?;

            // Quote multi-hop: USDC -> PathUSD -> EURC
            let amount_in = min_order_amount;
            let amount_out =
                exchange.quote_swap_exact_amount_in(usdc.address(), eurc.address(), amount_in)?;

            // With 1:1 rates at each hop, output should equal input
            assert_eq!(
                amount_out, amount_in,
                "With 1:1 rates, output should equal input"
            );

            Ok(())
        })
    }

    #[test]
    fn test_quote_exact_out_multi_hop() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let min_order_amount_x10 = U256::from(MIN_ORDER_AMOUNT * 10);

            // Setup: PathUSD <- USDC
            //        PathUSD <- EURC
            let _path_usd = TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;
            let usdc = TIP20Setup::create("USDC", "USDC", admin)
                .with_issuer(admin)
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;
            let eurc = TIP20Setup::create("EURC", "EURC", admin)
                .with_issuer(admin)
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;

            // Place orders at 1:1 rate
            exchange.place(alice, usdc.address(), min_order_amount * 5, true, 0)?;
            exchange.place(alice, eurc.address(), min_order_amount * 5, false, 0)?;

            // Quote multi-hop for exact output: USDC -> PathUSD -> EURC
            let amount_out = min_order_amount;
            let amount_in =
                exchange.quote_swap_exact_amount_out(usdc.address(), eurc.address(), amount_out)?;

            // With 1:1 rates at each hop, input should equal output
            assert_eq!(
                amount_in, amount_out,
                "With 1:1 rates, input should equal output"
            );

            Ok(())
        })
    }

    #[test]
    fn test_swap_exact_in_multi_hop_transitory_balances() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();
            let bob = Address::random();

            let min_order_amount = MIN_ORDER_AMOUNT;
            let min_order_amount_x10 = U256::from(MIN_ORDER_AMOUNT * 10);

            // Setup: PathUSD <- USDC <- EURC
            let path_usd = TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                // Setup alice as a liquidity provider
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;

            let usdc = TIP20Setup::create("USDC", "USDC", admin)
                .with_issuer(admin)
                // Setup alice as a liquidity provider
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                // Setup bob as a trader
                .with_mint(bob, min_order_amount_x10)
                .with_approval(bob, exchange.address, min_order_amount_x10)
                .apply()?;

            let eurc = TIP20Setup::create("EURC", "EURC", admin)
                .with_issuer(admin)
                // Setup alice as a liquidity provider
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;

            // Place liquidity orders at 1:1
            exchange.place(alice, usdc.address(), min_order_amount * 5, true, 0)?;
            exchange.place(alice, eurc.address(), min_order_amount * 5, false, 0)?;

            // Check bob's balances before swap
            let bob_usdc_before = usdc.balance_of(ITIP20::balanceOfCall { account: bob })?;
            let bob_eurc_before = eurc.balance_of(ITIP20::balanceOfCall { account: bob })?;

            // Execute multi-hop swap: USDC -> PathUSD -> EURC
            let amount_in = min_order_amount;
            let amount_out = exchange.swap_exact_amount_in(
                bob,
                usdc.address(),
                eurc.address(),
                amount_in,
                0, // min_amount_out
            )?;

            // Check bob's balances after swap
            let bob_usdc_after = usdc.balance_of(ITIP20::balanceOfCall { account: bob })?;
            let bob_eurc_after = eurc.balance_of(ITIP20::balanceOfCall { account: bob })?;

            // Verify bob spent USDC and received EURC
            assert_eq!(
                bob_usdc_before - bob_usdc_after,
                U256::from(amount_in),
                "Bob should have spent exact amount_in USDC"
            );
            assert_eq!(
                bob_eurc_after - bob_eurc_before,
                U256::from(amount_out),
                "Bob should have received amount_out EURC"
            );

            // Verify bob has ZERO PathUSD (intermediate token should be transitory)
            let bob_path_usd_wallet =
                path_usd.balance_of(ITIP20::balanceOfCall { account: bob })?;
            assert_eq!(
                bob_path_usd_wallet,
                U256::ZERO,
                "Bob should have ZERO PathUSD in wallet (transitory)"
            );

            let bob_path_usd_exchange = exchange.balance_of(bob, path_usd.address())?;
            assert_eq!(
                bob_path_usd_exchange, 0,
                "Bob should have ZERO PathUSD on exchange (transitory)"
            );

            Ok(())
        })
    }

    #[test]
    fn test_swap_exact_out_multi_hop_transitory_balances() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();
            let bob = Address::random();

            let min_order_amount = MIN_ORDER_AMOUNT;
            let min_order_amount_x10 = U256::from(MIN_ORDER_AMOUNT * 10);

            // Setup: PathUSD <- USDC <- EURC
            let path_usd = TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                // Setup alice as a liquidity provider
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;

            let usdc = TIP20Setup::create("USDC", "USDC", admin)
                .with_issuer(admin)
                // Setup alice as a liquidity provider
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                // Setup bob as a trader
                .with_mint(bob, min_order_amount_x10)
                .with_approval(bob, exchange.address, min_order_amount_x10)
                .apply()?;

            let eurc = TIP20Setup::create("EURC", "EURC", admin)
                .with_issuer(admin)
                // Setup alice as a liquidity provider
                .with_mint(alice, min_order_amount_x10)
                .with_approval(alice, exchange.address, min_order_amount_x10)
                .apply()?;

            // Place liquidity orders at 1:1
            exchange.place(alice, usdc.address(), min_order_amount * 5, true, 0)?;
            exchange.place(alice, eurc.address(), min_order_amount * 5, false, 0)?;

            // Check bob's balances before swap
            let bob_usdc_before = usdc.balance_of(ITIP20::balanceOfCall { account: bob })?;
            let bob_eurc_before = eurc.balance_of(ITIP20::balanceOfCall { account: bob })?;

            // Execute multi-hop swap: USDC -> PathUSD -> EURC (exact output)
            let amount_out = 90u128;
            let amount_in = exchange.swap_exact_amount_out(
                bob,
                usdc.address(),
                eurc.address(),
                amount_out,
                u128::MAX, // max_amount_in
            )?;

            // Check bob's balances after swap
            let bob_usdc_after = usdc.balance_of(ITIP20::balanceOfCall { account: bob })?;
            let bob_eurc_after = eurc.balance_of(ITIP20::balanceOfCall { account: bob })?;

            // Verify bob spent USDC and received exact EURC
            assert_eq!(
                bob_usdc_before - bob_usdc_after,
                U256::from(amount_in),
                "Bob should have spent amount_in USDC"
            );
            assert_eq!(
                bob_eurc_after - bob_eurc_before,
                U256::from(amount_out),
                "Bob should have received exact amount_out EURC"
            );

            // Verify bob has ZERO PathUSD (intermediate token should be transitory)
            let bob_path_usd_wallet =
                path_usd.balance_of(ITIP20::balanceOfCall { account: bob })?;
            assert_eq!(
                bob_path_usd_wallet,
                U256::ZERO,
                "Bob should have ZERO PathUSD in wallet (transitory)"
            );

            let bob_path_usd_exchange = exchange
                .balance_of(bob, path_usd.address())
                .expect("Failed to get bob's PathUSD exchange balance");
            assert_eq!(
                bob_path_usd_exchange, 0,
                "Bob should have ZERO PathUSD on exchange (transitory)"
            );

            Ok(())
        })
    }

    #[test]
    fn test_create_pair_invalid_currency() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let admin = Address::random();

            // Create EUR token with PATH USD as quote (valid non-USD token)
            let token_0 = TIP20Setup::create("EuroToken", "EURO", admin)
                .currency("EUR")
                .apply()?;

            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            // Test: create_pair should reject non-USD token (EUR token has EUR currency)
            let result = exchange.create_pair(token_0.address());
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_create_pair_rejects_non_tip20_base() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let admin = Address::random();
            let _path_usd = TIP20Setup::path_usd(admin).apply()?;

            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            // Test: create_pair should reject non-TIP20 address (random address without TIP20 prefix)
            let non_tip20_address = Address::random();
            let result = exchange.create_pair(non_tip20_address);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::StablecoinExchange(
                    StablecoinExchangeError::InvalidBaseToken(_)
                ))
            ));

            Ok(())
        })
    }

    #[test]
    fn test_max_in_check() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, 200_000_000u128)?;
            exchange.create_pair(base_token)?;

            let tick_50 = 50i16;
            let tick_100 = 100i16;
            let order_amount = MIN_ORDER_AMOUNT;

            exchange.place(alice, base_token, order_amount, false, tick_50)?;
            exchange.place(alice, base_token, order_amount, false, tick_100)?;

            exchange.set_balance(bob, quote_token, 200_000_000u128)?;

            let price_50 = orderbook::tick_to_price(tick_50);
            let price_100 = orderbook::tick_to_price(tick_100);
            let quote_for_first =
                (order_amount * price_50 as u128) / orderbook::PRICE_SCALE as u128;
            let quote_for_partial_second =
                (999 * price_100 as u128) / orderbook::PRICE_SCALE as u128;
            let total_needed = quote_for_first + quote_for_partial_second;

            let result = exchange.swap_exact_amount_out(
                bob,
                quote_token,
                base_token,
                order_amount + 999,
                total_needed,
            );
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_exact_out_bid_side() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, 1_000_000_000u128)?;
            exchange.create_pair(base_token)?;

            let tick = 1000i16;
            let price = tick_to_price(tick);
            let order_amount_base = MIN_ORDER_AMOUNT;

            exchange.place(alice, base_token, order_amount_base, true, tick)?;

            let amount_out_quote = 5_000_000u128;
            let base_needed = (amount_out_quote * PRICE_SCALE as u128) / price as u128;
            let max_amount_in = base_needed + 10000;

            exchange.set_balance(bob, base_token, max_amount_in * 2)?;

            let _amount_in = exchange.swap_exact_amount_out(
                bob,
                base_token,
                quote_token,
                amount_out_quote,
                max_amount_in,
            )?;

            // Verify Bob got exactly the quote amount requested
            let bob_quote_balance = TIP20Token::from_address(quote_token)?
                .balance_of(ITIP20::balanceOfCall { account: bob })?;
            assert_eq!(bob_quote_balance, U256::from(amount_out_quote));

            Ok(())
        })
    }

    #[test]
    fn test_exact_in_ask_side() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, 1_000_000_000u128)?;
            exchange.create_pair(base_token)?;

            let tick = 1000i16;
            let price = tick_to_price(tick);
            let order_amount_base = MIN_ORDER_AMOUNT;

            exchange.place(alice, base_token, order_amount_base, false, tick)?;

            let amount_in_quote = 5_000_000u128;
            let min_amount_out = 0;

            exchange.set_balance(bob, quote_token, amount_in_quote * 2)?;

            let amount_out = exchange.swap_exact_amount_in(
                bob,
                quote_token,
                base_token,
                amount_in_quote,
                min_amount_out,
            )?;

            let expected_base = (amount_in_quote * PRICE_SCALE as u128) / price as u128;
            assert_eq!(amount_out, expected_base);

            Ok(())
        })
    }

    #[test]
    fn test_clear_order() -> eyre::Result<()> {
        const AMOUNT: u128 = 1_000_000_000;

        // Test that fill_order properly clears the prev pointer when advancing to the next order
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let carol = Address::random();
            let admin = Address::random();

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, AMOUNT)?;
            exchange.create_pair(base_token)?;

            // Give bob base tokens and carol quote tokens
            TIP20Setup::config(base_token)
                .with_mint(bob, U256::from(AMOUNT))
                .with_approval(bob, exchange.address, U256::from(AMOUNT))
                .apply()?;
            TIP20Setup::config(quote_token)
                .with_mint(carol, U256::from(AMOUNT))
                .with_approval(carol, exchange.address, U256::from(AMOUNT))
                .apply()?;

            let tick = 100i16;

            // Place two ask orders at the same tick: Order 1 (alice), Order 2 (bob)
            let order1_amount = MIN_ORDER_AMOUNT;
            let order2_amount = MIN_ORDER_AMOUNT;

            let order1_id = exchange.place(alice, base_token, order1_amount, false, tick)?;
            let order2_id = exchange.place(bob, base_token, order2_amount, false, tick)?;

            // Verify linked list is set up correctly
            let order1 = exchange.orders.at(order1_id).read()?;
            let order2 = exchange.orders.at(order2_id).read()?;
            assert_eq!(order1.next(), order2_id);
            assert_eq!(order2.prev(), order1_id);

            // Swap to fill order1 completely
            let swap_amount = order1_amount;
            exchange.swap_exact_amount_out(
                carol,
                quote_token,
                base_token,
                swap_amount,
                u128::MAX,
            )?;

            // After filling order1, order2 should be the new head with prev = 0
            let order2_after = exchange.orders.at(order2_id).read()?;
            assert_eq!(
                order2_after.prev(),
                0,
                "New head order should have prev = 0 after previous head was filled"
            );

            Ok(())
        })
    }

    #[test]
    fn test_best_tick_updates_on_fill() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let bob = Address::random();
            let admin = Address::random();
            let amount = MIN_ORDER_AMOUNT;

            // Use different ticks for bids (100, 90) and asks (50, 60)
            let (bid_tick_1, bid_tick_2) = (100_i16, 90_i16); // (best, second best)
            let (ask_tick_1, ask_tick_2) = (50_i16, 60_i16); // (best, second best)

            // Calculate escrow for all orders
            let bid_price_1 = orderbook::tick_to_price(bid_tick_1);
            let bid_price_2 = orderbook::tick_to_price(bid_tick_2);
            let bid_escrow_1 = (amount * bid_price_1 as u128) / orderbook::PRICE_SCALE as u128;
            let bid_escrow_2 = (amount * bid_price_2 as u128) / orderbook::PRICE_SCALE as u128;
            let total_bid_escrow = bid_escrow_1 + bid_escrow_2;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, total_bid_escrow)?;
            exchange.create_pair(base_token)?;
            let book_key = compute_book_key(base_token, quote_token);

            // Place bid orders at two different ticks
            exchange.place(alice, base_token, amount, true, bid_tick_1)?;
            exchange.place(alice, base_token, amount, true, bid_tick_2)?;

            // Place ask orders at two different ticks
            TIP20Setup::config(base_token)
                .with_mint(alice, U256::from(amount * 2))
                .with_approval(alice, exchange.address, U256::from(amount * 2))
                .apply()?;
            exchange.place(alice, base_token, amount, false, ask_tick_1)?;
            exchange.place(alice, base_token, amount, false, ask_tick_2)?;

            // Verify initial best ticks
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, bid_tick_1);
            assert_eq!(orderbook.best_ask_tick, ask_tick_1);

            // Fill all bids at tick 100 (bob sells base)
            exchange.set_balance(bob, base_token, amount)?;
            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;
            // Verify best_bid_tick moved to tick 90, best_ask_tick unchanged
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, bid_tick_2);
            assert_eq!(orderbook.best_ask_tick, ask_tick_1);

            // Fill remaining bid at tick 90
            exchange.set_balance(bob, base_token, amount)?;
            exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;
            // Verify best_bid_tick is now i16::MIN, best_ask_tick unchanged
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, i16::MIN);
            assert_eq!(orderbook.best_ask_tick, ask_tick_1);

            // Fill all asks at tick 50 (bob buys base)
            let ask_price_1 = orderbook::tick_to_price(ask_tick_1);
            let quote_needed = (amount * ask_price_1 as u128) / orderbook::PRICE_SCALE as u128;
            exchange.set_balance(bob, quote_token, quote_needed)?;
            exchange.swap_exact_amount_in(bob, quote_token, base_token, quote_needed, 0)?;
            // Verify best_ask_tick moved to tick 60, best_bid_tick unchanged
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_ask_tick, ask_tick_2);
            assert_eq!(orderbook.best_bid_tick, i16::MIN);

            Ok(())
        })
    }

    #[test]
    fn test_best_tick_updates_on_cancel() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let amount = MIN_ORDER_AMOUNT;

            let (bid_tick_1, bid_tick_2) = (100_i16, 90_i16); // (best, second best)
            let (ask_tick_1, ask_tick_2) = (50_i16, 60_i16); // (best, second best)

            // Calculate escrow for 3 bid orders (2 at tick 100, 1 at tick 90)
            let price_1 = orderbook::tick_to_price(bid_tick_1);
            let price_2 = orderbook::tick_to_price(bid_tick_2);
            let escrow_1 = (amount * price_1 as u128) / orderbook::PRICE_SCALE as u128;
            let escrow_2 = (amount * price_2 as u128) / orderbook::PRICE_SCALE as u128;
            let total_escrow = escrow_1 * 2 + escrow_2;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, total_escrow)?;
            exchange.create_pair(base_token)?;
            let book_key = compute_book_key(base_token, quote_token);

            // Place 2 bid orders at tick 100, 1 at tick 90
            let bid_order_1 = exchange.place(alice, base_token, amount, true, bid_tick_1)?;
            let bid_order_2 = exchange.place(alice, base_token, amount, true, bid_tick_1)?;
            let bid_order_3 = exchange.place(alice, base_token, amount, true, bid_tick_2)?;

            // Place 2 ask orders at tick 50 and tick 60
            TIP20Setup::config(base_token)
                .with_mint(alice, U256::from(amount * 2))
                .with_approval(alice, exchange.address, U256::from(amount * 2))
                .apply()?;
            let ask_order_1 = exchange.place(alice, base_token, amount, false, ask_tick_1)?;
            let ask_order_2 = exchange.place(alice, base_token, amount, false, ask_tick_2)?;

            // Verify initial best ticks
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, bid_tick_1);
            assert_eq!(orderbook.best_ask_tick, ask_tick_1);

            // Cancel one bid at tick 100
            exchange.cancel(alice, bid_order_1)?;
            // Verify best_bid_tick remains 100, best_ask_tick unchanged
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, bid_tick_1);
            assert_eq!(orderbook.best_ask_tick, ask_tick_1);

            // Cancel remaining bid at tick 100
            exchange.cancel(alice, bid_order_2)?;
            // Verify best_bid_tick moved to 90, best_ask_tick unchanged
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, bid_tick_2);
            assert_eq!(orderbook.best_ask_tick, ask_tick_1);

            // Cancel ask at tick 50
            exchange.cancel(alice, ask_order_1)?;
            // Verify best_ask_tick moved to 60, best_bid_tick unchanged
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, bid_tick_2);
            assert_eq!(orderbook.best_ask_tick, ask_tick_2);

            // Cancel bid at tick 90
            exchange.cancel(alice, bid_order_3)?;
            // Verify best_bid_tick is now i16::MIN, best_ask_tick unchanged
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, i16::MIN);
            assert_eq!(orderbook.best_ask_tick, ask_tick_2);

            // Cancel ask at tick 60
            exchange.cancel(alice, ask_order_2)?;
            // Verify best_ask_tick is now i16::MAX, best_bid_tick unchanged
            let orderbook = exchange.books.at(book_key).read()?;
            assert_eq!(orderbook.best_bid_tick, i16::MIN);
            assert_eq!(orderbook.best_ask_tick, i16::MAX);

            Ok(())
        })
    }

    #[test]
    fn test_place() -> eyre::Result<()> {
        const AMOUNT: u128 = 1_000_000_000;

        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();

            let (base_token, _quote_token) =
                setup_test_tokens(admin, alice, exchange.address, AMOUNT)?;
            exchange.create_pair(base_token)?;

            // Give alice base tokens
            TIP20Setup::config(base_token)
                .with_mint(alice, U256::from(AMOUNT))
                .with_approval(alice, exchange.address, U256::from(AMOUNT))
                .apply()?;

            // Test invalid tick spacing
            let invalid_tick = 15i16;
            let result = exchange.place(alice, base_token, MIN_ORDER_AMOUNT, true, invalid_tick);

            let error = result.unwrap_err();
            assert!(matches!(
                error,
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));

            // Test valid tick spacing
            let valid_tick = -20i16;
            let result = exchange.place(alice, base_token, MIN_ORDER_AMOUNT, true, valid_tick);
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_place_flip_checks() -> eyre::Result<()> {
        const AMOUNT: u128 = 1_000_000_000;

        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();

            let (base_token, _quote_token) =
                setup_test_tokens(admin, alice, exchange.address, AMOUNT)?;
            exchange.create_pair(base_token)?;

            // Give alice base tokens
            TIP20Setup::config(base_token)
                .with_mint(alice, U256::from(AMOUNT))
                .with_approval(alice, exchange.address, U256::from(AMOUNT))
                .apply()?;

            // Test invalid tick spacing
            let invalid_tick = 15i16;
            let invalid_flip_tick = 25i16;
            let result = exchange.place_flip(
                alice,
                base_token,
                MIN_ORDER_AMOUNT,
                true,
                invalid_tick,
                invalid_flip_tick,
            );

            let error = result.unwrap_err();
            assert!(matches!(
                error,
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));

            // Test valid tick spacing
            let valid_tick = 20i16;
            let invalid_flip_tick = 25i16;
            let result = exchange.place_flip(
                alice,
                base_token,
                MIN_ORDER_AMOUNT,
                true,
                valid_tick,
                invalid_flip_tick,
            );

            let error = result.unwrap_err();
            assert!(matches!(
                error,
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidFlipTick(
                    _
                ))
            ));

            let valid_flip_tick = 30i16;
            let result = exchange.place_flip(
                alice,
                base_token,
                MIN_ORDER_AMOUNT,
                true,
                valid_tick,
                valid_flip_tick,
            );
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_find_trade_path_rejects_non_tip20() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let user = Address::random();

            let (_, quote_token) =
                setup_test_tokens(admin, user, exchange.address, MIN_ORDER_AMOUNT)?;

            let non_tip20_address = Address::random();
            let result = exchange.find_trade_path(non_tip20_address, quote_token);
            assert!(
                matches!(
                    result,
                    Err(TempoPrecompileError::StablecoinExchange(
                        StablecoinExchangeError::InvalidToken(_)
                    ))
                ),
                "Should return InvalidToken error for non-TIP20 token"
            );

            Ok(())
        })
    }

    #[test]
    fn test_quote_exact_in_handles_both_directions() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();
            let amount = MIN_ORDER_AMOUNT;
            let tick = 100_i16;
            let price = orderbook::tick_to_price(tick);

            // Calculate escrow for bid order (quote needed to buy `amount` base)
            let bid_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

            let (base_token, quote_token) =
                setup_test_tokens(admin, alice, exchange.address, bid_escrow)?;

            TIP20Setup::config(base_token)
                .with_mint(alice, U256::from(amount))
                .with_approval(alice, exchange.address, U256::from(amount))
                .apply()?;

            exchange.create_pair(base_token)?;
            let book_key = compute_book_key(base_token, quote_token);

            // Place a bid order (alice wants to buy base with quote)
            exchange.place(alice, base_token, amount, true, tick)?;

            // Test is_bid == true: base -> quote
            let quoted_out_bid = exchange.quote_exact_in(book_key, amount, true)?;
            let expected_quote_out = amount
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("calculation");
            assert_eq!(
                quoted_out_bid, expected_quote_out,
                "quote_exact_in with is_bid=true should return quote amount"
            );

            // Place an ask order (alice wants to sell base for quote)
            exchange.place(alice, base_token, amount, false, tick)?;

            // Test is_bid == false: quote -> base
            let quote_in = (amount * price as u128) / orderbook::PRICE_SCALE as u128;
            let quoted_out_ask = exchange.quote_exact_in(book_key, quote_in, false)?;
            let expected_base_out = quote_in
                .checked_mul(orderbook::PRICE_SCALE as u128)
                .and_then(|v| v.checked_div(price as u128))
                .expect("calculation");
            assert_eq!(
                quoted_out_ask, expected_base_out,
                "quote_exact_in with is_bid=false should return base amount"
            );

            Ok(())
        })
    }

    #[test]
    fn test_place_auto_creates_pair() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;
            let admin = Address::random();
            let user = Address::random();

            // Setup tokens
            let (base_token, quote_token) =
                setup_test_tokens(admin, user, exchange.address, 100_000_000)?;

            // Before placing order, verify pair doesn't exist
            let book_key = compute_book_key(base_token, quote_token);
            let book_before = exchange.books.at(book_key).read()?;
            assert!(book_before.base.is_zero(),);

            // Transfer tokens to exchange first
            let mut base = TIP20Token::new(1);
            base.transfer(
                user,
                ITIP20::transferCall {
                    to: exchange.address,
                    amount: U256::from(MIN_ORDER_AMOUNT),
                },
            )
            .expect("Base token transfer failed");

            // Place an order which should also create the pair
            exchange.place(user, base_token, MIN_ORDER_AMOUNT, true, 0)?;

            let book_after = exchange.books.at(book_key).read()?;
            assert_eq!(book_after.base, base_token);

            // Verify PairCreated event was emitted (along with OrderPlaced)
            let events = exchange.emitted_events();
            assert_eq!(events.len(), 2);
            assert_eq!(
                events[0],
                StablecoinExchangeEvents::PairCreated(IStablecoinExchange::PairCreated {
                    key: book_key,
                    base: base_token,
                    quote: quote_token,
                })
                .into_log_data()
            );

            Ok(())
        })
    }

    #[test]
    fn test_decrement_balance_preserves_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();

            let base = TIP20Setup::create("BASE", "BASE", admin).apply()?;
            let base_address = base.address();

            exchange.create_pair(base_address)?;

            let internal_balance = MIN_ORDER_AMOUNT / 2;
            exchange.set_balance(alice, base_address, internal_balance)?;

            assert_eq!(exchange.balance_of(alice, base_address)?, internal_balance);

            let tick = 0i16;
            let result = exchange.place(alice, base_address, MIN_ORDER_AMOUNT * 2, false, tick);

            assert!(result.is_err());
            assert_eq!(exchange.balance_of(alice, base_address)?, internal_balance);

            Ok(())
        })
    }

    #[test]
    fn test_place_order_immediately_active() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let tick = 100i16;

            let price = orderbook::tick_to_price(tick);
            let expected_escrow =
                (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(expected_escrow))
                .with_approval(alice, exchange.address, U256::from(expected_escrow))
                .apply()?;

            let base = TIP20Setup::create("BASE", "BASE", admin).apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;

            exchange.create_pair(base_token)?;

            let order_id = exchange.place(alice, base_token, min_order_amount, true, tick)?;

            assert_eq!(order_id, 1);

            let book_key = compute_book_key(base_token, quote_token);
            let book_handler = exchange.books.at(book_key);
            let level = book_handler.get_tick_level_handler(tick, true).read()?;
            assert_eq!(level.head, order_id, "Order should be head of tick level");
            assert_eq!(level.tail, order_id, "Order should be tail of tick level");
            assert_eq!(
                level.total_liquidity, min_order_amount,
                "Tick level should have order's liquidity"
            );

            let orderbook = book_handler.read()?;
            assert_eq!(
                orderbook.best_bid_tick, tick,
                "Best bid tick should be updated"
            );

            Ok(())
        })
    }

    #[test]
    fn test_place_flip_order_immediately_active() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Genesis);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let tick = 100i16;
            let flip_tick = 200i16;

            let price = orderbook::tick_to_price(tick);
            let expected_escrow =
                (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(expected_escrow))
                .with_approval(alice, exchange.address, U256::from(expected_escrow))
                .apply()?;

            let base = TIP20Setup::create("BASE", "BASE", admin).apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;

            exchange.create_pair(base_token)?;

            let order_id =
                exchange.place_flip(alice, base_token, min_order_amount, true, tick, flip_tick)?;

            assert_eq!(order_id, 1);

            let book_key = compute_book_key(base_token, quote_token);
            let book_handler = exchange.books.at(book_key);
            let level = book_handler.get_tick_level_handler(tick, true).read()?;
            assert_eq!(level.head, order_id, "Order should be head of tick level");
            assert_eq!(level.tail, order_id, "Order should be tail of tick level");
            assert_eq!(
                level.total_liquidity, min_order_amount,
                "Tick level should have order's liquidity"
            );

            let orderbook = book_handler.read()?;
            assert_eq!(
                orderbook.best_bid_tick, tick,
                "Best bid tick should be updated"
            );

            let stored_order = exchange.orders.at(order_id).read()?;
            assert!(stored_order.is_flip(), "Order should be a flip order");
            assert_eq!(
                stored_order.flip_tick(),
                flip_tick,
                "Flip tick should match"
            );

            Ok(())
        })
    }

    #[test]
    fn test_place_post() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let admin = Address::random();
            let alice = Address::random();
            let min_order_amount = MIN_ORDER_AMOUNT;
            let tick = 100i16;

            let price = orderbook::tick_to_price(tick);
            let expected_escrow =
                (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(alice, U256::from(expected_escrow))
                .with_approval(alice, exchange.address, U256::from(expected_escrow))
                .apply()?;

            let base = TIP20Setup::create("BASE", "BASE", admin).apply()?;
            let base_token = base.address();
            let quote_token = base.quote_token()?;

            exchange.create_pair(base_token)?;

            let order_id = exchange.place(alice, base_token, min_order_amount, true, tick)?;

            let stored_order = exchange.orders.at(order_id).read()?;
            assert_eq!(stored_order.maker(), alice);
            assert_eq!(stored_order.remaining(), min_order_amount);
            assert_eq!(stored_order.tick(), tick);
            assert!(stored_order.is_bid());

            let book_key = compute_book_key(base_token, quote_token);
            let level = exchange
                .books
                .at(book_key)
                .get_tick_level_handler(tick, true)
                .read()?;
            assert_eq!(level.head, order_id);
            assert_eq!(level.tail, order_id);
            assert_eq!(level.total_liquidity, min_order_amount);

            let book = exchange.books.at(book_key).read()?;
            assert_eq!(book.best_bid_tick, tick);

            assert_eq!(exchange.next_order_id()?, 2);

            Ok(())
        })
    }

    #[test]
    fn test_blacklisted_user_cannot_use_internal_balance() -> eyre::Result<()> {
        use crate::tip403_registry::{ITIP403Registry, TIP403Registry};

        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinExchange::new();
            exchange.initialize()?;

            let alice = Address::random();
            let admin = Address::random();

            // Create a blacklist policy
            let mut registry = TIP403Registry::new();
            let policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;

            // Setup quote token (PathUSD) with the blacklist policy
            let mut quote = TIP20Setup::path_usd(admin).with_issuer(admin).apply()?;

            quote.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )?;

            // Setup base token with the blacklist policy
            let mut base = TIP20Setup::create("BASE", "BASE", admin)
                .with_issuer(admin)
                .apply()?;
            let base_address = base.address();

            base.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )?;

            exchange.create_pair(base_address)?;

            // Set up internal balance for alice
            let internal_balance = MIN_ORDER_AMOUNT * 2;
            exchange.set_balance(alice, base_address, internal_balance)?;
            assert_eq!(exchange.balance_of(alice, base_address)?, internal_balance);

            // Blacklist alice
            registry.modify_policy_blacklist(
                admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: alice,
                    restricted: true,
                },
            )?;
            assert!(!registry.is_authorized(ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: alice,
            })?);

            // Attempt to place order using internal balance - should fail
            let tick = 0i16;
            let result = exchange.place(alice, base_address, MIN_ORDER_AMOUNT, false, tick);

            assert!(
                result.is_err(),
                "Blacklisted user should not be able to place orders using internal balance"
            );
            let err = result.unwrap_err();
            assert!(
                matches!(
                    err,
                    TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(_))
                ),
                "Expected PolicyForbids error, got: {err:?}"
            );
            assert_eq!(exchange.balance_of(alice, base_address)?, internal_balance);

            Ok(())
        })
    }
}
