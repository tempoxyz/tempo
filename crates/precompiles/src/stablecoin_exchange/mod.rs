//! Stablecoin DEX types and utilities.
pub mod dispatch;
pub mod error;
pub mod order;
pub mod orderbook;

pub use order::Order;
pub use orderbook::{MAX_TICK, MIN_TICK, Orderbook, PRICE_SCALE, TickLevel, tick_to_price};
use tempo_contracts::precompiles::PATH_USD_ADDRESS;
pub use tempo_contracts::precompiles::{
    IStablecoinExchange, StablecoinExchangeError, StablecoinExchangeEvents,
};

use crate::{
    STABLECOIN_EXCHANGE_ADDRESS,
    error::{Result, TempoPrecompileError},
    path_usd::PathUSD,
    stablecoin_exchange::orderbook::{
        MAX_PRICE_POST_MODERATO, MAX_PRICE_PRE_MODERATO, MIN_PRICE_POST_MODERATO,
        MIN_PRICE_PRE_MODERATO, compute_book_key,
    },
    storage::{Mapping, PrecompileStorageProvider, Slot, VecSlotExt},
    tip20::{
        ITIP20, TIP20Token, address_to_token_id_unchecked, is_tip20_prefix, validate_usd_currency,
    },
    tip20_factory::TIP20Factory,
};
use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256};
use revm::state::Bytecode;
use tempo_contracts::precompiles::ITIP20Factory;
use tempo_precompiles_macros::contract;

/// Minimum order size of $10 USD
pub const MIN_ORDER_AMOUNT: u128 = 10_000_000;

/// Allowed tick spacing for order placement
pub const TICK_SPACING: i16 = 10;

/// Calculate quote amount using floor division (rounds down)
/// Pre-Moderato behavior
fn calculate_quote_amount_floor(amount: u128, tick: i16) -> Option<u128> {
    let price = tick_to_price(tick) as u128;
    amount.checked_mul(price)?.checked_div(PRICE_SCALE as u128)
}

/// Calculate quote amount using ceiling division (rounds up)
/// Post-Moderato behavior
fn calculate_quote_amount_ceil(amount: u128, tick: i16) -> Option<u128> {
    let price = tick_to_price(tick) as u128;
    Some(amount.checked_mul(price)?.div_ceil(PRICE_SCALE as u128))
}

#[contract]
pub struct StablecoinExchange {
    books: Mapping<B256, Orderbook>,
    orders: Mapping<u128, Order>,
    balances: Mapping<Address, Mapping<Address, u128>>,
    active_order_id: u128,
    pending_order_id: u128,
    book_keys: Vec<B256>,
}

/// Helper type to easily interact with the `stream_ending_at` array
type BookKeys = Slot<Vec<B256>>;

impl<'a, S: PrecompileStorageProvider> StablecoinExchange<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(STABLECOIN_EXCHANGE_ADDRESS, storage)
    }

    /// Stablecoin exchange address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Initializes the contract
    ///
    /// This ensures the [`StablecoinExchange`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            self.address,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Read pending order ID
    fn get_pending_order_id(&mut self) -> Result<u128> {
        self.pending_order_id()
    }

    /// Set pending order ID
    fn set_pending_order_id(&mut self, order_id: u128) -> Result<()> {
        self.sstore_pending_order_id(order_id)
    }

    /// Read active order ID
    fn get_active_order_id(&mut self) -> Result<u128> {
        self.sload_active_order_id()
    }

    /// Set active order ID
    fn set_active_order_id(&mut self, order_id: u128) -> Result<()> {
        self.sstore_active_order_id(order_id)
    }

    /// Increment and return the pending order id
    fn increment_pending_order_id(&mut self) -> Result<u128> {
        let next_id = self.get_pending_order_id()? + 1;
        self.set_pending_order_id(next_id)?;
        Ok(next_id)
    }

    /// Get user's balance for a specific token
    pub fn balance_of(&mut self, user: Address, token: Address) -> Result<u128> {
        self.sload_balances(user, token)
    }

    /// Get MIN_PRICE value based on current hardfork
    pub fn min_price(&self) -> u32 {
        if self.storage.spec().is_moderato() {
            MIN_PRICE_POST_MODERATO
        } else {
            MIN_PRICE_PRE_MODERATO
        }
    }

    /// Get MAX_PRICE value based on current hardfork
    pub fn max_price(&self) -> u32 {
        if self.storage.spec().is_moderato() {
            MAX_PRICE_POST_MODERATO
        } else {
            MAX_PRICE_PRE_MODERATO
        }
    }

    /// Validates that a trading pair exists or creates the pair if
    /// the chain height is post allegretto hardfork
    fn validate_or_create_pair(&mut self, book: &Orderbook, token: Address) -> Result<()> {
        if book.base.is_zero() {
            if self.storage.spec().is_allegretto() {
                self.create_pair(token)?;
            } else {
                return Err(StablecoinExchangeError::pair_does_not_exist().into());
            }
        }
        Ok(())
    }

    /// Fetch order from storage. If the order is currently pending or filled, this function returns
    /// `StablecoinExchangeError::OrderDoesNotExist`
    pub fn get_order(&mut self, order_id: u128) -> Result<Order> {
        let order = self.sload_orders(order_id)?;

        // If the order is not filled and currently active
        if !order.maker().is_zero() && order.order_id() <= self.get_active_order_id()? {
            Ok(order)
        } else {
            Err(StablecoinExchangeError::order_does_not_exist().into())
        }
    }

    /// Set user's balance for a specific token
    fn set_balance(&mut self, user: Address, token: Address, amount: u128) -> Result<()> {
        self.sstore_balances(user, token, amount)
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

    /// Emit the appropriate OrderFilled event based on hardfork
    /// Pre-Allegretto: emits OrderFilled (without taker)
    /// Post-Allegretto: emits OrderFilled (with taker)
    fn emit_order_filled(
        &mut self,
        order_id: u128,
        maker: Address,
        taker: Address,
        amount_filled: u128,
        partial_fill: bool,
    ) -> Result<()> {
        if self.storage.spec().is_allegretto() {
            self.storage.emit_event(
                self.address,
                StablecoinExchangeEvents::OrderFilled_1(IStablecoinExchange::OrderFilled_1 {
                    orderId: order_id,
                    maker,
                    taker,
                    amountFilled: amount_filled,
                    partialFill: partial_fill,
                })
                .into_log_data(),
            )?;
        } else {
            self.storage.emit_event(
                self.address,
                StablecoinExchangeEvents::OrderFilled_0(IStablecoinExchange::OrderFilled_0 {
                    orderId: order_id,
                    maker,
                    amountFilled: amount_filled,
                    partialFill: partial_fill,
                })
                .into_log_data(),
            )?;
        }
        Ok(())
    }

    /// Transfer tokens, accounting for pathUSD
    fn transfer(&mut self, token: Address, to: Address, amount: u128) -> Result<()> {
        if token == PATH_USD_ADDRESS {
            PathUSD::new(self.storage).transfer(
                self.address,
                ITIP20::transferCall {
                    to,
                    amount: U256::from(amount),
                },
            )?;
        } else {
            TIP20Token::from_address(token, self.storage)?.transfer(
                self.address,
                ITIP20::transferCall {
                    to,
                    amount: U256::from(amount),
                },
            )?;
        }
        Ok(())
    }

    /// Transfer tokens from user, accounting for pathUSD
    fn transfer_from(&mut self, token: Address, from: Address, amount: u128) -> Result<()> {
        if token == PATH_USD_ADDRESS {
            PathUSD::new(self.storage).transfer_from(
                self.address,
                ITIP20::transferFromCall {
                    from,
                    to: self.address,
                    amount: U256::from(amount),
                },
            )?;
        } else {
            TIP20Token::from_address(token, self.storage)?.transfer_from(
                self.address,
                ITIP20::transferFromCall {
                    from,
                    to: self.address,
                    amount: U256::from(amount),
                },
            )?;
        }
        Ok(())
    }

    /// Decrement user's internal balance or transfer from external wallet
    fn decrement_balance_or_transfer_from(
        &mut self,
        user: Address,
        token: Address,
        amount: u128,
    ) -> Result<()> {
        let user_balance = self.balance_of(user, token)?;
        if user_balance >= amount {
            self.sub_balance(user, token, amount)
        } else {
            let remaining = amount
                .checked_sub(user_balance)
                .ok_or(TempoPrecompileError::under_overflow())?;

            // Post allegro-moderato hardfork, set balance after transfer from
            if self.storage.spec().is_allegro_moderato() {
                self.transfer_from(token, user, remaining)?;
                self.set_balance(user, token, 0)?;

                Ok(())
            } else {
                self.set_balance(user, token, 0)?;
                self.transfer_from(token, user, remaining)
            }
        }
    }

    pub fn quote_swap_exact_amount_out(
        &mut self,
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
        &mut self,
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
            amount = if self.storage.spec().is_moderato() {
                self.fill_orders_exact_in_post_moderato(book_key, base_for_quote, amount, sender)?
            } else {
                self.fill_orders_exact_in_pre_moderato(book_key, base_for_quote, amount, 0, sender)?
            };
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
            amount = if self.storage.spec().is_moderato() {
                self.fill_orders_exact_out_post_moderato(
                    *book_key,
                    *base_for_quote,
                    amount,
                    sender,
                )?
            } else {
                self.fill_orders_exact_out_pre_moderato(
                    *book_key,
                    *base_for_quote,
                    amount,
                    max_amount_in,
                    sender,
                )?
            };
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
    pub fn get_price_level(&mut self, base: Address, tick: i16, is_bid: bool) -> Result<TickLevel> {
        let quote = TIP20Token::from_address(base, self.storage)?.quote_token()?;
        let key = compute_book_key(base, quote);
        Orderbook::read_tick_level(self, key, is_bid, tick)
    }

    /// Get active order ID
    pub fn active_order_id(&mut self) -> Result<u128> {
        self.sload_active_order_id()
    }

    /// Get pending order ID
    pub fn pending_order_id(&mut self) -> Result<u128> {
        self.sload_pending_order_id()
    }

    /// Get orderbook by pair key
    pub fn books(&mut self, pair_key: B256) -> Result<Orderbook> {
        self.sload_books(pair_key)
    }

    /// Get all book keys
    pub fn get_book_keys(&mut self) -> Result<Vec<B256>> {
        self.sload_book_keys()
    }

    /// Convert scaled price to relative tick
    /// Post-Moderato: validates price is within [MIN_PRICE, MAX_PRICE]
    /// Pre-Moderato: no validation (legacy behavior)
    pub fn price_to_tick(&self, price: u32) -> Result<i16> {
        if self.storage.spec().is_moderato() {
            // Post-Moderato: validate price bounds
            orderbook::price_to_tick_post_moderato(price)
        } else {
            orderbook::price_to_tick_pre_moderato(price)
        }
    }

    pub fn create_pair(&mut self, base: Address) -> Result<B256> {
        // Validate that base is a TIP20 token (only after Moderato hardfork)
        if self.storage.spec().is_moderato() && !TIP20Factory::new(self.storage).is_tip20(base)? {
            return Err(StablecoinExchangeError::invalid_base_token().into());
        }

        let quote = TIP20Token::from_address(base, self.storage)?.quote_token()?;
        validate_usd_currency(base, self.storage)?;
        validate_usd_currency(quote, self.storage)?;

        let book_key = compute_book_key(base, quote);

        if self.sload_books(book_key)?.is_initialized() {
            return Err(StablecoinExchangeError::pair_already_exists().into());
        }

        let book = Orderbook::new(base, quote);
        self.sstore_books(book_key, book)?;
        BookKeys::new(slots::BOOK_KEYS).push(self, book_key)?;

        // Emit PairCreated event
        self.storage.emit_event(
            self.address,
            StablecoinExchangeEvents::PairCreated(IStablecoinExchange::PairCreated {
                key: book_key,
                base,
                quote,
            })
            .into_log_data(),
        )?;

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
        let quote_token = TIP20Token::from_address(token, self.storage)?.quote_token()?;

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);

        let book = self.sload_books(book_key)?;
        self.validate_or_create_pair(&book, token)?;

        // Validate tick is within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(tick).into());
        }

        // Post allegretto, enforce that the tick adheres to tick spacing
        if self.storage.spec().is_allegretto() && tick % TICK_SPACING != 0 {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        // Validate order amount meets minimum requirement
        if amount < MIN_ORDER_AMOUNT {
            return Err(StablecoinExchangeError::below_minimum_order_size(amount).into());
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount) = if is_bid {
            // For bids, escrow quote tokens based on price
            let quote_amount = if self.storage.spec().is_moderato() {
                calculate_quote_amount_ceil(amount, tick)
            } else {
                calculate_quote_amount_floor(amount, tick)
            }
            .ok_or(StablecoinExchangeError::insufficient_balance())?;
            (quote_token, quote_amount)
        } else {
            // For asks, escrow base tokens
            (token, amount)
        };

        // Debit from user's balance or transfer from wallet
        self.decrement_balance_or_transfer_from(sender, escrow_token, escrow_amount)?;

        // Create the order
        let order_id = self.increment_pending_order_id()?;
        let order = if is_bid {
            Order::new_bid(order_id, sender, book_key, amount, tick)
        } else {
            Order::new_ask(order_id, sender, book_key, amount, tick)
        };

        //Post Allegro Moderato, commit the order to the book immediately rather than storing in a pending state until end of block execution
        if self.storage.spec().is_allegro_moderato() {
            self.commit_order_to_book(order, book)?;
        } else {
            // Store in pending queue. Orders are stored as a DLL at each tick level and are initially
            // stored without a prev or next pointer. This is considered a "pending" order. Once `execute_block` is called, orders are
            // linked and then considered "active"
            self.sstore_orders(order_id, order)?;
        }

        // Emit OrderPlaced event
        self.storage.emit_event(
            self.address,
            StablecoinExchangeEvents::OrderPlaced(IStablecoinExchange::OrderPlaced {
                orderId: order_id,
                maker: sender,
                token,
                amount,
                isBid: is_bid,
                tick,
            })
            .into_log_data(),
        )?;

        Ok(order_id)
    }

    /// Commits an order to the specified orderbook, updating tick bits, best bid/ask, and total liquidity
    fn commit_order_to_book(&mut self, order: Order, orderbook: Orderbook) -> Result<()> {
        let order_id = order.order_id();

        // Store the order
        self.sstore_orders(order_id, order.clone())?;

        let mut level =
            Orderbook::read_tick_level(self, order.book_key(), order.is_bid(), order.tick())?;

        let prev_tail = level.tail;
        if prev_tail == 0 {
            level.head = order_id;
            level.tail = order_id;

            Orderbook::set_tick_bit(self, order.book_key(), order.tick(), order.is_bid())
                .expect("Tick is valid");

            if order.is_bid() {
                if order.tick() > orderbook.best_bid_tick {
                    Orderbook::update_best_bid_tick(self, order.book_key(), order.tick())?;
                }
            } else if order.tick() < orderbook.best_ask_tick {
                Orderbook::update_best_ask_tick(self, order.book_key(), order.tick())?;
            }
        } else {
            Order::update_next_order(self, prev_tail, order_id)?;
            Order::update_prev_order(self, order_id, prev_tail)?;
            level.tail = order_id;
        }

        let new_liquidity = level
            .total_liquidity
            .checked_add(order.remaining())
            .ok_or(TempoPrecompileError::under_overflow())?;
        level.total_liquidity = new_liquidity;

        Orderbook::write_tick_level(self, order.book_key(), order.is_bid(), order.tick(), level)
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
        let quote_token = TIP20Token::from_address(token, self.storage)?.quote_token()?;

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);

        // Check book existence (only after Moderato hardfork)
        if self.storage.spec().is_moderato() {
            let book = self.sload_books(book_key)?;
            self.validate_or_create_pair(&book, token)?;
        }

        // Validate tick and flip_tick are within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(tick).into());
        }

        // Post allegretto, enforce that the tick adheres to tick spacing
        if self.storage.spec().is_allegretto() && tick % TICK_SPACING != 0 {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        if !(MIN_TICK..=MAX_TICK).contains(&flip_tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(flip_tick).into());
        }

        // Post allegretto, enforce that the tick adheres to tick spacing
        if self.storage.spec().is_allegretto() && flip_tick % TICK_SPACING != 0 {
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
            let quote_amount = if self.storage.spec().is_moderato() {
                calculate_quote_amount_ceil(amount, tick)
            } else {
                calculate_quote_amount_floor(amount, tick)
            }
            .ok_or(StablecoinExchangeError::insufficient_balance())?;
            (quote_token, quote_amount)
        } else {
            // For asks, escrow base tokens
            (token, amount)
        };

        // Debit from user's balance or transfer from wallet
        self.decrement_balance_or_transfer_from(sender, escrow_token, escrow_amount)?;

        // Create the flip order
        let order_id = self.increment_pending_order_id()?;
        let order = Order::new_flip(order_id, sender, book_key, amount, tick, is_bid, flip_tick)
            .expect("Invalid flip tick");

        // Post Allegro Moderato, commit the order to the book immediately rather than storing in a pending state until end of block execution
        if self.storage.spec().is_allegro_moderato() {
            let book = self.sload_books(book_key)?;
            self.commit_order_to_book(order, book)?;
        } else {
            // Store in pending queue
            self.sstore_orders(order_id, order)?;
        }

        // Emit FlipOrderPlaced event
        self.storage.emit_event(
            self.address,
            StablecoinExchangeEvents::FlipOrderPlaced(IStablecoinExchange::FlipOrderPlaced {
                orderId: order_id,
                maker: sender,
                token,
                amount,
                isBid: is_bid,
                tick,
                flipTick: flip_tick,
            })
            .into_log_data(),
        )?;

        Ok(order_id)
    }

    /// Process all pending orders into the active orderbook
    ///
    /// Only callable by the protocol via system transaction (sender must be Address::ZERO)
    ///
    /// Post Allegro-Moderato: This function is a no-op since orders are immediately
    /// linked into the orderbook when placed.
    pub fn execute_block(&mut self, sender: Address) -> Result<()> {
        // Only protocol can call this
        if sender != Address::ZERO {
            return Err(StablecoinExchangeError::unauthorized().into());
        }

        // Post Allegro-Moderato: orders are immediately active, nothing to process
        if self.storage.spec().is_allegro_moderato() {
            return Ok(());
        }

        // Pre Allegro-Moderato: process pending orders into the active orderbook
        let next_order_id = self.get_active_order_id()?;

        let pending_order_id = self.get_pending_order_id()?;

        let mut current_order_id = next_order_id
            .checked_add(1)
            .ok_or(TempoPrecompileError::under_overflow())?;
        while current_order_id <= pending_order_id {
            self.process_pending_order(current_order_id)?;
            current_order_id = current_order_id
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?;
        }

        self.set_active_order_id(pending_order_id)?;

        Ok(())
    }

    /// Process a single pending order into the active orderbook (pre Allegro-Moderato only)
    fn process_pending_order(&mut self, order_id: u128) -> Result<()> {
        let order = self.sload_orders(order_id)?;

        // If the order is already canceled, return early
        if order.maker().is_zero() {
            return Ok(());
        }

        let orderbook = self.sload_books(order.book_key())?;
        self.commit_order_to_book(order, orderbook)
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
        let orderbook = self.sload_books(order.book_key())?;
        let price = tick_to_price(order.tick());

        // Update order remaining amount
        let new_remaining = order.remaining() - fill_amount;
        Order::update_remaining(self, order.order_id(), new_remaining)?;

        if order.is_bid() {
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
        } else {
            let quote_amount = fill_amount
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;
        }

        let amount_out = if order.is_bid() {
            fill_amount
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("Amount out calculation overflow")
        } else {
            fill_amount
        };

        // Update price level total liquidity
        let new_liquidity = level
            .total_liquidity
            .checked_sub(fill_amount)
            .ok_or(TempoPrecompileError::under_overflow())?;
        level.total_liquidity = new_liquidity;

        Orderbook::write_tick_level(self, order.book_key(), order.is_bid(), order.tick(), *level)?;

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
        let orderbook = self.sload_books(order.book_key())?;
        let price = tick_to_price(order.tick());
        let fill_amount = order.remaining();

        let amount_out = if order.is_bid() {
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
            fill_amount
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("Amount out calculation overflow")
        } else {
            let quote_amount = fill_amount
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("Amount out calculation overflow");
            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;

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
        self.clear_orders(order.order_id())?;

        // Advance tick if liquidity is exhausted
        let next_tick_info = if order.next() == 0 {
            Orderbook::delete_tick_level(self, book_key, order.is_bid(), order.tick())?;

            Orderbook::clear_tick_bit(self, order.book_key(), order.tick(), order.is_bid())
                .expect("Tick is valid");

            let (tick, has_liquidity) = Orderbook::next_initialized_tick(
                self,
                book_key,
                order.is_bid(),
                order.tick(),
                self.storage.spec(),
            );

            if self.storage.spec().is_allegretto() {
                // Update best_tick when tick is exhausted
                if order.is_bid() {
                    let new_best = if has_liquidity { tick } else { i16::MIN };
                    Orderbook::update_best_bid_tick(self, book_key, new_best)?;
                } else {
                    let new_best = if has_liquidity { tick } else { i16::MAX };
                    Orderbook::update_best_ask_tick(self, book_key, new_best)?;
                }
            }

            if !has_liquidity {
                // No more liquidity at better prices - return None to signal completion
                None
            } else {
                let new_level = Orderbook::read_tick_level(self, book_key, order.is_bid(), tick)?;
                let new_order = self.sload_orders(new_level.head)?;

                Some((new_level, new_order))
            }
        } else {
            // If there are subsequent orders at tick, advance to next order
            level.head = order.next();
            if self.storage.spec().is_allegretto() {
                Order::update_prev_order(self, order.next(), 0)?;
            }
            let new_liquidity = level
                .total_liquidity
                .checked_sub(fill_amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            level.total_liquidity = new_liquidity;

            Orderbook::write_tick_level(
                self,
                order.book_key(),
                order.is_bid(),
                order.tick(),
                level,
            )?;

            let new_order = self.sload_orders(order.next())?;
            Some((level, new_order))
        };

        Ok((amount_out, next_tick_info))
    }

    /// Fill orders for exact output amount, post moderato hardfork
    fn fill_orders_exact_out_post_moderato(
        &mut self,
        book_key: B256,
        bid: bool,
        mut amount_out: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = self.sload_orders(level.head)?;

        let mut total_amount_in: u128 = 0;

        while amount_out > 0 {
            let price = tick_to_price(order.tick());

            let (fill_amount, amount_in) = if bid {
                let base_needed = amount_out
                    .checked_mul(orderbook::PRICE_SCALE as u128)
                    .and_then(|v| v.checked_div(price as u128))
                    .ok_or(TempoPrecompileError::under_overflow())?;
                let fill_amount = base_needed.min(order.remaining());
                (fill_amount, fill_amount)
            } else {
                let fill_amount = amount_out.min(order.remaining());
                let amount_in = fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
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

                // Post-Moderato: set to 0 to avoid rounding errors
                if bid {
                    let base_needed = amount_out
                        .checked_mul(orderbook::PRICE_SCALE as u128)
                        .and_then(|v| v.checked_div(price as u128))
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

    /// Fill orders for exact output amount, pre moderato hardfork
    fn fill_orders_exact_out_pre_moderato(
        &mut self,
        book_key: B256,
        bid: bool,
        mut amount_out: u128,
        max_amount_in: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = self.sload_orders(level.head)?;

        let mut total_amount_in: u128 = 0;

        while amount_out > 0 {
            let price = tick_to_price(order.tick());
            let fill_amount = amount_out.min(order.remaining());
            let amount_in = if bid {
                fill_amount
            } else {
                fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .ok_or(TempoPrecompileError::under_overflow())?
            };

            // Pre-Moderato: Check maxIn on each iteration for consensus compatibility
            if total_amount_in + amount_in > max_amount_in {
                return Err(StablecoinExchangeError::max_input_exceeded().into());
            }

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

                // Pre-Moderato: always recalculate
                amount_out = amount_out
                    .checked_sub(amount_out_received)
                    .ok_or(TempoPrecompileError::under_overflow())?;

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

    /// Fill orders with exact amount in, post Moderato hardfork
    fn fill_orders_exact_in_post_moderato(
        &mut self,
        book_key: B256,
        bid: bool,
        mut amount_in: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = self.sload_orders(level.head)?;

        let mut total_amount_out: u128 = 0;

        while amount_in > 0 {
            let price = tick_to_price(order.tick());

            let fill_amount = if bid {
                amount_in.min(order.remaining())
            } else {
                let base_out = amount_in
                    .checked_mul(orderbook::PRICE_SCALE as u128)
                    .and_then(|v| v.checked_div(price as u128))
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

                // Post-Moderato: set to 0 to avoid rounding errors
                if bid {
                    if amount_in > order.remaining() {
                        amount_in = amount_in
                            .checked_sub(order.remaining())
                            .ok_or(TempoPrecompileError::under_overflow())?;
                    } else {
                        amount_in = 0;
                    }
                } else {
                    let base_out = amount_in
                        .checked_mul(orderbook::PRICE_SCALE as u128)
                        .and_then(|v| v.checked_div(price as u128))
                        .ok_or(TempoPrecompileError::under_overflow())?;
                    if base_out > order.remaining() {
                        let quote_needed = order
                            .remaining()
                            .checked_mul(price as u128)
                            .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
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

    /// Fill orders with exact amount in, pre Moderato hardfork
    fn fill_orders_exact_in_pre_moderato(
        &mut self,
        book_key: B256,
        bid: bool,
        mut amount_in: u128,
        min_amount_out: u128,
        taker: Address,
    ) -> Result<u128> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = self.sload_orders(level.head)?;

        let mut total_amount_out: u128 = 0;
        while amount_in > 0 {
            // Pre-Moderato: old behavior with unit mismatch
            let fill_amount = amount_in.min(order.remaining());

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

                // Pre-Moderato: always subtract order.remaining()
                amount_in = amount_in
                    .checked_sub(order.remaining())
                    .ok_or(TempoPrecompileError::under_overflow())?;

                if let Some((new_level, new_order)) = next_order_info {
                    level = new_level;
                    order = new_order;
                } else {
                    break;
                }
            }
        }

        // Pre-Moderato: Check min out after filling the full amount in
        if total_amount_out < min_amount_out {
            return Err(StablecoinExchangeError::insufficient_output().into());
        }

        Ok(total_amount_out)
    }

    /// Helper function to get best tick from orderbook
    fn get_best_price_level(&mut self, book_key: B256, is_bid: bool) -> Result<TickLevel> {
        let orderbook = self.sload_books(book_key)?;

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

        let level = Orderbook::read_tick_level(self, book_key, is_bid, current_tick)?;

        Ok(level)
    }

    /// Cancel an order and refund tokens to maker
    /// Only the order maker can cancel their own order
    pub fn cancel(&mut self, sender: Address, order_id: u128) -> Result<()> {
        let order = self.sload_orders(order_id)?;

        if order.maker().is_zero() {
            return Err(StablecoinExchangeError::order_does_not_exist().into());
        }

        if order.maker() != sender {
            return Err(StablecoinExchangeError::unauthorized().into());
        }

        if order.remaining() == 0 {
            return Err(StablecoinExchangeError::order_does_not_exist().into());
        }

        // Check if the order is still pending (not yet in active orderbook)
        let next_order_id = self.get_active_order_id()?;

        if order.order_id() > next_order_id {
            self.cancel_pending_order(order)?;
        } else {
            self.cancel_active_order(order)?;
        }

        Ok(())
    }

    /// Cancel a pending order (not yet in the active orderbook)
    fn cancel_pending_order(&mut self, order: Order) -> Result<()> {
        let orderbook = self.sload_books(order.book_key())?;
        let token = if order.is_bid() {
            orderbook.quote
        } else {
            orderbook.base
        };

        // For bids, calculate quote amount to refund; for asks, refund base amount
        let refund_amount = if order.is_bid() {
            let price = orderbook::tick_to_price(order.tick());
            (order.remaining() * price as u128) / orderbook::PRICE_SCALE as u128
        } else {
            order.remaining()
        };

        // Credit remaining tokens to user's withdrawable balance
        self.increment_balance(order.maker(), token, refund_amount)?;

        // Clear the order from storage
        self.clear_orders(order.order_id())?;

        // Emit OrderCancelled event
        self.storage.emit_event(
            self.address,
            StablecoinExchangeEvents::OrderCancelled(IStablecoinExchange::OrderCancelled {
                orderId: order.order_id(),
            })
            .into_log_data(),
        )
    }

    /// Cancel an active order (already in the orderbook)
    fn cancel_active_order(&mut self, order: Order) -> Result<()> {
        let mut level =
            Orderbook::read_tick_level(self, order.book_key(), order.is_bid(), order.tick())?;

        // Update linked list
        if order.prev() != 0 {
            Order::update_next_order(self, order.prev(), order.next())?;
        } else {
            level.head = order.next();
        }

        if order.next() != 0 {
            Order::update_prev_order(self, order.next(), order.prev())?;
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
            Orderbook::clear_tick_bit(self, order.book_key(), order.tick(), order.is_bid())
                .expect("Tick is valid");

            if self.storage.spec().is_allegretto() {
                // If this was the best tick, update it
                let orderbook = self.sload_books(order.book_key())?;
                let best_tick = if order.is_bid() {
                    orderbook.best_bid_tick
                } else {
                    orderbook.best_ask_tick
                };

                if best_tick == order.tick() {
                    let (next_tick, has_liquidity) = Orderbook::next_initialized_tick(
                        self,
                        order.book_key(),
                        order.is_bid(),
                        order.tick(),
                        self.storage.spec(),
                    );

                    if order.is_bid() {
                        let new_best = if has_liquidity { next_tick } else { i16::MIN };
                        Orderbook::update_best_bid_tick(self, order.book_key(), new_best)?;
                    } else {
                        let new_best = if has_liquidity { next_tick } else { i16::MAX };
                        Orderbook::update_best_ask_tick(self, order.book_key(), new_best)?;
                    }
                }
            }
        }

        Orderbook::write_tick_level(self, order.book_key(), order.is_bid(), order.tick(), level)?;

        // Refund tokens to maker
        let orderbook = self.sload_books(order.book_key())?;
        if order.is_bid() {
            // Bid orders are in quote token, refund quote amount
            let price = orderbook::tick_to_price(order.tick());
            let quote_amount = order
                .remaining()
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("Quote amount calculation overflow");
            self.increment_balance(order.maker(), orderbook.quote, quote_amount)?;
        } else {
            // Ask orders are in base token, refund base amount
            self.increment_balance(order.maker(), orderbook.base, order.remaining())?;
        }

        // Clear the order from storage
        self.clear_orders(order.order_id())?;

        // Emit OrderCancelled event
        self.storage.emit_event(
            self.address,
            StablecoinExchangeEvents::OrderCancelled(IStablecoinExchange::OrderCancelled {
                orderId: order.order_id(),
            })
            .into_log_data(),
        )
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
    fn quote_exact_out(&mut self, book_key: B256, amount_out: u128, is_bid: bool) -> Result<u128> {
        let mut remaining_out = amount_out;
        let mut amount_in = 0u128;
        let orderbook = self.sload_books(book_key)?;

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };
        // Check for no liquidity: i16::MIN means no bids, i16::MAX means no asks
        if current_tick == i16::MIN
            || self.storage.spec().is_allegretto() && current_tick == i16::MAX
        {
            return Err(StablecoinExchangeError::insufficient_liquidity().into());
        }

        while remaining_out > 0 {
            let level = Orderbook::read_tick_level(self, book_key, is_bid, current_tick)?;

            // If no liquidity at this level, move to next tick
            if level.total_liquidity == 0 {
                let (next_tick, initialized) = Orderbook::next_initialized_tick(
                    self,
                    book_key,
                    is_bid,
                    current_tick,
                    self.storage.spec(),
                );

                if !initialized {
                    return Err(StablecoinExchangeError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
                continue;
            }

            let price = orderbook::tick_to_price(current_tick);

            let (fill_amount, amount_in_tick) = if is_bid {
                // For bids: remaining_out is in quote, amount_in is in base
                let base_needed = remaining_out
                    .checked_mul(orderbook::PRICE_SCALE as u128)
                    .and_then(|v| v.checked_div(price as u128))
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
                let quote_needed = fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .ok_or(TempoPrecompileError::under_overflow())?;
                (fill_amount, quote_needed)
            };

            let amount_out_tick = if is_bid {
                fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
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
                let (next_tick, initialized) = Orderbook::next_initialized_tick(
                    self,
                    book_key,
                    is_bid,
                    current_tick,
                    self.storage.spec(),
                );

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
    fn find_trade_path(
        &mut self,
        token_in: Address,
        token_out: Address,
    ) -> Result<Vec<(B256, bool)>> {
        // Cannot trade same token
        if token_in == token_out {
            return Err(StablecoinExchangeError::identical_tokens().into());
        }

        // Validate that both tokens are TIP20 tokens
        if self.storage.spec().is_allegretto()
            && (!is_tip20_prefix(token_in) || !is_tip20_prefix(token_out))
        {
            return Err(StablecoinExchangeError::invalid_token().into());
        }

        // Check if direct or reverse pair exists
        let in_quote = TIP20Token::from_address(token_in, self.storage)?.quote_token()?;
        let out_quote = TIP20Token::from_address(token_out, self.storage)?.quote_token()?;

        if in_quote == token_out || out_quote == token_in {
            return self.validate_and_build_route(&[token_in, token_out]);
        }

        // Multi-hop: Find LCA and build path
        let path_in = self.find_path_to_root(token_in)?;
        let path_out = self.find_path_to_root(token_out)?;

        // Find the lowest common ancestor (LCA)
        let mut lca = None;
        for token_a in &path_in {
            if path_out.contains(token_a) {
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
    fn validate_and_build_route(&mut self, path: &[Address]) -> Result<Vec<(B256, bool)>> {
        let mut route = Vec::new();

        for i in 0..path.len() - 1 {
            let hop_token_in = path[i];
            let hop_token_out = path[i + 1];

            let book_key = compute_book_key(hop_token_in, hop_token_out);
            let orderbook = self.sload_books(book_key)?;

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
    fn find_path_to_root(&mut self, mut token: Address) -> Result<Vec<Address>> {
        let mut path = vec![token];

        while token != PATH_USD_ADDRESS {
            token = TIP20Token::from_address(token, self.storage)?.quote_token()?;
            path.push(token);
        }

        Ok(path)
    }

    /// Quote exact input amount without executing trades
    fn quote_exact_in(&mut self, book_key: B256, amount_in: u128, is_bid: bool) -> Result<u128> {
        let mut remaining_in = amount_in;
        let mut amount_out = 0u128;
        let orderbook = self.sload_books(book_key)?;

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };

        // Check for no liquidity: i16::MIN means no bids, i16::MAX means no asks
        if current_tick == i16::MIN
            || self.storage.spec().is_allegretto() && current_tick == i16::MAX
        {
            return Err(StablecoinExchangeError::insufficient_liquidity().into());
        }

        while remaining_in > 0 {
            let level = Orderbook::read_tick_level(self, book_key, is_bid, current_tick)?;

            // If no liquidity at this level, move to next tick
            if level.total_liquidity == 0 {
                let (next_tick, initialized) = Orderbook::next_initialized_tick(
                    self,
                    book_key,
                    is_bid,
                    current_tick,
                    self.storage.spec(),
                );

                if !initialized {
                    return Err(StablecoinExchangeError::insufficient_liquidity().into());
                }
                current_tick = next_tick;
                continue;
            }

            let price = orderbook::tick_to_price(current_tick);

            // Compute (fill_amount, amount_out_tick, amount_consumed) based on hardfork
            let (fill_amount, amount_out_tick, amount_consumed) =
                if self.storage.spec().is_allegretto() {
                    // Post-allegretto: logic accounts for `is_bid`
                    if is_bid {
                        // For bids: remaining_in is base, amount_out is quote
                        let fill = remaining_in.min(level.total_liquidity);
                        let quote_out = fill
                            .checked_mul(price as u128)
                            .ok_or(TempoPrecompileError::under_overflow())?
                            / orderbook::PRICE_SCALE as u128;
                        (fill, quote_out, fill)
                    } else {
                        // For asks: remaining_in is quote, amount_out is base
                        let base_to_get = remaining_in
                            .checked_mul(orderbook::PRICE_SCALE as u128)
                            .and_then(|v| v.checked_div(price as u128))
                            .ok_or(TempoPrecompileError::under_overflow())?;
                        let fill = base_to_get.min(level.total_liquidity);
                        let quote_consumed = fill
                            .checked_mul(price as u128)
                            .ok_or(TempoPrecompileError::under_overflow())?
                            / orderbook::PRICE_SCALE as u128;
                        (fill, fill, quote_consumed)
                    }
                } else {
                    // Pre-allegretto: doesn't account for `is_bid`
                    let fill = remaining_in.min(level.total_liquidity);
                    let amount_out_tick = fill
                        .checked_mul(price as u128)
                        .ok_or(TempoPrecompileError::under_overflow())?
                        / orderbook::PRICE_SCALE as u128;
                    (fill, amount_out_tick, fill)
                };

            remaining_in = remaining_in
                .checked_sub(amount_consumed)
                .ok_or(TempoPrecompileError::under_overflow())?;
            amount_out = amount_out
                .checked_add(amount_out_tick)
                .ok_or(TempoPrecompileError::under_overflow())?;

            // If we exhausted this level, move to next tick
            if fill_amount == level.total_liquidity {
                let (next_tick, initialized) = Orderbook::next_initialized_tick(
                    self,
                    book_key,
                    is_bid,
                    current_tick,
                    self.storage.spec(),
                );

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
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::TIP20Error;

    use crate::{
        error::TempoPrecompileError,
        path_usd::TRANSFER_ROLE,
        storage::{ContractStorage, hashmap::HashMapStorageProvider},
        tip20::{ISSUER_ROLE, tests::initialize_path_usd},
    };

    use super::*;

    fn mint_and_approve_token<S: PrecompileStorageProvider>(
        storage: &mut S,
        token_id: u64,
        admin: Address,
        user: Address,
        exchange_address: Address,
        amount: u128,
    ) {
        let mut token = TIP20Token::new(token_id, storage);
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: user,
                    amount: U256::from(amount),
                },
            )
            .expect("Base mint failed");
        token
            .approve(
                user,
                ITIP20::approveCall {
                    spender: exchange_address,
                    amount: U256::from(amount),
                },
            )
            .expect("Base approve failed");
    }

    fn mint_and_approve_quote<S: PrecompileStorageProvider>(
        storage: &mut S,
        admin: Address,
        user: Address,
        exchange_address: Address,
        amount: u128,
    ) {
        mint_and_approve_token(storage, 0, admin, user, exchange_address, amount);
        let mut quote = PathUSD::new(storage);
        quote
            .token
            .grant_role_internal(user, *TRANSFER_ROLE)
            .unwrap();
    }

    fn setup_test_tokens(
        storage: &mut HashMapStorageProvider,
        admin: Address,
        user: Address,
        exchange_address: Address,
        amount: u128,
    ) -> (Address, Address) {
        // Initialize PathUSD and factory properly (handles hardfork differences)
        initialize_path_usd(storage, admin).expect("PathUSD initialization failed");
        let quote_address = PATH_USD_ADDRESS;

        // Grant issuer role to admin for quote token
        let mut quote = PathUSD::new(storage);
        quote
            .token
            .grant_role_internal(admin, *ISSUER_ROLE)
            .unwrap();

        // Create base token via factory (properly registers it)
        let mut factory = TIP20Factory::new(storage);
        let base_address = factory
            .create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: "BASE".to_string(),
                    symbol: "BASE".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: quote_address,
                    admin,
                },
            )
            .expect("Base token creation failed");

        let token_id = address_to_token_id_unchecked(base_address);

        // Grant issuer role to admin for base token
        let mut base = TIP20Token::new(token_id, storage);
        base.grant_role_internal(admin, *ISSUER_ROLE).unwrap();

        // Mint and approve tokens for user
        mint_and_approve_quote(storage, admin, user, exchange_address, amount);
        mint_and_approve_token(storage, token_id, admin, user, exchange_address, amount);

        (base_address, quote_address)
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
    fn test_price_to_tick() {
        let test_prices = [
            98000u32, 99000, 99900, 99999, 100000, 100001, 100100, 101000, 102000,
        ];

        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let exchange = StablecoinExchange::new(&mut storage);

        for price in test_prices {
            let tick = exchange.price_to_tick(price).unwrap();
            let expected_tick = (price as i32 - orderbook::PRICE_SCALE as i32) as i16;
            assert_eq!(tick, expected_tick);
        }
    }

    #[test]
    fn test_price_to_tick_post_moderato() -> eyre::Result<()> {
        // Post-Moderato: price validation should be enforced
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let exchange = StablecoinExchange::new(&mut storage);

        // Valid prices should succeed
        assert_eq!(exchange.price_to_tick(orderbook::PRICE_SCALE)?, 0);
        assert_eq!(
            exchange.price_to_tick(orderbook::MIN_PRICE_POST_MODERATO)?,
            MIN_TICK
        );
        assert_eq!(
            exchange.price_to_tick(orderbook::MAX_PRICE_POST_MODERATO)?,
            MAX_TICK
        );

        // Out of bounds prices should fail
        let result = exchange.price_to_tick(orderbook::MIN_PRICE_POST_MODERATO - 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::TickOutOfBounds(_))
        ));

        let result = exchange.price_to_tick(orderbook::MAX_PRICE_POST_MODERATO + 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::TickOutOfBounds(_))
        ));

        Ok(())
    }

    #[test]
    fn test_price_to_tick_pre_moderato() -> eyre::Result<()> {
        // Pre-Moderato: no price validation (legacy behavior)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let exchange = StablecoinExchange::new(&mut storage);

        // Valid prices should succeed
        assert_eq!(exchange.price_to_tick(orderbook::PRICE_SCALE)?, 0);
        assert_eq!(
            exchange.price_to_tick(orderbook::MIN_PRICE_PRE_MODERATO)?,
            i16::MIN
        );
        assert_eq!(
            exchange.price_to_tick(orderbook::MAX_PRICE_PRE_MODERATO)?,
            i16::MAX
        );

        // Out of bounds prices should also succeed (legacy behavior)
        let tick = exchange.price_to_tick(orderbook::MIN_PRICE_PRE_MODERATO - 1)?;
        assert_eq!(
            tick,
            ((orderbook::MIN_PRICE_PRE_MODERATO - 1) as i32 - orderbook::PRICE_SCALE as i32) as i16
        );

        let tick = exchange.price_to_tick(orderbook::MAX_PRICE_PRE_MODERATO + 1)?;
        assert_eq!(
            tick,
            ((orderbook::MAX_PRICE_PRE_MODERATO + 1) as i32 - orderbook::PRICE_SCALE as i32) as i16
        );

        Ok(())
    }

    #[test]
    fn test_calculate_quote_amount_floor() {
        // Floor division rounds DOWN
        // amount = 100, tick = 1 means price = 100001
        // 100 * 100001 / 100000 = 10000100 / 100000 = 100.001
        // Should round down to 100
        let amount = 100u128;
        let tick = 1i16;
        let result = calculate_quote_amount_floor(amount, tick).unwrap();

        assert_eq!(result, 100, "Expected 100 (rounded down from 100.001)");

        // Another test case
        let amount2 = 999u128;
        let tick2 = 5i16; // price = 100005
        let result2 = calculate_quote_amount_floor(amount2, tick2).unwrap();
        // 999 * 100005 / 100000 = 99904995 / 100000 = 999.04995 -> should be 999
        assert_eq!(result2, 999, "Expected 999 (rounded down from 999.04995)");

        // Test with no remainder (should work the same)
        let amount3 = 100000u128;
        let tick3 = 0i16; // price = 100000
        let result3 = calculate_quote_amount_floor(amount3, tick3).unwrap();
        // 100000 * 100000 / 100000 = 100000 (exact, no rounding)
        assert_eq!(result3, 100000, "Exact division should remain exact");
    }

    #[test]
    fn test_calculate_quote_amount_ceil() {
        // Ceiling division rounds UP
        // amount = 100, tick = 1 means price = 100001
        // 100 * 100001 / 100000 = 10000100 / 100000 = 100.001
        // Should round up to 101
        let amount = 100u128;
        let tick = 1i16;
        let result = calculate_quote_amount_ceil(amount, tick).unwrap();

        assert_eq!(result, 101, "Expected 101 (rounded up from 100.001)");

        // Another test case
        let amount2 = 999u128;
        let tick2 = 5i16; // price = 100005
        let result2 = calculate_quote_amount_ceil(amount2, tick2).unwrap();
        // 999 * 100005 / 100000 = 99904995 / 100000 = 999.04995 -> should be 1000
        assert_eq!(result2, 1000, "Expected 1000 (rounded up from 999.04995)");

        // Test with no remainder (should work the same)
        let amount3 = 100000u128;
        let tick3 = 0i16; // price = 100000
        let result3 = calculate_quote_amount_ceil(amount3, tick3).unwrap();
        // 100000 * 100000 / 100000 = 100000 (exact, no rounding needed)
        assert_eq!(result3, 100000, "Exact division should remain exact");
    }

    #[test]
    fn test_place_order_pair_does_not_exist_post_moderato() -> eyre::Result<()> {
        // Test with Moderato hardfork (validation should be enforced)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        let result = exchange.place(alice, base_token, min_order_amount, true, tick);
        assert_eq!(
            result,
            Err(StablecoinExchangeError::pair_does_not_exist().into())
        );

        Ok(())
    }

    #[test]
    fn test_place_order_pair_does_not_exist_pre_moderato() -> eyre::Result<()> {
        // Test with Adagio (pre-Moderato) - validation is enforced in all hardforks
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        // Try to place an order without creating the pair first
        // This validation is enforced both pre and post Moderato
        let result = exchange.place(alice, base_token, min_order_amount, true, tick);

        // Should fail with pair_does_not_exist error
        assert_eq!(
            result,
            Err(StablecoinExchangeError::pair_does_not_exist().into())
        );

        Ok(())
    }

    #[test]
    fn test_place_order_below_minimum_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let below_minimum = min_order_amount - 1;
        let tick = 100i16;

        let price = orderbook::tick_to_price(tick);
        let escrow_amount = (below_minimum * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            escrow_amount,
        );

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
    }

    #[test]
    fn test_place_bid_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens with enough balance for the escrow
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        // Create the pair before placing orders
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        // Place the bid order
        let order_id = exchange
            .place(alice, base_token, min_order_amount, true, tick)
            .expect("Place bid order should succeed");

        assert_eq!(order_id, 1);
        assert_eq!(exchange.active_order_id()?, 0);
        assert_eq!(exchange.pending_order_id()?, 1);

        // Verify the order was stored correctly
        let stored_order = exchange.sload_orders(order_id)?;
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.amount(), min_order_amount);
        assert_eq!(stored_order.remaining(), min_order_amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(stored_order.is_bid());
        assert!(!stored_order.is_flip());
        assert_eq!(stored_order.prev(), 0);
        assert_eq!(stored_order.next(), 0);

        // Verify the order is not yet in the active orderbook
        let book_key = compute_book_key(base_token, quote_token);
        let level = Orderbook::read_tick_level(&mut exchange, book_key, true, tick)?;
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage).unwrap();
            let remaining_balance =
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice })?;
            assert_eq!(remaining_balance, U256::ZERO);

            // Verify exchange received the tokens
            let exchange_balance = quote_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            })?;
            assert_eq!(exchange_balance, U256::from(expected_escrow));
        }

        Ok(())
    }

    #[test]
    fn test_place_ask_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 50i16; // Use positive tick to avoid conversion issues

        // Setup tokens with enough base token balance for the order
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            min_order_amount,
        );
        // Create the pair before placing orders
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        let order_id = exchange
            .place(alice, base_token, min_order_amount, false, tick) // is_bid = false for ask
            .expect("Place ask order should succeed");

        assert_eq!(order_id, 1);
        assert_eq!(exchange.active_order_id()?, 0);
        assert_eq!(exchange.pending_order_id()?, 1);

        // Verify the order was stored correctly
        let stored_order = exchange.sload_orders(order_id)?;
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.amount(), min_order_amount);
        assert_eq!(stored_order.remaining(), min_order_amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(!stored_order.is_bid());
        assert!(!stored_order.is_flip());
        assert_eq!(stored_order.prev(), 0);
        assert_eq!(stored_order.next(), 0);

        let book_key = compute_book_key(base_token, quote_token);
        let level = Orderbook::read_tick_level(&mut exchange, book_key, false, tick)?;
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut base_tip20 = TIP20Token::from_address(base_token, exchange.storage).unwrap();
            let remaining_balance =
                base_tip20.balance_of(ITIP20::balanceOfCall { account: alice })?;
            assert_eq!(remaining_balance, U256::ZERO); // All tokens should be escrowed

            // Verify exchange received the base tokens
            let exchange_balance = base_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            })?;
            assert_eq!(exchange_balance, U256::from(min_order_amount));
        }

        Ok(())
    }

    #[test]
    fn test_place_flip_order_below_minimum_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let below_minimum = min_order_amount - 1;
        let tick = 100i16;
        let flip_tick = 200i16;

        let price = orderbook::tick_to_price(tick);
        let escrow_amount = (below_minimum * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            escrow_amount,
        );

        // Create the pair
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        // Try to place a flip order below minimum amount
        let result = exchange.place_flip(alice, base_token, below_minimum, true, tick, flip_tick);
        assert_eq!(
            result,
            Err(StablecoinExchangeError::below_minimum_order_size(below_minimum).into())
        );

        Ok(())
    }

    #[test]
    fn test_place_flip_order_pair_does_not_exist_post_moderato() -> eyre::Result<()> {
        // Test with Moderato hardfork (validation should be enforced)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;
        let flip_tick = 200i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        // Try to place a flip order without creating the pair first
        let result =
            exchange.place_flip(alice, base_token, min_order_amount, true, tick, flip_tick);
        assert_eq!(
            result,
            Err(StablecoinExchangeError::pair_does_not_exist().into())
        );

        Ok(())
    }

    #[test]
    fn test_place_flip_order_pair_does_not_exist_pre_moderato() -> eyre::Result<()> {
        // Test with Adagio (pre-Moderato) - validation should not be enforced
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;
        let flip_tick = 200i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        // Try to place a flip order without creating the pair first
        // Pre-Moderato, the book existence check is skipped, so the order is accepted
        // (it would only fail later during execute_block when trying to process it)
        let result =
            exchange.place_flip(alice, base_token, min_order_amount, true, tick, flip_tick);

        // Pre-Moderato: order should be accepted (placed in pending queue)
        assert!(result.is_ok());

        Ok(())
    }

    #[test]
    fn test_place_flip_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;
        let flip_tick = 200i16; // Must be > tick for bid flip orders

        // Calculate escrow amount needed for bid
        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens with enough balance for the escrow
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        let order_id = exchange
            .place_flip(alice, base_token, min_order_amount, true, tick, flip_tick)
            .expect("Place flip bid order should succeed");

        assert_eq!(order_id, 1);
        assert_eq!(exchange.active_order_id()?, 0);
        assert_eq!(exchange.pending_order_id()?, 1);

        // Verify the order was stored correctly
        let stored_order = exchange.sload_orders(order_id)?;
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.amount(), min_order_amount);
        assert_eq!(stored_order.remaining(), min_order_amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(stored_order.is_bid());
        assert!(stored_order.is_flip());
        assert_eq!(stored_order.flip_tick(), flip_tick);
        assert_eq!(stored_order.prev(), 0);
        assert_eq!(stored_order.next(), 0);

        // Verify the order is not yet in the active orderbook
        let book_key = compute_book_key(base_token, quote_token);
        let level = Orderbook::read_tick_level(&mut exchange, book_key, true, tick)?;
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage).unwrap();
            let remaining_balance =
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice })?;
            assert_eq!(remaining_balance, U256::ZERO);

            // Verify exchange received the tokens
            let exchange_balance = quote_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            })?;
            assert_eq!(exchange_balance, U256::from(expected_escrow));
        }

        Ok(())
    }

    #[test]
    fn test_cancel_pending_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;

        // Calculate escrow amount needed for bid
        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        // Place the bid order
        let order_id = exchange
            .place(alice, base_token, min_order_amount, true, tick)
            .expect("Place bid order should succeed");

        // Verify order was placed and tokens were escrowed
        assert_eq!(exchange.balance_of(alice, quote_token)?, 0);

        let (alice_balance_before, exchange_balance_before) = {
            let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage).unwrap();

            (
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice })?,
                quote_tip20.balance_of(ITIP20::balanceOfCall {
                    account: exchange.address,
                })?,
            )
        };

        assert_eq!(alice_balance_before, U256::ZERO);
        assert_eq!(exchange_balance_before, U256::from(expected_escrow));

        // Cancel the pending order
        exchange
            .cancel(alice, order_id)
            .expect("Cancel pending order should succeed");

        // Verify order was deleted
        let cancelled_order = exchange.sload_orders(order_id)?;
        assert_eq!(cancelled_order.maker(), Address::ZERO);

        // Verify tokens were refunded to user's internal balance
        assert_eq!(exchange.balance_of(alice, quote_token)?, expected_escrow);

        Ok(())
    }

    #[test]
    fn test_execute_block() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;

        // Calculate escrow amount needed for both orders
        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens with enough balance for two orders
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow * 2,
        );

        // Create the pair
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        let order_id_0 = exchange
            .place(alice, base_token, min_order_amount, true, tick)
            .expect("Swap should succeed");

        let order_id_1 = exchange
            .place(alice, base_token, min_order_amount, true, tick)
            .expect("Swap should succeed");
        assert_eq!(order_id_0, 1);
        assert_eq!(order_id_1, 2);
        assert_eq!(exchange.active_order_id()?, 0);
        assert_eq!(exchange.pending_order_id()?, 2);

        // Verify orders are in pending state
        let order_0 = exchange.sload_orders(order_id_0)?;
        let order_1 = exchange.sload_orders(order_id_1)?;
        assert_eq!(order_0.prev(), 0);
        assert_eq!(order_0.next(), 0);
        assert_eq!(order_1.prev(), 0);
        assert_eq!(order_1.next(), 0);

        // Verify tick level is empty before execute_block
        let book_key = compute_book_key(base_token, quote_token);
        let level_before = Orderbook::read_tick_level(&mut exchange, book_key, true, tick)?;
        assert_eq!(level_before.head, 0);
        assert_eq!(level_before.tail, 0);
        assert_eq!(level_before.total_liquidity, 0);

        // Execute block and assert that orders have been linked
        exchange
            .execute_block(Address::ZERO)
            .expect("Execute block should succeed");

        assert_eq!(exchange.active_order_id()?, 2);
        assert_eq!(exchange.pending_order_id()?, 2);

        let order_0 = exchange.sload_orders(order_id_0)?;
        let order_1 = exchange.sload_orders(order_id_1)?;
        assert_eq!(order_0.prev(), 0);
        assert_eq!(order_0.next(), order_1.order_id());
        assert_eq!(order_1.prev(), order_0.order_id());
        assert_eq!(order_1.next(), 0);

        // Assert tick level is updated
        let level_after = Orderbook::read_tick_level(&mut exchange, book_key, true, tick)?;
        assert_eq!(level_after.head, order_0.order_id());
        assert_eq!(level_after.tail, order_1.order_id());
        assert_eq!(level_after.total_liquidity, min_order_amount * 2);

        // Verify orderbook best bid tick is updated
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, tick);

        Ok(())
    }

    #[test]
    fn test_execute_block_unauthorized() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let result = exchange.execute_block(Address::random());
        assert_eq!(result, Err(StablecoinExchangeError::unauthorized().into()));
    }

    #[test]
    fn test_withdraw() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;
        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );
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
        let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage).unwrap();

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
    }

    #[test]
    fn test_withdraw_insufficient_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        let (_base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            min_order_amount,
        );

        // Alice has 0 balance on the exchange
        assert_eq!(exchange.balance_of(alice, quote_token)?, 0);

        // Try to withdraw more than balance
        let result = exchange.withdraw(alice, quote_token, 100u128);

        assert_eq!(
            result,
            Err(StablecoinExchangeError::insufficient_balance().into())
        );

        Ok(())
    }

    #[test]
    fn test_quote_swap_exact_amount_out() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let amount_out = 500_000u128;
        let tick = 10;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            200_000_000u128,
        );
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        let order_amount = min_order_amount;
        exchange
            .place(alice, base_token, order_amount, false, tick)
            .expect("Order should succeed");

        exchange
            .execute_block(Address::ZERO)
            .expect("Execute block should succeed");

        let amount_in = exchange
            .quote_swap_exact_amount_out(quote_token, base_token, amount_out)
            .expect("Swap should succeed");

        let price = orderbook::tick_to_price(tick);
        let expected_amount_in = (amount_out * price as u128) / orderbook::PRICE_SCALE as u128;
        assert_eq!(amount_in, expected_amount_in);
    }

    #[test]
    fn test_quote_swap_exact_amount_in() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let amount_in = 500_000u128;
        let tick = 10;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            200_000_000u128,
        );
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        let order_amount = min_order_amount;
        exchange
            .place(alice, base_token, order_amount, true, tick)
            .expect("Place bid order should succeed");

        exchange
            .execute_block(Address::ZERO)
            .expect("Execute block should succeed");

        let amount_out = exchange
            .quote_swap_exact_amount_in(base_token, quote_token, amount_in)
            .expect("Swap should succeed");

        // Calculate expected amount_out based on tick price
        let price = orderbook::tick_to_price(tick);
        let expected_amount_out = (amount_in * price as u128) / orderbook::PRICE_SCALE as u128;
        assert_eq!(amount_out, expected_amount_out);
    }

    #[test]
    fn test_quote_swap_exact_amount_out_base_for_quote() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let amount_out = 500_000u128;
        let tick = 0;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            200_000_000u128,
        );
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        // Alice places a bid: willing to BUY base using quote
        let order_amount = min_order_amount;
        exchange
            .place(alice, base_token, order_amount, true, tick)
            .expect("Place bid order should succeed");

        exchange
            .execute_block(Address::ZERO)
            .expect("Execute block should succeed");

        // Quote: sell base to get quote
        // Should match against Alice's bid (buyer of base)
        let amount_in = exchange
            .quote_swap_exact_amount_out(base_token, quote_token, amount_out)
            .expect("Quote should succeed");

        let price = orderbook::tick_to_price(tick);
        let expected_amount_in = (amount_out * price as u128) / orderbook::PRICE_SCALE as u128;
        assert_eq!(amount_in, expected_amount_in);
    }

    #[test]
    fn test_swap_exact_amount_out() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let amount_out = 500_000u128;
        let tick = 10;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            200_000_000u128,
        );
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        let order_amount = min_order_amount;
        exchange
            .place(alice, base_token, order_amount, false, tick)
            .expect("Order should succeed");

        exchange
            .execute_block(Address::ZERO)
            .expect("Execute block should succeed");

        exchange
            .set_balance(bob, quote_token, 200_000_000u128)
            .expect("Could not set balance");

        let price = orderbook::tick_to_price(tick);
        let max_amount_in = (amount_out * price as u128) / orderbook::PRICE_SCALE as u128;

        let amount_in = exchange
            .swap_exact_amount_out(bob, quote_token, base_token, amount_out, max_amount_in)
            .expect("Swap should succeed");

        let mut base_tip20 = TIP20Token::from_address(base_token, exchange.storage).unwrap();
        let bob_base_balance = base_tip20.balance_of(ITIP20::balanceOfCall { account: bob })?;
        assert_eq!(bob_base_balance, U256::from(amount_out));

        let alice_quote_exchange_balance = exchange.balance_of(alice, quote_token)?;
        assert_eq!(alice_quote_exchange_balance, amount_in);

        Ok(())
    }

    #[test]
    fn test_swap_exact_amount_in() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let amount_in = 500_000u128;
        let tick = 10;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            200_000_000u128,
        );
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        let order_amount = min_order_amount;
        exchange
            .place(alice, base_token, order_amount, true, tick)
            .expect("Order should succeed");

        exchange
            .execute_block(Address::ZERO)
            .expect("Execute block should succeed");

        exchange
            .set_balance(bob, base_token, 200_000_000u128)
            .expect("Could not set balance");

        let price = orderbook::tick_to_price(tick);
        let min_amount_out = (amount_in * price as u128) / orderbook::PRICE_SCALE as u128;

        let amount_out = exchange
            .swap_exact_amount_in(bob, base_token, quote_token, amount_in, min_amount_out)
            .expect("Swap should succeed");

        let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage).unwrap();
        let bob_quote_balance = quote_tip20.balance_of(ITIP20::balanceOfCall { account: bob })?;
        assert_eq!(bob_quote_balance, U256::from(amount_out));

        let alice_base_exchange_balance = exchange.balance_of(alice, base_token)?;
        assert_eq!(alice_base_exchange_balance, amount_in);

        Ok(())
    }

    #[test]
    fn test_flip_order_execution() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let amount = min_order_amount;
        let tick = 100i16;
        let flip_tick = 200i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow * 2,
        );
        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        // Place a flip bid order
        let flip_order_id = exchange
            .place_flip(alice, base_token, amount, true, tick, flip_tick)
            .expect("Place flip order should succeed");

        exchange
            .execute_block(Address::ZERO)
            .expect("Execute block should succeed");

        exchange
            .set_balance(bob, base_token, amount)
            .expect("Could not set balance");

        exchange
            .swap_exact_amount_in(bob, base_token, quote_token, amount, 0)
            .expect("Swap should succeed");

        // Assert that the order has filled
        let filled_order = exchange.sload_orders(flip_order_id)?;
        assert_eq!(filled_order.maker(), Address::ZERO);

        let new_order_id = exchange.pending_order_id()?;
        assert_eq!(new_order_id, flip_order_id + 1);

        let new_order = exchange.sload_orders(new_order_id)?;
        assert_eq!(new_order.maker(), alice);
        assert_eq!(new_order.tick(), flip_tick);
        assert_eq!(new_order.flip_tick(), tick);
        assert!(new_order.is_ask());
        assert_eq!(new_order.amount(), amount);
        assert_eq!(new_order.remaining(), amount);

        Ok(())
    }

    #[test]
    fn test_pair_created() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let admin = Address::random();
        let alice = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        // Setup tokens
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            min_order_amount,
        );

        // Create the pair
        let key = exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        // Verify PairCreated event was emitted
        let events = &exchange.storage.events[&exchange.address];
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            StablecoinExchangeEvents::PairCreated(IStablecoinExchange::PairCreated {
                key,
                base: base_token,
                quote: quote_token,
            })
            .into_log_data()
        );
    }

    #[test]
    fn test_pair_already_created() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let admin = Address::random();
        let alice = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        // Setup tokens
        let (base_token, _) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            min_order_amount,
        );

        exchange
            .create_pair(base_token)
            .expect("Could not create pair");

        let result = exchange.create_pair(base_token);
        assert_eq!(
            result,
            Err(StablecoinExchangeError::pair_already_exists().into())
        );
    }

    /// Helper to verify a single hop in a route
    fn verify_hop(
        storage: &mut impl PrecompileStorageProvider,
        exchange_addr: Address,
        hop: (B256, bool),
        token_in: Address,
        token_out: Address,
    ) -> eyre::Result<()> {
        let (book_key, base_for_quote) = hop;
        let expected_book_key = compute_book_key(token_in, token_out);
        assert_eq!(book_key, expected_book_key, "Book key should match");

        let mut exchange = StablecoinExchange::_new(exchange_addr, storage);
        let orderbook = exchange.sload_books(book_key)?;
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
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();

        // Setup: PathUSD <- USDC <- TokenA
        let path_usd_addr = {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .initialize(admin)
                .expect("Failed to initialize PathUSD");
            path_usd.token.address()
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize USDC");
            usdc.address()
        };

        let token_a_addr = {
            let mut token_a = TIP20Token::new(3, exchange.storage);
            token_a
                .initialize("TokenA", "TKA", "USD", usdc_addr, admin, Address::ZERO)
                .expect("Failed to initialize TokenA");
            token_a.address()
        };

        // Find path from TokenA to root
        let path = exchange
            .find_path_to_root(token_a_addr)
            .expect("Failed to find path");

        // Expected: [TokenA, USDC, PathUSD]
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], token_a_addr);
        assert_eq!(path[1], usdc_addr);
        assert_eq!(path[2], path_usd_addr);

        Ok(())
    }

    #[test]
    fn test_find_trade_path_same_token_errors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let user = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        let (token, _) = setup_test_tokens(
            exchange.storage,
            admin,
            user,
            exchange.address,
            min_order_amount,
        );

        // Trading same token should error with IdenticalTokens
        let result = exchange.find_trade_path(token, token);
        assert_eq!(
            result,
            Err(StablecoinExchangeError::identical_tokens().into()),
            "Should return IdenticalTokens error when token_in == token_out"
        );

        Ok(())
    }

    #[test]
    fn test_find_trade_path_direct_pair() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let user = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        // Setup: PathUSD <- Token (direct pair)
        let (token, path_usd) = setup_test_tokens(
            exchange.storage,
            admin,
            user,
            exchange.address,
            min_order_amount,
        );

        // Create the pair first
        exchange.create_pair(token).expect("Failed to create pair");

        // Trade token -> path_usd (direct pair)
        let route = exchange
            .find_trade_path(token, path_usd)
            .expect("Should find direct pair");

        // Expected: 1 hop (token -> path_usd)
        assert_eq!(route.len(), 1, "Should have 1 hop for direct pair");
        verify_hop(
            exchange.storage,
            exchange.address,
            route[0],
            token,
            path_usd,
        )?;

        Ok(())
    }

    #[test]
    fn test_find_trade_path_reverse_pair() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let user = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        // Setup: PathUSD <- Token
        let (token, path_usd) = setup_test_tokens(
            exchange.storage,
            admin,
            user,
            exchange.address,
            min_order_amount,
        );

        // Create the pair first
        exchange.create_pair(token).expect("Failed to create pair");

        // Trade path_usd -> token (reverse direction)
        let route = exchange
            .find_trade_path(path_usd, token)
            .expect("Should find reverse pair");

        // Expected: 1 hop (path_usd -> token)
        assert_eq!(route.len(), 1, "Should have 1 hop for reverse pair");
        verify_hop(
            exchange.storage,
            exchange.address,
            route[0],
            path_usd,
            token,
        )?;

        Ok(())
    }

    #[test]
    fn test_find_trade_path_two_hop_siblings() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();

        // Setup: PathUSD <- USDC
        //        PathUSD <- EURC
        // (USDC and EURC are siblings, both have PathUSD as quote)
        let path_usd_addr = {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .initialize(admin)
                .expect("Failed to initialize PathUSD");
            path_usd.token.address()
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize USDC");
            usdc.address()
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize EURC");
            eurc.address()
        };

        // Create pairs first
        exchange
            .create_pair(usdc_addr)
            .expect("Failed to create USDC pair");
        exchange
            .create_pair(eurc_addr)
            .expect("Failed to create EURC pair");

        // Trade USDC -> EURC should go through PathUSD
        let route = exchange
            .find_trade_path(usdc_addr, eurc_addr)
            .expect("Should find path");

        // Expected: 2 hops (USDC -> PathUSD, PathUSD -> EURC)
        assert_eq!(route.len(), 2, "Should have 2 hops for sibling tokens");
        verify_hop(
            exchange.storage,
            exchange.address,
            route[0],
            usdc_addr,
            path_usd_addr,
        )?;
        verify_hop(
            exchange.storage,
            exchange.address,
            route[1],
            path_usd_addr,
            eurc_addr,
        )?;

        Ok(())
    }

    #[test]
    fn test_quote_exact_in_multi_hop() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let alice = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;

        // Setup: PathUSD <- USDC
        //        PathUSD <- EURC
        let path_usd_addr = {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .initialize(admin)
                .expect("Failed to initialize PathUSD");
            path_usd.token.address()
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize USDC");
            usdc.address()
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize EURC");
            eurc.address()
        };

        // Create pairs
        exchange
            .create_pair(usdc_addr)
            .expect("Failed to create USDC pair");
        exchange
            .create_pair(eurc_addr)
            .expect("Failed to create EURC pair");

        // Setup tokens and roles
        {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.grant_role_internal(admin, *ISSUER_ROLE)?;
            usdc.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint USDC");
        }

        {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.grant_role_internal(admin, *ISSUER_ROLE)?;
            eurc.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint EURC");
        }

        {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd
                .token
                .mint(
                    admin,
                    ITIP20::mintCall {
                        to: alice,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to mint PathUSD");
        }

        // Approve exchange
        {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve USDC");
        }

        {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve EURC");
        }

        {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .token
                .approve(
                    alice,
                    ITIP20::approveCall {
                        spender: exchange.address,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to approve PathUSD");
        }

        // Place orders to provide liquidity at 1:1 rate (tick 0)
        // For trade USDC -> PathUSD -> EURC:
        // - First hop needs: bid on USDC (someone buying USDC with PathUSD)
        // - Second hop needs: ask on EURC (someone selling EURC for PathUSD)

        // USDC bid: buy USDC with PathUSD
        exchange
            .place(alice, usdc_addr, min_order_amount * 5, true, 0)
            .expect("Failed to place USDC bid order");

        // EURC ask: sell EURC for PathUSD
        exchange
            .place(alice, eurc_addr, min_order_amount * 5, false, 0)
            .expect("Failed to place EURC ask order");

        exchange
            .execute_block(Address::ZERO)
            .expect("Failed to execute block");

        // Quote multi-hop: USDC -> PathUSD -> EURC
        let amount_in = min_order_amount;
        let amount_out = exchange
            .quote_swap_exact_amount_in(usdc_addr, eurc_addr, amount_in)
            .expect("Should quote multi-hop trade");

        // With 1:1 rates at each hop, output should equal input
        assert_eq!(
            amount_out, amount_in,
            "With 1:1 rates, output should equal input"
        );

        Ok(())
    }

    #[test]
    fn test_quote_exact_out_multi_hop() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let alice = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        // Setup: PathUSD <- USDC
        //        PathUSD <- EURC
        let path_usd_addr = {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .initialize(admin)
                .expect("Failed to initialize PathUSD");
            path_usd.token.address()
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize USDC");
            usdc.address()
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize EURC");
            eurc.address()
        };

        // Create pairs and setup (same as previous test)
        exchange
            .create_pair(usdc_addr)
            .expect("Failed to create USDC pair");
        exchange
            .create_pair(eurc_addr)
            .expect("Failed to create EURC pair");

        {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.grant_role_internal(admin, *ISSUER_ROLE)?;
            usdc.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint USDC");
            usdc.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve USDC");
        }

        {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.grant_role_internal(admin, *ISSUER_ROLE)?;
            eurc.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint EURC");
            eurc.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve EURC");
        }

        {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd
                .token
                .mint(
                    admin,
                    ITIP20::mintCall {
                        to: alice,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to mint PathUSD");
            path_usd
                .token
                .approve(
                    alice,
                    ITIP20::approveCall {
                        spender: exchange.address,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to approve PathUSD");
        }

        // Place orders at 1:1 rate
        exchange
            .place(alice, usdc_addr, min_order_amount * 5, true, 0)
            .expect("Failed to place USDC bid order");
        exchange
            .place(alice, eurc_addr, min_order_amount * 5, false, 0)
            .expect("Failed to place EURC ask order");

        exchange
            .execute_block(Address::ZERO)
            .expect("Failed to execute block");

        // Quote multi-hop for exact output: USDC -> PathUSD -> EURC
        let amount_out = min_order_amount;
        let amount_in = exchange
            .quote_swap_exact_amount_out(usdc_addr, eurc_addr, amount_out)
            .expect("Should quote multi-hop trade for exact output");

        // With 1:1 rates at each hop, input should equal output
        assert_eq!(
            amount_in, amount_out,
            "With 1:1 rates, input should equal output"
        );

        Ok(())
    }

    #[test]
    fn test_swap_exact_in_multi_hop_transitory_balances() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let alice = Address::random();
        let bob = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        // Setup: PathUSD <- USDC <- EURC
        let path_usd_addr = {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .initialize(admin)
                .expect("Failed to initialize PathUSD");
            path_usd.token.address()
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize USDC");
            usdc.address()
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize EURC");
            eurc.address()
        };

        exchange
            .create_pair(usdc_addr)
            .expect("Failed to create USDC pair");
        exchange
            .create_pair(eurc_addr)
            .expect("Failed to create EURC pair");

        // Setup alice as liquidity provider
        {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.grant_role_internal(admin, *ISSUER_ROLE)?;
            usdc.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint USDC");
            usdc.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve USDC");
        }

        {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.grant_role_internal(admin, *ISSUER_ROLE)?;
            eurc.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint EURC");
            eurc.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve EURC");
        }

        {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd.token.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )?;

            path_usd.token.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )?;
        }

        // Setup bob as trader
        {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.mint(
                admin,
                ITIP20::mintCall {
                    to: bob,
                    amount: U256::from(min_order_amount * 10),
                },
            )?;

            usdc.approve(
                bob,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )?;
        }

        // Place liquidity orders at 1:1
        exchange
            .place(alice, usdc_addr, min_order_amount * 5, true, 0)
            .expect("Failed to place USDC bid order");
        exchange
            .place(alice, eurc_addr, min_order_amount * 5, false, 0)
            .expect("Failed to place EURC ask order");
        exchange
            .execute_block(Address::ZERO)
            .expect("Failed to execute block");

        // Check bob's balances before swap
        let bob_usdc_before = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.balance_of(ITIP20::balanceOfCall { account: bob })?
        };
        let bob_eurc_before = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.balance_of(ITIP20::balanceOfCall { account: bob })?
        };

        // Execute multi-hop swap: USDC -> PathUSD -> EURC
        let amount_in = min_order_amount;
        let amount_out = exchange
            .swap_exact_amount_in(
                bob, usdc_addr, eurc_addr, amount_in, 0, // min_amount_out
            )
            .expect("Should execute multi-hop swap");

        // Check bob's balances after swap
        let bob_usdc_after = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.balance_of(ITIP20::balanceOfCall { account: bob })?
        };
        let bob_eurc_after = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.balance_of(ITIP20::balanceOfCall { account: bob })?
        };

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
        let bob_path_usd_wallet = {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .token
                .balance_of(ITIP20::balanceOfCall { account: bob })?
        };
        assert_eq!(
            bob_path_usd_wallet,
            U256::ZERO,
            "Bob should have ZERO PathUSD in wallet (transitory)"
        );

        let bob_path_usd_exchange = exchange
            .balance_of(bob, path_usd_addr)
            .expect("Failed to get bob's PathUSD exchange balance");
        assert_eq!(
            bob_path_usd_exchange, 0,
            "Bob should have ZERO PathUSD on exchange (transitory)"
        );

        Ok(())
    }

    #[test]
    fn test_swap_exact_out_multi_hop_transitory_balances() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let alice = Address::random();
        let bob = Address::random();

        let min_order_amount = MIN_ORDER_AMOUNT;
        // Setup: PathUSD <- USDC <- EURC
        let path_usd_addr = {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .initialize(admin)
                .expect("Failed to initialize PathUSD");
            path_usd.token.address()
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize USDC");
            usdc.address()
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", path_usd_addr, admin, Address::ZERO)
                .expect("Failed to initialize EURC");
            eurc.address()
        };

        exchange
            .create_pair(usdc_addr)
            .expect("Failed to create USDC pair");
        exchange
            .create_pair(eurc_addr)
            .expect("Failed to create EURC pair");

        // Setup alice as liquidity provider
        {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.grant_role_internal(admin, *ISSUER_ROLE)?;
            usdc.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint USDC");
            usdc.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve USDC");
        }

        {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.grant_role_internal(admin, *ISSUER_ROLE)?;
            eurc.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint EURC");
            eurc.approve(
                alice,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve EURC");
        }

        {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd
                .token
                .mint(
                    admin,
                    ITIP20::mintCall {
                        to: alice,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to mint PathUSD");
            path_usd
                .token
                .approve(
                    alice,
                    ITIP20::approveCall {
                        spender: exchange.address,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to approve PathUSD");
        }

        // Setup bob as trader
        {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.mint(
                admin,
                ITIP20::mintCall {
                    to: bob,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to mint USDC for bob");
            usdc.approve(
                bob,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(min_order_amount * 10),
                },
            )
            .expect("Failed to approve USDC for bob");
        }

        // Place liquidity orders at 1:1
        exchange
            .place(alice, usdc_addr, min_order_amount * 5, true, 0)
            .expect("Failed to place USDC bid order");
        exchange
            .place(alice, eurc_addr, min_order_amount * 5, false, 0)
            .expect("Failed to place EURC ask order");
        exchange
            .execute_block(Address::ZERO)
            .expect("Failed to execute block");

        // Check bob's balances before swap
        let bob_usdc_before = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.balance_of(ITIP20::balanceOfCall { account: bob })?
        };
        let bob_eurc_before = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.balance_of(ITIP20::balanceOfCall { account: bob })?
        };

        // Execute multi-hop swap: USDC -> PathUSD -> EURC (exact output)
        let amount_out = 90u128;
        let amount_in = exchange.swap_exact_amount_out(
            bob,
            usdc_addr,
            eurc_addr,
            amount_out,
            u128::MAX, // max_amount_in
        )?;

        // Check bob's balances after swap
        let bob_usdc_after = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.balance_of(ITIP20::balanceOfCall { account: bob })?
        };
        let bob_eurc_after = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.balance_of(ITIP20::balanceOfCall { account: bob })?
        };

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
        let bob_path_usd_wallet = {
            let mut path_usd = PathUSD::new(exchange.storage);
            path_usd
                .token
                .balance_of(ITIP20::balanceOfCall { account: bob })?
        };
        assert_eq!(
            bob_path_usd_wallet,
            U256::ZERO,
            "Bob should have ZERO PathUSD in wallet (transitory)"
        );

        let bob_path_usd_exchange = exchange
            .balance_of(bob, path_usd_addr)
            .expect("Failed to get bob's PathUSD exchange balance");
        assert_eq!(
            bob_path_usd_exchange, 0,
            "Bob should have ZERO PathUSD on exchange (transitory)"
        );

        Ok(())
    }

    #[test]
    fn test_create_pair_invalid_currency() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);

        let admin = Address::random();
        // Init path USD
        let mut path_usd = TIP20Token::from_address(PATH_USD_ADDRESS, &mut storage).unwrap();
        path_usd
            .initialize(
                "PathUSD",
                "LUSD",
                "USD",
                Address::ZERO,
                admin,
                Address::ZERO,
            )
            .unwrap();

        // Create EUR token with PATH USD as quote (valid non-USD token)
        let mut token_0 = TIP20Token::new(1, path_usd.storage());
        token_0
            .initialize(
                "EuroToken",
                "EURO",
                "EUR",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();
        let token_0_address = token_0.address();

        let mut exchange = StablecoinExchange::new(token_0.storage());
        exchange.initialize()?;

        // Test: create_pair should reject non-USD token (EUR token has EUR currency)
        let result = exchange.create_pair(token_0_address);
        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));

        Ok(())
    }

    #[test]
    fn test_max_in_check_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            200_000_000u128,
        );
        exchange.create_pair(base_token)?;

        let tick_50 = 50i16;
        let tick_100 = 100i16;
        let order_amount = MIN_ORDER_AMOUNT;

        exchange.place(alice, base_token, order_amount, false, tick_50)?;
        exchange.place(alice, base_token, order_amount, false, tick_100)?;
        exchange.execute_block(Address::ZERO)?;

        exchange.set_balance(bob, quote_token, 200_000_000u128)?;

        let price_50 = orderbook::tick_to_price(tick_50);
        let quote_for_first = (order_amount * price_50 as u128) / orderbook::PRICE_SCALE as u128;
        let max_in_between = quote_for_first + 500;

        let result = exchange.swap_exact_amount_out(
            bob,
            quote_token,
            base_token,
            order_amount + 999,
            max_in_between,
        );
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_create_pair_rejects_non_tip20_base_post_moderato() -> eyre::Result<()> {
        // Test with Moderato hardfork (validation should be enforced)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);

        let admin = Address::random();
        // Init PATH USD
        let mut path_usd = TIP20Token::from_address(PATH_USD_ADDRESS, &mut storage).unwrap();
        path_usd
            .initialize(
                "PathUSD",
                "LUSD",
                "USD",
                Address::ZERO,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let mut exchange = StablecoinExchange::new(path_usd.storage());
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
    }

    #[test]
    fn test_max_in_check_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            200_000_000u128,
        );
        exchange.create_pair(base_token)?;

        let tick_50 = 50i16;
        let tick_100 = 100i16;
        let order_amount = MIN_ORDER_AMOUNT;

        exchange.place(alice, base_token, order_amount, false, tick_50)?;
        exchange.place(alice, base_token, order_amount, false, tick_100)?;
        exchange.execute_block(Address::ZERO)?;

        exchange.set_balance(bob, quote_token, 200_000_000u128)?;

        let price_50 = orderbook::tick_to_price(tick_50);
        let price_100 = orderbook::tick_to_price(tick_100);
        let quote_for_first = (order_amount * price_50 as u128) / orderbook::PRICE_SCALE as u128;
        let quote_for_partial_second = (999 * price_100 as u128) / orderbook::PRICE_SCALE as u128;
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
    }

    #[test]
    fn test_create_pair_allows_non_tip20_base_pre_moderato() -> eyre::Result<()> {
        // Test with Adagio (pre-Moderato) - validation should not be enforced
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);

        let admin = Address::random();
        // Init Linking USD
        let mut path_usd = TIP20Token::from_address(PATH_USD_ADDRESS, &mut storage).unwrap();
        path_usd
            .initialize(
                "PathUSD",
                "LUSD",
                "USD",
                Address::ZERO,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let mut exchange = StablecoinExchange::new(path_usd.storage());
        exchange.initialize()?;

        // Test: create_pair should not reject non-TIP20 address pre-Moderato
        // This will fail with a different error (trying to read quote_token from non-TIP20)
        // but NOT the InvalidQuoteToken error from the is_tip20 check
        let non_tip20_address = Address::random();
        let result = exchange.create_pair(non_tip20_address);

        // Should fail but not with InvalidQuoteToken error (that check is skipped pre-Moderato)
        assert!(result.is_err());
        assert!(!matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidQuoteToken(
                _
            )))
        ));

        Ok(())
    }

    #[test]
    fn test_exact_out_bid_side_pre_moderato() -> eyre::Result<()> {
        // Pre-Moderato: old behavior with unit mismatch causes MaxInputExceeded
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            1_000_000_000u128,
        );
        exchange.create_pair(base_token)?;

        let tick = 1000i16;
        let price = tick_to_price(tick);
        let order_amount_base = MIN_ORDER_AMOUNT;

        exchange.place(alice, base_token, order_amount_base, true, tick)?;
        exchange.execute_block(Address::ZERO)?;

        let amount_out_quote = 5_000_000u128;
        let base_needed = (amount_out_quote * PRICE_SCALE as u128) / price as u128;
        let max_amount_in = base_needed + 10000;

        exchange.set_balance(bob, base_token, max_amount_in * 2)?;

        // Pre-Moderato: should fail with MaxInputExceeded due to unit mismatch
        let result = exchange.swap_exact_amount_out(
            bob,
            base_token,
            quote_token,
            amount_out_quote,
            max_amount_in,
        );

        assert!(
            matches!(
                result,
                Err(TempoPrecompileError::StablecoinExchange(
                    StablecoinExchangeError::MaxInputExceeded(_)
                ))
            ),
            "Pre-Moderato should fail with MaxInputExceeded"
        );

        Ok(())
    }

    #[test]
    fn test_exact_out_bid_side_post_moderato() -> eyre::Result<()> {
        // Post-Moderato: new behavior with correct unit conversion
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            1_000_000_000u128,
        );
        exchange.create_pair(base_token)?;

        let tick = 1000i16;
        let price = tick_to_price(tick);
        let order_amount_base = MIN_ORDER_AMOUNT;

        exchange.place(alice, base_token, order_amount_base, true, tick)?;
        exchange.execute_block(Address::ZERO)?;

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
        let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage).unwrap();
        let bob_quote_balance = quote_tip20.balance_of(ITIP20::balanceOfCall { account: bob })?;
        assert_eq!(bob_quote_balance, U256::from(amount_out_quote));

        Ok(())
    }

    #[test]
    fn test_exact_in_ask_side_pre_moderato() -> eyre::Result<()> {
        // Pre-Moderato: old behavior treats quote amount as base amount
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            1_000_000_000u128,
        );
        exchange.create_pair(base_token)?;

        let tick = 1000i16;
        let price = tick_to_price(tick);
        let order_amount_base = MIN_ORDER_AMOUNT;

        exchange.place(alice, base_token, order_amount_base, false, tick)?;
        exchange.execute_block(Address::ZERO)?;

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

        // Pre-Moderato: returns incorrect amount (treats quote as base)
        // It will return amount_in_quote (5M) instead of the correct converted amount
        assert_eq!(amount_out, amount_in_quote);
        assert_ne!(
            amount_out,
            (amount_in_quote * PRICE_SCALE as u128) / price as u128
        );

        Ok(())
    }

    #[test]
    fn test_exact_in_ask_side_post_moderato() -> eyre::Result<()> {
        // Post-Moderato: new behavior with correct unit conversion
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            1_000_000_000u128,
        );
        exchange.create_pair(base_token)?;

        let tick = 1000i16;
        let price = tick_to_price(tick);
        let order_amount_base = MIN_ORDER_AMOUNT;

        exchange.place(alice, base_token, order_amount_base, false, tick)?;
        exchange.execute_block(Address::ZERO)?;

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

        // Post-Moderato: returns correct converted amount
        let expected_base = (amount_in_quote * PRICE_SCALE as u128) / price as u128;
        assert_eq!(amount_out, expected_base);

        Ok(())
    }

    #[test]
    fn test_clear_order_post_allegretto() -> eyre::Result<()> {
        const AMOUNT: u128 = 1_000_000_000;

        // Test that fill_order properly clears the prev pointer when advancing to the next order
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let bob = Address::random();
        let carol = Address::random();
        let admin = Address::random();

        let (base_token, quote_token) =
            setup_test_tokens(exchange.storage, admin, alice, exchange.address, AMOUNT);
        exchange.create_pair(base_token)?;

        // Give bob base tokens and carol quote tokens
        mint_and_approve_token(exchange.storage, 1, admin, bob, exchange.address, AMOUNT);
        mint_and_approve_quote(exchange.storage, admin, carol, exchange.address, AMOUNT);

        let tick = 100i16;

        // Place two ask orders at the same tick: Order 1 (alice), Order 2 (bob)
        let order1_amount = MIN_ORDER_AMOUNT;
        let order2_amount = MIN_ORDER_AMOUNT;

        let order1_id = exchange.place(alice, base_token, order1_amount, false, tick)?;
        let order2_id = exchange.place(bob, base_token, order2_amount, false, tick)?;
        exchange.execute_block(Address::ZERO)?;

        // Verify linked list is set up correctly
        let order1 = exchange.sload_orders(order1_id)?;
        let order2 = exchange.sload_orders(order2_id)?;
        assert_eq!(order1.next(), order2_id);
        assert_eq!(order2.prev(), order1_id);

        // Swap to fill order1 completely
        let swap_amount = order1_amount;
        exchange.swap_exact_amount_out(carol, quote_token, base_token, swap_amount, u128::MAX)?;

        // After filling order1, order2 should be the new head with prev = 0
        let order2_after = exchange.sload_orders(order2_id)?;
        assert_eq!(
            order2_after.prev(),
            0,
            "New head order should have prev = 0 after previous head was filled"
        );

        Ok(())
    }

    #[test]
    fn test_best_tick_updates_on_fill() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
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

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            total_bid_escrow,
        );
        exchange.create_pair(base_token)?;
        let book_key = compute_book_key(base_token, quote_token);

        // Place bid orders at two different ticks
        exchange.place(alice, base_token, amount, true, bid_tick_1)?;
        exchange.place(alice, base_token, amount, true, bid_tick_2)?;

        // Place ask orders at two different ticks
        mint_and_approve_token(
            exchange.storage,
            1,
            admin,
            alice,
            exchange.address,
            amount * 2,
        );
        exchange.place(alice, base_token, amount, false, ask_tick_1)?;
        exchange.place(alice, base_token, amount, false, ask_tick_2)?;

        exchange.execute_block(Address::ZERO)?;

        // Verify initial best ticks
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, bid_tick_1);
        assert_eq!(orderbook.best_ask_tick, ask_tick_1);

        // Fill all bids at tick 100 (bob sells base)
        exchange.set_balance(bob, base_token, amount)?;
        exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;
        // Verify best_bid_tick moved to tick 90, best_ask_tick unchanged
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, bid_tick_2);
        assert_eq!(orderbook.best_ask_tick, ask_tick_1);

        // Fill remaining bid at tick 90
        exchange.set_balance(bob, base_token, amount)?;
        exchange.swap_exact_amount_in(bob, base_token, quote_token, amount, 0)?;
        // Verify best_bid_tick is now i16::MIN, best_ask_tick unchanged
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, i16::MIN);
        assert_eq!(orderbook.best_ask_tick, ask_tick_1);

        // Fill all asks at tick 50 (bob buys base)
        let ask_price_1 = orderbook::tick_to_price(ask_tick_1);
        let quote_needed = (amount * ask_price_1 as u128) / orderbook::PRICE_SCALE as u128;
        exchange.set_balance(bob, quote_token, quote_needed)?;
        exchange.swap_exact_amount_in(bob, quote_token, base_token, quote_needed, 0)?;
        // Verify best_ask_tick moved to tick 60, best_bid_tick unchanged
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_ask_tick, ask_tick_2);
        assert_eq!(orderbook.best_bid_tick, i16::MIN);

        Ok(())
    }

    #[test]
    fn test_best_tick_updates_on_cancel() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
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

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            total_escrow,
        );
        exchange.create_pair(base_token)?;
        let book_key = compute_book_key(base_token, quote_token);

        // Place 2 bid orders at tick 100, 1 at tick 90
        let bid_order_1 = exchange.place(alice, base_token, amount, true, bid_tick_1)?;
        let bid_order_2 = exchange.place(alice, base_token, amount, true, bid_tick_1)?;
        let bid_order_3 = exchange.place(alice, base_token, amount, true, bid_tick_2)?;

        // Place 2 ask orders at tick 50 and tick 60
        mint_and_approve_token(
            exchange.storage,
            1,
            admin,
            alice,
            exchange.address,
            amount * 2,
        );
        let ask_order_1 = exchange.place(alice, base_token, amount, false, ask_tick_1)?;
        let ask_order_2 = exchange.place(alice, base_token, amount, false, ask_tick_2)?;

        exchange.execute_block(Address::ZERO)?;

        // Verify initial best ticks
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, bid_tick_1);
        assert_eq!(orderbook.best_ask_tick, ask_tick_1);

        // Cancel one bid at tick 100
        exchange.cancel(alice, bid_order_1)?;
        // Verify best_bid_tick remains 100, best_ask_tick unchanged
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, bid_tick_1);
        assert_eq!(orderbook.best_ask_tick, ask_tick_1);

        // Cancel remaining bid at tick 100
        exchange.cancel(alice, bid_order_2)?;
        // Verify best_bid_tick moved to 90, best_ask_tick unchanged
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, bid_tick_2);
        assert_eq!(orderbook.best_ask_tick, ask_tick_1);

        // Cancel ask at tick 50
        exchange.cancel(alice, ask_order_1)?;
        // Verify best_ask_tick moved to 60, best_bid_tick unchanged
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, bid_tick_2);
        assert_eq!(orderbook.best_ask_tick, ask_tick_2);

        // Cancel bid at tick 90
        exchange.cancel(alice, bid_order_3)?;
        // Verify best_bid_tick is now i16::MIN, best_ask_tick unchanged
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, i16::MIN);
        assert_eq!(orderbook.best_ask_tick, ask_tick_2);

        // Cancel ask at tick 60
        exchange.cancel(alice, ask_order_2)?;
        // Verify best_ask_tick is now i16::MAX, best_bid_tick unchanged
        let orderbook = exchange.sload_books(book_key)?;
        assert_eq!(orderbook.best_bid_tick, i16::MIN);
        assert_eq!(orderbook.best_ask_tick, i16::MAX);

        Ok(())
    }

    #[test]
    fn test_place_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            1_000_000_000,
        );
        exchange.create_pair(base_token)?;

        // Give alice base tokens
        mint_and_approve_token(
            exchange.storage,
            1,
            admin,
            alice,
            exchange.address,
            1_000_000_000,
        );

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
    }

    #[test]
    fn test_place_flip_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            1_000_000_000,
        );
        exchange.create_pair(base_token)?;

        // Give alice base tokens
        mint_and_approve_token(
            exchange.storage,
            1,
            admin,
            alice,
            exchange.address,
            1_000_000_000,
        );

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
            TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidFlipTick(_))
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
    }

    #[test]
    fn test_find_trade_path_rejects_non_tip20_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let user = Address::random();

        let (_, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            user,
            exchange.address,
            MIN_ORDER_AMOUNT,
        );

        let non_tip20_address = Address::random();
        let result = exchange.find_trade_path(non_tip20_address, quote_token);
        assert!(
            matches!(
                result,
                Err(TempoPrecompileError::StablecoinExchange(
                    StablecoinExchangeError::InvalidToken(_)
                ))
            ),
            "Should return InvalidToken error for non-TIP20 token post-Allegretto"
        );

        Ok(())
    }

    #[test]
    fn test_quote_exact_in_handles_both_directions() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let amount = MIN_ORDER_AMOUNT;
        let tick = 100_i16;
        let price = orderbook::tick_to_price(tick);

        // Calculate escrow for bid order (quote needed to buy `amount` base)
        let bid_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, quote_token) =
            setup_test_tokens(exchange.storage, admin, alice, exchange.address, bid_escrow);
        exchange.create_pair(base_token)?;
        let book_key = compute_book_key(base_token, quote_token);
        mint_and_approve_token(exchange.storage, 1, admin, alice, exchange.address, amount);

        // Place a bid order (alice wants to buy base with quote)
        exchange.place(alice, base_token, amount, true, tick)?;
        exchange.execute_block(Address::ZERO)?;

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
        exchange.execute_block(Address::ZERO)?;

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
    }

    #[test]
    fn test_place_auto_creates_pair_post_allegretto() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;
        let admin = Address::random();
        let user = Address::random();

        // Setup tokens
        let (base_token, quote_token) =
            setup_test_tokens(exchange.storage, admin, user, exchange.address, 100_000_000);

        // Before placing order, verify pair doesn't exist
        let book_key = compute_book_key(base_token, quote_token);
        let book_before = exchange.sload_books(book_key)?;
        assert!(book_before.base.is_zero(),);

        // Transfer tokens to exchange first
        let mut base = TIP20Token::new(1, exchange.storage);
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

        let book_after = exchange.sload_books(book_key)?;
        assert_eq!(book_after.base, base_token);

        // Verify PairCreated event was emitted (along with OrderPlaced)
        let events = &exchange.storage.events[&exchange.address];
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
    }

    #[test]
    fn test_place_flip_auto_creates_pair_post_allegretto() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let user = Address::random();

        // Setup tokens
        let (base_token, quote_token) =
            setup_test_tokens(exchange.storage, admin, user, exchange.address, 100_000_000);

        // Before placing flip order, verify pair doesn't exist
        let book_key = compute_book_key(base_token, quote_token);
        let book_before = exchange.sload_books(book_key)?;
        assert!(book_before.base.is_zero(),);

        // Transfer tokens to exchange first
        let mut base = TIP20Token::new(1, exchange.storage);
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

        let book_after = exchange.sload_books(book_key)?;
        assert_eq!(book_after.base, base_token);

        // Verify PairCreated event was emitted (along with FlipOrderPlaced)
        let events = &exchange.storage.events[&exchange.address];
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
    }

    #[test]
    fn test_decrement_balance_zeroes_balance_pre_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);

        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();

        let mut quote = PathUSD::new(exchange.storage);
        quote.initialize(admin)?;
        let quote_address = quote.token.address();

        let mut base = TIP20Token::new(1, quote.token.storage());
        base.initialize("BASE", "BASE", "USD", quote_address, admin, Address::ZERO)?;
        base.grant_role_internal(admin, *ISSUER_ROLE)?;
        let base_address = base.address();

        exchange.create_pair(base_address)?;

        let internal_balance = MIN_ORDER_AMOUNT / 2;
        exchange.sstore_balances(alice, base_address, internal_balance)?;

        assert_eq!(exchange.balance_of(alice, base_address)?, internal_balance);

        let tick = 0i16;
        let result = exchange.place(alice, base_address, MIN_ORDER_AMOUNT, false, tick);

        assert!(result.is_err());
        assert_eq!(exchange.balance_of(alice, base_address)?, 0);

        Ok(())
    }

    #[test]
    fn test_decrement_balance_preserves_balance_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();

        let mut quote = PathUSD::new(exchange.storage);
        quote.initialize(admin)?;
        let quote_address = quote.token.address();

        // Set token_id_counter to 2 so that token id 1 is considered valid
        TIP20Factory::new(quote.token.storage()).set_token_id_counter(U256::from(2))?;

        let mut base = TIP20Token::new(1, quote.token.storage());
        base.initialize("BASE", "BASE", "USD", quote_address, admin, Address::ZERO)?;
        base.grant_role_internal(admin, *ISSUER_ROLE)?;
        let base_address = base.address();

        exchange.create_pair(base_address)?;

        let internal_balance = MIN_ORDER_AMOUNT / 2;
        exchange.sstore_balances(alice, base_address, internal_balance)?;

        assert_eq!(exchange.balance_of(alice, base_address)?, internal_balance);

        let tick = 0i16;
        let result = exchange.place(alice, base_address, MIN_ORDER_AMOUNT * 2, false, tick);

        assert!(result.is_err());
        assert_eq!(exchange.balance_of(alice, base_address)?, internal_balance);

        Ok(())
    }

    #[test]
    fn test_place_pre_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        let order_id = exchange.place(alice, base_token, min_order_amount, true, tick)?;

        let stored_order = exchange.sload_orders(order_id)?;
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.remaining(), min_order_amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(stored_order.is_bid());

        let book_key = compute_book_key(base_token, quote_token);
        let level = Orderbook::read_tick_level(&mut exchange, book_key, true, tick)?;
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        Ok(())
    }

    #[test]
    fn test_place_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        let order_id = exchange.place(alice, base_token, min_order_amount, true, tick)?;

        let stored_order = exchange.sload_orders(order_id)?;
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.remaining(), min_order_amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(stored_order.is_bid());

        let book_key = compute_book_key(base_token, quote_token);
        let level = Orderbook::read_tick_level(&mut exchange, book_key, true, tick)?;
        assert_eq!(level.head, order_id);
        assert_eq!(level.tail, order_id);
        assert_eq!(level.total_liquidity, min_order_amount);

        let book = exchange.sload_books(book_key)?;
        assert_eq!(book.best_bid_tick, tick);

        Ok(())
    }

    #[test]
    fn test_place_flip_pre_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;
        let flip_tick = 200i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        let order_id =
            exchange.place_flip(alice, base_token, min_order_amount, true, tick, flip_tick)?;

        let stored_order = exchange.sload_orders(order_id)?;
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.remaining(), min_order_amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(stored_order.is_bid());
        assert!(stored_order.is_flip());

        let book_key = compute_book_key(base_token, quote_token);
        let level = Orderbook::read_tick_level(&mut exchange, book_key, true, tick)?;
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        Ok(())
    }

    #[test]
    fn test_place_flip_post_allegro_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::AllegroModerato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = MIN_ORDER_AMOUNT;
        let tick = 100i16;
        let flip_tick = 200i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (min_order_amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            admin,
            alice,
            exchange.address,
            expected_escrow,
        );

        let order_id =
            exchange.place_flip(alice, base_token, min_order_amount, true, tick, flip_tick)?;

        let stored_order = exchange.sload_orders(order_id)?;
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.remaining(), min_order_amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(stored_order.is_bid());
        assert!(stored_order.is_flip());

        let book_key = compute_book_key(base_token, quote_token);
        let level = Orderbook::read_tick_level(&mut exchange, book_key, true, tick)?;
        assert_eq!(level.head, order_id);
        assert_eq!(level.tail, order_id);
        assert_eq!(level.total_liquidity, min_order_amount);

        let book = exchange.sload_books(book_key)?;
        assert_eq!(book.best_bid_tick, tick);

        Ok(())
    }
}
