//! Stablecoin DEX types and utilities.

pub mod error;
pub mod offsets;
pub mod order;
pub mod orderbook;
pub mod slots;

pub use error::OrderError;
pub use order::Order;
pub use orderbook::{
    MAX_TICK, MIN_TICK, Orderbook, PRICE_SCALE, PriceLevel, TickBitmap, price_to_tick,
    tick_to_price,
};

use crate::{
    LINKING_USD_ADDRESS, STABLECOIN_EXCHANGE_ADDRESS,
    contracts::{
        LinkingUSD, StorageProvider, TIP20Token, address_to_token_id_unchecked,
        stablecoin_exchange::orderbook::{
            compute_book_key, next_initialized_ask_tick, next_initialized_bid_tick,
        },
        storage::{StorageOps, slots::mapping_slot},
        types::{IStablecoinExchange, ITIP20, StablecoinExchangeError, StablecoinExchangeEvents},
    },
};
use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256};
use revm::state::Bytecode;

/// Calculate quote amount from base amount and tick price using checked arithmetic
///
/// Returns None if overflow would occur
fn calculate_quote_amount(amount: u128, tick: i16) -> Option<u128> {
    let price = tick_to_price(tick) as u128;
    amount.checked_mul(price)?.checked_div(PRICE_SCALE as u128)
}

pub struct StablecoinExchange<'a, S: StorageProvider> {
    address: Address,
    storage: &'a mut S,
}

impl<'a, S: StorageProvider> StablecoinExchange<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            address: STABLECOIN_EXCHANGE_ADDRESS,
            storage,
        }
    }

    /// Initializes the contract
    ///
    /// This ensures the [`StablecoinExchange`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) {
        // must ensure the account is not empty, by setting some code
        self.storage
            .set_code(
                self.address,
                Bytecode::new_legacy(Bytes::from_static(&[0xef])),
            )
            .expect("TODO: handle error");
    }

    /// Read pending order ID
    fn get_pending_order_id(&mut self) -> u128 {
        self.storage
            .sload(self.address, slots::PENDING_ORDER_ID)
            .expect("Storage read failed")
            .to::<u128>()
    }

    /// Set pending order ID
    fn set_pending_order_id(&mut self, order_id: u128) {
        self.storage
            .sstore(self.address, slots::PENDING_ORDER_ID, U256::from(order_id))
            .expect("Storage write failed");
    }

    /// Read active order ID
    fn get_active_order_id(&mut self) -> u128 {
        self.storage
            .sload(self.address, slots::ACTIVE_ORDER_ID)
            .expect("Storage read failed")
            .to::<u128>()
    }

    /// Set active order ID
    fn set_active_order_id(&mut self, order_id: u128) {
        self.storage
            .sstore(self.address, slots::ACTIVE_ORDER_ID, U256::from(order_id))
            .expect("Storage write failed");
    }

    /// Increment and return the pending order id
    fn increment_pending_order_id(&mut self) -> u128 {
        let next_id = self.get_pending_order_id() + 1;
        self.set_pending_order_id(next_id);
        next_id
    }

    /// Get user's balance for a specific token
    pub fn balance_of(&mut self, user: Address, token: Address) -> u128 {
        let user_slot = mapping_slot(user.as_slice(), slots::BALANCES);
        let balance_slot = mapping_slot(token.as_slice(), user_slot);

        self.storage
            .sload(self.address, balance_slot)
            .expect("TODO: handle error")
            .to::<u128>()
    }

    /// Fetch order from storage. If the order is currently pending or filled, this function returns
    /// `StablecoinExchangeError::OrderDoesNotExist`   
    pub fn get_order(&mut self, order_id: u128) -> Result<Order, StablecoinExchangeError> {
        let order = Order::from_storage(order_id, self.storage, self.address);

        // If the order is not filled and currently active
        if !order.maker().is_zero() && order.order_id() <= self.get_active_order_id() {
            Ok(order)
        } else {
            Err(StablecoinExchangeError::order_does_not_exist())
        }
    }

    /// Set user's balance for a specific token
    fn set_balance(&mut self, user: Address, token: Address, amount: u128) {
        let user_slot = mapping_slot(user.as_slice(), slots::BALANCES);
        let balance_slot = mapping_slot(token.as_slice(), user_slot);

        self.storage
            .sstore(self.address, balance_slot, U256::from(amount))
            .expect("TODO: handle error");
    }

    /// Add to user's balance
    fn increment_balance(&mut self, user: Address, token: Address, amount: u128) {
        let current = self.balance_of(user, token);
        self.set_balance(user, token, current + amount);
    }

    /// Subtract from user's balance
    fn sub_balance(&mut self, user: Address, token: Address, amount: u128) {
        let current = self.balance_of(user, token);
        self.set_balance(user, token, current.saturating_sub(amount));
    }

    /// Transfer tokens, accounting for linking USD
    fn transfer(
        &mut self,
        token: Address,
        to: Address,
        amount: u128,
    ) -> Result<(), StablecoinExchangeError> {
        if token == LINKING_USD_ADDRESS {
            LinkingUSD::new(self.storage)
                .transfer(
                    &self.address,
                    ITIP20::transferCall {
                        to,
                        amount: U256::from(amount),
                    },
                )
                .map_err(|_| StablecoinExchangeError::insufficient_balance())?;
        } else {
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage)
                .transfer(
                    &self.address,
                    ITIP20::transferCall {
                        to,
                        amount: U256::from(amount),
                    },
                )
                .map_err(|_| StablecoinExchangeError::insufficient_balance())?;
        }
        Ok(())
    }

    /// Transfer tokens from user, accounting for linking USD
    fn transfer_from(
        &mut self,
        token: Address,
        from: Address,
        amount: u128,
    ) -> Result<(), StablecoinExchangeError> {
        if token == LINKING_USD_ADDRESS {
            LinkingUSD::new(self.storage)
                .transfer_from(
                    &self.address,
                    ITIP20::transferFromCall {
                        from,
                        to: self.address,
                        amount: U256::from(amount),
                    },
                )
                // TODO: propagate TIP20 errors
                .map_err(|_| StablecoinExchangeError::insufficient_balance())?;
        } else {
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage)
                .transfer_from(
                    &self.address,
                    ITIP20::transferFromCall {
                        from,
                        to: self.address,
                        amount: U256::from(amount),
                    },
                )
                // TODO: propagate TIP20 errors
                .map_err(|_| StablecoinExchangeError::insufficient_balance())?;
        }
        Ok(())
    }

    /// Decrement user's internal balance or transfer from external wallet
    fn decrement_balance_or_transfer_from(
        &mut self,
        user: Address,
        token: Address,
        amount: u128,
    ) -> Result<(), StablecoinExchangeError> {
        let user_balance = self.balance_of(user, token);
        if user_balance >= amount {
            self.sub_balance(user, token, amount);
        } else {
            self.set_balance(user, token, 0);
            let remaining = amount - user_balance;
            self.transfer_from(token, user, remaining)?;
        }
        Ok(())
    }

    pub fn quote_swap_exact_amount_out(
        &mut self,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let book_key = compute_book_key(token_in, token_out);
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address);

        if orderbook.base == Address::ZERO {
            return Err(StablecoinExchangeError::pair_does_not_exist());
        }

        let base_for_quote = token_in == orderbook.base;
        self.quote_exact_out(book_key, amount_out, base_for_quote)
    }

    pub fn quote_swap_exact_amount_in(
        &mut self,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let book_key = compute_book_key(token_in, token_out);
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address);

        if orderbook.base == Address::ZERO {
            return Err(StablecoinExchangeError::pair_does_not_exist());
        }

        let base_for_quote = token_in == orderbook.base;
        self.quote_exact_in(book_key, amount_in, base_for_quote)
    }

    pub fn swap_exact_amount_in(
        &mut self,
        sender: &Address,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let book_key = compute_book_key(token_in, token_out);
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address);

        if orderbook.base == Address::ZERO {
            return Err(StablecoinExchangeError::pair_does_not_exist());
        }

        let base_for_quote = token_in == orderbook.base;
        let amount_out =
            self.fill_orders_exact_in(book_key, base_for_quote, amount_in, min_amount_out)?;

        self.decrement_balance_or_transfer_from(*sender, token_in, amount_in)?;
        self.transfer(token_out, *sender, amount_out)?;

        Ok(amount_out)
    }

    pub fn swap_exact_amount_out(
        &mut self,
        sender: &Address,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
        max_amount_in: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let book_key = compute_book_key(token_in, token_out);
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address);

        if orderbook.base == Address::ZERO {
            return Err(StablecoinExchangeError::pair_does_not_exist());
        }

        let base_for_quote = token_in == orderbook.base;
        let amount_in =
            self.fill_orders_exact_out(book_key, base_for_quote, amount_out, max_amount_in)?;

        self.decrement_balance_or_transfer_from(*sender, token_in, amount_in)?;
        self.transfer(token_out, *sender, amount_out)?;

        Ok(amount_in)
    }

    /// Generate deterministic key for token pair
    pub fn pair_key(&self, token_a: Address, token_b: Address) -> B256 {
        compute_book_key(token_a, token_b)
    }

    /// Get price level information
    pub fn get_price_level(&mut self, base: Address, tick: i16, is_bid: bool) -> PriceLevel {
        let quote =
            TIP20Token::new(address_to_token_id_unchecked(&base), self.storage).quote_token();
        let key = compute_book_key(base, quote);
        PriceLevel::from_storage(self.storage, self.address, key, tick, is_bid)
    }

    /// Get active order ID
    pub fn active_order_id(&mut self) -> u128 {
        self.storage
            .sload(self.address, slots::ACTIVE_ORDER_ID)
            .expect("TODO: handle error")
            .to::<u128>()
    }

    /// Get pending order ID
    pub fn pending_order_id(&mut self) -> u128 {
        self.storage
            .sload(self.address, slots::PENDING_ORDER_ID)
            .expect("TODO: handle error")
            .to::<u128>()
    }

    pub fn create_pair(&mut self, base: &Address) -> Result<B256, StablecoinExchangeError> {
        let quote =
            TIP20Token::new(address_to_token_id_unchecked(base), self.storage).quote_token();

        let book_key = compute_book_key(*base, quote);

        if Orderbook::exists(book_key, self.storage, self.address) {
            return Err(StablecoinExchangeError::pair_already_exists());
        }

        let book = Orderbook::new(*base, quote);
        book.store(self.storage, self.address);

        // Emit PairCreated event
        self.storage
            .emit_event(
                self.address,
                StablecoinExchangeEvents::PairCreated(IStablecoinExchange::PairCreated {
                    key: book_key,
                    base: *base,
                    quote,
                })
                .into_log_data(),
            )
            .expect("Event emission failed");

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
        sender: &Address,
        token: Address,
        amount: u128,
        is_bid: bool,
        tick: i16,
    ) -> Result<u128, StablecoinExchangeError> {
        // Lookup quote token from TIP20 token
        let quote_token =
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage).quote_token();

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);
        let book = Orderbook::from_storage(book_key, self.storage, self.address);
        if book.base.is_zero() {
            return Err(StablecoinExchangeError::pair_does_not_exist());
        }

        // Validate tick is within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(tick));
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount) = if is_bid {
            // For bids, escrow quote tokens based on price
            let quote_amount = calculate_quote_amount(amount, tick)
                .ok_or(StablecoinExchangeError::insufficient_balance())?;
            (quote_token, quote_amount)
        } else {
            // For asks, escrow base tokens
            (token, amount)
        };

        // Debit from user's balance or transfer from wallet
        self.decrement_balance_or_transfer_from(*sender, escrow_token, escrow_amount)?;

        // Create the order
        let order_id = self.increment_pending_order_id();
        let order = if is_bid {
            Order::new_bid(order_id, *sender, book_key, amount, tick)
        } else {
            Order::new_ask(order_id, *sender, book_key, amount, tick)
        };

        // Store in pending queue. Orders are stored as a DLL at each tick level and are initially
        // stored without a prev or next pointer. This is considered a "pending" order. Once `execute_block` is called, orders are
        // linked and then considered "active"
        order.store(self.storage, self.address);

        // Emit OrderPlaced event
        self.storage
            .emit_event(
                self.address,
                StablecoinExchangeEvents::OrderPlaced(IStablecoinExchange::OrderPlaced {
                    orderId: order_id,
                    maker: *sender,
                    token,
                    amount,
                    isBid: is_bid,
                    tick,
                })
                .into_log_data(),
            )
            .expect("Event emission failed");

        Ok(order_id)
    }

    /// Place a flip order that auto-flips when filled
    ///
    /// Flip orders automatically create a new order on the opposite side when completely filled.
    /// For bids: flip_tick must be > tick
    /// For asks: flip_tick must be < tick
    pub fn place_flip(
        &mut self,
        sender: &Address,
        token: Address,
        amount: u128,
        is_bid: bool,
        tick: i16,
        flip_tick: i16,
    ) -> Result<u128, StablecoinExchangeError> {
        // Lookup quote token from TIP20 token
        let quote_token =
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage).quote_token();

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);

        // Validate tick and flip_tick are within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(tick));
        }
        if !(MIN_TICK..=MAX_TICK).contains(&flip_tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(flip_tick));
        }

        // Validate flip_tick relationship to tick based on order side
        if (is_bid && flip_tick <= tick) || (!is_bid && flip_tick >= tick) {
            return Err(StablecoinExchangeError::invalid_flip_tick());
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount) = if is_bid {
            // For bids, escrow quote tokens based on price
            let quote_amount = calculate_quote_amount(amount, tick)
                .ok_or(StablecoinExchangeError::insufficient_balance())?;
            (quote_token, quote_amount)
        } else {
            // For asks, escrow base tokens
            (token, amount)
        };

        // Debit from user's balance or transfer from wallet
        self.decrement_balance_or_transfer_from(*sender, escrow_token, escrow_amount)?;

        // Create the flip order
        let order_id = self.increment_pending_order_id();
        let order = Order::new_flip(order_id, *sender, book_key, amount, tick, is_bid, flip_tick)
            .expect("Invalid flip tick");

        // Store in pending queue
        order.store(self.storage, self.address);

        // Emit FlipOrderPlaced event
        self.storage
            .emit_event(
                self.address,
                StablecoinExchangeEvents::FlipOrderPlaced(IStablecoinExchange::FlipOrderPlaced {
                    orderId: order_id,
                    maker: *sender,
                    token,
                    amount,
                    isBid: is_bid,
                    tick,
                    flipTick: flip_tick,
                })
                .into_log_data(),
            )
            .expect("Event emission failed");

        Ok(order_id)
    }

    /// Process all pending orders into the active orderbook
    ///
    /// Only callable by the protocol via system transaction (sender must be Address::ZERO)
    pub fn execute_block(&mut self, sender: &Address) -> Result<(), StablecoinExchangeError> {
        // Only protocol can call this
        if *sender != Address::ZERO {
            return Err(StablecoinExchangeError::unauthorized());
        }

        let next_order_id = self
            .storage
            .sload(self.address, slots::ACTIVE_ORDER_ID)
            .expect("TODO: handle error")
            .to::<u128>();

        let pending_order_id = self.get_pending_order_id();

        let mut current_order_id = next_order_id + 1;
        while current_order_id <= pending_order_id {
            self.process_pending_order(current_order_id);
            current_order_id += 1;
        }

        self.set_active_order_id(pending_order_id);

        Ok(())
    }

    /// Process a single pending order into the active orderbook
    fn process_pending_order(&mut self, order_id: u128) {
        let order = Order::from_storage(order_id, self.storage, self.address);

        // If the order is already canceled, return early
        if order.maker().is_zero() {
            return;
        }

        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address);
        let mut level = PriceLevel::from_storage(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
        );

        let prev_tail = level.tail;
        if prev_tail == 0 {
            level.head = order_id;
            level.tail = order_id;

            let mut bitmap =
                orderbook::TickBitmap::new(self.storage, self.address, order.book_key());
            bitmap
                .set_tick_bit(order.tick(), order.is_bid())
                .expect("Tick is valid");

            if order.is_bid() {
                if order.tick() > orderbook.best_bid_tick {
                    orderbook::Orderbook::update_best_bid_tick(
                        self.storage,
                        self.address,
                        order.book_key(),
                        order.tick(),
                    );
                }
            } else if order.tick() < orderbook.best_ask_tick {
                orderbook::Orderbook::update_best_ask_tick(
                    self.storage,
                    self.address,
                    order.book_key(),
                    order.tick(),
                );
            }
        } else {
            Order::update_next_order(prev_tail, order_id, self.storage, self.address);
            Order::update_prev_order(order_id, prev_tail, self.storage, self.address);
            level.tail = order_id;
        }

        level.total_liquidity += order.remaining();
        level.store(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
        );
    }

    /// Partially fill an order with the specified amount.
    /// Fill amount is denominated in base token
    fn partial_fill_order(
        &mut self,
        order: &mut Order,
        level: &mut PriceLevel,
        fill_amount: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address);
        let price = tick_to_price(order.tick());

        // Update order remaining amount
        let new_remaining = order.remaining() - fill_amount;
        order.update_remaining(new_remaining, self.storage, self.address);

        if order.is_bid() {
            self.increment_balance(order.maker(), orderbook.base, fill_amount);
        } else {
            let quote_amount = (fill_amount * price as u128) / orderbook::PRICE_SCALE as u128;
            self.increment_balance(order.maker(), orderbook.quote, quote_amount);
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
        PriceLevel::update_total_liquidity(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
            level.total_liquidity - fill_amount,
        );

        // Emit OrderFilled event for partial fill
        self.storage
            .emit_event(
                self.address,
                StablecoinExchangeEvents::OrderFilled(IStablecoinExchange::OrderFilled {
                    orderId: order.order_id(),
                    maker: order.maker(),
                    amountFilled: fill_amount,
                    partialFill: true,
                })
                .into_log_data(),
            )
            .expect("Event emission failed");

        Ok(amount_out)
    }

    /// Fill an order and delete from storage. Returns the next best order and price level.
    fn fill_order(
        &mut self,
        book_key: B256,
        order: &mut Order,
        mut level: PriceLevel,
    ) -> Result<(u128, Option<(PriceLevel, Order)>), StablecoinExchangeError> {
        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address);
        let price = tick_to_price(order.tick());
        let fill_amount = order.remaining();

        let amount_out = if order.is_bid() {
            self.increment_balance(order.maker(), orderbook.base, fill_amount);
            fill_amount
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("Amount out calculation overflow")
        } else {
            let quote_amount = fill_amount
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("Amount out calculation overflow");
            self.increment_balance(order.maker(), orderbook.quote, quote_amount);

            fill_amount
        };

        // Emit OrderFilled event for complete fill
        self.storage
            .emit_event(
                self.address,
                StablecoinExchangeEvents::OrderFilled(IStablecoinExchange::OrderFilled {
                    orderId: order.order_id(),
                    maker: order.maker(),
                    amountFilled: fill_amount,
                    partialFill: false,
                })
                .into_log_data(),
            )
            .expect("Event emission failed");

        if order.is_flip() {
            // Create a new flip order with flipped side and swapped ticks
            // Bid becomes Ask, Ask becomes Bid
            // The current tick becomes the new flip_tick, and flip_tick becomes the new tick
            let _ = self.place_flip(
                &order.maker(),
                orderbook.base,
                order.amount(),
                !order.is_bid(),
                order.flip_tick(),
                order.tick(),
            );
        }

        // Delete the filled order
        order.delete(self.storage, self.address);

        // Advance tick if liquidity is exhausted
        let next_tick_info = if order.next() == 0 {
            level.delete(
                self.storage,
                self.address,
                book_key,
                order.tick(),
                order.is_bid(),
            );

            let mut bitmap =
                orderbook::TickBitmap::new(self.storage, self.address, order.book_key());
            bitmap
                .clear_tick_bit(order.tick(), order.is_bid())
                .expect("Tick is valid");

            let (tick, has_liquidity) = if order.is_bid() {
                next_initialized_bid_tick(self.storage, self.address, book_key, order.tick())
            } else {
                next_initialized_ask_tick(self.storage, self.address, book_key, order.tick())
            };

            if !has_liquidity {
                // No more liquidity at better prices - return None to signal completion
                None
            } else {
                let new_level = PriceLevel::from_storage(
                    self.storage,
                    self.address,
                    book_key,
                    tick,
                    order.is_bid(),
                );
                let new_order = Order::from_storage(new_level.head, self.storage, self.address);

                Some((new_level, new_order))
            }
        } else {
            // If there are subsequent orders at tick, advance to next order
            level.head = order.next();
            level.total_liquidity -= fill_amount;
            level.store(
                self.storage,
                self.address,
                order.book_key(),
                order.tick(),
                order.is_bid(),
            );

            let new_order = Order::from_storage(order.next(), self.storage, self.address);
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
        max_amount_in: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = Order::from_storage(level.head, self.storage, self.address);

        let mut total_amount_in = 0;
        while amount_out > 0 {
            let price = tick_to_price(order.tick());
            let fill_amount = amount_out.min(order.remaining());
            let amount_in = if bid {
                fill_amount
            } else {
                fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Input needed calculation overflow")
            };

            if total_amount_in + amount_in > max_amount_in {
                return Err(StablecoinExchangeError::max_input_exceeded());
            }

            if fill_amount < order.remaining() {
                self.partial_fill_order(&mut order, &mut level, fill_amount)?;
                total_amount_in += amount_in;
                break;
            } else {
                let (amount_out_received, next_order_info) =
                    self.fill_order(book_key, &mut order, level)?;
                total_amount_in += amount_in;
                amount_out -= amount_out_received;

                if let Some((new_level, new_order)) = next_order_info {
                    level = new_level;
                    order = new_order;
                } else {
                    if amount_out > 0 {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
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
        min_amount_out: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = Order::from_storage(level.head, self.storage, self.address);

        let mut total_amount_out = 0;
        while amount_in > 0 {
            if amount_in < order.remaining() {
                let amount_out = self.partial_fill_order(&mut order, &mut level, amount_in)?;
                total_amount_out += amount_out;
                break;
            } else {
                amount_in -= order.remaining();

                let (amount_out, next_order_info) = self.fill_order(book_key, &mut order, level)?;
                total_amount_out += amount_out;

                if let Some((new_level, new_order)) = next_order_info {
                    level = new_level;
                    order = new_order;
                } else {
                    break;
                }
            }
        }

        if total_amount_out < min_amount_out {
            return Err(StablecoinExchangeError::insufficient_output());
        }

        Ok(total_amount_out)
    }

    /// Helper function to get best tick from orderbook
    fn get_best_price_level(
        &mut self,
        book_key: B256,
        bid: bool,
    ) -> Result<PriceLevel, StablecoinExchangeError> {
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address);

        let current_tick = if bid {
            if orderbook.best_bid_tick == i16::MIN {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }
            orderbook.best_bid_tick
        } else {
            if orderbook.best_ask_tick == i16::MAX {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }
            orderbook.best_ask_tick
        };

        let level =
            PriceLevel::from_storage(self.storage, self.address, book_key, current_tick, bid);

        Ok(level)
    }

    /// Cancel an order and refund tokens to maker
    /// Only the order maker can cancel their own order
    pub fn cancel(
        &mut self,
        sender: &Address,
        order_id: u128,
    ) -> Result<(), StablecoinExchangeError> {
        let order = Order::from_storage(order_id, self.storage, self.address);

        if order.maker().is_zero() {
            return Err(StablecoinExchangeError::order_does_not_exist());
        }

        if order.maker() != *sender {
            return Err(StablecoinExchangeError::unauthorized());
        }

        if order.remaining() == 0 {
            return Err(StablecoinExchangeError::order_does_not_exist());
        }

        // Check if the order is still pending (not yet in active orderbook)
        let next_order_id = self
            .storage
            .sload(self.address, slots::ACTIVE_ORDER_ID)
            .expect("TODO: handle error")
            .to::<u128>();

        if order.order_id() > next_order_id {
            self.cancel_pending_order(order)
        } else {
            self.cancel_active_order(order)
        }
    }

    /// Cancel a pending order (not yet in the active orderbook)
    fn cancel_pending_order(&mut self, order: Order) -> Result<(), StablecoinExchangeError> {
        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address);
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
        self.increment_balance(order.maker(), token, refund_amount);

        // Clear the order from storage
        order.delete(self.storage, self.address);

        // Emit OrderCancelled event
        self.storage
            .emit_event(
                self.address,
                StablecoinExchangeEvents::OrderCancelled(IStablecoinExchange::OrderCancelled {
                    orderId: order.order_id(),
                })
                .into_log_data(),
            )
            .expect("Event emission failed");

        Ok(())
    }

    /// Cancel an active order (already in the orderbook)
    fn cancel_active_order(&mut self, order: Order) -> Result<(), StablecoinExchangeError> {
        let mut level = PriceLevel::from_storage(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
        );

        // Update linked list
        if order.prev() != 0 {
            Order::update_next_order(order.prev(), order.next(), self.storage, self.address);
        } else {
            level.head = order.next();
        }

        if order.next() != 0 {
            Order::update_prev_order(order.next(), order.prev(), self.storage, self.address);
        } else {
            level.tail = order.prev();
        }

        // Update level liquidity
        level.total_liquidity -= order.remaining();

        // If this was the last order at this tick, clear the bitmap bit
        if level.head == 0 {
            let mut bitmap =
                orderbook::TickBitmap::new(self.storage, self.address, order.book_key());
            bitmap
                .clear_tick_bit(order.tick(), order.is_bid())
                .expect("Tick is valid");
        }

        level.store(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
        );

        // Refund tokens to maker
        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address);
        if order.is_bid() {
            // Bid orders are in quote token, refund quote amount
            let price = orderbook::tick_to_price(order.tick());
            let quote_amount = order
                .remaining()
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("Quote amount calculation overflow");
            self.increment_balance(order.maker(), orderbook.quote, quote_amount);
        } else {
            // Ask orders are in base token, refund base amount
            self.increment_balance(order.maker(), orderbook.base, order.remaining());
        }

        // Clear the order from storage
        order.delete(self.storage, self.address);

        // Emit OrderCancelled event
        self.storage
            .emit_event(
                self.address,
                StablecoinExchangeEvents::OrderCancelled(IStablecoinExchange::OrderCancelled {
                    orderId: order.order_id(),
                })
                .into_log_data(),
            )
            .expect("Event emission failed");

        Ok(())
    }

    /// Withdraw tokens from exchange balance
    pub fn withdraw(
        &mut self,
        user: Address,
        token: Address,
        amount: u128,
    ) -> Result<(), StablecoinExchangeError> {
        let current_balance = self.balance_of(user, token);
        if current_balance < amount {
            return Err(StablecoinExchangeError::insufficient_balance());
        }
        self.sub_balance(user, token, amount);
        self.transfer(token, user, amount)?;

        Ok(())
    }

    /// Quote exact output amount without executing trades
    fn quote_exact_out(
        &mut self,
        book_key: B256,
        amount_out: u128,
        is_bid: bool,
    ) -> Result<u128, StablecoinExchangeError> {
        let mut remaining_out = amount_out;
        let mut amount_in = 0u128;
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address);

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };
        if current_tick == i16::MIN {
            return Err(StablecoinExchangeError::insufficient_liquidity());
        }

        while remaining_out > 0 {
            let level = PriceLevel::from_storage(
                self.storage,
                self.address,
                book_key,
                current_tick,
                is_bid,
            );

            // If no liquidity at this level, move to next tick
            if level.total_liquidity == 0 {
                let (next_tick, initialized) = if is_bid {
                    orderbook::next_initialized_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    )
                } else {
                    orderbook::next_initialized_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    )
                };
                if !initialized {
                    return Err(StablecoinExchangeError::insufficient_liquidity());
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
                    .expect("Base needed calculation overflow");
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
                    .expect("Quote needed calculation overflow");
                (fill_amount, quote_needed)
            };

            let amount_out_tick = if is_bid {
                fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Amount out calculation overflow")
            } else {
                fill_amount
            };

            remaining_out -= amount_out_tick;
            amount_in += amount_in_tick;

            // If we exhausted this level or filled our requirement, move to next tick
            if fill_amount == level.total_liquidity {
                let (next_tick, initialized) = if is_bid {
                    orderbook::next_initialized_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    )
                } else {
                    orderbook::next_initialized_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    )
                };
                if !initialized && remaining_out > 0 {
                    return Err(StablecoinExchangeError::insufficient_liquidity());
                }
                current_tick = next_tick;
            } else {
                break;
            }
        }

        Ok(amount_in)
    }

    /// Quote exact input amount without executing trades
    fn quote_exact_in(
        &mut self,
        book_key: B256,
        amount_in: u128,
        is_bid: bool,
    ) -> Result<u128, StablecoinExchangeError> {
        let mut remaining_in = amount_in;
        let mut amount_out = 0u128;
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address);

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };

        if current_tick == i16::MIN {
            return Err(StablecoinExchangeError::insufficient_liquidity());
        }

        while remaining_in > 0 {
            let level = PriceLevel::from_storage(
                self.storage,
                self.address,
                book_key,
                current_tick,
                is_bid,
            );

            // If no liquidity at this level, move to next tick
            if level.total_liquidity == 0 {
                let (next_tick, initialized) = if is_bid {
                    orderbook::next_initialized_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    )
                } else {
                    orderbook::next_initialized_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    )
                };
                if !initialized {
                    return Err(StablecoinExchangeError::insufficient_liquidity());
                }
                current_tick = next_tick;
                continue;
            }

            let price = orderbook::tick_to_price(current_tick);

            let fill_amount = if remaining_in > level.total_liquidity {
                level.total_liquidity
            } else {
                remaining_in
            };
            let amount_out_tick = fill_amount
                .checked_mul(price as u128)
                .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                .expect("Amount out calculation overflow");

            remaining_in -= fill_amount;
            amount_out += amount_out_tick;

            // If we exhausted this level, move to next tick
            if fill_amount == level.total_liquidity {
                let (next_tick, initialized) = if is_bid {
                    orderbook::next_initialized_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    )
                } else {
                    orderbook::next_initialized_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    )
                };
                if !initialized && remaining_in > 0 {
                    return Err(StablecoinExchangeError::insufficient_liquidity());
                }
                current_tick = next_tick;
            } else {
                break;
            }
        }

        Ok(amount_out)
    }
}

impl<'a, S: StorageProvider> StorageOps for StablecoinExchange<'a, S> {
    fn sstore(&mut self, slot: U256, value: U256) {
        self.storage
            .sstore(self.address, slot, value)
            .expect("Storage operation failed");
    }

    fn sload(&mut self, slot: U256) -> U256 {
        self.storage
            .sload(self.address, slot)
            .expect("Storage operation failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        HashMapStorageProvider, LinkingUSD, linking_usd, tip20, types::StablecoinExchangeError,
    };

    fn setup_test_tokens<S: StorageProvider>(
        storage: &mut S,
        admin: &Address,
        user: &Address,
        exchange_address: Address,
        amount: u128,
    ) -> (Address, Address) {
        // Initialize quote token (LinkingUSD)
        let mut quote = LinkingUSD::new(storage);
        quote
            .initialize(admin)
            .expect("Quote token initialization failed");

        // Grant issuer role to admin for quote token
        let mut quote_roles = quote.get_roles_contract();
        quote_roles.grant_role_internal(admin, *tip20::ISSUER_ROLE);
        quote_roles.grant_role_internal(user, *linking_usd::TRANSFER_ROLE);

        // Mint tokens to user
        quote
            .mint(
                admin,
                ITIP20::mintCall {
                    to: *user,
                    amount: U256::from(amount),
                },
            )
            .expect("Quote mint failed");

        // Approve exchange to spend user's tokens
        quote
            .approve(
                user,
                ITIP20::approveCall {
                    spender: exchange_address,
                    amount: U256::from(amount),
                },
            )
            .expect("Quote approve failed");

        // Initialize base token  and mint amount
        let mut base = TIP20Token::new(1, quote.token.storage);
        base.initialize("BASE", "BASE", "USD", quote.token.token_address, admin)
            .expect("Base token initialization failed");

        let mut base_roles = base.get_roles_contract();
        base_roles.grant_role_internal(admin, *crate::contracts::tip20::ISSUER_ROLE);

        base.approve(
            user,
            ITIP20::approveCall {
                spender: exchange_address,
                amount: U256::from(amount),
            },
        )
        .expect("Base approve failed");

        base.mint(
            admin,
            ITIP20::mintCall {
                to: *user,
                amount: U256::from(amount),
            },
        )
        .expect("Base mint failed");

        (base.token_address, quote.token.token_address)
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
        for price in test_prices {
            let tick = orderbook::price_to_tick(price);
            let expected_tick = (price as i32 - orderbook::PRICE_SCALE as i32) as i16;
            assert_eq!(tick, expected_tick);
        }
    }

    #[test]
    fn test_place_order_pair_does_not_exist() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount = 1_000_000u128;
        let tick = 100i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, _quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            expected_escrow,
        );

        let result = exchange.place(&alice, base_token, amount, true, tick);
        assert_eq!(result, Err(StablecoinExchangeError::pair_does_not_exist()));
    }

    #[test]
    fn test_place_bid_order() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount = 1_000_000u128;
        let tick = 100i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens with enough balance for the escrow
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            expected_escrow,
        );

        // Create the pair before placing orders
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        // Place the bid order
        let order_id = exchange
            .place(&alice, base_token, amount, true, tick)
            .expect("Place bid order should succeed");

        assert_eq!(order_id, 1);
        assert_eq!(exchange.active_order_id(), 0);
        assert_eq!(exchange.pending_order_id(), 1);

        // Verify the order was stored correctly
        let stored_order = Order::from_storage(order_id, exchange.storage, exchange.address);
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.amount(), amount);
        assert_eq!(stored_order.remaining(), amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(stored_order.is_bid());
        assert!(!stored_order.is_flip());
        assert_eq!(stored_order.prev(), 0);
        assert_eq!(stored_order.next(), 0);

        // Verify the order is not yet in the active orderbook
        let book_key = compute_book_key(base_token, quote_token);
        let level =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, true);
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut quote_tip20 = TIP20Token::new(
                address_to_token_id_unchecked(&quote_token),
                exchange.storage,
            );
            let remaining_balance =
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice });
            assert_eq!(remaining_balance, U256::ZERO);

            // Verify exchange received the tokens
            let exchange_balance = quote_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            });
            assert_eq!(exchange_balance, U256::from(expected_escrow));
        }
    }

    #[test]
    fn test_place_ask_order() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount = 1_000_000u128;
        let tick = 50i16; // Use positive tick to avoid conversion issues

        // Setup tokens with enough base token balance for the order
        let (base_token, quote_token) =
            setup_test_tokens(exchange.storage, &admin, &alice, exchange.address, amount);
        // Create the pair before placing orders
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        let order_id = exchange
            .place(&alice, base_token, amount, false, tick) // is_bid = false for ask
            .expect("Place ask order should succeed");

        assert_eq!(order_id, 1);
        assert_eq!(exchange.active_order_id(), 0);
        assert_eq!(exchange.pending_order_id(), 1);

        // Verify the order was stored correctly
        let stored_order = Order::from_storage(order_id, exchange.storage, exchange.address);
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.amount(), amount);
        assert_eq!(stored_order.remaining(), amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(!stored_order.is_bid());
        assert!(!stored_order.is_flip());
        assert_eq!(stored_order.prev(), 0);
        assert_eq!(stored_order.next(), 0);

        let book_key = compute_book_key(base_token, quote_token);
        let level =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, false); // is_bid = false for ask
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut base_tip20 =
                TIP20Token::new(address_to_token_id_unchecked(&base_token), exchange.storage);
            let remaining_balance = base_tip20.balance_of(ITIP20::balanceOfCall { account: alice });
            assert_eq!(remaining_balance, U256::ZERO); // All tokens should be escrowed

            // Verify exchange received the base tokens
            let exchange_balance = base_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            });
            assert_eq!(exchange_balance, U256::from(amount));
        }
    }

    #[test]
    fn test_place_flip_order() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount = 1_000_000u128;
        let tick = 100i16;
        let flip_tick = 200i16; // Must be > tick for bid flip orders

        // Calculate escrow amount needed for bid
        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens with enough balance for the escrow
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            expected_escrow,
        );
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        let order_id = exchange
            .place_flip(&alice, base_token, amount, true, tick, flip_tick)
            .expect("Place flip bid order should succeed");

        assert_eq!(order_id, 1);
        assert_eq!(exchange.active_order_id(), 0);
        assert_eq!(exchange.pending_order_id(), 1);

        // Verify the order was stored correctly
        let stored_order = Order::from_storage(order_id, exchange.storage, exchange.address);
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.amount(), amount);
        assert_eq!(stored_order.remaining(), amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(stored_order.is_bid());
        assert!(stored_order.is_flip());
        assert_eq!(stored_order.flip_tick(), flip_tick);
        assert_eq!(stored_order.prev(), 0);
        assert_eq!(stored_order.next(), 0);

        // Verify the order is not yet in the active orderbook
        let book_key = compute_book_key(base_token, quote_token);
        let level =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, true);
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut quote_tip20 = TIP20Token::new(
                address_to_token_id_unchecked(&quote_token),
                exchange.storage,
            );
            let remaining_balance =
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice });
            assert_eq!(remaining_balance, U256::ZERO);

            // Verify exchange received the tokens
            let exchange_balance = quote_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address,
            });
            assert_eq!(exchange_balance, U256::from(expected_escrow));
        }
    }

    #[test]
    fn test_cancel_pending_order() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount = 1_000_000u128;
        let tick = 100i16;

        // Calculate escrow amount needed for bid
        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            expected_escrow,
        );

        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        // Place the bid order
        let order_id = exchange
            .place(&alice, base_token, amount, true, tick)
            .expect("Place bid order should succeed");

        // Verify order was placed and tokens were escrowed
        assert_eq!(exchange.balance_of(alice, quote_token), 0);

        let (alice_balance_before, exchange_balance_before) = {
            let mut quote_tip20 = TIP20Token::new(
                address_to_token_id_unchecked(&quote_token),
                exchange.storage,
            );

            (
                quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice }),
                quote_tip20.balance_of(ITIP20::balanceOfCall {
                    account: exchange.address,
                }),
            )
        };

        assert_eq!(alice_balance_before, U256::ZERO);
        assert_eq!(exchange_balance_before, U256::from(expected_escrow));

        // Cancel the pending order
        exchange
            .cancel(&alice, order_id)
            .expect("Cancel pending order should succeed");

        // Verify order was deleted
        let cancelled_order = Order::from_storage(order_id, exchange.storage, exchange.address);
        assert_eq!(cancelled_order.maker(), Address::ZERO);

        // Verify tokens were refunded to user's internal balance
        assert_eq!(exchange.balance_of(alice, quote_token), expected_escrow);
    }

    #[test]
    fn test_execute_block() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount = 1_000_000u128;
        let tick = 100i16;

        // Calculate escrow amount needed for both orders
        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens with enough balance for two orders
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            expected_escrow * 2,
        );

        // Create the pair
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        let order_id_0 = exchange
            .place(&alice, base_token, amount, true, tick)
            .expect("Swap should succeed");

        let order_id_1 = exchange
            .place(&alice, base_token, amount, true, tick)
            .expect("Swap should succeed");
        assert_eq!(order_id_0, 1);
        assert_eq!(order_id_1, 2);
        assert_eq!(exchange.active_order_id(), 0);
        assert_eq!(exchange.pending_order_id(), 2);

        // Verify orders are in pending state
        let order_1 = Order::from_storage(order_id_1, exchange.storage, exchange.address);
        let order_2 = Order::from_storage(order_id_1, exchange.storage, exchange.address);
        assert_eq!(order_1.prev(), 0);
        assert_eq!(order_1.next(), 0);
        assert_eq!(order_2.prev(), 0);
        assert_eq!(order_2.next(), 0);

        // Verify tick level is empty before execute_block
        let book_key = compute_book_key(base_token, quote_token);
        let level_before =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, true);
        assert_eq!(level_before.head, 0);
        assert_eq!(level_before.tail, 0);
        assert_eq!(level_before.total_liquidity, 0);

        // Execute block and assert that orders have been linked
        exchange
            .execute_block(&Address::ZERO)
            .expect("Execute block should succeed");

        assert_eq!(exchange.active_order_id(), 2);
        assert_eq!(exchange.pending_order_id(), 2);

        let order_0 = Order::from_storage(order_id_0, exchange.storage, exchange.address);
        let order_1 = Order::from_storage(order_id_1, exchange.storage, exchange.address);
        assert_eq!(order_0.prev(), 0);
        assert_eq!(order_0.next(), order_1.order_id());
        assert_eq!(order_1.prev(), order_0.order_id());
        assert_eq!(order_1.next(), 0);

        // Assert tick level is updated
        let level_after =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, true);
        assert_eq!(level_after.head, order_0.order_id());
        assert_eq!(level_after.tail, order_1.order_id());
        assert_eq!(level_after.total_liquidity, amount * 2);

        // Verify orderbook best bid tick is updated
        let orderbook = Orderbook::from_storage(book_key, exchange.storage, exchange.address);
        assert_eq!(orderbook.best_bid_tick, tick);
    }

    #[test]
    fn test_execute_block_unauthorized() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let result = exchange.execute_block(&Address::random());
        assert_eq!(result, Err(StablecoinExchangeError::unauthorized()));
    }

    #[test]
    fn test_withdraw() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount = 1_000_000u128;
        let tick = 100i16;
        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        // Setup tokens
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            expected_escrow,
        );
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        // Place the bid order and cancel
        let order_id = exchange
            .place(&alice, base_token, amount, true, tick)
            .expect("Place bid order should succeed");

        exchange
            .cancel(&alice, order_id)
            .expect("Cancel pending order should succeed");

        assert_eq!(exchange.balance_of(alice, quote_token), expected_escrow);

        // Get balances before withdrawal
        exchange
            .withdraw(alice, quote_token, expected_escrow)
            .expect("Withdraw should succeed");
        assert_eq!(exchange.balance_of(alice, quote_token), 0);

        // Verify wallet balances changed correctly
        let mut quote_tip20 = TIP20Token::new(
            address_to_token_id_unchecked(&quote_token),
            exchange.storage,
        );

        assert_eq!(
            quote_tip20.balance_of(ITIP20::balanceOfCall { account: alice }),
            expected_escrow
        );
        assert_eq!(
            quote_tip20.balance_of(ITIP20::balanceOfCall {
                account: exchange.address
            }),
            0
        );
    }

    #[test]
    fn test_withdraw_insufficient_balance() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();

        let (_base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            1_000_000u128,
        );

        // Alice has 0 balance on the exchange
        assert_eq!(exchange.balance_of(alice, quote_token), 0);

        // Try to withdraw more than balance
        let result = exchange.withdraw(alice, quote_token, 100u128);

        assert_eq!(result, Err(StablecoinExchangeError::insufficient_balance()));
    }

    #[test]
    fn test_quote_swap_exact_amount_out() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount_out = 500_000u128;
        let tick = 1;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            2_000_000u128,
        );
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        let order_amount = 1_000_000u128;
        exchange
            .place(&alice, base_token, order_amount, false, tick)
            .expect("Order should succeed");

        exchange
            .execute_block(&Address::ZERO)
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
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount_in = 500_000u128;
        let tick = 1;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            2_000_000u128,
        );
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        let order_amount = 1_000_000u128;
        exchange
            .place(&alice, base_token, order_amount, true, tick)
            .expect("Place bid order should succeed");

        exchange
            .execute_block(&Address::ZERO)
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
        exchange.initialize();

        let alice = Address::random();
        let admin = Address::random();
        let amount_out = 500_000u128;
        let tick = 0;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            2_000_000u128,
        );
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        // Alice places a bid: willing to BUY base using quote
        let order_amount = 1_000_000u128;
        exchange
            .place(&alice, base_token, order_amount, true, tick)
            .expect("Place bid order should succeed");

        exchange
            .execute_block(&Address::ZERO)
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
    fn test_swap_exact_amount_out() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();
        let amount_out = 500_000u128;
        let tick = 1;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            2_000_000u128,
        );
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        let order_amount = 1_000_000u128;
        exchange
            .place(&alice, base_token, order_amount, false, tick)
            .expect("Order should succeed");

        exchange
            .execute_block(&Address::ZERO)
            .expect("Execute block should succeed");

        exchange.set_balance(bob, quote_token, 2_000_000u128);

        let price = orderbook::tick_to_price(tick);
        let max_amount_in = (amount_out * price as u128) / orderbook::PRICE_SCALE as u128;

        let amount_in = exchange
            .swap_exact_amount_out(&bob, quote_token, base_token, amount_out, max_amount_in)
            .expect("Swap should succeed");

        let mut base_tip20 =
            TIP20Token::new(address_to_token_id_unchecked(&base_token), exchange.storage);
        let bob_base_balance = base_tip20.balance_of(ITIP20::balanceOfCall { account: bob });
        assert_eq!(bob_base_balance, U256::from(amount_out));

        let alice_quote_exchange_balance = exchange.balance_of(alice, quote_token);
        assert_eq!(alice_quote_exchange_balance, amount_in);
    }

    #[test]
    fn test_swap_exact_amount_in() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();
        let amount_in = 500_000u128;
        let tick = 1;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            2_000_000u128,
        );
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        let order_amount = 1_000_000u128;
        exchange
            .place(&alice, base_token, order_amount, true, tick)
            .expect("Order should succeed");

        exchange
            .execute_block(&Address::ZERO)
            .expect("Execute block should succeed");

        exchange.set_balance(bob, base_token, 2_000_000u128);

        let price = orderbook::tick_to_price(tick);
        let min_amount_out = (amount_in * price as u128) / orderbook::PRICE_SCALE as u128;

        let amount_out = exchange
            .swap_exact_amount_in(&bob, base_token, quote_token, amount_in, min_amount_out)
            .expect("Swap should succeed");

        let mut quote_tip20 = TIP20Token::new(
            address_to_token_id_unchecked(&quote_token),
            exchange.storage,
        );
        let bob_quote_balance = quote_tip20.balance_of(ITIP20::balanceOfCall { account: bob });
        assert_eq!(bob_quote_balance, U256::from(amount_out));

        let alice_base_exchange_balance = exchange.balance_of(alice, base_token);
        assert_eq!(alice_base_exchange_balance, amount_in);
    }

    #[test]
    fn test_flip_order_execution() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let alice = Address::random();
        let bob = Address::random();
        let admin = Address::random();
        let amount = 1_000_000u128;
        let tick = 100i16;
        let flip_tick = 200i16;

        let price = orderbook::tick_to_price(tick);
        let expected_escrow = (amount * price as u128) / orderbook::PRICE_SCALE as u128;

        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            expected_escrow * 2,
        );
        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        // Place a flip bid order
        let flip_order_id = exchange
            .place_flip(&alice, base_token, amount, true, tick, flip_tick)
            .expect("Place flip order should succeed");

        exchange
            .execute_block(&Address::ZERO)
            .expect("Execute block should succeed");

        exchange.set_balance(bob, base_token, amount);

        exchange
            .swap_exact_amount_in(&bob, base_token, quote_token, amount, 0)
            .expect("Swap should succeed");

        // Assert that the order has filled
        let filled_order = Order::from_storage(flip_order_id, exchange.storage, exchange.address);
        assert_eq!(filled_order.maker(), Address::ZERO);

        let new_order_id = exchange.pending_order_id();
        assert_eq!(new_order_id, flip_order_id + 1);

        let new_order = Order::from_storage(new_order_id, exchange.storage, exchange.address);
        assert_eq!(new_order.maker(), alice);
        assert_eq!(new_order.tick(), flip_tick);
        assert_eq!(new_order.flip_tick(), tick);
        assert!(new_order.is_ask());
        assert_eq!(new_order.amount(), amount);
        assert_eq!(new_order.remaining(), amount);
    }

    #[test]
    fn test_pair_created() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize();

        let admin = Address::random();
        let alice = Address::random();

        // Setup tokens
        let (base_token, quote_token) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            1_000_000u128,
        );

        // Create the pair
        let key = exchange
            .create_pair(&base_token)
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
        exchange.initialize();

        let admin = Address::random();
        let alice = Address::random();

        // Setup tokens
        let (base_token, _) = setup_test_tokens(
            exchange.storage,
            &admin,
            &alice,
            exchange.address,
            1_000_000u128,
        );

        exchange
            .create_pair(&base_token)
            .expect("Could not create pair");

        let result = exchange.create_pair(&base_token);
        assert_eq!(result, Err(StablecoinExchangeError::pair_already_exists()));
    }
}
