//! Stablecoin DEX types and utilities.

pub mod error;
pub mod offsets;
pub mod order;
pub mod orderbook;
pub mod slots;

pub use error::OrderError;
pub use order::Order;
pub use orderbook::{
    MAX_TICK, MIN_TICK, Orderbook, PRICE_SCALE, TickBitmap, TickLevel, price_to_tick, tick_to_price,
};

use crate::{
    STABLECOIN_EXCHANGE_ADDRESS,
    contracts::{
        StorageProvider, TIP20Token, address_to_token_id_unchecked,
        storage::{StorageOps, slots::mapping_slot},
        types::{IStablecoinExchange, ITIP20, StablecoinExchangeError, StablecoinExchangeEvents},
    },
};
use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256, keccak256};
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

    /// Read pending order ID (last order placed but not yet processed)
    fn get_pending_order_id(&mut self) -> u128 {
        self.storage
            .sload(self.address, slots::PENDING_ORDER_ID)
            .expect("Storage read failed")
            .to::<u128>()
    }

    /// Get current pending order ID and increment for next use
    fn get_and_increment_pending_order_id(&mut self) -> u128 {
        let current = self.get_pending_order_id();
        let next_id = current + 1;
        self.storage
            .sstore(self.address, slots::PENDING_ORDER_ID, U256::from(next_id))
            .expect("Storage write failed");
        current
    }

    /// Compute deterministic book key from token pair
    /// Matches Solidity _pairKey function
    fn compute_book_key(&self, token_a: Address, token_b: Address) -> B256 {
        // Sort tokens to ensure deterministic key
        let (token_a, token_b) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };

        // Compute keccak256(abi.encodePacked(tokenA, tokenB))
        let mut buf = [0u8; 40];
        buf[..20].copy_from_slice(token_a.as_slice());
        buf[20..].copy_from_slice(token_b.as_slice());
        keccak256(buf)
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

impl<'a, S: StorageProvider> StablecoinExchange<'a, S> {
    /// Get user's balance for a specific token
    pub fn balance_of(&mut self, user: Address, token: Address) -> u128 {
        let user_slot = mapping_slot(user.as_slice(), slots::BALANCES);
        let balance_slot = mapping_slot(token.as_slice(), user_slot);

        self.storage
            .sload(self.address, balance_slot)
            .expect("TODO: handle error")
            .to::<u128>()
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
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage)
                .transfer_from(
                    &user,
                    ITIP20::transferFromCall {
                        from: user,
                        to: self.address,
                        amount: U256::from(remaining),
                    },
                )
                .map_err(|_| StablecoinExchangeError::insufficient_balance())?;
        }
        Ok(())
    }

    pub fn quote_buy(
        &mut self,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let book_key = self.compute_book_key(token_in, token_out);
        let orderbook = Orderbook::from_storage(self.storage, self.address, book_key);

        if orderbook.base == Address::ZERO {
            return Err(StablecoinExchangeError::insufficient_liquidity());
        }

        let base_for_quote = token_in == orderbook.base;
        self.quote_exact_out(book_key, base_for_quote, amount_out)
    }

    pub fn quote_sell(
        &mut self,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let book_key = self.compute_book_key(token_in, token_out);
        let orderbook = Orderbook::from_storage(self.storage, self.address, book_key);

        if orderbook.base == Address::ZERO {
            return Err(StablecoinExchangeError::insufficient_liquidity());
        }

        let base_for_quote = token_in == orderbook.base;
        self.quote_exact_in(book_key, base_for_quote, amount_in)
    }

    pub fn sell(
        &mut self,
        sender: &Address,
        token_in: Address,
        token_out: Address,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let book_key = self.compute_book_key(token_in, token_out);
        let orderbook = Orderbook::from_storage(self.storage, self.address, book_key);

        if orderbook.base == Address::ZERO {
            return Err(StablecoinExchangeError::insufficient_liquidity());
        }

        let base_for_quote = token_in == orderbook.base;
        let amount_out =
            self.fill_orders_exact_in(book_key, base_for_quote, amount_in, min_amount_out)?;

        self.decrement_balance_or_transfer_from(*sender, token_in, amount_in)?;
        self.increment_balance(*sender, token_out, amount_out);

        Ok(amount_out)
    }

    pub fn buy(
        &mut self,
        sender: &Address,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
        max_amount_in: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let book_key = self.compute_book_key(token_in, token_out);
        let orderbook = Orderbook::from_storage(self.storage, self.address, book_key);

        if orderbook.base == Address::ZERO {
            return Err(StablecoinExchangeError::insufficient_liquidity());
        }

        let base_for_quote = token_in == orderbook.base;
        let amount_in =
            self.fill_orders_exact_out(book_key, base_for_quote, amount_out, max_amount_in)?;

        self.decrement_balance_or_transfer_from(*sender, token_in, amount_in)?;
        self.increment_balance(*sender, token_out, amount_out);

        Ok(amount_in)
    }

    /// Generate deterministic key for token pair
    pub fn pair_key(&self, token_a: Address, token_b: Address) -> B256 {
        self.compute_book_key(token_a, token_b)
    }

    /// Get tick level information
    pub fn get_tick_level(&mut self, base: Address, tick: i16, is_bid: bool) -> (u128, u128, u128) {
        // For now, assume quote token is passed or use a default approach
        // This would need proper integration with TIP20 interface
        let quote = Address::ZERO; // TODO: Get from TIP20 interface
        let key = self.compute_book_key(base, quote);

        let level =
            orderbook::TickLevel::from_storage(self.storage, self.address, key, tick, is_bid);

        (level.head, level.tail, level.total_liquidity)
    }

    /// Get active order ID
    pub fn active_order_id(&mut self) -> u128 {
        self.storage
            .sload(self.address, slots::NEXT_ORDER_ID)
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

    /// Place a limit order on the orderbook
    ///
    /// Only supports placing an order on a pair between a token and its quote token.
    /// The order is queued in the pending queue and will be processed at end of block.
    ///
    /// # Arguments
    /// * `token` - The token to trade (not the linking token)
    /// * `amount` - Order amount in the token
    /// * `is_bid` - True for buy orders (using linking token to buy token), false for sell orders
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
        // Lookup quote token (linking token) from TIP20 token
        let quote_token =
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage).linking_token();

        // Compute book_key from token pair
        let book_key = self.compute_book_key(token, quote_token);

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
        let order_id = self.get_and_increment_pending_order_id();
        let order = if is_bid {
            Order::new_bid(order_id, *sender, book_key, amount, tick)
        } else {
            Order::new_ask(order_id, *sender, book_key, amount, tick)
        };

        // Store in pending queue. Orders are stored as a doubly-linked list at each tick level and are initially
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
        // Lookup quote token (linking token) from TIP20 token
        let quote_token =
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage).linking_token();

        // Compute book_key from token pair
        let book_key = self.compute_book_key(token, quote_token);

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

        // Create the flip order (with validation)
        let order_id = self.get_and_increment_pending_order_id();
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
            .sload(self.address, slots::NEXT_ORDER_ID)
            .expect("TODO: handle error")
            .to::<u128>();

        let pending_order_id = self.get_pending_order_id();

        let mut current_order_id = next_order_id + 1;
        while current_order_id <= pending_order_id {
            self.process_pending_order(current_order_id);
            current_order_id += 1;
        }

        self.storage
            .sstore(
                self.address,
                slots::NEXT_ORDER_ID,
                U256::from(pending_order_id),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    /// Process a single pending order into the active orderbook
    fn process_pending_order(&mut self, order_id: u128) {
        let order = Order::from_storage(order_id, self.storage, self.address);
        if order.maker().is_zero() {
            return;
        }

        let orderbook = Orderbook::from_storage(self.storage, self.address, order.book_key());
        let mut level = TickLevel::from_storage(
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

    /// Fill an order and handle cleanup when fully filled
    /// Returns the next order ID to process. If there is no more liquidity at the current tick,
    /// then, 0 will be returned instead.
    #[allow(dead_code)]
    fn fill_order(&mut self, order_id: u128, fill_amount: u128) -> u128 {
        let mut order = Order::from_storage(order_id, self.storage, self.address);
        let orderbook = Orderbook::from_storage(self.storage, self.address, order.book_key());
        let mut level = TickLevel::from_storage(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
        );

        let new_remaining = order.remaining() - fill_amount;
        order.update_remaining(new_remaining, self.storage, self.address);
        level.total_liquidity -= fill_amount;

        if order.is_bid() {
            self.increment_balance(order.maker(), orderbook.base, fill_amount);
        } else {
            let price = tick_to_price(order.tick());
            let quote_amount = (fill_amount * price as u128) / orderbook::PRICE_SCALE as u128;
            self.increment_balance(order.maker(), orderbook.quote, quote_amount);
        }

        if new_remaining == 0 {
            if order.is_flip() {
                // Create a new flip order with flipped side and swapped ticks
                // Bid becomes Ask, Ask becomes Bid
                // The current tick becomes the new flip_tick, and flip_tick becomes the new tick
                let new_order_id = self.get_and_increment_pending_order_id();

                let new_order = Order::new_flip(
                    new_order_id,
                    order.maker(),
                    order.book_key(),
                    order.amount(),
                    order.flip_tick(),
                    !order.is_bid(),
                    order.tick(),
                )
                .expect("TODO: error handling");

                new_order.store(self.storage, self.address);
            }

            if order.prev() != 0 {
                Order::update_next_order(order.prev(), order.next(), self.storage, self.address);
            } else {
                level.head = order.next();
            }

            if order.next() != 0 {
                Order::update_prev_order(
                    order.order_id(),
                    order.prev(),
                    self.storage,
                    self.address,
                );
            } else {
                level.tail = order.prev();
            }
            order.delete(self.storage, self.address);

            level.store(
                self.storage,
                self.address,
                order.book_key(),
                order.tick(),
                order.is_bid(),
            );

            if level.head == 0 {
                let mut bitmap =
                    orderbook::TickBitmap::new(self.storage, self.address, order.book_key());
                bitmap
                    .clear_tick_bit(order.tick(), order.is_bid())
                    .expect("Tick is valid");

                0
            } else {
                order.next()
            }
        } else {
            level.store(
                self.storage,
                self.address,
                order.book_key(),
                order.tick(),
                order.is_bid(),
            );

            order_id
        }
    }

    // TODO: clean up
    /// Fill orders for exact output amount
    #[allow(dead_code)]
    fn fill_orders_exact_out(
        &mut self,
        book_key: B256,
        base_for_quote: bool,
        amount_out: u128,
        max_amount_in: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let mut remaining_out = amount_out;
        let mut amount_in = 0u128;
        let orderbook = Orderbook::from_storage(self.storage, self.address, book_key);

        if base_for_quote {
            let mut current_tick = orderbook.best_bid_tick;
            if current_tick == i16::MIN {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }

            let mut level =
                TickLevel::from_storage(self.storage, self.address, book_key, current_tick, true);
            let mut order_id = level.head;

            while remaining_out > 0 {
                let price = orderbook::tick_to_price(current_tick);

                let order = Order::from_storage(order_id, self.storage, self.address);
                let order_remaining = order.remaining();

                let base_needed = remaining_out
                    .checked_mul(orderbook::PRICE_SCALE as u128)
                    .and_then(|v| v.checked_div(price as u128))
                    .expect("Base needed calculation overflow");

                let fill_amount = if base_needed > order_remaining {
                    order_remaining
                } else {
                    base_needed
                };

                if amount_in + fill_amount > max_amount_in {
                    return Err(StablecoinExchangeError::max_input_exceeded());
                }

                remaining_out -= fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Remaining out calculation overflow");
                amount_in += fill_amount;

                order_id = self.fill_order(order_id, fill_amount);

                if remaining_out == 0 {
                    return Ok(amount_in);
                }

                if order_id == 0 {
                    let mut bitmap =
                        orderbook::TickBitmap::new(self.storage, self.address, book_key);
                    let (next_tick, initialized) = bitmap.next_initialized_bid_tick(current_tick);
                    if !initialized {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
                    }

                    current_tick = next_tick;
                    orderbook::Orderbook::update_best_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    level = TickLevel::from_storage(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                        true,
                    );
                    order_id = level.head;
                }
            }
        } else {
            let mut current_tick = orderbook.best_ask_tick;
            if current_tick == i16::MAX {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }

            let mut level =
                TickLevel::from_storage(self.storage, self.address, book_key, current_tick, false);
            let mut order_id = level.head;

            while remaining_out > 0 {
                let price = orderbook::tick_to_price(current_tick);

                let order = Order::from_storage(order_id, self.storage, self.address);
                let order_remaining = order.remaining();

                let fill_amount = if remaining_out > order_remaining {
                    order_remaining
                } else {
                    remaining_out
                };
                let quote_in = fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Quote in calculation overflow");

                if amount_in + quote_in > max_amount_in {
                    return Err(StablecoinExchangeError::max_input_exceeded());
                }

                remaining_out -= fill_amount;
                amount_in += quote_in;

                order_id = self.fill_order(order_id, fill_amount);

                if remaining_out == 0 {
                    return Ok(amount_in);
                }

                if order_id == 0 {
                    let mut bitmap =
                        orderbook::TickBitmap::new(self.storage, self.address, book_key);
                    let (next_tick, initialized) = bitmap.next_initialized_ask_tick(current_tick);
                    if !initialized {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
                    }

                    current_tick = next_tick;
                    Orderbook::update_best_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    level = TickLevel::from_storage(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                        false,
                    );
                    order_id = level.head;
                }
            }
        }

        Ok(amount_in)
    }

    // TODO: clean up
    /// Fill orders for exact input amount
    #[allow(dead_code)]
    fn fill_orders_exact_in(
        &mut self,
        book_key: B256,
        base_for_quote: bool,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let mut remaining_in = amount_in;
        let mut amount_out = 0u128;
        let orderbook = Orderbook::from_storage(self.storage, self.address, book_key);

        if base_for_quote {
            let mut current_tick = orderbook.best_bid_tick;
            if current_tick == i16::MIN {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }

            let mut level =
                TickLevel::from_storage(self.storage, self.address, book_key, current_tick, true);
            let mut order_id = level.head;

            while remaining_in > 0 {
                let price = orderbook::tick_to_price(current_tick);

                let order = Order::from_storage(order_id, self.storage, self.address);
                let order_remaining = order.remaining();

                let fill_amount = if remaining_in > order_remaining {
                    order_remaining
                } else {
                    remaining_in
                };
                let quote_out = fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Quote out calculation overflow");

                remaining_in -= fill_amount;
                amount_out += quote_out;

                order_id = self.fill_order(order_id, fill_amount);

                if remaining_in == 0 {
                    if amount_out < min_amount_out {
                        return Err(StablecoinExchangeError::insufficient_output());
                    }
                    return Ok(amount_out);
                }

                if order_id == 0 {
                    let mut bitmap =
                        orderbook::TickBitmap::new(self.storage, self.address, book_key);
                    let (next_tick, initialized) = bitmap.next_initialized_bid_tick(current_tick);
                    if !initialized {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
                    }

                    current_tick = next_tick;
                    orderbook::Orderbook::update_best_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    level = TickLevel::from_storage(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                        true,
                    );
                    order_id = level.head;
                }
            }
        } else {
            let mut current_tick = orderbook.best_ask_tick;
            if current_tick == i16::MAX {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }

            let mut level =
                TickLevel::from_storage(self.storage, self.address, book_key, current_tick, false);
            let mut order_id = level.head;

            while remaining_in > 0 {
                let price = orderbook::tick_to_price(current_tick);

                let order = Order::from_storage(order_id, self.storage, self.address);
                let order_remaining = order.remaining();

                let base_out = remaining_in
                    .checked_mul(orderbook::PRICE_SCALE as u128)
                    .and_then(|v| v.checked_div(price as u128))
                    .expect("Base out calculation overflow");
                let fill_amount = if base_out > order_remaining {
                    order_remaining
                } else {
                    base_out
                };

                remaining_in -= (fill_amount * price as u128) / orderbook::PRICE_SCALE as u128;
                amount_out += fill_amount;

                order_id = self.fill_order(order_id, fill_amount);

                if remaining_in == 0 {
                    if amount_out < min_amount_out {
                        return Err(StablecoinExchangeError::insufficient_output());
                    }
                    return Ok(amount_out);
                }

                if order_id == 0 {
                    let mut bitmap =
                        orderbook::TickBitmap::new(self.storage, self.address, book_key);
                    let (next_tick, initialized) = bitmap.next_initialized_ask_tick(current_tick);
                    if !initialized {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
                    }

                    current_tick = next_tick;
                    orderbook::Orderbook::update_best_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    level = TickLevel::from_storage(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                        false,
                    );
                    order_id = level.head;
                }
            }
        }

        Ok(amount_out)
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
            .sload(self.address, slots::NEXT_ORDER_ID)
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
        let orderbook = Orderbook::from_storage(self.storage, self.address, order.book_key());
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
        let mut level = TickLevel::from_storage(
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
        let orderbook = Orderbook::from_storage(self.storage, self.address, order.book_key());
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
        assert!(current_balance >= amount, "Insufficient balance");
        self.sub_balance(user, token, amount);
        TIP20Token::new(address_to_token_id_unchecked(&token), self.storage)
            .transfer(
                &self.address,
                ITIP20::transferCall {
                    to: user,
                    amount: U256::from(amount),
                },
            )
            .expect("TODO: handle error");

        Ok(())
    }

    /// Quote exact output amount without executing trades
    fn quote_exact_out(
        &mut self,
        book_key: B256,
        base_for_quote: bool,
        amount_out: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let mut remaining_out = amount_out;
        let mut amount_in = 0u128;
        let orderbook = Orderbook::from_storage(self.storage, self.address, book_key);

        if base_for_quote {
            // Buying quote tokens with base tokens - use bid side
            let mut current_tick = orderbook.best_bid_tick;
            if current_tick == i16::MIN {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }

            while remaining_out > 0 {
                let level = TickLevel::from_storage(
                    self.storage,
                    self.address,
                    book_key,
                    current_tick,
                    true,
                );

                let price = orderbook::tick_to_price(current_tick);

                // Calculate how much quote we can get from this tick's liquidity
                let base_needed = remaining_out
                    .checked_mul(orderbook::PRICE_SCALE as u128)
                    .and_then(|v| v.checked_div(price as u128))
                    .expect("Base needed calculation overflow");
                let fill_amount = if base_needed > level.total_liquidity {
                    level.total_liquidity
                } else {
                    base_needed
                };
                let quote_out = fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Quote out calculation overflow");

                remaining_out -= quote_out;
                amount_in += fill_amount;

                if fill_amount == level.total_liquidity {
                    // Move to next tick if we exhaust this level
                    let (next_tick, initialized) = orderbook::next_initialized_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    if !initialized && remaining_out > 0 {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
                    }
                    current_tick = next_tick;
                }
            }
        } else {
            // Buying base tokens with quote tokens - use ask side
            let mut current_tick = orderbook.best_ask_tick;
            if current_tick == i16::MAX {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }

            while remaining_out > 0 {
                let level = TickLevel::from_storage(
                    self.storage,
                    self.address,
                    book_key,
                    current_tick,
                    false,
                );

                let price = orderbook::tick_to_price(current_tick);

                let fill_amount = if remaining_out > level.total_liquidity {
                    level.total_liquidity
                } else {
                    remaining_out
                };
                let quote_in = fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Quote in calculation overflow");

                remaining_out -= fill_amount;
                amount_in += quote_in;

                if fill_amount == level.total_liquidity {
                    // Move to next tick if we exhaust this level
                    let (next_tick, initialized) = orderbook::next_initialized_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    if !initialized && remaining_out > 0 {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
                    }
                    current_tick = next_tick;
                }
            }
        }

        Ok(amount_in)
    }

    /// Quote exact input amount without executing trades
    fn quote_exact_in(
        &mut self,
        book_key: B256,
        base_for_quote: bool,
        amount_in: u128,
    ) -> Result<u128, StablecoinExchangeError> {
        let mut remaining_in = amount_in;
        let mut amount_out = 0u128;
        let orderbook = Orderbook::from_storage(self.storage, self.address, book_key);

        if base_for_quote {
            // Selling base tokens for quote tokens - use bid side
            let mut current_tick = orderbook.best_bid_tick;
            if current_tick == i16::MIN {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }

            while remaining_in > 0 {
                let level = TickLevel::from_storage(
                    self.storage,
                    self.address,
                    book_key,
                    current_tick,
                    true,
                );

                let price = orderbook::tick_to_price(current_tick);

                let fill_amount = if remaining_in > level.total_liquidity {
                    level.total_liquidity
                } else {
                    remaining_in
                };
                let quote_out = fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Quote out calculation overflow");

                remaining_in -= fill_amount;
                amount_out += quote_out;

                if fill_amount == level.total_liquidity {
                    // Move to next tick if we exhaust this level
                    let (next_tick, initialized) = orderbook::next_initialized_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    if !initialized && remaining_in > 0 {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
                    }
                    current_tick = next_tick;
                }
            }
        } else {
            // Selling quote tokens for base tokens - use ask side
            let mut current_tick = orderbook.best_ask_tick;
            if current_tick == i16::MAX {
                return Err(StablecoinExchangeError::insufficient_liquidity());
            }

            while remaining_in > 0 {
                let level = TickLevel::from_storage(
                    self.storage,
                    self.address,
                    book_key,
                    current_tick,
                    false,
                );

                let price = orderbook::tick_to_price(current_tick);

                // Calculate how much base we can get for remaining_in quote
                let base_out = remaining_in
                    .checked_mul(orderbook::PRICE_SCALE as u128)
                    .and_then(|v| v.checked_div(price as u128))
                    .expect("Base out calculation overflow");
                let fill_amount = if base_out > level.total_liquidity {
                    level.total_liquidity
                } else {
                    base_out
                };
                let quote_needed = fill_amount
                    .checked_mul(price as u128)
                    .and_then(|v| v.checked_div(orderbook::PRICE_SCALE as u128))
                    .expect("Quote needed calculation overflow");

                remaining_in -= quote_needed;
                amount_out += fill_amount;

                if fill_amount == level.total_liquidity {
                    // Move to next tick if we exhaust this level
                    let (next_tick, initialized) = orderbook::next_initialized_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    if !initialized && remaining_in > 0 {
                        return Err(StablecoinExchangeError::insufficient_liquidity());
                    }
                    current_tick = next_tick;
                }
            }
        }

        Ok(amount_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::HashMapStorageProvider;
    use alloy::primitives::address;

    #[test]
    fn test_compute_book_key_deterministic() {
        let storage = HashMapStorageProvider::new(1);
        let exchange = StablecoinExchange {
            address: STABLECOIN_EXCHANGE_ADDRESS,
            storage: &mut { storage },
        };

        let token_a = Address::random();
        let token_b = Address::random();

        // Key should be the same regardless of input order
        let key_ab = exchange.compute_book_key(token_a, token_b);
        let key_ba = exchange.compute_book_key(token_b, token_a);

        assert_eq!(key_ab, key_ba, "Book key should be deterministic");
    }

    #[test]
    fn test_compute_book_key_matches_expected_hash() {
        let storage = HashMapStorageProvider::new(1);
        let exchange = StablecoinExchange {
            address: STABLECOIN_EXCHANGE_ADDRESS,
            storage: &mut { storage },
        };

        // Use specific addresses to verify the hash
        let token_a = address!("0x1111111111111111111111111111111111111111");
        let token_b = address!("0x2222222222222222222222222222222222222222");

        let key = exchange.compute_book_key(token_a, token_b);

        // Manually compute the expected hash:
        // token_a < token_b, so order is token_a then token_b
        let mut buf = [0u8; 40];
        buf[..20].copy_from_slice(token_a.as_slice());
        buf[20..].copy_from_slice(token_b.as_slice());
        let expected = keccak256(buf);

        assert_eq!(
            key, expected,
            "Computed book key should match keccak256 of sorted concatenated addresses"
        );
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
    fn test_place_bid_order() {
        // TODO:
    }

    #[test]
    fn test_place_ask_order() {
        // TODO:
    }

    #[test]
    fn test_place_flip_ask_order() {
        // TODO:
    }

    #[test]
    fn test_cancel_pending_order() {
        // TODO:
    }

    #[test]
    fn test_execute_block() {
        // TODO:
    }

    #[test]
    fn test_withdraw() {
        // TODO:
    }

    #[test]
    fn test_quote_buy() {
        // TODO:
    }

    #[test]
    fn test_quote_sell() {
        // TODO:
    }

    #[test]
    fn test_buy() {
        // TODO:
    }

    #[test]
    fn test_sell() {
        // TODO:
    }

    #[test]
    fn test_flip_order_execution() {
        // TODO:
    }
}
