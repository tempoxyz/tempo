//! Stablecoin DEX types and utilities.
pub mod dispatch;
pub mod error;
pub mod offsets;
pub mod order;
pub mod orderbook;
pub mod slots;

pub use tempo_contracts::precompiles::{
    IStablecoinExchange, StablecoinExchangeError, StablecoinExchangeEvents,
};

pub use order::Order;
pub use orderbook::{
    MAX_TICK, MIN_TICK, Orderbook, PRICE_SCALE, PriceLevel, TickBitmap, price_to_tick,
    tick_to_price,
};

use crate::{
    LINKING_USD_ADDRESS, STABLECOIN_EXCHANGE_ADDRESS,
    error::TempoPrecompileError,
    linking_usd::LinkingUSD,
    stablecoin_exchange::orderbook::{
        compute_book_key, next_initialized_ask_tick, next_initialized_bid_tick,
    },
    storage::{PrecompileStorageProvider, StorageOps, slots::mapping_slot},
    tip20::{ITIP20, TIP20Token},
};
use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256};
use revm::state::Bytecode;

/// Minimum order size in token units (10 units of the token)
pub const MIN_ORDER_UNITS: u128 = 10;

/// Calculate minimum order amount based on token decimals
/// Returns MIN_ORDER_UNITS scaled by the token's decimals
/// For example: 6 decimals -> 10_000_000, 18 decimals -> 10_000_000_000_000_000_000
pub fn calculate_min_order_amount(decimals: u8) -> u128 {
    MIN_ORDER_UNITS * 10u128.pow(decimals as u32)
}

/// Calculate quote amount from base amount and tick price using checked arithmetic
///
/// Returns None if overflow would occur
fn calculate_quote_amount(amount: u128, tick: i16) -> Option<u128> {
    let price = tick_to_price(tick) as u128;
    amount.checked_mul(price)?.checked_div(PRICE_SCALE as u128)
}

pub struct StablecoinExchange<'a, S: PrecompileStorageProvider> {
    address: Address,
    storage: &'a mut S,
}

impl<'a, S: PrecompileStorageProvider> StablecoinExchange<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            address: STABLECOIN_EXCHANGE_ADDRESS,
            storage,
        }
    }

    /// Stablecoin exchange address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Initializes the contract
    ///
    /// This ensures the [`StablecoinExchange`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<(), TempoPrecompileError> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            self.address,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Read pending order ID
    fn get_pending_order_id(&mut self) -> Result<u128, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.address, slots::PENDING_ORDER_ID)?
            .to::<u128>())
    }

    /// Set pending order ID
    fn set_pending_order_id(&mut self, order_id: u128) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.address, slots::PENDING_ORDER_ID, U256::from(order_id))
    }

    /// Read active order ID
    fn get_active_order_id(&mut self) -> Result<u128, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.address, slots::ACTIVE_ORDER_ID)?
            .to::<u128>())
    }

    /// Set active order ID
    fn set_active_order_id(&mut self, order_id: u128) -> Result<(), TempoPrecompileError> {
        self.storage
            .sstore(self.address, slots::ACTIVE_ORDER_ID, U256::from(order_id))
    }

    /// Increment and return the pending order id
    fn increment_pending_order_id(&mut self) -> Result<u128, TempoPrecompileError> {
        let next_id = self.get_pending_order_id()? + 1;
        self.set_pending_order_id(next_id)?;
        Ok(next_id)
    }

    /// Get user's balance for a specific token
    pub fn balance_of(
        &mut self,
        user: Address,
        token: Address,
    ) -> Result<u128, TempoPrecompileError> {
        let user_slot = mapping_slot(user.as_slice(), slots::BALANCES);
        let balance_slot = mapping_slot(token.as_slice(), user_slot);
        let balance = self.storage.sload(self.address, balance_slot)?.to::<u128>();

        Ok(balance)
    }

    /// Fetch order from storage. If the order is currently pending or filled, this function returns
    /// `StablecoinExchangeError::OrderDoesNotExist`
    pub fn get_order(&mut self, order_id: u128) -> Result<Order, TempoPrecompileError> {
        let order = Order::from_storage(order_id, self.storage, self.address)?;

        // If the order is not filled and currently active
        if !order.maker().is_zero() && order.order_id() <= self.get_active_order_id()? {
            Ok(order)
        } else {
            Err(StablecoinExchangeError::order_does_not_exist().into())
        }
    }

    /// Set user's balance for a specific token
    fn set_balance(
        &mut self,
        user: Address,
        token: Address,
        amount: u128,
    ) -> Result<(), TempoPrecompileError> {
        let user_slot = mapping_slot(user.as_slice(), slots::BALANCES);
        let balance_slot = mapping_slot(token.as_slice(), user_slot);
        self.storage
            .sstore(self.address, balance_slot, U256::from(amount))
    }

    /// Add to user's balance
    fn increment_balance(
        &mut self,
        user: Address,
        token: Address,
        amount: u128,
    ) -> Result<(), TempoPrecompileError> {
        let current = self.balance_of(user, token)?;
        self.set_balance(user, token, current + amount)
    }

    /// Subtract from user's balance
    fn sub_balance(
        &mut self,
        user: Address,
        token: Address,
        amount: u128,
    ) -> Result<(), TempoPrecompileError> {
        let current = self.balance_of(user, token)?;
        self.set_balance(user, token, current.saturating_sub(amount))
    }

    /// Transfer tokens, accounting for linking USD
    fn transfer(
        &mut self,
        token: Address,
        to: Address,
        amount: u128,
    ) -> Result<(), TempoPrecompileError> {
        if token == LINKING_USD_ADDRESS {
            LinkingUSD::new(self.storage).transfer(
                self.address,
                ITIP20::transferCall {
                    to,
                    amount: U256::from(amount),
                },
            )?;
        } else {
            TIP20Token::from_address(token, self.storage).transfer(
                self.address,
                ITIP20::transferCall {
                    to,
                    amount: U256::from(amount),
                },
            )?;
        }
        Ok(())
    }

    /// Transfer tokens from user, accounting for linking USD
    fn transfer_from(
        &mut self,
        token: Address,
        from: Address,
        amount: u128,
    ) -> Result<(), TempoPrecompileError> {
        if token == LINKING_USD_ADDRESS {
            LinkingUSD::new(self.storage).transfer_from(
                self.address,
                ITIP20::transferFromCall {
                    from,
                    to: self.address,
                    amount: U256::from(amount),
                },
            )?;
        } else {
            TIP20Token::from_address(token, self.storage).transfer_from(
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
    ) -> Result<(), TempoPrecompileError> {
        let user_balance = self.balance_of(user, token)?;
        if user_balance >= amount {
            self.sub_balance(user, token, amount)
        } else {
            self.set_balance(user, token, 0)?;
            let remaining = amount - user_balance;
            self.transfer_from(token, user, remaining)
        }
    }

    pub fn quote_swap_exact_amount_out(
        &mut self,
        token_in: Address,
        token_out: Address,
        amount_out: u128,
    ) -> Result<u128, TempoPrecompileError> {
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
    ) -> Result<u128, TempoPrecompileError> {
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
    ) -> Result<u128, TempoPrecompileError> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Deduct input tokens from sender (only once, at the start)
        self.decrement_balance_or_transfer_from(sender, token_in, amount_in)?;

        // Execute swaps for each hop - intermediate balances are transitory
        let mut amount = amount_in;
        for (book_key, base_for_quote) in route {
            // Fill orders for this hop - no min check on intermediate hops
            amount = self.fill_orders_exact_in(book_key, base_for_quote, amount, 0)?;
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
    ) -> Result<u128, TempoPrecompileError> {
        // Find and validate the trade route (book keys + direction for each hop)
        let route = self.find_trade_path(token_in, token_out)?;

        // Work backwards from output to calculate input needed - intermediate amounts are TRANSITORY
        let mut amount = amount_out;
        for (book_key, base_for_quote) in route.iter().rev() {
            amount =
                self.fill_orders_exact_out(*book_key, *base_for_quote, amount, max_amount_in)?;
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
    pub fn get_price_level(
        &mut self,
        base: Address,
        tick: i16,
        is_bid: bool,
    ) -> Result<PriceLevel, TempoPrecompileError> {
        let quote = TIP20Token::from_address(base, self.storage).quote_token()?;
        let key = compute_book_key(base, quote);
        PriceLevel::from_storage(self.storage, self.address, key, tick, is_bid)
    }

    /// Get active order ID
    pub fn active_order_id(&mut self) -> Result<u128, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.address, slots::ACTIVE_ORDER_ID)?
            .to::<u128>())
    }

    /// Get pending order ID
    pub fn pending_order_id(&mut self) -> Result<u128, TempoPrecompileError> {
        Ok(self
            .storage
            .sload(self.address, slots::PENDING_ORDER_ID)?
            .to::<u128>())
    }

    /// Get orderbook by pair key
    pub fn books(&mut self, pair_key: B256) -> Result<Orderbook, TempoPrecompileError> {
        Orderbook::from_storage(pair_key, self.storage, self.address)
    }

    /// Add book key to book keys array
    /// This function adds the specified book key to the `book_keys` array in storage
    /// and increments the length of the array
    fn push_to_book_keys(&mut self, book_key: B256) -> Result<(), TempoPrecompileError> {
        let length = self.storage.sload(self.address, slots::BOOK_KEYS_LENGTH)?;
        self.storage.sstore(
            self.address,
            slots::BOOK_KEYS_BASE + length,
            book_key.into(),
        )?;
        self.storage
            .sstore(self.address, slots::BOOK_KEYS_LENGTH, length + U256::ONE)?;
        Ok(())
    }

    /// Get all book keys
    pub fn get_book_keys(&mut self) -> Result<Vec<B256>, TempoPrecompileError> {
        let length = self.storage.sload(self.address, slots::BOOK_KEYS_LENGTH)?;
        let mut book_keys = Vec::new();
        let mut i = U256::ZERO;
        while i < length {
            let book_key = self
                .storage
                .sload(self.address, slots::BOOK_KEYS_BASE + i)?;
            book_keys.push(B256::from(book_key));
            i += U256::ONE;
        }
        Ok(book_keys)
    }

    pub fn create_pair(&mut self, base: Address) -> Result<B256, TempoPrecompileError> {
        let quote = TIP20Token::from_address(base, self.storage).quote_token()?;

        let book_key = compute_book_key(base, quote);

        if Orderbook::exists(book_key, self.storage, self.address)? {
            return Err(StablecoinExchangeError::pair_already_exists().into());
        }

        let book = Orderbook::new(base, quote);
        book.store(self.storage, self.address)?;
        self.push_to_book_keys(book_key)?;

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
    ) -> Result<u128, TempoPrecompileError> {
        // Lookup quote token and decimals from TIP20 token
        let mut token_contract = TIP20Token::from_address(token, self.storage);
        let quote_token = token_contract.quote_token()?;
        let decimals = token_contract.decimals()?;

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);
        let book = Orderbook::from_storage(book_key, self.storage, self.address)?;
        if book.base.is_zero() {
            return Err(StablecoinExchangeError::pair_does_not_exist().into());
        }

        // Validate tick is within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(tick).into());
        }

        // Validate order amount meets minimum requirement
        let min_order_amount = calculate_min_order_amount(decimals);
        if amount < min_order_amount {
            return Err(StablecoinExchangeError::below_minimum_order_size(amount).into());
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
        self.decrement_balance_or_transfer_from(sender, escrow_token, escrow_amount)?;

        // Create the order
        let order_id = self.increment_pending_order_id()?;
        let order = if is_bid {
            Order::new_bid(order_id, sender, book_key, amount, tick)
        } else {
            Order::new_ask(order_id, sender, book_key, amount, tick)
        };

        // Store in pending queue. Orders are stored as a DLL at each tick level and are initially
        // stored without a prev or next pointer. This is considered a "pending" order. Once `execute_block` is called, orders are
        // linked and then considered "active"
        order.store(self.storage, self.address)?;

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
    ) -> Result<u128, TempoPrecompileError> {
        // Lookup quote token and decimals from TIP20 token
        let mut token_contract = TIP20Token::from_address(token, self.storage);
        let quote_token = token_contract.quote_token()?;
        let decimals = token_contract.decimals()?;

        // Compute book_key from token pair
        let book_key = compute_book_key(token, quote_token);

        // Validate tick and flip_tick are within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(tick).into());
        }
        if !(MIN_TICK..=MAX_TICK).contains(&flip_tick) {
            return Err(StablecoinExchangeError::tick_out_of_bounds(flip_tick).into());
        }

        // Validate flip_tick relationship to tick based on order side
        if (is_bid && flip_tick <= tick) || (!is_bid && flip_tick >= tick) {
            return Err(StablecoinExchangeError::invalid_flip_tick().into());
        }

        // Validate order amount meets minimum requirement
        let min_order_amount = calculate_min_order_amount(decimals);
        if amount < min_order_amount {
            return Err(StablecoinExchangeError::below_minimum_order_size(amount).into());
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
        self.decrement_balance_or_transfer_from(sender, escrow_token, escrow_amount)?;

        // Create the flip order
        let order_id = self.increment_pending_order_id()?;
        let order = Order::new_flip(order_id, sender, book_key, amount, tick, is_bid, flip_tick)
            .expect("Invalid flip tick");

        // Store in pending queue
        order.store(self.storage, self.address)?;

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
    pub fn execute_block(&mut self, sender: Address) -> Result<(), TempoPrecompileError> {
        // Only protocol can call this
        if sender != Address::ZERO {
            return Err(StablecoinExchangeError::unauthorized().into());
        }

        let next_order_id = self
            .storage
            .sload(self.address, slots::ACTIVE_ORDER_ID)?
            .to::<u128>();

        let pending_order_id = self.get_pending_order_id()?;

        let mut current_order_id = next_order_id + 1;
        while current_order_id <= pending_order_id {
            self.process_pending_order(current_order_id)?;
            current_order_id += 1;
        }

        self.set_active_order_id(pending_order_id)?;

        Ok(())
    }

    /// Process a single pending order into the active orderbook
    fn process_pending_order(&mut self, order_id: u128) -> Result<(), TempoPrecompileError> {
        let order = Order::from_storage(order_id, self.storage, self.address)?;

        // If the order is already canceled, return early
        if order.maker().is_zero() {
            return Ok(());
        }

        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address)?;
        let mut level = PriceLevel::from_storage(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
        )?;

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
                    )?;
                }
            } else if order.tick() < orderbook.best_ask_tick {
                orderbook::Orderbook::update_best_ask_tick(
                    self.storage,
                    self.address,
                    order.book_key(),
                    order.tick(),
                )?;
            }
        } else {
            Order::update_next_order(prev_tail, order_id, self.storage, self.address)?;
            Order::update_prev_order(order_id, prev_tail, self.storage, self.address)?;
            level.tail = order_id;
        }

        level.total_liquidity += order.remaining();
        level.store(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
        )
    }

    /// Partially fill an order with the specified amount.
    /// Fill amount is denominated in base token
    fn partial_fill_order(
        &mut self,
        order: &mut Order,
        level: &mut PriceLevel,
        fill_amount: u128,
    ) -> Result<u128, TempoPrecompileError> {
        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address)?;
        let price = tick_to_price(order.tick());

        // Update order remaining amount
        let new_remaining = order.remaining() - fill_amount;
        order.update_remaining(new_remaining, self.storage, self.address)?;

        if order.is_bid() {
            self.increment_balance(order.maker(), orderbook.base, fill_amount)?;
        } else {
            let quote_amount = (fill_amount * price as u128) / orderbook::PRICE_SCALE as u128;
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
        PriceLevel::update_total_liquidity(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
            level.total_liquidity - fill_amount,
        )?;

        // Emit OrderFilled event for partial fill
        self.storage.emit_event(
            self.address,
            StablecoinExchangeEvents::OrderFilled(IStablecoinExchange::OrderFilled {
                orderId: order.order_id(),
                maker: order.maker(),
                amountFilled: fill_amount,
                partialFill: true,
            })
            .into_log_data(),
        )?;

        Ok(amount_out)
    }

    /// Fill an order and delete from storage. Returns the next best order and price level.
    fn fill_order(
        &mut self,
        book_key: B256,
        order: &mut Order,
        mut level: PriceLevel,
    ) -> Result<(u128, Option<(PriceLevel, Order)>), TempoPrecompileError> {
        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address)?;
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
        self.storage.emit_event(
            self.address,
            StablecoinExchangeEvents::OrderFilled(IStablecoinExchange::OrderFilled {
                orderId: order.order_id(),
                maker: order.maker(),
                amountFilled: fill_amount,
                partialFill: false,
            })
            .into_log_data(),
        )?;

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
        order.delete(self.storage, self.address)?;

        // Advance tick if liquidity is exhausted
        let next_tick_info = if order.next() == 0 {
            level.delete(
                self.storage,
                self.address,
                book_key,
                order.tick(),
                order.is_bid(),
            )?;

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
                )?;
                let new_order = Order::from_storage(new_level.head, self.storage, self.address)?;

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
            )?;

            let new_order = Order::from_storage(order.next(), self.storage, self.address)?;
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
    ) -> Result<u128, TempoPrecompileError> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = Order::from_storage(level.head, self.storage, self.address)?;

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
                return Err(StablecoinExchangeError::max_input_exceeded().into());
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
        min_amount_out: u128,
    ) -> Result<u128, TempoPrecompileError> {
        let mut level = self.get_best_price_level(book_key, bid)?;
        let mut order = Order::from_storage(level.head, self.storage, self.address)?;

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
            return Err(StablecoinExchangeError::insufficient_output().into());
        }

        Ok(total_amount_out)
    }

    /// Helper function to get best tick from orderbook
    fn get_best_price_level(
        &mut self,
        book_key: B256,
        bid: bool,
    ) -> Result<PriceLevel, TempoPrecompileError> {
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address)?;

        let current_tick = if bid {
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

        let level =
            PriceLevel::from_storage(self.storage, self.address, book_key, current_tick, bid)?;

        Ok(level)
    }

    /// Cancel an order and refund tokens to maker
    /// Only the order maker can cancel their own order
    pub fn cancel(&mut self, sender: Address, order_id: u128) -> Result<(), TempoPrecompileError> {
        let order = Order::from_storage(order_id, self.storage, self.address)?;

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
        let next_order_id = self
            .storage
            .sload(self.address, slots::ACTIVE_ORDER_ID)?
            .to::<u128>();

        if order.order_id() > next_order_id {
            self.cancel_pending_order(order)?;
        } else {
            self.cancel_active_order(order)?;
        }

        Ok(())
    }

    /// Cancel a pending order (not yet in the active orderbook)
    fn cancel_pending_order(&mut self, order: Order) -> Result<(), TempoPrecompileError> {
        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address)?;
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
        order.delete(self.storage, self.address)?;

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
    fn cancel_active_order(&mut self, order: Order) -> Result<(), TempoPrecompileError> {
        let mut level = PriceLevel::from_storage(
            self.storage,
            self.address,
            order.book_key(),
            order.tick(),
            order.is_bid(),
        )?;

        // Update linked list
        if order.prev() != 0 {
            Order::update_next_order(order.prev(), order.next(), self.storage, self.address)?;
        } else {
            level.head = order.next();
        }

        if order.next() != 0 {
            Order::update_prev_order(order.next(), order.prev(), self.storage, self.address)?;
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
        )?;

        // Refund tokens to maker
        let orderbook = Orderbook::from_storage(order.book_key(), self.storage, self.address)?;
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
        order.delete(self.storage, self.address)?;

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
    pub fn withdraw(
        &mut self,
        user: Address,
        token: Address,
        amount: u128,
    ) -> Result<(), TempoPrecompileError> {
        let current_balance = self.balance_of(user, token)?;
        if current_balance < amount {
            return Err(StablecoinExchangeError::insufficient_balance().into());
        }
        self.sub_balance(user, token, amount)?;
        self.transfer(token, user, amount)?;

        Ok(())
    }

    /// Quote exact output amount without executing trades
    fn quote_exact_out(
        &mut self,
        book_key: B256,
        amount_out: u128,
        is_bid: bool,
    ) -> Result<u128, TempoPrecompileError> {
        let mut remaining_out = amount_out;
        let mut amount_in = 0u128;
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address)?;

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };
        if current_tick == i16::MIN {
            return Err(StablecoinExchangeError::insufficient_liquidity().into());
        }

        while remaining_out > 0 {
            let level = PriceLevel::from_storage(
                self.storage,
                self.address,
                book_key,
                current_tick,
                is_bid,
            )?;

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
    ) -> Result<Vec<(B256, bool)>, TempoPrecompileError> {
        // Cannot trade same token
        if token_in == token_out {
            return Err(StablecoinExchangeError::identical_tokens().into());
        }

        // Check if direct or reverse pair exists
        let in_quote = TIP20Token::from_address(token_in, self.storage).quote_token()?;
        let out_quote = TIP20Token::from_address(token_out, self.storage).quote_token()?;

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
    fn validate_and_build_route(
        &mut self,
        path: &[Address],
    ) -> Result<Vec<(B256, bool)>, TempoPrecompileError> {
        let mut route = Vec::new();

        for i in 0..path.len() - 1 {
            let hop_token_in = path[i];
            let hop_token_out = path[i + 1];

            let book_key = compute_book_key(hop_token_in, hop_token_out);
            let orderbook = Orderbook::from_storage(book_key, self.storage, self.address)?;

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

    /// Find the path from a token to the root (LinkingUSD)
    /// Returns a vector of addresses starting with the token and ending with LinkingUSD
    fn find_path_to_root(
        &mut self,
        mut token: Address,
    ) -> Result<Vec<Address>, TempoPrecompileError> {
        let mut path = vec![token];

        while token != LINKING_USD_ADDRESS {
            token = TIP20Token::from_address(token, self.storage).quote_token()?;
            path.push(token);
        }

        Ok(path)
    }

    /// Quote exact input amount without executing trades
    fn quote_exact_in(
        &mut self,
        book_key: B256,
        amount_in: u128,
        is_bid: bool,
    ) -> Result<u128, TempoPrecompileError> {
        let mut remaining_in = amount_in;
        let mut amount_out = 0u128;
        let orderbook = Orderbook::from_storage(book_key, self.storage, self.address)?;

        let mut current_tick = if is_bid {
            orderbook.best_bid_tick
        } else {
            orderbook.best_ask_tick
        };

        if current_tick == i16::MIN {
            return Err(StablecoinExchangeError::insufficient_liquidity().into());
        }

        while remaining_in > 0 {
            let level = PriceLevel::from_storage(
                self.storage,
                self.address,
                book_key,
                current_tick,
                is_bid,
            )?;

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
                    return Err(StablecoinExchangeError::insufficient_liquidity().into());
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

impl<'a, S: PrecompileStorageProvider> StorageOps for StablecoinExchange<'a, S> {
    fn sstore(&mut self, slot: U256, value: U256) -> Result<(), TempoPrecompileError> {
        self.storage.sstore(self.address, slot, value)
    }

    fn sload(&mut self, slot: U256) -> Result<U256, TempoPrecompileError> {
        self.storage.sload(self.address, slot)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        linking_usd::TRANSFER_ROLE, storage::hashmap::HashMapStorageProvider, tip20::ISSUER_ROLE,
    };

    use super::*;

    fn setup_test_tokens<S: PrecompileStorageProvider>(
        storage: &mut S,
        admin: Address,
        user: Address,
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
        quote_roles
            .grant_role_internal(admin, *ISSUER_ROLE)
            .unwrap();
        quote_roles
            .grant_role_internal(user, *TRANSFER_ROLE)
            .unwrap();

        // Mint tokens to user
        quote
            .mint(
                admin,
                ITIP20::mintCall {
                    to: user,
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
        base_roles.grant_role_internal(admin, *ISSUER_ROLE).unwrap();

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
                to: user,
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
    fn test_place_order_pair_does_not_exist() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = calculate_min_order_amount(6);
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
    fn test_place_order_below_minimum_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = calculate_min_order_amount(6);
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
        let min_order_amount = calculate_min_order_amount(6);
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
        let stored_order = Order::from_storage(order_id, exchange.storage, exchange.address)?;
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
        let level =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, true)?;
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage);
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
        let min_order_amount = calculate_min_order_amount(6);
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
        let stored_order = Order::from_storage(order_id, exchange.storage, exchange.address)?;
        assert_eq!(stored_order.maker(), alice);
        assert_eq!(stored_order.amount(), min_order_amount);
        assert_eq!(stored_order.remaining(), min_order_amount);
        assert_eq!(stored_order.tick(), tick);
        assert!(!stored_order.is_bid());
        assert!(!stored_order.is_flip());
        assert_eq!(stored_order.prev(), 0);
        assert_eq!(stored_order.next(), 0);

        let book_key = compute_book_key(base_token, quote_token);
        let level =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, false)?;
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut base_tip20 = TIP20Token::from_address(base_token, exchange.storage);
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
        let min_order_amount = calculate_min_order_amount(6);
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
    fn test_place_flip_order() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().expect("Could not init exchange");

        let alice = Address::random();
        let admin = Address::random();
        let min_order_amount = calculate_min_order_amount(6);
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
        let stored_order = Order::from_storage(order_id, exchange.storage, exchange.address)?;
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
        let level =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, true)?;
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);

        // Verify balance was reduced by the escrow amount
        {
            let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage);
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
        let min_order_amount = calculate_min_order_amount(6);
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
            let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage);

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
        let cancelled_order = Order::from_storage(order_id, exchange.storage, exchange.address)?;
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
        let min_order_amount = calculate_min_order_amount(6);
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
        let order_1 = Order::from_storage(order_id_1, exchange.storage, exchange.address)?;
        let order_2 = Order::from_storage(order_id_1, exchange.storage, exchange.address)?;
        assert_eq!(order_1.prev(), 0);
        assert_eq!(order_1.next(), 0);
        assert_eq!(order_2.prev(), 0);
        assert_eq!(order_2.next(), 0);

        // Verify tick level is empty before execute_block
        let book_key = compute_book_key(base_token, quote_token);
        let level_before =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, true)?;
        assert_eq!(level_before.head, 0);
        assert_eq!(level_before.tail, 0);
        assert_eq!(level_before.total_liquidity, 0);

        // Execute block and assert that orders have been linked
        exchange
            .execute_block(Address::ZERO)
            .expect("Execute block should succeed");

        assert_eq!(exchange.active_order_id()?, 2);
        assert_eq!(exchange.pending_order_id()?, 2);

        let order_0 = Order::from_storage(order_id_0, exchange.storage, exchange.address)?;
        let order_1 = Order::from_storage(order_id_1, exchange.storage, exchange.address)?;
        assert_eq!(order_0.prev(), 0);
        assert_eq!(order_0.next(), order_1.order_id());
        assert_eq!(order_1.prev(), order_0.order_id());
        assert_eq!(order_1.next(), 0);

        // Assert tick level is updated
        let level_after =
            PriceLevel::from_storage(exchange.storage, exchange.address, book_key, tick, true)?;
        assert_eq!(level_after.head, order_0.order_id());
        assert_eq!(level_after.tail, order_1.order_id());
        assert_eq!(level_after.total_liquidity, min_order_amount * 2);

        // Verify orderbook best bid tick is updated
        let orderbook = Orderbook::from_storage(book_key, exchange.storage, exchange.address)?;
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
        let min_order_amount = calculate_min_order_amount(6);
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
        let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage);

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

        let min_order_amount = calculate_min_order_amount(6);
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
        let min_order_amount = calculate_min_order_amount(6);
        let amount_out = 500_000u128;
        let tick = 1;

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
        let min_order_amount = calculate_min_order_amount(6);
        let amount_in = 500_000u128;
        let tick = 1;

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
        let min_order_amount = calculate_min_order_amount(6);
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
        let min_order_amount = calculate_min_order_amount(6);
        let amount_out = 500_000u128;
        let tick = 1;

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

        let mut base_tip20 = TIP20Token::from_address(base_token, exchange.storage);
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
        let min_order_amount = calculate_min_order_amount(6);
        let amount_in = 500_000u128;
        let tick = 1;

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

        let mut quote_tip20 = TIP20Token::from_address(quote_token, exchange.storage);
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
        let min_order_amount = calculate_min_order_amount(6);
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
        let filled_order = Order::from_storage(flip_order_id, exchange.storage, exchange.address)?;
        assert_eq!(filled_order.maker(), Address::ZERO);

        let new_order_id = exchange.pending_order_id()?;
        assert_eq!(new_order_id, flip_order_id + 1);

        let new_order = Order::from_storage(new_order_id, exchange.storage, exchange.address)?;
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

        let min_order_amount = calculate_min_order_amount(6);
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

        let min_order_amount = calculate_min_order_amount(6);
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

        let orderbook = Orderbook::from_storage(book_key, storage, exchange_addr)?;
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

        // Setup: LinkingUSD <- USDC <- TokenA
        let linking_usd_addr = {
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .initialize(admin)
                .expect("Failed to initialize LinkingUSD");
            linking_usd.token.token_address
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize USDC");
            usdc.token_address
        };

        let token_a_addr = {
            let mut token_a = TIP20Token::new(3, exchange.storage);
            token_a
                .initialize("TokenA", "TKA", "USD", usdc_addr, admin)
                .expect("Failed to initialize TokenA");
            token_a.token_address
        };

        // Find path from TokenA to root
        let path = exchange
            .find_path_to_root(token_a_addr)
            .expect("Failed to find path");

        // Expected: [TokenA, USDC, LinkingUSD]
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], token_a_addr);
        assert_eq!(path[1], usdc_addr);
        assert_eq!(path[2], linking_usd_addr);

        Ok(())
    }

    #[test]
    fn test_find_trade_path_same_token_errors() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize()?;

        let admin = Address::random();
        let user = Address::random();

        let min_order_amount = calculate_min_order_amount(6);
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

        let min_order_amount = calculate_min_order_amount(6);
        // Setup: LinkingUSD <- Token (direct pair)
        let (token, linking_usd) = setup_test_tokens(
            exchange.storage,
            admin,
            user,
            exchange.address,
            min_order_amount,
        );

        // Create the pair first
        exchange.create_pair(token).expect("Failed to create pair");

        // Trade token -> linking_usd (direct pair)
        let route = exchange
            .find_trade_path(token, linking_usd)
            .expect("Should find direct pair");

        // Expected: 1 hop (token -> linking_usd)
        assert_eq!(route.len(), 1, "Should have 1 hop for direct pair");
        verify_hop(
            exchange.storage,
            exchange.address,
            route[0],
            token,
            linking_usd,
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

        let min_order_amount = calculate_min_order_amount(6);
        // Setup: LinkingUSD <- Token
        let (token, linking_usd) = setup_test_tokens(
            exchange.storage,
            admin,
            user,
            exchange.address,
            min_order_amount,
        );

        // Create the pair first
        exchange.create_pair(token).expect("Failed to create pair");

        // Trade linking_usd -> token (reverse direction)
        let route = exchange
            .find_trade_path(linking_usd, token)
            .expect("Should find reverse pair");

        // Expected: 1 hop (linking_usd -> token)
        assert_eq!(route.len(), 1, "Should have 1 hop for reverse pair");
        verify_hop(
            exchange.storage,
            exchange.address,
            route[0],
            linking_usd,
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

        // Setup: LinkingUSD <- USDC
        //        LinkingUSD <- EURC
        // (USDC and EURC are siblings, both have LinkingUSD as quote)
        let linking_usd_addr = {
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .initialize(admin)
                .expect("Failed to initialize LinkingUSD");
            linking_usd.token.token_address
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize USDC");
            usdc.token_address
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize EURC");
            eurc.token_address
        };

        // Create pairs first
        exchange
            .create_pair(usdc_addr)
            .expect("Failed to create USDC pair");
        exchange
            .create_pair(eurc_addr)
            .expect("Failed to create EURC pair");

        // Trade USDC -> EURC should go through LinkingUSD
        let route = exchange
            .find_trade_path(usdc_addr, eurc_addr)
            .expect("Should find path");

        // Expected: 2 hops (USDC -> LinkingUSD, LinkingUSD -> EURC)
        assert_eq!(route.len(), 2, "Should have 2 hops for sibling tokens");
        verify_hop(
            exchange.storage,
            exchange.address,
            route[0],
            usdc_addr,
            linking_usd_addr,
        )?;
        verify_hop(
            exchange.storage,
            exchange.address,
            route[1],
            linking_usd_addr,
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
        let min_order_amount = calculate_min_order_amount(6);

        // Setup: LinkingUSD <- USDC
        //        LinkingUSD <- EURC
        let linking_usd_addr = {
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .initialize(admin)
                .expect("Failed to initialize LinkingUSD");
            linking_usd.token.token_address
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize USDC");
            usdc.token_address
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize EURC");
            eurc.token_address
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
            let mut usdc_roles = usdc.get_roles_contract();
            usdc_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
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
            let mut eurc_roles = eurc.get_roles_contract();
            eurc_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
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
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            let mut linking_usd_roles = linking_usd.get_roles_contract();
            linking_usd_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
            linking_usd
                .token
                .mint(
                    admin,
                    ITIP20::mintCall {
                        to: alice,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to mint LinkingUSD");
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
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .token
                .approve(
                    alice,
                    ITIP20::approveCall {
                        spender: exchange.address,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to approve LinkingUSD");
        }

        // Place orders to provide liquidity at 1:1 rate (tick 0)
        // For trade USDC -> LinkingUSD -> EURC:
        // - First hop needs: bid on USDC (someone buying USDC with LinkingUSD)
        // - Second hop needs: ask on EURC (someone selling EURC for LinkingUSD)

        // USDC bid: buy USDC with LinkingUSD
        exchange
            .place(alice, usdc_addr, min_order_amount * 5, true, 0)
            .expect("Failed to place USDC bid order");

        // EURC ask: sell EURC for LinkingUSD
        exchange
            .place(alice, eurc_addr, min_order_amount * 5, false, 0)
            .expect("Failed to place EURC ask order");

        exchange
            .execute_block(Address::ZERO)
            .expect("Failed to execute block");

        // Quote multi-hop: USDC -> LinkingUSD -> EURC
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

        let min_order_amount = calculate_min_order_amount(6);
        // Setup: LinkingUSD <- USDC
        //        LinkingUSD <- EURC
        let linking_usd_addr = {
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .initialize(admin)
                .expect("Failed to initialize LinkingUSD");
            linking_usd.token.token_address
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize USDC");
            usdc.token_address
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize EURC");
            eurc.token_address
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
            let mut usdc_roles = usdc.get_roles_contract();
            usdc_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
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
            let mut eurc_roles = eurc.get_roles_contract();
            eurc_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
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
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            let mut linking_usd_roles = linking_usd.get_roles_contract();
            linking_usd_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
            linking_usd
                .token
                .mint(
                    admin,
                    ITIP20::mintCall {
                        to: alice,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to mint LinkingUSD");
            linking_usd
                .token
                .approve(
                    alice,
                    ITIP20::approveCall {
                        spender: exchange.address,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to approve LinkingUSD");
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

        // Quote multi-hop for exact output: USDC -> LinkingUSD -> EURC
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

        let min_order_amount = calculate_min_order_amount(6);
        // Setup: LinkingUSD <- USDC <- EURC
        let linking_usd_addr = {
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .initialize(admin)
                .expect("Failed to initialize LinkingUSD");
            linking_usd.token.token_address
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize USDC");
            usdc.token_address
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize EURC");
            eurc.token_address
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
            let mut usdc_roles = usdc.get_roles_contract();
            usdc_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
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
            let mut eurc_roles = eurc.get_roles_contract();
            eurc_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
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
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            let mut linking_usd_roles = linking_usd.get_roles_contract();
            linking_usd_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
            linking_usd.token.mint(
                admin,
                ITIP20::mintCall {
                    to: alice,
                    amount: U256::from(min_order_amount * 10),
                },
            )?;

            linking_usd.token.approve(
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

        // Execute multi-hop swap: USDC -> LinkingUSD -> EURC
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

        // Verify bob has ZERO LinkingUSD (intermediate token should be transitory)
        let bob_linking_usd_wallet = {
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .token
                .balance_of(ITIP20::balanceOfCall { account: bob })?
        };
        assert_eq!(
            bob_linking_usd_wallet,
            U256::ZERO,
            "Bob should have ZERO LinkingUSD in wallet (transitory)"
        );

        let bob_linking_usd_exchange = exchange
            .balance_of(bob, linking_usd_addr)
            .expect("Failed to get bob's LinkingUSD exchange balance");
        assert_eq!(
            bob_linking_usd_exchange, 0,
            "Bob should have ZERO LinkingUSD on exchange (transitory)"
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

        let min_order_amount = calculate_min_order_amount(6);
        // Setup: LinkingUSD <- USDC <- EURC
        let linking_usd_addr = {
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .initialize(admin)
                .expect("Failed to initialize LinkingUSD");
            linking_usd.token.token_address
        };

        let usdc_addr = {
            let mut usdc = TIP20Token::new(2, exchange.storage);
            usdc.initialize("USDC", "USDC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize USDC");
            usdc.token_address
        };

        let eurc_addr = {
            let mut eurc = TIP20Token::new(3, exchange.storage);
            eurc.initialize("EURC", "EURC", "USD", linking_usd_addr, admin)
                .expect("Failed to initialize EURC");
            eurc.token_address
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
            let mut usdc_roles = usdc.get_roles_contract();
            usdc_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
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
            let mut eurc_roles = eurc.get_roles_contract();
            eurc_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
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
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            let mut linking_usd_roles = linking_usd.get_roles_contract();
            linking_usd_roles.grant_role_internal(admin, *ISSUER_ROLE)?;
            linking_usd
                .token
                .mint(
                    admin,
                    ITIP20::mintCall {
                        to: alice,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to mint LinkingUSD");
            linking_usd
                .token
                .approve(
                    alice,
                    ITIP20::approveCall {
                        spender: exchange.address,
                        amount: U256::from(min_order_amount * 10),
                    },
                )
                .expect("Failed to approve LinkingUSD");
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

        // Execute multi-hop swap: USDC -> LinkingUSD -> EURC (exact output)
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

        // Verify bob has ZERO LinkingUSD (intermediate token should be transitory)
        let bob_linking_usd_wallet = {
            let mut linking_usd = LinkingUSD::new(exchange.storage);
            linking_usd
                .token
                .balance_of(ITIP20::balanceOfCall { account: bob })?
        };
        assert_eq!(
            bob_linking_usd_wallet,
            U256::ZERO,
            "Bob should have ZERO LinkingUSD in wallet (transitory)"
        );

        let bob_linking_usd_exchange = exchange
            .balance_of(bob, linking_usd_addr)
            .expect("Failed to get bob's LinkingUSD exchange balance");
        assert_eq!(
            bob_linking_usd_exchange, 0,
            "Bob should have ZERO LinkingUSD on exchange (transitory)"
        );

        Ok(())
    }
}
