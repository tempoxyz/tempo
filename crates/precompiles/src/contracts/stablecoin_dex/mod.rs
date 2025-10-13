//! Stablecoin DEX types and utilities.

pub mod error;
pub mod offsets;
pub mod order;
pub mod orderbook;
pub mod slots;

pub use error::OrderError;
pub use order::{Order, Side};
pub use orderbook::{
    MAX_TICK, MIN_TICK, Orderbook, PRICE_SCALE, TickBitmap, TickLevel, price_to_tick, tick_to_price,
};

use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256, keccak256};
use revm::{
    interpreter::instructions::utility::{IntoAddress, IntoU256},
    state::Bytecode,
};

use crate::{
    STABLECOIN_DEX_ADDRESS,
    contracts::{
        StorageProvider, TIP20Token, address_to_token_id_unchecked,
        storage::{StorageOps, slots::mapping_slot},
        types::{IStablecoinDex, ITIP20, StablecoinDexError, StablecoinDexEvent},
    },
};

pub struct StablecoinDex<'a, S: StorageProvider> {
    address: Address,
    storage: &'a mut S,
}

impl<'a, S: StorageProvider> StablecoinDex<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            address: STABLECOIN_DEX_ADDRESS,
            storage,
        }
    }

    /// Initializes the contract
    ///
    /// This ensures the [`StablecoinDex`] isn't empty and prevents state clear.
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

    /// Store a pending order
    fn store_pending_order(&mut self, order_id: u128, order: &Order) {
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);

        // Store maker address
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_MAKER_OFFSET,
                order.maker().into_u256(),
            )
            .expect("Storage write failed");

        // Store book_key
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_BOOK_KEY_OFFSET,
                U256::from_be_bytes(order.book_key().0),
            )
            .expect("Storage write failed");

        // Store side (Bid = 0, Ask = 1)
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_SIDE_OFFSET,
                order.side().into(),
            )
            .expect("Storage write failed");

        // Store tick
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_TICK_OFFSET,
                U256::from(order.tick() as i128 as u128), // Cast i16 through i128 to preserve sign
            )
            .expect("Storage write failed");

        // Store original amount
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_AMOUNT_OFFSET,
                U256::from(order.amount()),
            )
            .expect("Storage write failed");

        // Store remaining amount
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_REMAINING_OFFSET,
                U256::from(order.remaining()),
            )
            .expect("Storage write failed");

        // Store is_flip boolean
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_IS_FLIP_OFFSET,
                U256::from(order.is_flip() as u8),
            )
            .expect("Storage write failed");

        // Store flip_tick (always store, even if 0 for non-flip orders)
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_FLIP_TICK_OFFSET,
                U256::from(order.flip_tick() as i128 as u128),
            )
            .expect("Storage write failed");
    }
}

impl<'a, S: StorageProvider> StorageOps for StablecoinDex<'a, S> {
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

impl<'a, S: StorageProvider> StablecoinDex<'a, S> {
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
    fn add_balance(&mut self, user: Address, token: Address, amount: u128) {
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
    ) -> Result<(), StablecoinDexError> {
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
                .map_err(|_| StablecoinDexError::insufficient_balance())?;
        }
        Ok(())
    }

    pub fn quote_buy(
        &mut self,
        _token_in: Address,
        _token_out: Address,
        _amount_out: u128,
    ) -> u128 {
        todo!()
    }

    pub fn quote_sell(
        &mut self,
        _token_in: Address,
        _token_out: Address,
        _amount_in: u128,
    ) -> u128 {
        todo!()
    }

    pub fn sell(
        &mut self,
        _token_in: Address,
        _token_out: Address,
        _amount_in: u128,
        _min_amount_out: u128,
    ) -> u128 {
        todo!()
    }

    pub fn buy(
        &mut self,
        _token_in: Address,
        _token_out: Address,
        _amount_out: u128,
        _max_amount_in: u128,
    ) -> u128 {
        todo!()
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
    ) -> Result<u128, StablecoinDexError> {
        // Lookup quote token (linking token) from TIP20 token
        let quote_token =
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage).linking_token();

        // Compute book_key from token pair
        let book_key = self.compute_book_key(token, quote_token);

        // Validate tick is within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinDexError::tick_out_of_bounds(tick));
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount) = if is_bid {
            // For bids, escrow quote tokens based on price
            let price = tick_to_price(tick);
            let quote_amount = (amount * price as u128) / PRICE_SCALE as u128;
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

        // Store in pending queue
        self.store_pending_order(order_id, &order);

        // Emit OrderPlaced event
        self.storage
            .emit_event(
                self.address,
                StablecoinDexEvent::OrderPlaced(IStablecoinDex::OrderPlaced {
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
    ) -> Result<u128, StablecoinDexError> {
        // Lookup quote token (linking token) from TIP20 token
        let quote_token =
            TIP20Token::new(address_to_token_id_unchecked(&token), self.storage).linking_token();

        // Compute book_key from token pair
        let book_key = self.compute_book_key(token, quote_token);

        // Validate tick and flip_tick are within bounds
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinDexError::tick_out_of_bounds(tick));
        }
        if !(MIN_TICK..=MAX_TICK).contains(&flip_tick) {
            return Err(StablecoinDexError::tick_out_of_bounds(flip_tick));
        }

        // Validate flip_tick relationship to tick based on order side
        if (is_bid && flip_tick <= tick) || (!is_bid && flip_tick >= tick) {
            return Err(StablecoinDexError::invalid_flip_tick());
        }

        // Calculate escrow amount and token based on order side
        let (escrow_token, escrow_amount) = if is_bid {
            // For bids, escrow quote tokens based on price
            let price = tick_to_price(tick);
            let quote_amount = (amount * price as u128) / PRICE_SCALE as u128;
            (quote_token, quote_amount)
        } else {
            // For asks, escrow base tokens
            (token, amount)
        };

        // Debit from user's balance or transfer from wallet
        self.decrement_balance_or_transfer_from(*sender, escrow_token, escrow_amount)?;

        // Create the flip order (with validation)
        let order_id = self.get_and_increment_pending_order_id();
        let side = if is_bid { Side::Bid } else { Side::Ask };
        let order = Order::new_flip(order_id, *sender, book_key, amount, side, tick, flip_tick)
            .expect("Invalid flip tick");

        // Store in pending queue
        self.store_pending_order(order_id, &order);

        // Emit FlipOrderPlaced event
        self.storage
            .emit_event(
                self.address,
                StablecoinDexEvent::FlipOrderPlaced(IStablecoinDex::FlipOrderPlaced {
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
    pub fn execute_block(&mut self) {
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
    }

    /// Process a single pending order into the active orderbook
    fn process_pending_order(&mut self, order_id: u128) {
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);

        let maker = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_MAKER_OFFSET)
            .expect("TODO: handle error");
        if maker == U256::ZERO {
            return;
        }

        let book_key = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_BOOK_KEY_OFFSET)
            .expect("TODO: handle error");

        let side_u256 = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_SIDE_OFFSET)
            .expect("TODO: handle error");
        let is_bid = side_u256 == U256::ZERO;

        let tick = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_TICK_OFFSET)
            .expect("TODO: handle error")
            .to::<i16>();

        let remaining = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_REMAINING_OFFSET)
            .expect("TODO: handle error")
            .to::<u128>();

        let orderbook =
            orderbook::Orderbook::load(self.storage, self.address, B256::from(book_key));
        let mut level = orderbook::TickLevel::load(
            self.storage,
            self.address,
            B256::from(book_key),
            tick,
            is_bid,
        );

        let prev_tail = level.tail;
        if prev_tail == 0 {
            level.head = order_id;
            level.tail = order_id;

            let mut bitmap =
                orderbook::TickBitmap::new(self.storage, self.address, B256::from(book_key));
            bitmap.set_tick_bit(tick, is_bid);

            if is_bid {
                if tick > orderbook.best_bid_tick {
                    orderbook::Orderbook::update_best_bid_tick(
                        self.storage,
                        self.address,
                        B256::from(book_key),
                        tick,
                    );
                }
            } else if tick < orderbook.best_ask_tick {
                orderbook::Orderbook::update_best_ask_tick(
                    self.storage,
                    self.address,
                    B256::from(book_key),
                    tick,
                );
            }
        } else {
            let prev_tail_slot = mapping_slot(prev_tail.to_be_bytes(), slots::ORDERS);
            self.storage
                .sstore(
                    self.address,
                    prev_tail_slot + offsets::ORDER_NEXT_OFFSET,
                    U256::from(order_id),
                )
                .expect("TODO: handle error");

            self.storage
                .sstore(
                    self.address,
                    order_slot + offsets::ORDER_PREV_OFFSET,
                    U256::from(prev_tail),
                )
                .expect("TODO: handle error");

            level.tail = order_id;
        }

        level.total_liquidity += remaining;
        level.store(
            self.storage,
            self.address,
            B256::from(book_key),
            tick,
            is_bid,
        );
    }

    /// Fill an order and handle cleanup when fully filled
    /// Returns the next order ID to process (0 if no more liquidity at this tick)
    #[allow(dead_code)]
    fn fill_order(&mut self, order_id: u128, fill_amount: u128) -> u128 {
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);

        let book_key = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_BOOK_KEY_OFFSET)
            .expect("TODO: handle error");

        let side_u256 = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_SIDE_OFFSET)
            .expect("TODO: handle error");
        let is_bid = side_u256 == U256::ZERO;

        let tick = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_TICK_OFFSET)
            .expect("TODO: handle error")
            .to::<i16>();

        let remaining = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_REMAINING_OFFSET)
            .expect("TODO: handle error")
            .to::<u128>();

        let maker = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_MAKER_OFFSET)
            .expect("TODO: handle error")
            .into_address();

        let orderbook =
            orderbook::Orderbook::load(self.storage, self.address, B256::from(book_key));
        let mut level = orderbook::TickLevel::load(
            self.storage,
            self.address,
            B256::from(book_key),
            tick,
            is_bid,
        );

        let new_remaining = remaining - fill_amount;
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_REMAINING_OFFSET,
                U256::from(new_remaining),
            )
            .expect("TODO: handle error");

        level.total_liquidity -= fill_amount;

        if is_bid {
            self.add_balance(maker, orderbook.base, fill_amount);
        } else {
            let price = orderbook::tick_to_price(tick);
            let quote_amount = (fill_amount * price as u128) / orderbook::PRICE_SCALE as u128;
            self.add_balance(maker, orderbook.quote, quote_amount);
        }

        if new_remaining == 0 {
            // Check if this is a flip order before removing it
            let is_flip = self
                .storage
                .sload(self.address, order_slot + offsets::ORDER_IS_FLIP_OFFSET)
                .expect("TODO: handle error");

            if is_flip != U256::ZERO {
                // Get the flip tick and original amount
                let flip_tick = self
                    .storage
                    .sload(self.address, order_slot + offsets::ORDER_FLIP_TICK_OFFSET)
                    .expect("TODO: handle error")
                    .to::<i16>();

                let original_amount = self
                    .storage
                    .sload(self.address, order_slot + offsets::ORDER_AMOUNT_OFFSET)
                    .expect("TODO: handle error")
                    .to::<u128>();

                // Create a new flip order with flipped side and swapped ticks
                // Bid becomes Ask, Ask becomes Bid
                // The current tick becomes the new flip_tick, and flip_tick becomes the new tick
                let new_order_id = self.get_and_increment_pending_order_id();
                let new_side = if is_bid { Side::Ask } else { Side::Bid };

                let new_order = Order::new_flip(
                    new_order_id,
                    maker,
                    B256::from(book_key),
                    original_amount,
                    new_side,
                    flip_tick, // New tick is the old flip_tick
                    tick,      // New flip_tick is the old tick
                )
                .expect("Invalid flip order");

                self.store_pending_order(new_order_id, &new_order);
            }

            let next = self
                .storage
                .sload(self.address, order_slot + offsets::ORDER_NEXT_OFFSET)
                .expect("TODO: handle error")
                .to::<u128>();

            let prev = self
                .storage
                .sload(self.address, order_slot + offsets::ORDER_PREV_OFFSET)
                .expect("TODO: handle error")
                .to::<u128>();

            if prev != 0 {
                let prev_slot = mapping_slot(prev.to_be_bytes(), slots::ORDERS);
                self.storage
                    .sstore(
                        self.address,
                        prev_slot + offsets::ORDER_NEXT_OFFSET,
                        U256::from(next),
                    )
                    .expect("TODO: handle error");
            } else {
                level.head = next;
            }

            if next != 0 {
                let next_slot = mapping_slot(next.to_be_bytes(), slots::ORDERS);
                self.storage
                    .sstore(
                        self.address,
                        next_slot + offsets::ORDER_PREV_OFFSET,
                        U256::from(prev),
                    )
                    .expect("TODO: handle error");
            } else {
                level.tail = prev;
            }

            self.storage
                .sstore(
                    self.address,
                    order_slot + offsets::ORDER_MAKER_OFFSET,
                    U256::ZERO,
                )
                .expect("TODO: handle error");

            if level.head == 0 {
                let mut bitmap =
                    orderbook::TickBitmap::new(self.storage, self.address, B256::from(book_key));
                bitmap.clear_tick_bit(tick, is_bid);
                level.store(
                    self.storage,
                    self.address,
                    B256::from(book_key),
                    tick,
                    is_bid,
                );
                return 0;
            }

            level.store(
                self.storage,
                self.address,
                B256::from(book_key),
                tick,
                is_bid,
            );
            next
        } else {
            level.store(
                self.storage,
                self.address,
                B256::from(book_key),
                tick,
                is_bid,
            );
            order_id
        }
    }

    /// Fill orders for exact output amount
    #[allow(dead_code)]
    fn fill_orders_exact_out(
        &mut self,
        book_key: B256,
        base_for_quote: bool,
        amount_out: u128,
        max_amount_in: u128,
    ) -> Result<u128, StablecoinDexError> {
        let mut remaining_out = amount_out;
        let mut amount_in = 0u128;
        let orderbook = orderbook::Orderbook::load(self.storage, self.address, book_key);

        if base_for_quote {
            let mut current_tick = orderbook.best_bid_tick;
            if current_tick == i16::MIN {
                return Err(StablecoinDexError::insufficient_liquidity());
            }

            let mut level = orderbook::TickLevel::load(
                self.storage,
                self.address,
                book_key,
                current_tick,
                true,
            );
            let mut order_id = level.head;

            while remaining_out > 0 {
                let price = orderbook::tick_to_price(current_tick);

                let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);
                let order_remaining = self
                    .storage
                    .sload(self.address, order_slot + offsets::ORDER_REMAINING_OFFSET)
                    .expect("TODO: handle error")
                    .to::<u128>();

                let base_needed = (remaining_out * orderbook::PRICE_SCALE as u128) / price as u128;
                let fill_amount = if base_needed > order_remaining {
                    order_remaining
                } else {
                    base_needed
                };

                if amount_in + fill_amount > max_amount_in {
                    return Err(StablecoinDexError::max_input_exceeded());
                }

                remaining_out -= (fill_amount * price as u128) / orderbook::PRICE_SCALE as u128;
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
                        return Err(StablecoinDexError::insufficient_liquidity());
                    }

                    current_tick = next_tick;
                    orderbook::Orderbook::update_best_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    level = orderbook::TickLevel::load(
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
                return Err(StablecoinDexError::insufficient_liquidity());
            }

            let mut level = orderbook::TickLevel::load(
                self.storage,
                self.address,
                book_key,
                current_tick,
                false,
            );
            let mut order_id = level.head;

            while remaining_out > 0 {
                let price = orderbook::tick_to_price(current_tick);

                let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);
                let order_remaining = self
                    .storage
                    .sload(self.address, order_slot + offsets::ORDER_REMAINING_OFFSET)
                    .expect("TODO: handle error")
                    .to::<u128>();

                let fill_amount = if remaining_out > order_remaining {
                    order_remaining
                } else {
                    remaining_out
                };
                let quote_in = (fill_amount * price as u128) / orderbook::PRICE_SCALE as u128;

                if amount_in + quote_in > max_amount_in {
                    return Err(StablecoinDexError::max_input_exceeded());
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
                        return Err(StablecoinDexError::insufficient_liquidity());
                    }

                    current_tick = next_tick;
                    orderbook::Orderbook::update_best_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    level = orderbook::TickLevel::load(
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

    /// Fill orders for exact input amount
    #[allow(dead_code)]
    fn fill_orders_exact_in(
        &mut self,
        book_key: B256,
        base_for_quote: bool,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<u128, StablecoinDexError> {
        let mut remaining_in = amount_in;
        let mut amount_out = 0u128;
        let orderbook = orderbook::Orderbook::load(self.storage, self.address, book_key);

        if base_for_quote {
            let mut current_tick = orderbook.best_bid_tick;
            if current_tick == i16::MIN {
                return Err(StablecoinDexError::insufficient_liquidity());
            }

            let mut level = orderbook::TickLevel::load(
                self.storage,
                self.address,
                book_key,
                current_tick,
                true,
            );
            let mut order_id = level.head;

            while remaining_in > 0 {
                let price = orderbook::tick_to_price(current_tick);

                let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);
                let order_remaining = self
                    .storage
                    .sload(self.address, order_slot + offsets::ORDER_REMAINING_OFFSET)
                    .expect("TODO: handle error")
                    .to::<u128>();

                let fill_amount = if remaining_in > order_remaining {
                    order_remaining
                } else {
                    remaining_in
                };
                let quote_out = (fill_amount * price as u128) / orderbook::PRICE_SCALE as u128;

                remaining_in -= fill_amount;
                amount_out += quote_out;

                order_id = self.fill_order(order_id, fill_amount);

                if remaining_in == 0 {
                    if amount_out < min_amount_out {
                        return Err(StablecoinDexError::insufficient_output());
                    }
                    return Ok(amount_out);
                }

                if order_id == 0 {
                    let mut bitmap =
                        orderbook::TickBitmap::new(self.storage, self.address, book_key);
                    let (next_tick, initialized) = bitmap.next_initialized_bid_tick(current_tick);
                    if !initialized {
                        return Err(StablecoinDexError::insufficient_liquidity());
                    }

                    current_tick = next_tick;
                    orderbook::Orderbook::update_best_bid_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    level = orderbook::TickLevel::load(
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
                return Err(StablecoinDexError::insufficient_liquidity());
            }

            let mut level = orderbook::TickLevel::load(
                self.storage,
                self.address,
                book_key,
                current_tick,
                false,
            );
            let mut order_id = level.head;

            while remaining_in > 0 {
                let price = orderbook::tick_to_price(current_tick);

                let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);
                let order_remaining = self
                    .storage
                    .sload(self.address, order_slot + offsets::ORDER_REMAINING_OFFSET)
                    .expect("TODO: handle error")
                    .to::<u128>();

                let base_out = (remaining_in * orderbook::PRICE_SCALE as u128) / price as u128;
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
                        return Err(StablecoinDexError::insufficient_output());
                    }
                    return Ok(amount_out);
                }

                if order_id == 0 {
                    let mut bitmap =
                        orderbook::TickBitmap::new(self.storage, self.address, book_key);
                    let (next_tick, initialized) = bitmap.next_initialized_ask_tick(current_tick);
                    if !initialized {
                        return Err(StablecoinDexError::insufficient_liquidity());
                    }

                    current_tick = next_tick;
                    orderbook::Orderbook::update_best_ask_tick(
                        self.storage,
                        self.address,
                        book_key,
                        current_tick,
                    );
                    level = orderbook::TickLevel::load(
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
    pub fn cancel(&mut self, sender: &Address, order_id: u128) -> Result<(), StablecoinDexError> {
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);

        let maker = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_MAKER_OFFSET)
            .expect("TODO: handle error")
            .into_address();

        if maker.is_zero() {
            return Err(StablecoinDexError::order_does_not_exist());
        }

        if maker != *sender {
            return Err(StablecoinDexError::unauthorized());
        }

        let book_key = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_BOOK_KEY_OFFSET)
            .expect("TODO: handle error");

        let side_u256 = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_SIDE_OFFSET)
            .expect("TODO: handle error");
        let is_bid = side_u256 == U256::ZERO;

        let tick = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_TICK_OFFSET)
            .expect("TODO: handle error")
            .to::<i16>();

        let remaining = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_REMAINING_OFFSET)
            .expect("TODO: handle error")
            .to::<u128>();

        if remaining == 0 {
            return Err(StablecoinDexError::order_does_not_exist());
        }

        // Check if the order is still pending (not yet in active orderbook)
        let next_order_id = self
            .storage
            .sload(self.address, slots::NEXT_ORDER_ID)
            .expect("TODO: handle error")
            .to::<u128>();

        // If the order is pending, delete it without touching the orderbook
        if order_id > next_order_id {
            let orderbook =
                orderbook::Orderbook::load(self.storage, self.address, B256::from(book_key));
            let token = if is_bid {
                orderbook.quote
            } else {
                orderbook.base
            };

            // For bids, calculate quote amount to refund; for asks, refund base amount
            let refund_amount = if is_bid {
                let price = orderbook::tick_to_price(tick);
                (remaining * price as u128) / orderbook::PRICE_SCALE as u128
            } else {
                remaining
            };

            // Credit remaining tokens to user's withdrawable balance
            self.add_balance(maker, token, refund_amount);

            // Clear the order from storage
            self.storage
                .sstore(
                    self.address,
                    order_slot + offsets::ORDER_MAKER_OFFSET,
                    U256::ZERO,
                )
                .expect("TODO: handle error");

            // Emit OrderCancelled event
            self.storage
                .emit_event(
                    self.address,
                    StablecoinDexEvent::OrderCancelled(IStablecoinDex::OrderCancelled {
                        orderId: order_id,
                    })
                    .into_log_data(),
                )
                .expect("Event emission failed");

            return Ok(());
        }

        let prev = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_PREV_OFFSET)
            .expect("TODO: handle error")
            .to::<u128>();

        let next = self
            .storage
            .sload(self.address, order_slot + offsets::ORDER_NEXT_OFFSET)
            .expect("TODO: handle error")
            .to::<u128>();

        let mut level = orderbook::TickLevel::load(
            self.storage,
            self.address,
            B256::from(book_key),
            tick,
            is_bid,
        );

        // Update linked list
        if prev != 0 {
            let prev_slot = mapping_slot(prev.to_be_bytes(), slots::ORDERS);
            self.storage
                .sstore(
                    self.address,
                    prev_slot + offsets::ORDER_NEXT_OFFSET,
                    U256::from(next),
                )
                .expect("TODO: handle error");
        } else {
            level.head = next;
        }

        if next != 0 {
            let next_slot = mapping_slot(next.to_be_bytes(), slots::ORDERS);
            self.storage
                .sstore(
                    self.address,
                    next_slot + offsets::ORDER_PREV_OFFSET,
                    U256::from(prev),
                )
                .expect("TODO: handle error");
        } else {
            level.tail = prev;
        }

        // Update level liquidity
        level.total_liquidity -= remaining;

        // If this was the last order at this tick, clear the bitmap bit
        if level.head == 0 {
            let mut bitmap =
                orderbook::TickBitmap::new(self.storage, self.address, B256::from(book_key));
            bitmap.clear_tick_bit(tick, is_bid);
        }

        level.store(
            self.storage,
            self.address,
            B256::from(book_key),
            tick,
            is_bid,
        );

        // Clear the order from storage
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_MAKER_OFFSET,
                U256::ZERO,
            )
            .expect("TODO: handle error");

        // Refund tokens to maker
        let orderbook =
            orderbook::Orderbook::load(self.storage, self.address, B256::from(book_key));
        if is_bid {
            // Bid orders are in quote token, refund quote amount
            let price = orderbook::tick_to_price(tick);
            let quote_amount = (remaining * price as u128) / orderbook::PRICE_SCALE as u128;
            self.add_balance(maker, orderbook.quote, quote_amount);
        } else {
            // Ask orders are in base token, refund base amount
            self.add_balance(maker, orderbook.base, remaining);
        }

        // Emit OrderCancelled event
        self.storage
            .emit_event(
                self.address,
                StablecoinDexEvent::OrderCancelled(IStablecoinDex::OrderCancelled {
                    orderId: order_id,
                })
                .into_log_data(),
            )
            .expect("Event emission failed");

        Ok(())
    }

    /// Withdraw tokens from exchange balance
    pub fn withdraw(&mut self, user: Address, token: Address, amount: u128) {
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
        let dex = StablecoinDex {
            address: STABLECOIN_DEX_ADDRESS,
            storage: &mut { storage },
        };

        let token_a = address!("0x1111111111111111111111111111111111111111");
        let token_b = address!("0x2222222222222222222222222222222222222222");

        // Key should be the same regardless of input order
        let key_ab = dex.compute_book_key(token_a, token_b);
        let key_ba = dex.compute_book_key(token_b, token_a);

        assert_eq!(key_ab, key_ba, "Book key should be deterministic");
    }

    #[test]
    fn test_compute_book_key_matches_expected_hash() {
        let storage = HashMapStorageProvider::new(1);
        let dex = StablecoinDex {
            address: STABLECOIN_DEX_ADDRESS,
            storage: &mut { storage },
        };

        // Use specific addresses to verify the hash
        let token_a = address!("0x1111111111111111111111111111111111111111");
        let token_b = address!("0x2222222222222222222222222222222222222222");

        let key = dex.compute_book_key(token_a, token_b);

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
}
