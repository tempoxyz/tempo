//! Stablecoin DEX types and utilities.

pub mod error;
pub mod offsets;
pub mod order;
pub mod slots;

pub use error::OrderError;
pub use order::Order;

use alloy::primitives::{Address, Bytes, IntoLogData, U256};
use revm::{interpreter::instructions::utility::IntoU256, state::Bytecode};

use crate::{
    STABLECOIN_DEX_ADDRESS,
    contracts::{
        StorageProvider,
        storage::{StorageOps, slots::mapping_slot},
        types::{IStablecoinDex, StablecoinDexEvent},
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

    /// Increment and return new pending order ID
    fn increment_pending_order_id(&mut self) -> u128 {
        let current = self.get_pending_order_id();
        let new_id = current + 1;
        self.storage
            .sstore(self.address, slots::PENDING_ORDER_ID, U256::from(new_id))
            .expect("Storage write failed");
        new_id
    }

    /// Store a pending order
    fn store_pending_order(&mut self, order_id: u128, order: &Order) {
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);

        // Store order fields
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_MAKER_OFFSET,
                order.maker().into_u256(),
            )
            .expect("Storage write failed");

        // TODO: Store actual book key (pair_key) once orderbook management is implemented
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_BOOK_KEY_OFFSET,
                order.linking_token().into_u256(),
            )
            .expect("Storage write failed");

        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_SIDE_OFFSET,
                U256::from(order.is_bid() as u8),
            )
            .expect("Storage write failed");

        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_TICK_OFFSET,
                U256::from(order.tick() as i128 as u128), // Cast i16 through i128 to preserve sign
            )
            .expect("Storage write failed");

        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_AMOUNT_OFFSET,
                U256::from(order.amount()),
            )
            .expect("Storage write failed");

        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_REMAINING_OFFSET,
                U256::from(order.amount()),
            )
            .expect("Storage write failed");

        // Store flip order info
        self.storage
            .sstore(
                self.address,
                order_slot + offsets::ORDER_IS_FLIP_OFFSET,
                U256::from(order.is_flip() as u8),
            )
            .expect("Storage write failed");

        if let Some(flip_tick) = order.flip_tick() {
            self.storage
                .sstore(
                    self.address,
                    order_slot + offsets::ORDER_FLIP_TICK_OFFSET,
                    U256::from(flip_tick as i128 as u128),
                )
                .expect("Storage write failed");
        }
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
    // TODO: Implement in follow-up issue - balance management
    pub fn balance_of(&mut self, _user: Address, _token: Address) -> u128 {
        todo!()
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
    ) -> u128 {
        // TODO: Lookup linking token from TIP20 token
        let linking_token = Address::ZERO;

        // TODO: Validate pair exists and tick is within bounds

        // TODO: Balance management - debit from user or transfer from user

        // Create the order
        let order_id = self.increment_pending_order_id();
        let order = if is_bid {
            Order::new_bid(order_id, *sender, token, linking_token, amount, tick)
        } else {
            Order::new_ask(order_id, *sender, token, linking_token, amount, tick)
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

        order_id
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
    ) -> u128 {
        // TODO: Lookup linking token from TIP20 token
        let linking_token = Address::ZERO;

        // TODO: Validate pair exists and both tick and flip_tick are within bounds

        // TODO: Balance management

        // Create the flip order (with validation)
        let order_id = self.increment_pending_order_id();
        let order = Order::new_flip(
            order_id,
            *sender,
            token,
            linking_token,
            amount,
            is_bid,
            tick,
            flip_tick,
        )
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

        order_id
    }

    pub fn cancel(&mut self, _order_id: u128) {
        todo!()
    }

    pub fn withdraw(&mut self, _token: Address, _amount: u128) {
        todo!()
    }
}
