//! Stablecoin DEX types and utilities.

pub mod error;
pub mod offsets;
pub mod order;
pub mod slots;

pub use error::OrderError;
pub use order::{Order, Side};

use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256, keccak256};
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

        // Compute book_key from token pair
        let book_key = self.compute_book_key(token, linking_token);

        // TODO: Validate pair exists and tick is within bounds
        // TODO: Balance management - debit from user or transfer from user

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

        // Compute book_key from token pair
        let book_key = self.compute_book_key(token, linking_token);

        // TODO: Validate pair exists and both tick and flip_tick are within bounds
        // TODO: Balance management

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

        order_id
    }

    pub fn cancel(&mut self, _order_id: u128) {
        todo!()
    }

    pub fn withdraw(&mut self, _token: Address, _amount: u128) {
        todo!()
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
