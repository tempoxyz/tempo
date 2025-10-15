//! Orderbook and tick level management for the stablecoin DEX.

use super::{
    OrderError, offsets,
    slots::{ASK_BITMAPS, ASK_TICK_LEVELS, BID_BITMAPS, BID_TICK_LEVELS, ORDERBOOKS},
};
use crate::contracts::{StorageProvider, storage::slots::mapping_slot};
use alloy::primitives::{Address, B256, U256};
use revm::interpreter::instructions::utility::{IntoAddress, IntoU256};

/// Constants from Solidity implementation
pub const MIN_TICK: i16 = -2000;
pub const MAX_TICK: i16 = 2000;
pub const PRICE_SCALE: u32 = 100_000;

/// Represents a price level in the orderbook with a doubly-linked list of orders
/// Orders are maintained in FIFO order at each tick level
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickLevel {
    // TODO: add tick
    // TODO: add bid or ask
    // TODO: add book key
    //
    //
    /// Order ID of the first order at this tick (0 if empty)
    pub head: u128,
    /// Order ID of the last order at this tick (0 if empty)
    pub tail: u128,
    /// Total liquidity available at this tick level
    pub total_liquidity: u128,
}

impl TickLevel {
    /// Creates a new empty tick level
    pub fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            total_liquidity: 0,
        }
    }

    /// Returns true if this tick level has no orders
    pub fn is_empty(&self) -> bool {
        self.head == 0 && self.tail == 0
    }

    /// Returns true if this tick level has orders
    pub fn has_liquidity(&self) -> bool {
        !self.is_empty()
    }

    /// Load a TickLevel from storage
    pub fn from_storage<S: StorageProvider>(
        storage: &mut S,
        address: Address,
        book_key: B256,
        tick: i16,
        is_bid: bool,
    ) -> Self {
        let base_slot = if is_bid {
            BID_TICK_LEVELS
        } else {
            ASK_TICK_LEVELS
        };

        // Create nested mapping slot: mapping(book_key => mapping(tick => TickLevel))
        let book_key_slot = mapping_slot(book_key.as_slice(), base_slot);
        let tick_level_slot = mapping_slot(tick.to_be_bytes(), book_key_slot);

        // Load each field
        let head = storage
            .sload(address, tick_level_slot + offsets::TICK_LEVEL_HEAD_OFFSET)
            .expect("TODO: handle error")
            .to::<u128>();

        let tail = storage
            .sload(address, tick_level_slot + offsets::TICK_LEVEL_TAIL_OFFSET)
            .expect("TODO: handle error")
            .to::<u128>();

        let total_liquidity = storage
            .sload(
                address,
                tick_level_slot + offsets::TICK_LEVEL_TOTAL_LIQUIDITY_OFFSET,
            )
            .expect("TODO: handle error")
            .to::<u128>();

        Self {
            head,
            tail,
            total_liquidity,
        }
    }

    /// Store this TickLevel to storage
    pub fn store<S: StorageProvider>(
        &self,
        storage: &mut S,
        address: Address,
        book_key: B256,
        tick: i16,
        is_bid: bool,
    ) {
        let base_slot = if is_bid {
            BID_TICK_LEVELS
        } else {
            ASK_TICK_LEVELS
        };

        // Create nested mapping slot: mapping(book_key => mapping(tick => TickLevel))
        let book_key_slot = mapping_slot(book_key.as_slice(), base_slot);
        let tick_level_slot = mapping_slot(tick.to_be_bytes(), book_key_slot);

        // Store each field
        storage
            .sstore(
                address,
                tick_level_slot + offsets::TICK_LEVEL_HEAD_OFFSET,
                U256::from(self.head),
            )
            .expect("TODO: handle error");

        storage
            .sstore(
                address,
                tick_level_slot + offsets::TICK_LEVEL_TAIL_OFFSET,
                U256::from(self.tail),
            )
            .expect("TODO: handle error");

        storage
            .sstore(
                address,
                tick_level_slot + offsets::TICK_LEVEL_TOTAL_LIQUIDITY_OFFSET,
                U256::from(self.total_liquidity),
            )
            .expect("TODO: handle error");
    }

    /// Update only the head order ID
    pub fn update_head<S: StorageProvider>(
        storage: &mut S,
        address: Address,
        book_key: B256,
        tick: i16,
        is_bid: bool,
        new_head: u128,
    ) {
        let base_slot = if is_bid {
            BID_TICK_LEVELS
        } else {
            ASK_TICK_LEVELS
        };
        let book_key_slot = mapping_slot(book_key.as_slice(), base_slot);
        let tick_level_slot = mapping_slot(tick.to_be_bytes(), book_key_slot);

        storage
            .sstore(
                address,
                tick_level_slot + offsets::TICK_LEVEL_HEAD_OFFSET,
                U256::from(new_head),
            )
            .expect("TODO: handle error");
    }

    /// Update only the tail order ID
    pub fn update_tail<S: StorageProvider>(
        storage: &mut S,
        address: Address,
        book_key: B256,
        tick: i16,
        is_bid: bool,
        new_tail: u128,
    ) {
        let base_slot = if is_bid {
            BID_TICK_LEVELS
        } else {
            ASK_TICK_LEVELS
        };
        let book_key_slot = mapping_slot(book_key.as_slice(), base_slot);
        let tick_level_slot = mapping_slot(tick.to_be_bytes(), book_key_slot);

        storage
            .sstore(
                address,
                tick_level_slot + offsets::TICK_LEVEL_TAIL_OFFSET,
                U256::from(new_tail),
            )
            .expect("TODO: handle error");
    }

    /// Update only the total liquidity
    pub fn update_total_liquidity<S: StorageProvider>(
        storage: &mut S,
        address: Address,
        book_key: B256,
        tick: i16,
        is_bid: bool,
        new_total: u128,
    ) {
        let base_slot = if is_bid {
            BID_TICK_LEVELS
        } else {
            ASK_TICK_LEVELS
        };
        let book_key_slot = mapping_slot(book_key.as_slice(), base_slot);
        let tick_level_slot = mapping_slot(tick.to_be_bytes(), book_key_slot);

        storage
            .sstore(
                address,
                tick_level_slot + offsets::TICK_LEVEL_TOTAL_LIQUIDITY_OFFSET,
                U256::from(new_total),
            )
            .expect("TODO: handle error");
    }
}

impl Default for TickLevel {
    fn default() -> Self {
        Self::new()
    }
}

/// Orderbook for token pair with price-time priority
/// Uses tick-based pricing with bitmaps for price discovery
#[derive(Debug)]
pub struct Orderbook {
    /// Base token address
    pub base: Address,
    /// Quote token address
    pub quote: Address,
    /// Best bid tick for highest bid price
    pub best_bid_tick: i16,
    /// Best ask tick for lowest ask price
    pub best_ask_tick: i16,
}

impl Orderbook {
    /// Creates a new orderbook for a token pair
    pub fn new(base: Address, quote: Address) -> Self {
        Self {
            base,
            quote,
            best_bid_tick: i16::MIN,
            best_ask_tick: i16::MAX,
        }
    }

    /// Returns true if this orderbook is initialized
    pub fn is_initialized(&self) -> bool {
        self.base != Address::ZERO
    }

    /// Load an Orderbook from storage
    pub fn from_storage<S: StorageProvider>(
        storage: &mut S,
        address: Address,
        book_key: B256,
    ) -> Self {
        let orderbook_slot = mapping_slot(book_key.as_slice(), ORDERBOOKS);

        let base = storage
            .sload(address, orderbook_slot + offsets::ORDERBOOK_BASE_OFFSET)
            .expect("TODO: handle error")
            .into_address();

        let quote = storage
            .sload(address, orderbook_slot + offsets::ORDERBOOK_QUOTE_OFFSET)
            .expect("TODO: handle error")
            .into_address();

        let best_bid_tick = storage
            .sload(
                address,
                orderbook_slot + offsets::ORDERBOOK_BEST_BID_TICK_OFFSET,
            )
            .expect("TODO: handle error")
            .to::<i16>();

        let best_ask_tick = storage
            .sload(
                address,
                orderbook_slot + offsets::ORDERBOOK_BEST_ASK_TICK_OFFSET,
            )
            .expect("TODO: handle error")
            .to::<i16>();

        Self {
            base,
            quote,
            best_bid_tick,
            best_ask_tick,
        }
    }

    /// Store this Orderbook to storage
    pub fn store<S: StorageProvider>(&self, storage: &mut S, address: Address, book_key: B256) {
        let orderbook_slot = mapping_slot(book_key.as_slice(), ORDERBOOKS);

        storage
            .sstore(
                address,
                orderbook_slot + offsets::ORDERBOOK_BASE_OFFSET,
                self.base.into_u256(),
            )
            .expect("TODO: handle error");

        storage
            .sstore(
                address,
                orderbook_slot + offsets::ORDERBOOK_QUOTE_OFFSET,
                self.quote.into_u256(),
            )
            .expect("TODO: handle error");

        storage
            .sstore(
                address,
                orderbook_slot + offsets::ORDERBOOK_BEST_BID_TICK_OFFSET,
                U256::from(self.best_bid_tick as u16),
            )
            .expect("TODO: handle error");

        storage
            .sstore(
                address,
                orderbook_slot + offsets::ORDERBOOK_BEST_ASK_TICK_OFFSET,
                U256::from(self.best_ask_tick as u16),
            )
            .expect("TODO: handle error");
    }

    /// Update only the best bid tick
    pub fn update_best_bid_tick<S: StorageProvider>(
        storage: &mut S,
        address: Address,
        book_key: B256,
        new_best_bid: i16,
    ) {
        let orderbook_slot = mapping_slot(book_key.as_slice(), ORDERBOOKS);
        storage
            .sstore(
                address,
                orderbook_slot + offsets::ORDERBOOK_BEST_BID_TICK_OFFSET,
                U256::from(new_best_bid as u16),
            )
            .expect("TODO: handle error");
    }

    /// Update only the best ask tick
    pub fn update_best_ask_tick<S: StorageProvider>(
        storage: &mut S,
        address: Address,
        book_key: B256,
        new_best_ask: i16,
    ) {
        let orderbook_slot = mapping_slot(book_key.as_slice(), ORDERBOOKS);
        storage
            .sstore(
                address,
                orderbook_slot + offsets::ORDERBOOK_BEST_ASK_TICK_OFFSET,
                U256::from(new_best_ask as u16),
            )
            .expect("TODO: handle error");
    }

    /// Check if this orderbook exists in storage
    pub fn exists<S: StorageProvider>(storage: &mut S, address: Address, book_key: B256) -> bool {
        let orderbook_slot = mapping_slot(book_key.as_slice(), ORDERBOOKS);
        let base = storage
            .sload(address, orderbook_slot + offsets::ORDERBOOK_BASE_OFFSET)
            .expect("TODO: handle error");
        base != U256::ZERO
    }
}

/// Tick bitmap manager for efficient price discovery
pub struct TickBitmap<'a, S: StorageProvider> {
    storage: &'a mut S,
    address: Address,
    book_key: B256,
}

impl<'a, S: StorageProvider> TickBitmap<'a, S> {
    pub fn new(storage: &'a mut S, address: Address, book_key: B256) -> Self {
        Self {
            storage,
            address,
            book_key,
        }
    }

    /// Set bit in bitmap to mark tick as active
    pub fn set_tick_bit(&mut self, tick: i16, is_bid: bool) -> Result<(), OrderError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(OrderError::InvalidTick {
                tick,
                min: MIN_TICK,
                max: MAX_TICK,
            });
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        // Casting negative i16 to u8 wraps incorrectly (e.g., -100 as u8 = 156)
        let bit_index = (tick & 0xFF) as usize;
        let mask = U256::from(1u8) << bit_index;

        // Get storage slot for this word in the bitmap
        let bitmap_slot = self.get_bitmap_slot(word_index, is_bid);
        let current_word = self
            .storage
            .sload(self.address, bitmap_slot)
            .expect("TODO: handle error");

        // Set the bit
        let new_word = current_word | mask;
        self.storage
            .sstore(self.address, bitmap_slot, new_word)
            .expect("TODO: handle error");

        Ok(())
    }

    /// Clear bit in bitmap to mark tick as inactive
    pub fn clear_tick_bit(&mut self, tick: i16, is_bid: bool) -> Result<(), OrderError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(OrderError::InvalidTick {
                tick,
                min: MIN_TICK,
                max: MAX_TICK,
            });
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        // Casting negative i16 to u8 wraps incorrectly (e.g., -100 as u8 = 156)
        let bit_index = (tick & 0xFF) as usize;
        let mask = !(U256::from(1u8) << bit_index);

        // Get storage slot for this word in the bitmap
        let bitmap_slot = self.get_bitmap_slot(word_index, is_bid);
        let current_word = self
            .storage
            .sload(self.address, bitmap_slot)
            .expect("TODO: handle error");

        // Clear the bit
        let new_word = current_word & mask;
        self.storage
            .sstore(self.address, bitmap_slot, new_word)
            .expect("TODO: handle error");

        Ok(())
    }

    /// Check if a tick is initialized (has orders)
    pub fn is_tick_initialized(&mut self, tick: i16, is_bid: bool) -> Result<bool, OrderError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(OrderError::InvalidTick {
                tick,
                min: MIN_TICK,
                max: MAX_TICK,
            });
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        // Casting negative i16 to u8 wraps incorrectly (e.g., -100 as u8 = 156)
        let bit_index = (tick & 0xFF) as usize;
        let mask = U256::from(1u8) << bit_index;

        let bitmap_slot = self.get_bitmap_slot(word_index, is_bid);
        let word = self
            .storage
            .sload(self.address, bitmap_slot)
            .expect("TODO: handle error");

        Ok((word & mask) != U256::ZERO)
    }

    /// Find next initialized ask tick higher than current tick
    pub fn next_initialized_ask_tick(&mut self, tick: i16) -> (i16, bool) {
        let mut next_tick = tick + 1;
        while next_tick <= MAX_TICK {
            if self.is_tick_initialized(next_tick, false).unwrap_or(false) {
                return (next_tick, true);
            }
            next_tick += 1;
        }
        (next_tick, false)
    }

    /// Find next initialized bid tick lower than current tick
    pub fn next_initialized_bid_tick(&mut self, tick: i16) -> (i16, bool) {
        let mut next_tick = tick - 1;
        while next_tick >= MIN_TICK {
            if self.is_tick_initialized(next_tick, true).unwrap_or(false) {
                return (next_tick, true);
            }
            next_tick -= 1;
        }
        (next_tick, false)
    }

    /// Get storage slot for bitmap word
    fn get_bitmap_slot(&self, word_index: i16, is_bid: bool) -> U256 {
        let base_slot = if is_bid { BID_BITMAPS } else { ASK_BITMAPS };

        // Create nested mapping slot: mapping(book_key => mapping(word_index => bitmap_word))
        let book_key_slot = mapping_slot(self.book_key.as_slice(), base_slot);
        mapping_slot(word_index.to_be_bytes(), book_key_slot)
    }
}

/// Convert relative tick to scaled price
pub fn tick_to_price(tick: i16) -> u32 {
    (PRICE_SCALE as i32 + tick as i32) as u32
}

/// Convert scaled price to relative tick
pub fn price_to_tick(price: u32) -> i16 {
    (price as i32 - PRICE_SCALE as i32) as i16
}

/// Find next initialized bid tick lower than current tick
pub fn next_initialized_bid_tick<S: StorageProvider>(
    storage: &mut S,
    address: Address,
    book_key: B256,
    tick: i16,
) -> (i16, bool) {
    let mut bitmap = TickBitmap::new(storage, address, book_key);
    bitmap.next_initialized_bid_tick(tick)
}

/// Find next initialized ask tick higher than current tick
pub fn next_initialized_ask_tick<S: StorageProvider>(
    storage: &mut S,
    address: Address,
    book_key: B256,
    tick: i16,
) -> (i16, bool) {
    let mut bitmap = TickBitmap::new(storage, address, book_key);
    bitmap.next_initialized_ask_tick(tick)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_tick_level_creation() {
        let level = TickLevel::new();
        assert_eq!(level.head, 0);
        assert_eq!(level.tail, 0);
        assert_eq!(level.total_liquidity, 0);
        assert!(level.is_empty());
        assert!(!level.has_liquidity());
    }

    #[test]
    fn test_orderbook_creation() {
        let base = address!("0x1111111111111111111111111111111111111111");
        let quote = address!("0x2222222222222222222222222222222222222222");
        let book = Orderbook::new(base, quote);

        assert_eq!(book.base, base);
        assert_eq!(book.quote, quote);
        assert_eq!(book.best_bid_tick, i16::MIN);
        assert_eq!(book.best_ask_tick, i16::MAX);
        assert!(book.is_initialized());
    }

    #[test]
    fn test_tick_price_conversion() {
        // Test at peg price (tick 0)
        assert_eq!(tick_to_price(0), PRICE_SCALE);
        assert_eq!(price_to_tick(PRICE_SCALE), 0);

        // Test above peg
        assert_eq!(tick_to_price(100), PRICE_SCALE + 100);
        assert_eq!(price_to_tick(PRICE_SCALE + 100), 100);

        // Test below peg
        assert_eq!(tick_to_price(-100), PRICE_SCALE - 100);
        assert_eq!(price_to_tick(PRICE_SCALE - 100), -100);
    }

    #[test]
    fn test_tick_bounds() {
        assert_eq!(MIN_TICK, -2000);
        assert_eq!(MAX_TICK, 2000);

        // Test boundary values
        assert_eq!(tick_to_price(MIN_TICK), PRICE_SCALE - 2000);
        assert_eq!(tick_to_price(MAX_TICK), PRICE_SCALE + 2000);
    }

    mod bitmap_tests {
        use super::*;
        use crate::contracts::HashMapStorageProvider;

        #[test]
        fn test_tick_lifecycle() {
            let mut storage = HashMapStorageProvider::new(1);
            let address = Address::random();
            let book_key = B256::ZERO;

            // Test full lifecycle (set, check, clear, check) for positive and negative ticks
            // Include boundary cases, word boundaries, and various representative values
            let test_ticks = [
                MIN_TICK, -1000, -500, -257, -256, -100, -1, 0, 1, 100, 255, 256, 500, 1000,
                MAX_TICK,
            ];

            for &tick in &test_ticks {
                // Initially not set
                let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
                assert!(
                    !bitmap.is_tick_initialized(tick, true).unwrap(),
                    "Tick {tick} should not be initialized initially"
                );

                // Set the bit
                let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
                bitmap.set_tick_bit(tick, true).unwrap();

                let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
                assert!(
                    bitmap.is_tick_initialized(tick, true).unwrap(),
                    "Tick {tick} should be initialized after set"
                );

                // Clear the bit
                let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
                bitmap.clear_tick_bit(tick, true).unwrap();

                let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
                assert!(
                    !bitmap.is_tick_initialized(tick, true).unwrap(),
                    "Tick {tick} should not be initialized after clear"
                );
            }
        }

        #[test]
        fn test_boundary_ticks() {
            let mut storage = HashMapStorageProvider::new(1);
            let address = Address::random();
            let book_key = B256::ZERO;

            // Test MIN_TICK
            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            bitmap.set_tick_bit(MIN_TICK, true).unwrap();

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            assert!(
                bitmap.is_tick_initialized(MIN_TICK, true).unwrap(),
                "MIN_TICK should be settable"
            );

            // Test MAX_TICK (use different storage for ask side)
            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            bitmap.set_tick_bit(MAX_TICK, false).unwrap();

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            assert!(
                bitmap.is_tick_initialized(MAX_TICK, false).unwrap(),
                "MAX_TICK should be settable"
            );

            // Clear MIN_TICK
            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            bitmap.clear_tick_bit(MIN_TICK, true).unwrap();

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            assert!(
                !bitmap.is_tick_initialized(MIN_TICK, true).unwrap(),
                "MIN_TICK should be clearable"
            );
        }

        #[test]
        fn test_bid_and_ask_separate() {
            let mut storage = HashMapStorageProvider::new(1);
            let address = Address::random();
            let book_key = B256::ZERO;
            let tick = 100;

            // Set as bid
            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            bitmap.set_tick_bit(tick, true).unwrap();

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            assert!(
                bitmap.is_tick_initialized(tick, true).unwrap(),
                "Tick should be initialized for bids"
            );
            assert!(
                !bitmap.is_tick_initialized(tick, false).unwrap(),
                "Tick should not be initialized for asks"
            );

            // Set as ask
            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            bitmap.set_tick_bit(tick, false).unwrap();

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            assert!(
                bitmap.is_tick_initialized(tick, true).unwrap(),
                "Tick should still be initialized for bids"
            );
            assert!(
                bitmap.is_tick_initialized(tick, false).unwrap(),
                "Tick should now be initialized for asks"
            );
        }

        #[test]
        fn test_ticks_across_word_boundary() {
            let mut storage = HashMapStorageProvider::new(1);
            let address = Address::random();
            let book_key = B256::ZERO;

            // Ticks that span word boundary at 256
            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            bitmap.set_tick_bit(255, true).unwrap(); // word_index = 0, bit_index = 255
            bitmap.set_tick_bit(256, true).unwrap(); // word_index = 1, bit_index = 0

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);
            assert!(bitmap.is_tick_initialized(255, true).unwrap());
            assert!(bitmap.is_tick_initialized(256, true).unwrap());
        }

        #[test]
        fn test_ticks_different_words() {
            let mut storage = HashMapStorageProvider::new(1);
            let address = Address::random();
            let book_key = B256::ZERO;

            // Test ticks in different words (both positive and negative)
            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);

            // Negative ticks in different words
            bitmap.set_tick_bit(-1, true).unwrap(); // word_index = -1, bit_index = 255
            bitmap.set_tick_bit(-100, true).unwrap(); // word_index = -1, bit_index = 156
            bitmap.set_tick_bit(-256, true).unwrap(); // word_index = -1, bit_index = 0
            bitmap.set_tick_bit(-257, true).unwrap(); // word_index = -2, bit_index = 255

            // Positive ticks in different words
            bitmap.set_tick_bit(1, true).unwrap(); // word_index = 0, bit_index = 1
            bitmap.set_tick_bit(100, true).unwrap(); // word_index = 0, bit_index = 100
            bitmap.set_tick_bit(256, true).unwrap(); // word_index = 1, bit_index = 0
            bitmap.set_tick_bit(512, true).unwrap(); // word_index = 2, bit_index = 0

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);

            // Verify negative ticks
            assert!(bitmap.is_tick_initialized(-1, true).unwrap());
            assert!(bitmap.is_tick_initialized(-100, true).unwrap());
            assert!(bitmap.is_tick_initialized(-256, true).unwrap());
            assert!(bitmap.is_tick_initialized(-257, true).unwrap());

            // Verify positive ticks
            assert!(bitmap.is_tick_initialized(1, true).unwrap());
            assert!(bitmap.is_tick_initialized(100, true).unwrap());
            assert!(bitmap.is_tick_initialized(256, true).unwrap());
            assert!(bitmap.is_tick_initialized(512, true).unwrap());

            // Verify unset ticks
            assert!(
                !bitmap.is_tick_initialized(-50, true).unwrap(),
                "Unset negative tick should not be initialized"
            );
            assert!(
                !bitmap.is_tick_initialized(50, true).unwrap(),
                "Unset positive tick should not be initialized"
            );
        }

        #[test]
        fn test_set_tick_bit_out_of_bounds() {
            let mut storage = HashMapStorageProvider::new(1);
            let address = Address::random();
            let book_key = B256::ZERO;

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);

            // Test tick above MAX_TICK
            let result = bitmap.set_tick_bit(MAX_TICK + 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                OrderError::InvalidTick { .. }
            ));

            // Test tick below MIN_TICK
            let result = bitmap.set_tick_bit(MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                OrderError::InvalidTick { .. }
            ));
        }

        #[test]
        fn test_clear_tick_bit_out_of_bounds() {
            let mut storage = HashMapStorageProvider::new(1);
            let address = Address::random();
            let book_key = B256::ZERO;

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);

            // Test tick above MAX_TICK
            let result = bitmap.clear_tick_bit(MAX_TICK + 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                OrderError::InvalidTick { .. }
            ));

            // Test tick below MIN_TICK
            let result = bitmap.clear_tick_bit(MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                OrderError::InvalidTick { .. }
            ));
        }

        #[test]
        fn test_is_tick_initialized_out_of_bounds() {
            let mut storage = HashMapStorageProvider::new(1);
            let address = Address::random();
            let book_key = B256::ZERO;

            let mut bitmap = TickBitmap::new(&mut storage, address, book_key);

            // Test tick above MAX_TICK
            let result = bitmap.is_tick_initialized(MAX_TICK + 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                OrderError::InvalidTick { .. }
            ));

            // Test tick below MIN_TICK
            let result = bitmap.is_tick_initialized(MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                OrderError::InvalidTick { .. }
            ));
        }
    }
}
