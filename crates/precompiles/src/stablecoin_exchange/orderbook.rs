//! Orderbook and tick level management for the stablecoin DEX.

use crate::{
    error::TempoPrecompileError,
    stablecoin_exchange::IStablecoinExchange,
    storage::{
        DummySlot, Mapping, PrecompileStorageProvider, Slot, SlotId, StorageOps,
        slots::mapping_slot,
    },
};
use alloy::primitives::{Address, B256, U256, keccak256};
use tempo_contracts::precompiles::StablecoinExchangeError;
use tempo_precompiles_macros::Storable;

/// Constants from Solidity implementation
pub const MIN_TICK: i16 = -2000;
pub const MAX_TICK: i16 = 2000;
pub const PRICE_SCALE: u32 = 100_000;
pub const MIN_PRICE: u32 = 67_232;
pub const MAX_PRICE: u32 = 132_767;

/// Represents a price level in the orderbook with a doubly-linked list of orders
/// Orders are maintained in FIFO order at each tick level
#[derive(Debug, Storable, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickLevel {
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

    /// Creates a tick level with specific values
    pub fn with_values(head: u128, tail: u128, total_liquidity: u128) -> Self {
        Self {
            head,
            tail,
            total_liquidity,
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
}

impl From<TickLevel> for IStablecoinExchange::PriceLevel {
    fn from(value: TickLevel) -> Self {
        Self {
            head: value.head,
            tail: value.tail,
            totalLiquidity: value.total_liquidity,
        }
    }
}

/// Orderbook for token pair with price-time priority
/// Uses tick-based pricing with bitmaps for price discovery
#[derive(Storable, Default)]
pub struct Orderbook {
    /// Base token address
    pub base: Address,
    /// Quote token address
    pub quote: Address,
    /// Bid orders by tick
    #[allow(dead_code)]
    bids: Mapping<i16, TickLevel, DummySlot>,
    /// Ask orders by tick
    #[allow(dead_code)]
    asks: Mapping<i16, TickLevel, DummySlot>,
    /// Best bid tick for highest bid price
    pub best_bid_tick: i16,
    /// Best ask tick for lowest ask price
    pub best_ask_tick: i16,
}

// Helper type to easily access storage for orderbook tokens (base, quote)
type Tokens = Slot<Address, DummySlot>;
// Helper type to easile access storage for orders (bids, asks)
type Orders = Mapping<i16, TickLevel, DummySlot>;
// Helper type to easily access storage for best orderbook orders (best bid, best ask)
type BestOrders = Slot<i16, DummySlot>;

impl Orderbook {
    /// Creates a new orderbook for a token pair
    pub fn new(base: Address, quote: Address) -> Self {
        Self {
            base,
            quote,
            best_bid_tick: i16::MIN,
            best_ask_tick: i16::MAX,
            ..Default::default()
        }
    }

    /// Returns true if this orderbook is initialized
    pub fn is_initialized(&self) -> bool {
        self.base != Address::ZERO
    }

    /// Returns true if the base and quote tokens match the provided base and quote token options.
    pub fn matches_tokens(
        &self,
        base_token: Option<Address>,
        quote_token: Option<Address>,
    ) -> bool {
        // Check base token filter
        if let Some(base) = base_token
            && base != self.base
        {
            return false;
        }

        // Check quote token filter
        if let Some(quote) = quote_token
            && quote != self.quote
        {
            return false;
        }

        true
    }

    /// Update only the best bid tick
    pub fn update_best_bid_tick<S: StorageOps>(
        contract: &mut S,
        book_key: B256,
        new_best_bid: i16,
    ) -> Result<(), TempoPrecompileError> {
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::Field0Slot::SLOT);
        BestOrders::write_at_offset_packed(
            contract,
            orderbook_base_slot,
            __packing_orderbook::BEST_BID_TICK_SLOT,
            __packing_orderbook::BEST_BID_TICK_OFFSET,
            __packing_orderbook::BEST_BID_TICK_BYTES,
            new_best_bid,
        )?;
        Ok(())
    }

    /// Update only the best ask tick
    pub fn update_best_ask_tick<S: StorageOps>(
        contract: &mut S,
        book_key: B256,
        new_best_ask: i16,
    ) -> Result<(), TempoPrecompileError> {
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::Field0Slot::SLOT);
        BestOrders::write_at_offset_packed(
            contract,
            orderbook_base_slot,
            __packing_orderbook::BEST_ASK_TICK_SLOT,
            __packing_orderbook::BEST_ASK_TICK_OFFSET,
            __packing_orderbook::BEST_ASK_TICK_BYTES,
            new_best_ask,
        )?;
        Ok(())
    }

    /// Check if this orderbook exists in storage
    pub fn exists<S: StorageOps>(
        book_key: B256,
        contract: &mut S,
    ) -> Result<bool, TempoPrecompileError> {
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::Field0Slot::SLOT);
        let base = Tokens::read_at_offset(
            contract,
            orderbook_base_slot,
            __packing_orderbook::BASE_SLOT,
        )?;

        Ok(base != Address::ZERO)
    }

    /// Read a `TickLevel` at a specific tick
    pub fn read_tick_level<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        is_bid: bool,
        tick: i16,
    ) -> Result<TickLevel, TempoPrecompileError> {
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::Field0Slot::SLOT);
        if is_bid {
            Orders::read_at_offset(
                storage,
                orderbook_base_slot,
                __packing_orderbook::BIDS_SLOT,
                tick,
            )
        } else {
            Orders::read_at_offset(
                storage,
                orderbook_base_slot,
                __packing_orderbook::ASKS_SLOT,
                tick,
            )
        }
    }

    /// Write a `TickLevel` at a specific tick
    pub fn write_tick_level<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        is_bid: bool,
        tick: i16,
        tick_level: TickLevel,
    ) -> Result<(), TempoPrecompileError> {
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::Field0Slot::SLOT);
        if is_bid {
            Orders::write_at_offset(
                storage,
                orderbook_base_slot,
                __packing_orderbook::BIDS_SLOT,
                tick,
                tick_level,
            )
        } else {
            Orders::write_at_offset(
                storage,
                orderbook_base_slot,
                __packing_orderbook::ASKS_SLOT,
                tick,
                tick_level,
            )
        }
    }

    /// Delete a `TickLevel` at a specific tick
    pub fn delete_tick_level<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        is_bid: bool,
        tick: i16,
    ) -> Result<(), TempoPrecompileError> {
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::Field0Slot::SLOT);
        if is_bid {
            Orders::delete_at_offset(
                storage,
                orderbook_base_slot,
                __packing_orderbook::BIDS_SLOT,
                tick,
            )
        } else {
            Orders::delete_at_offset(
                storage,
                orderbook_base_slot,
                __packing_orderbook::ASKS_SLOT,
                tick,
            )
        }
    }
}

impl From<Orderbook> for IStablecoinExchange::Orderbook {
    fn from(value: Orderbook) -> Self {
        Self {
            base: value.base,
            quote: value.quote,
            bestBidTick: value.best_bid_tick,
            bestAskTick: value.best_ask_tick,
        }
    }
}

/// Tick bitmap manager for efficient price discovery
pub struct TickBitmap<'a, S: PrecompileStorageProvider> {
    storage: &'a mut S,
    address: Address,
    book_key: B256,
}

impl<'a, S: PrecompileStorageProvider> TickBitmap<'a, S> {
    pub fn new(storage: &'a mut S, address: Address, book_key: B256) -> Self {
        Self {
            storage,
            address,
            book_key,
        }
    }

    /// Set bit in bitmap to mark tick as active
    pub fn set_tick_bit(&mut self, tick: i16, is_bid: bool) -> Result<(), TempoPrecompileError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        // Casting negative i16 to u8 wraps incorrectly (e.g., -100 as u8 = 156)
        let bit_index = (tick & 0xFF) as usize;
        let mask = U256::from(1u8) << bit_index;

        // Get storage slot for this word in the bitmap
        let bitmap_slot = self.get_bitmap_slot(word_index, is_bid);
        let current_word = self.storage.sload(self.address, bitmap_slot)?;

        // Set the bit
        let new_word = current_word | mask;
        self.storage.sstore(self.address, bitmap_slot, new_word)?;

        Ok(())
    }

    /// Clear bit in bitmap to mark tick as inactive and update storage
    pub fn clear_tick_bit(&mut self, tick: i16, is_bid: bool) -> Result<(), TempoPrecompileError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        // Casting negative i16 to u8 wraps incorrectly (e.g., -100 as u8 = 156)
        let bit_index = (tick & 0xFF) as usize;
        let mask = !(U256::from(1u8) << bit_index);

        // Get storage slot for this word in the bitmap
        let bitmap_slot = self.get_bitmap_slot(word_index, is_bid);
        let current_word = self.storage.sload(self.address, bitmap_slot)?;

        // Clear the bit
        let new_word = current_word & mask;
        self.storage.sstore(self.address, bitmap_slot, new_word)?;

        Ok(())
    }

    /// Check if a tick is initialized (has orders)
    pub fn is_tick_initialized(
        &mut self,
        tick: i16,
        is_bid: bool,
    ) -> Result<bool, TempoPrecompileError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        // Casting negative i16 to u8 wraps incorrectly (e.g., -100 as u8 = 156)
        let bit_index = (tick & 0xFF) as usize;
        let mask = U256::from(1u8) << bit_index;

        let bitmap_slot = self.get_bitmap_slot(word_index, is_bid);
        let word = self.storage.sload(self.address, bitmap_slot)?;

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
        let base_slot = if is_bid {
            super::slots::Field5Slot::SLOT
        } else {
            super::slots::Field6Slot::SLOT
        };

        let book_key_slot = mapping_slot(self.book_key.as_slice(), base_slot);
        mapping_slot(word_index.to_be_bytes(), book_key_slot)
    }
}

/// Compute deterministic book key from base, quote token pair
pub fn compute_book_key(token_a: Address, token_b: Address) -> B256 {
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

/// Convert relative tick to scaled price
pub fn tick_to_price(tick: i16) -> u32 {
    (PRICE_SCALE as i32 + tick as i32) as u32
}

/// Convert scaled price to relative tick
pub fn price_to_tick(price: u32) -> i16 {
    (price as i32 - PRICE_SCALE as i32) as i16
}

/// Find next initialized bid tick lower than current tick
pub fn next_initialized_bid_tick<S: PrecompileStorageProvider>(
    storage: &mut S,
    address: Address,
    book_key: B256,
    tick: i16,
) -> (i16, bool) {
    let mut bitmap = TickBitmap::new(storage, address, book_key);
    bitmap.next_initialized_bid_tick(tick)
}

/// Find next initialized ask tick higher than current tick
pub fn next_initialized_ask_tick<S: PrecompileStorageProvider>(
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

    #[test]
    fn test_compute_book_key() {
        let token_a = address!("0x1111111111111111111111111111111111111111");
        let token_b = address!("0x2222222222222222222222222222222222222222");

        let key_ab = compute_book_key(token_a, token_b);
        let key_ba = compute_book_key(token_b, token_a);
        assert_eq!(key_ab, key_ba);

        assert_eq!(
            key_ab, key_ba,
            "Book key should be the same regardless of address order"
        );

        let mut buf = [0u8; 40];
        buf[..20].copy_from_slice(token_a.as_slice());
        buf[20..].copy_from_slice(token_b.as_slice());
        let expected_hash = keccak256(buf);

        assert_eq!(
            key_ab, expected_hash,
            "Book key should match manual keccak256 computation"
        );
    }

    mod bitmap_tests {
        use super::*;
        use crate::storage::hashmap::HashMapStorageProvider;

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
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));

            // Test tick below MIN_TICK
            let result = bitmap.set_tick_bit(MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
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
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));

            // Test tick below MIN_TICK
            let result = bitmap.clear_tick_bit(MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
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
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));

            // Test tick below MIN_TICK
            let result = bitmap.is_tick_initialized(MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));
        }
    }
}
