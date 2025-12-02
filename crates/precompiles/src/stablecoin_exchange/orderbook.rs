//! Orderbook and tick level management for the stablecoin DEX.

use crate::{
    error::TempoPrecompileError,
    stablecoin_exchange::IStablecoinExchange,
    storage::{DummySlot, Mapping, Slot, SlotId, StorageOps, slots::mapping_slot},
};
use alloy::primitives::{Address, B256, U256, keccak256};
use tempo_contracts::precompiles::StablecoinExchangeError;
use tempo_precompiles_macros::Storable;

/// Constants from Solidity implementation
pub const MIN_TICK: i16 = -2000;
pub const MAX_TICK: i16 = 2000;
pub const PRICE_SCALE: u32 = 100_000;

// Pre-moderato: MIN_PRICE and MAX_PRICE covered full i16 range
//
// i16::MIN as price
pub(crate) const MIN_PRICE_PRE_MODERATO: u32 = 67_232;
// i16::MAX as price
pub(crate) const MAX_PRICE_PRE_MODERATO: u32 = 132_767;

// Post-moderato: MIN_PRICE and MAX_PRICE match MIN_TICK and MAX_TICK
//
// PRICE_SCALE + MIN_TICK = 100_000 - 2000
pub(crate) const MIN_PRICE_POST_MODERATO: u32 = 98_000;
// PRICE_SCALE + MAX_TICK = 100_000 + 2000
pub(crate) const MAX_PRICE_POST_MODERATO: u32 = 102_000;

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
        Self { head: 0, tail: 0, total_liquidity: 0 }
    }

    /// Creates a tick level with specific values
    pub fn with_values(head: u128, tail: u128, total_liquidity: u128) -> Self {
        Self { head, tail, total_liquidity }
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
        Self { head: value.head, tail: value.tail, totalLiquidity: value.total_liquidity }
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
    #[allow(dead_code)]
    /// Mapping of tick index to bid bitmap for price discovery
    bid_bitmap: Mapping<i16, U256, DummySlot>,
    /// Mapping of tick index to ask bitmap for price discovery
    #[allow(dead_code)]
    ask_bitmap: Mapping<i16, U256, DummySlot>,
}

// Helper type to easily access storage for orderbook tokens (base, quote)
type Tokens = Slot<Address, DummySlot>;
// Helper type to easily access storage for best orderbook orders (best_bid, best_ask)
type BestOrders = Slot<i16, DummySlot>;
// Helper type to easile access storage for orders (bids, asks)
type Orders = Mapping<i16, TickLevel, DummySlot>;
// Helper type to easily access storage for bitmaps (bid_bitmap, ask_bitmap)
type BitMaps = Mapping<i16, U256, DummySlot>;

impl Orderbook {
    /// Creates a new orderbook for a token pair
    pub fn new(base: Address, quote: Address) -> Self {
        Self { base, quote, best_bid_tick: i16::MIN, best_ask_tick: i16::MAX, ..Default::default() }
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
        if let Some(base) = base_token &&
            base != self.base
        {
            return false;
        }

        // Check quote token filter
        if let Some(quote) = quote_token &&
            quote != self.quote
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
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
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
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
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
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
        let base =
            Tokens::read_at_offset(contract, orderbook_base_slot, __packing_orderbook::BASE_SLOT)?;

        Ok(base != Address::ZERO)
    }

    /// Read a `TickLevel` at a specific tick
    pub fn read_tick_level<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        is_bid: bool,
        tick: i16,
    ) -> Result<TickLevel, TempoPrecompileError> {
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
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
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
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
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
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

    /// Set bit in bitmap to mark tick as active
    pub fn set_tick_bit<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        tick: i16,
        is_bid: bool,
    ) -> Result<(), TempoPrecompileError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        let bit_index = (tick & 0xFF) as usize;
        let mask = U256::from(1u8) << bit_index;

        // Read current bitmap word
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
        let bitmap_slot = if is_bid {
            __packing_orderbook::BID_BITMAP_SLOT
        } else {
            __packing_orderbook::ASK_BITMAP_SLOT
        };
        let current_word =
            BitMaps::read_at_offset(storage, orderbook_base_slot, bitmap_slot, word_index)?;

        // Set the bit
        let new_word = current_word | mask;
        BitMaps::write_at_offset(storage, orderbook_base_slot, bitmap_slot, word_index, new_word)?;

        Ok(())
    }

    /// Clear bit in bitmap to mark tick as inactive
    pub fn clear_tick_bit<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        tick: i16,
        is_bid: bool,
    ) -> Result<(), TempoPrecompileError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        let bit_index = (tick & 0xFF) as usize;
        let mask = !(U256::from(1u8) << bit_index);

        // Read current bitmap word
        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
        let bitmap_slot = if is_bid {
            __packing_orderbook::BID_BITMAP_SLOT
        } else {
            __packing_orderbook::ASK_BITMAP_SLOT
        };
        let current_word =
            BitMaps::read_at_offset(storage, orderbook_base_slot, bitmap_slot, word_index)?;

        // Clear the bit
        let new_word = current_word & mask;
        BitMaps::write_at_offset(storage, orderbook_base_slot, bitmap_slot, word_index, new_word)?;

        Ok(())
    }

    /// Check if a tick is initialized (has orders)
    pub fn is_tick_initialized<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        tick: i16,
        is_bid: bool,
    ) -> Result<bool, TempoPrecompileError> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        let word_index = tick >> 8;
        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        let bit_index = (tick & 0xFF) as usize;
        let mask = U256::from(1u8) << bit_index;

        let orderbook_base_slot = mapping_slot(book_key.as_slice(), super::slots::BooksSlot::SLOT);
        let bitmap_slot = if is_bid {
            __packing_orderbook::BID_BITMAP_SLOT
        } else {
            __packing_orderbook::ASK_BITMAP_SLOT
        };
        let word = BitMaps::read_at_offset(storage, orderbook_base_slot, bitmap_slot, word_index)?;

        Ok((word & mask) != U256::ZERO)
    }

    /// Find next initialized ask tick higher than current tick
    pub fn next_initialized_tick<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        is_bid: bool,
        tick: i16,
    ) -> (i16, bool) {
        if is_bid {
            Self::next_initialized_bid_tick(storage, book_key, tick)
        } else {
            Self::next_initialized_ask_tick(storage, book_key, tick)
        }
    }

    /// Find next initialized ask tick higher than current tick
    fn next_initialized_ask_tick<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        tick: i16,
    ) -> (i16, bool) {
        let mut next_tick = tick + 1;
        while next_tick <= MAX_TICK {
            if Self::is_tick_initialized(storage, book_key, next_tick, false).unwrap_or(false) {
                return (next_tick, true);
            }
            next_tick += 1;
        }
        (next_tick, false)
    }

    /// Find next initialized bid tick lower than current tick
    fn next_initialized_bid_tick<S: StorageOps>(
        storage: &mut S,
        book_key: B256,
        tick: i16,
    ) -> (i16, bool) {
        let mut next_tick = tick - 1;
        while next_tick >= MIN_TICK {
            if Self::is_tick_initialized(storage, book_key, next_tick, true).unwrap_or(false) {
                return (next_tick, true);
            }
            next_tick -= 1;
        }
        (next_tick, false)
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

/// Compute deterministic book key from base, quote token pair
pub fn compute_book_key(token_a: Address, token_b: Address) -> B256 {
    // Sort tokens to ensure deterministic key
    let (token_a, token_b) =
        if token_a < token_b { (token_a, token_b) } else { (token_b, token_a) };

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

/// Convert scaled price to relative tick pre moderato hardfork
pub fn price_to_tick_pre_moderato(price: u32) -> Result<i16, TempoPrecompileError> {
    // Pre-Moderato: legacy behavior without validation
    Ok((price as i32 - PRICE_SCALE as i32) as i16)
}

/// Convert scaled price to relative tick post moderato hardfork
pub fn price_to_tick_post_moderato(price: u32) -> Result<i16, TempoPrecompileError> {
    if !(MIN_PRICE_POST_MODERATO..=MAX_PRICE_POST_MODERATO).contains(&price) {
        let invalid_tick = (price as i32 - PRICE_SCALE as i32) as i16;
        return Err(StablecoinExchangeError::tick_out_of_bounds(invalid_tick).into());
    }
    Ok((price as i32 - PRICE_SCALE as i32) as i16)
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
        assert_eq!(price_to_tick_post_moderato(PRICE_SCALE).unwrap(), 0);

        // Test above peg
        assert_eq!(tick_to_price(100), PRICE_SCALE + 100);
        assert_eq!(price_to_tick_post_moderato(PRICE_SCALE + 100).unwrap(), 100);

        // Test below peg
        assert_eq!(tick_to_price(-100), PRICE_SCALE - 100);
        assert_eq!(price_to_tick_post_moderato(PRICE_SCALE - 100).unwrap(), -100);
    }

    #[test]
    fn test_price_to_tick_below_min() {
        // Price below MIN_PRICE should return an error
        let result = price_to_tick_post_moderato(MIN_PRICE_POST_MODERATO - 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::TickOutOfBounds(_))
        ));
    }

    #[test]
    fn test_price_to_tick_above_max() {
        // Price above MAX_PRICE should return an error
        let result = price_to_tick_post_moderato(MAX_PRICE_POST_MODERATO + 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::TickOutOfBounds(_))
        ));
    }

    #[test]
    fn test_price_to_tick_at_min_boundary_pre_moderato() {
        // MIN_PRICE should be valid and return i16::MIN (the minimum representable tick)
        let result = price_to_tick_pre_moderato(MIN_PRICE_PRE_MODERATO);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), i16::MIN);
        // Verify MIN_PRICE = PRICE_SCALE + i16::MIN
        assert_eq!(MIN_PRICE_PRE_MODERATO, (PRICE_SCALE as i32 + i16::MIN as i32) as u32);
    }

    #[test]
    fn test_price_to_tick_at_max_boundary_pre_moderato() {
        // MAX_PRICE should be valid and return i16::MAX (the maximum representable tick)
        let result = price_to_tick_pre_moderato(MAX_PRICE_PRE_MODERATO);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), i16::MAX);
        // Verify MAX_PRICE = PRICE_SCALE + i16::MAX
        assert_eq!(MAX_PRICE_PRE_MODERATO, (PRICE_SCALE as i32 + i16::MAX as i32) as u32);
    }

    #[test]
    fn test_price_to_tick_at_min_boundary_post_moderato() {
        let result = price_to_tick_post_moderato(MIN_PRICE_POST_MODERATO);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MIN_TICK);
        assert_eq!(MIN_PRICE_POST_MODERATO, (PRICE_SCALE as i32 + MIN_TICK as i32) as u32);
    }

    #[test]
    fn test_price_to_tick_at_max_boundary_post_moderato() {
        let result = price_to_tick_post_moderato(MAX_PRICE_POST_MODERATO);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MAX_TICK);
        assert_eq!(MAX_PRICE_POST_MODERATO, (PRICE_SCALE as i32 + MAX_TICK as i32) as u32);
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

        assert_eq!(key_ab, key_ba, "Book key should be the same regardless of address order");

        let mut buf = [0u8; 40];
        buf[..20].copy_from_slice(token_a.as_slice());
        buf[20..].copy_from_slice(token_b.as_slice());
        let expected_hash = keccak256(buf);

        assert_eq!(key_ab, expected_hash, "Book key should match manual keccak256 computation");
    }

    mod bitmap_tests {
        use super::*;
        use crate::storage::{ContractStorage, hashmap::HashMapStorageProvider};

        // Test wrapper that implements ContractStorage for HashMapStorageProvider
        struct TestStorage(HashMapStorageProvider);

        impl TestStorage {
            fn new(chain_id: u64) -> Self {
                Self(HashMapStorageProvider::new(chain_id))
            }
        }

        impl ContractStorage for TestStorage {
            type Storage = HashMapStorageProvider;

            fn address(&self) -> Address {
                Address::ZERO
            }

            fn storage(&mut self) -> &mut Self::Storage {
                &mut self.0
            }
        }

        #[test]
        fn test_tick_lifecycle() {
            let mut storage = TestStorage::new(1);
            let book_key = B256::ZERO;

            // Test full lifecycle (set, check, clear, check) for positive and negative ticks
            // Include boundary cases, word boundaries, and various representative values
            let test_ticks = [
                MIN_TICK, -1000, -500, -257, -256, -100, -1, 0, 1, 100, 255, 256, 500, 1000,
                MAX_TICK,
            ];

            for &tick in &test_ticks {
                // Initially not set
                assert!(
                    !Orderbook::is_tick_initialized(&mut storage, book_key, tick, true).unwrap(),
                    "Tick {tick} should not be initialized initially"
                );

                // Set the bit
                Orderbook::set_tick_bit(&mut storage, book_key, tick, true).unwrap();

                assert!(
                    Orderbook::is_tick_initialized(&mut storage, book_key, tick, true).unwrap(),
                    "Tick {tick} should be initialized after set"
                );

                // Clear the bit
                Orderbook::clear_tick_bit(&mut storage, book_key, tick, true).unwrap();

                assert!(
                    !Orderbook::is_tick_initialized(&mut storage, book_key, tick, true).unwrap(),
                    "Tick {tick} should not be initialized after clear"
                );
            }
        }

        #[test]
        fn test_boundary_ticks() {
            let mut storage = TestStorage::new(1);
            let book_key = B256::ZERO;

            // Test MIN_TICK
            Orderbook::set_tick_bit(&mut storage, book_key, MIN_TICK, true).unwrap();

            assert!(
                Orderbook::is_tick_initialized(&mut storage, book_key, MIN_TICK, true).unwrap(),
                "MIN_TICK should be settable"
            );

            // Test MAX_TICK (use different storage for ask side)
            Orderbook::set_tick_bit(&mut storage, book_key, MAX_TICK, false).unwrap();

            assert!(
                Orderbook::is_tick_initialized(&mut storage, book_key, MAX_TICK, false).unwrap(),
                "MAX_TICK should be settable"
            );

            // Clear MIN_TICK
            Orderbook::clear_tick_bit(&mut storage, book_key, MIN_TICK, true).unwrap();

            assert!(
                !Orderbook::is_tick_initialized(&mut storage, book_key, MIN_TICK, true).unwrap(),
                "MIN_TICK should be clearable"
            );
        }

        #[test]
        fn test_bid_and_ask_separate() {
            let mut storage = TestStorage::new(1);
            let book_key = B256::ZERO;
            let tick = 100;

            // Set as bid
            Orderbook::set_tick_bit(&mut storage, book_key, tick, true).unwrap();

            assert!(
                Orderbook::is_tick_initialized(&mut storage, book_key, tick, true).unwrap(),
                "Tick should be initialized for bids"
            );
            assert!(
                !Orderbook::is_tick_initialized(&mut storage, book_key, tick, false).unwrap(),
                "Tick should not be initialized for asks"
            );

            // Set as ask
            Orderbook::set_tick_bit(&mut storage, book_key, tick, false).unwrap();

            assert!(
                Orderbook::is_tick_initialized(&mut storage, book_key, tick, true).unwrap(),
                "Tick should still be initialized for bids"
            );
            assert!(
                Orderbook::is_tick_initialized(&mut storage, book_key, tick, false).unwrap(),
                "Tick should now be initialized for asks"
            );
        }

        #[test]
        fn test_ticks_across_word_boundary() {
            let mut storage = TestStorage::new(1);
            let book_key = B256::ZERO;

            // Ticks that span word boundary at 256
            Orderbook::set_tick_bit(&mut storage, book_key, 255, true).unwrap(); // word_index = 0, bit_index = 255
            Orderbook::set_tick_bit(&mut storage, book_key, 256, true).unwrap(); // word_index = 1, bit_index = 0

            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, 255, true).unwrap());
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, 256, true).unwrap());
        }

        #[test]
        fn test_ticks_different_words() {
            let mut storage = TestStorage::new(1);
            let book_key = B256::ZERO;

            // Test ticks in different words (both positive and negative)

            // Negative ticks in different words
            Orderbook::set_tick_bit(&mut storage, book_key, -1, true).unwrap(); // word_index = -1, bit_index = 255
            Orderbook::set_tick_bit(&mut storage, book_key, -100, true).unwrap(); // word_index = -1, bit_index = 156
            Orderbook::set_tick_bit(&mut storage, book_key, -256, true).unwrap(); // word_index = -1, bit_index = 0
            Orderbook::set_tick_bit(&mut storage, book_key, -257, true).unwrap(); // word_index = -2, bit_index = 255

            // Positive ticks in different words
            Orderbook::set_tick_bit(&mut storage, book_key, 1, true).unwrap(); // word_index = 0, bit_index = 1
            Orderbook::set_tick_bit(&mut storage, book_key, 100, true).unwrap(); // word_index = 0, bit_index = 100
            Orderbook::set_tick_bit(&mut storage, book_key, 256, true).unwrap(); // word_index = 1, bit_index = 0
            Orderbook::set_tick_bit(&mut storage, book_key, 512, true).unwrap(); // word_index = 2, bit_index = 0

            // Verify negative ticks
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, -1, true).unwrap());
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, -100, true).unwrap());
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, -256, true).unwrap());
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, -257, true).unwrap());

            // Verify positive ticks
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, 1, true).unwrap());
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, 100, true).unwrap());
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, 256, true).unwrap());
            assert!(Orderbook::is_tick_initialized(&mut storage, book_key, 512, true).unwrap());

            // Verify unset ticks
            assert!(
                !Orderbook::is_tick_initialized(&mut storage, book_key, -50, true).unwrap(),
                "Unset negative tick should not be initialized"
            );
            assert!(
                !Orderbook::is_tick_initialized(&mut storage, book_key, 50, true).unwrap(),
                "Unset positive tick should not be initialized"
            );
        }

        #[test]
        fn test_set_tick_bit_out_of_bounds() {
            let mut storage = TestStorage::new(1);
            let book_key = B256::ZERO;

            // Test tick above MAX_TICK
            let result = Orderbook::set_tick_bit(&mut storage, book_key, MAX_TICK + 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));

            // Test tick below MIN_TICK
            let result = Orderbook::set_tick_bit(&mut storage, book_key, MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));
        }

        #[test]
        fn test_clear_tick_bit_out_of_bounds() {
            let mut storage = TestStorage::new(1);
            let book_key = B256::ZERO;

            // Test tick above MAX_TICK
            let result = Orderbook::clear_tick_bit(&mut storage, book_key, MAX_TICK + 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));

            // Test tick below MIN_TICK
            let result = Orderbook::clear_tick_bit(&mut storage, book_key, MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));
        }

        #[test]
        fn test_is_tick_initialized_out_of_bounds() {
            let mut storage = TestStorage::new(1);
            let book_key = B256::ZERO;

            // Test tick above MAX_TICK
            let result = Orderbook::is_tick_initialized(&mut storage, book_key, MAX_TICK + 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));

            // Test tick below MIN_TICK
            let result = Orderbook::is_tick_initialized(&mut storage, book_key, MIN_TICK - 1, true);
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(_))
            ));
        }
    }
}
