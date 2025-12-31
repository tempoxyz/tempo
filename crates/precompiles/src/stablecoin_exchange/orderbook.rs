//! Orderbook and tick level management for the stablecoin DEX.

use crate::{
    error::Result,
    stablecoin_exchange::IStablecoinExchange,
    storage::{Handler, Mapping, Slot},
};
use alloy::primitives::{Address, B256, U256, keccak256};
use tempo_contracts::precompiles::StablecoinExchangeError;
use tempo_precompiles_macros::Storable;

/// Constants from Solidity implementation
pub const MIN_TICK: i16 = -2000;
pub const MAX_TICK: i16 = 2000;
pub const PRICE_SCALE: u32 = 100_000;

/// Rounding direction for price conversions.
///
/// Rounding should always favor the protocol to prevent insolvency:
/// - When users deposit funds (escrow) → round UP (user pays more)
/// - When users receive funds (settlement/refunds) → round DOWN (user receives less)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundingDirection {
    /// Round down (floor division) - favors protocol when user receives funds
    Down,
    /// Round up (ceiling division) - favors protocol when user deposits funds
    Up,
}

/// Checked ceiling division for u128.
/// Returns None if divisor is zero.
fn checked_div_ceil(numerator: u128, divisor: u128) -> Option<u128> {
    if divisor == 0 {
        return None;
    }
    Some(numerator.div_ceil(divisor))
}

/// Convert base token amount to quote token amount at a given tick.
///
/// Formula: quote_amount = (base_amount * price) / PRICE_SCALE
///
/// # Arguments
/// * `base_amount` - Amount of base tokens
/// * `tick` - Price tick
/// * `rounding` - Rounding direction
///
/// # Returns
/// Quote token amount, or None on overflow
pub fn base_to_quote(base_amount: u128, tick: i16, rounding: RoundingDirection) -> Option<u128> {
    let price = tick_to_price(tick) as u128;
    let numerator = base_amount.checked_mul(price)?;

    match rounding {
        RoundingDirection::Down => numerator.checked_div(PRICE_SCALE as u128),
        RoundingDirection::Up => checked_div_ceil(numerator, PRICE_SCALE as u128),
    }
}

/// Convert quote token amount to base token amount at a given tick.
///
/// Formula: base_amount = (quote_amount * PRICE_SCALE) / price
///
/// # Arguments
/// * `quote_amount` - Amount of quote tokens
/// * `tick` - Price tick
/// * `rounding` - Rounding direction
///
/// # Returns
/// Base token amount, or None on overflow
pub fn quote_to_base(quote_amount: u128, tick: i16, rounding: RoundingDirection) -> Option<u128> {
    let price = tick_to_price(tick) as u128;
    let numerator = quote_amount.checked_mul(PRICE_SCALE as u128)?;

    match rounding {
        RoundingDirection::Down => numerator.checked_div(price),
        RoundingDirection::Up => checked_div_ceil(numerator, price),
    }
}

// PRICE_SCALE + MIN_TICK = 100_000 - 2000
pub(crate) const MIN_PRICE: u32 = 98_000;
// PRICE_SCALE + MAX_TICK = 100_000 + 2000
pub(crate) const MAX_PRICE: u32 = 102_000;

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
    bids: Mapping<i16, TickLevel>,
    /// Ask orders by tick
    #[allow(dead_code)]
    asks: Mapping<i16, TickLevel>,
    /// Best bid tick for highest bid price
    pub best_bid_tick: i16,
    /// Best ask tick for lowest ask price
    pub best_ask_tick: i16,
    #[allow(dead_code)]
    /// Mapping of tick index to bid bitmap for price discovery
    bid_bitmap: Mapping<i16, U256>,
    /// Mapping of tick index to ask bitmap for price discovery
    #[allow(dead_code)]
    ask_bitmap: Mapping<i16, U256>,
}

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
}

impl OrderbookHandler {
    pub fn get_tick_level_handler(&self, tick: i16, is_bid: bool) -> TickLevelHandler {
        if is_bid {
            self.bids.at(tick)
        } else {
            self.asks.at(tick)
        }
    }

    fn get_tick_bit_handler(&self, tick: i16, is_bid: bool) -> Result<Slot<U256>> {
        if !(MIN_TICK..=MAX_TICK).contains(&tick) {
            return Err(StablecoinExchangeError::invalid_tick().into());
        }

        let word_index = tick >> 8;

        if is_bid {
            Ok(self.bid_bitmap.at(word_index))
        } else {
            Ok(self.ask_bitmap.at(word_index))
        }
    }

    /// Set bit in bitmap to mark tick as active
    pub fn set_tick_bit(&mut self, tick: i16, is_bid: bool) -> Result<()> {
        let mut bitmap = self.get_tick_bit_handler(tick, is_bid)?;

        // Read current bitmap word
        let current_word = bitmap.read()?;

        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        let bit_index = (tick & 0xFF) as usize;
        let mask = U256::from(1u8) << bit_index;

        // Set the bit
        bitmap.write(current_word | mask)
    }

    /// Clear bit in bitmap to mark tick as inactive
    pub fn delete_tick_bit(&mut self, tick: i16, is_bid: bool) -> Result<()> {
        let mut bitmap = self.get_tick_bit_handler(tick, is_bid)?;

        // Read current bitmap word
        let current_word = bitmap.read()?;

        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        let bit_index = (tick & 0xFF) as usize;
        let mask = !(U256::from(1u8) << bit_index);

        // Set the bit
        bitmap.write(current_word & mask)
    }

    /// Check if a tick is initialized (has orders)
    pub fn is_tick_initialized(&self, tick: i16, is_bid: bool) -> Result<bool> {
        let bitmap = self.get_tick_bit_handler(tick, is_bid)?;

        // Read current bitmap word
        let word = bitmap.read()?;

        // Use bitwise AND to get lower 8 bits correctly for both positive and negative ticks
        let bit_index = (tick & 0xFF) as usize;
        let mask = U256::from(1u8) << bit_index;

        Ok((word & mask) != U256::ZERO)
    }

    /// Find next initialized ask tick higher than current tick
    pub fn next_initialized_tick(&self, tick: i16, is_bid: bool) -> Result<(i16, bool)> {
        if is_bid {
            self.next_initialized_bid_tick(tick)
        } else {
            self.next_initialized_ask_tick(tick)
        }
    }

    /// Find next initialized ask tick higher than current tick.
    ///
    /// Uses efficient bitmap word traversal: reads entire 256-bit words and uses
    /// bit manipulation to find set bits, minimizing storage reads.
    fn next_initialized_ask_tick(&self, tick: i16) -> Result<(i16, bool)> {
        // Guard against overflow when tick is at or above MAX_TICK
        if tick >= MAX_TICK {
            return Ok((MAX_TICK, false));
        }

        let mut next_tick = tick + 1;
        let max_word_index = MAX_TICK >> 8;

        loop {
            let word_index = next_tick >> 8;
            if word_index > max_word_index {
                return Ok((next_tick, false));
            }

            let bit_index = (next_tick & 0xFF) as usize;

            let word = self.ask_bitmap.at(word_index).read()?;

            // Mask off bits below bit_index to only consider ticks >= next_tick
            let mask = if bit_index == 0 {
                U256::MAX
            } else {
                U256::MAX << bit_index
            };
            let masked_word = word & mask;

            if masked_word != U256::ZERO {
                // Find the lowest set bit position using trailing_zeros
                let lowest_bit = masked_word.trailing_zeros();
                let found_tick = (word_index << 8) | (lowest_bit as i16);
                if found_tick <= MAX_TICK {
                    return Ok((found_tick, true));
                }
                return Ok((found_tick, false));
            }

            // No set bits in this word, move to next word
            let next_word_index = word_index + 1;
            if next_word_index > max_word_index {
                return Ok((next_word_index << 8, false));
            }
            next_tick = next_word_index << 8; // First tick of next word
        }
    }

    /// Find next initialized bid tick lower than current tick.
    ///
    /// Uses efficient bitmap word traversal: reads entire 256-bit words and uses
    /// bit manipulation to find set bits, minimizing storage reads.
    fn next_initialized_bid_tick(&self, tick: i16) -> Result<(i16, bool)> {
        // Guard against underflow when tick is at or below MIN_TICK
        if tick <= MIN_TICK {
            return Ok((MIN_TICK, false));
        }

        let mut next_tick = tick - 1;
        let min_word_index = MIN_TICK >> 8;

        loop {
            let word_index = next_tick >> 8;
            if word_index < min_word_index {
                return Ok((next_tick, false));
            }

            let bit_index = (next_tick & 0xFF) as usize;

            let word = self.bid_bitmap.at(word_index).read()?;

            // Mask off bits above bit_index to only consider ticks <= next_tick
            let mask = if bit_index == 255 {
                U256::MAX
            } else {
                U256::MAX >> (255 - bit_index)
            };
            let masked_word = word & mask;

            if masked_word != U256::ZERO {
                // Find the highest set bit position using leading_zeros
                // U256 is 256 bits, so highest bit index = 255 - leading_zeros
                let leading = masked_word.leading_zeros();
                let highest_bit = 255 - leading;
                let found_tick = (word_index << 8) | (highest_bit as i16);
                if found_tick >= MIN_TICK {
                    return Ok((found_tick, true));
                }
                return Ok((found_tick, false));
            }

            // No set bits in this word, move to previous word
            let prev_word_index = word_index - 1;
            if prev_word_index < min_word_index {
                return Ok(((prev_word_index << 8) | 0xFF, false));
            }
            next_tick = (prev_word_index << 8) | 0xFF; // Last tick of previous word
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

/// Compute deterministic book key from ordered (base, quote) token pair
pub fn compute_book_key(base: Address, quote: Address) -> B256 {
    // Compute keccak256(abi.encodePacked(base, quote))
    let mut buf = [0u8; 40];
    buf[..20].copy_from_slice(base.as_slice());
    buf[20..].copy_from_slice(quote.as_slice());
    keccak256(buf)
}

/// Convert relative tick to scaled price
pub fn tick_to_price(tick: i16) -> u32 {
    (PRICE_SCALE as i32 + tick as i32) as u32
}

/// Convert scaled price to relative tick
pub fn price_to_tick(price: u32) -> Result<i16> {
    if !(MIN_PRICE..=MAX_PRICE).contains(&price) {
        let invalid_tick = (price as i32 - PRICE_SCALE as i32) as i16;
        return Err(StablecoinExchangeError::tick_out_of_bounds(invalid_tick).into());
    }
    Ok((price as i32 - PRICE_SCALE as i32) as i16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TempoPrecompileError;

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
    fn test_tick_price_conversion() -> eyre::Result<()> {
        // Test at peg price (tick 0)
        assert_eq!(tick_to_price(0), PRICE_SCALE);
        assert_eq!(price_to_tick(PRICE_SCALE)?, 0);

        // Test above peg
        assert_eq!(tick_to_price(100), PRICE_SCALE + 100);
        assert_eq!(price_to_tick(PRICE_SCALE + 100)?, 100);

        // Test below peg
        assert_eq!(tick_to_price(-100), PRICE_SCALE - 100);
        assert_eq!(price_to_tick(PRICE_SCALE - 100)?, -100);

        Ok(())
    }

    #[test]
    fn test_price_to_tick_below_min() {
        // Price below MIN_PRICE should return an error
        let result = price_to_tick(MIN_PRICE - 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::TickOutOfBounds(_))
        ));
    }

    #[test]
    fn test_price_to_tick_above_max() {
        // Price above MAX_PRICE should return an error
        let result = price_to_tick(MAX_PRICE + 1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::TickOutOfBounds(_))
        ));
    }

    #[test]
    fn test_price_to_tick_at_min_boundary() {
        let result = price_to_tick(MIN_PRICE);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MIN_TICK);
        assert_eq!(MIN_PRICE, (PRICE_SCALE as i32 + MIN_TICK as i32) as u32);
    }

    #[test]
    fn test_price_to_tick_at_max_boundary() {
        let result = price_to_tick(MAX_PRICE);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), MAX_TICK);
        assert_eq!(MAX_PRICE, (PRICE_SCALE as i32 + MAX_TICK as i32) as u32);
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
        use crate::{
            stablecoin_exchange::StablecoinExchange,
            storage::{StorageCtx, hashmap::HashMapStorageProvider},
        };
        const BOOK_KEY: B256 = B256::ZERO;

        #[test]
        fn test_tick_lifecycle() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Test full lifecycle (set, check, clear, check) for positive and negative ticks
                // Include boundary cases, word boundaries, and various representative values
                let test_ticks = [
                    MIN_TICK, -1000, -500, -257, -256, -100, -1, 0, 1, 100, 255, 256, 500, 1000,
                    MAX_TICK,
                ];

                for &tick in &test_ticks {
                    // Initially not set
                    assert!(
                        !book_handler.is_tick_initialized(tick, true)?,
                        "Tick {tick} should not be initialized initially"
                    );

                    // Set the bit
                    book_handler.set_tick_bit(tick, true)?;

                    assert!(
                        book_handler.is_tick_initialized(tick, true)?,
                        "Tick {tick} should be initialized after set"
                    );

                    // Clear the bit
                    book_handler.delete_tick_bit(tick, true)?;

                    assert!(
                        !book_handler.is_tick_initialized(tick, true)?,
                        "Tick {tick} should not be initialized after clear"
                    );
                }

                Ok(())
            })
        }

        #[test]
        fn test_boundary_ticks() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Test MIN_TICK
                book_handler.set_tick_bit(MIN_TICK, true)?;

                assert!(
                    book_handler.is_tick_initialized(MIN_TICK, true)?,
                    "MIN_TICK should be settable"
                );

                // Test MAX_TICK (use different storage for ask side)
                book_handler.set_tick_bit(MAX_TICK, false)?;

                assert!(
                    book_handler.is_tick_initialized(MAX_TICK, false)?,
                    "MAX_TICK should be settable"
                );

                // Clear MIN_TICK
                book_handler.delete_tick_bit(MIN_TICK, true)?;

                assert!(
                    !book_handler.is_tick_initialized(MIN_TICK, true)?,
                    "MIN_TICK should be clearable"
                );
                Ok(())
            })
        }

        #[test]
        fn test_bid_and_ask_separate() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                let tick = 100;

                // Set as bid
                book_handler.set_tick_bit(tick, true)?;

                assert!(
                    book_handler.is_tick_initialized(tick, true)?,
                    "Tick should be initialized for bids"
                );
                assert!(
                    !book_handler.is_tick_initialized(tick, false)?,
                    "Tick should not be initialized for asks"
                );

                // Set as ask
                book_handler.set_tick_bit(tick, false)?;

                assert!(
                    book_handler.is_tick_initialized(tick, true)?,
                    "Tick should still be initialized for bids"
                );
                assert!(
                    book_handler.is_tick_initialized(tick, false)?,
                    "Tick should now be initialized for asks"
                );
                Ok(())
            })
        }

        #[test]
        fn test_ticks_across_word_boundary() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Ticks that span word boundary at 256
                book_handler.set_tick_bit(255, true)?; // word_index = 0, bit_index = 255
                book_handler.set_tick_bit(256, true)?; // word_index = 1, bit_index = 0

                assert!(book_handler.is_tick_initialized(255, true)?);
                assert!(book_handler.is_tick_initialized(256, true)?);
                Ok(())
            })
        }

        #[test]
        fn test_ticks_different_words() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Test ticks in different words (both positive and negative)

                // Negative ticks in different words
                book_handler.set_tick_bit(-1, true)?; // word_index = -1, bit_index = 255
                book_handler.set_tick_bit(-100, true)?; // word_index = -1, bit_index = 156
                book_handler.set_tick_bit(-256, true)?; // word_index = -1, bit_index = 0
                book_handler.set_tick_bit(-257, true)?; // word_index = -2, bit_index = 255

                // Positive ticks in different words
                book_handler.set_tick_bit(1, true)?; // word_index = 0, bit_index = 1
                book_handler.set_tick_bit(100, true)?; // word_index = 0, bit_index = 100
                book_handler.set_tick_bit(256, true)?; // word_index = 1, bit_index = 0
                book_handler.set_tick_bit(512, true)?; // word_index = 2, bit_index = 0

                // Verify negative ticks
                assert!(book_handler.is_tick_initialized(-1, true)?);
                assert!(book_handler.is_tick_initialized(-100, true)?);
                assert!(book_handler.is_tick_initialized(-256, true)?);
                assert!(book_handler.is_tick_initialized(-257, true)?);

                // Verify positive ticks
                assert!(book_handler.is_tick_initialized(1, true)?);
                assert!(book_handler.is_tick_initialized(100, true)?);
                assert!(book_handler.is_tick_initialized(256, true)?);
                assert!(book_handler.is_tick_initialized(512, true)?);

                // Verify unset ticks
                assert!(
                    !book_handler.is_tick_initialized(-50, true)?,
                    "Unset negative tick should not be initialized"
                );
                assert!(
                    !book_handler.is_tick_initialized(50, true)?,
                    "Unset positive tick should not be initialized"
                );
                Ok(())
            })
        }

        #[test]
        fn test_set_tick_bit_out_of_bounds() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Test tick above MAX_TICK
                let result = book_handler.set_tick_bit(MAX_TICK + 1, true);
                assert!(result.is_err());
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(
                        _
                    ))
                ));

                // Test tick below MIN_TICK
                let result = book_handler.set_tick_bit(MIN_TICK - 1, true);
                assert!(result.is_err());
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(
                        _
                    ))
                ));
                Ok(())
            })
        }

        #[test]
        fn test_clear_tick_bit_out_of_bounds() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Test tick above MAX_TICK
                let result = book_handler.delete_tick_bit(MAX_TICK + 1, true);
                assert!(result.is_err());
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(
                        _
                    ))
                ));

                // Test tick below MIN_TICK
                let result = book_handler.delete_tick_bit(MIN_TICK - 1, true);
                assert!(result.is_err());
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(
                        _
                    ))
                ));
                Ok(())
            })
        }

        #[test]
        fn test_is_tick_initialized_out_of_bounds() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let exchange = StablecoinExchange::new();
                let book_handler = exchange.books.at(BOOK_KEY);

                // Test tick above MAX_TICK
                let result = book_handler.is_tick_initialized(MAX_TICK + 1, true);
                assert!(result.is_err());
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(
                        _
                    ))
                ));

                // Test tick below MIN_TICK
                let result = book_handler.is_tick_initialized(MIN_TICK - 1, true);
                assert!(result.is_err());
                assert!(matches!(
                    result.unwrap_err(),
                    TempoPrecompileError::StablecoinExchange(StablecoinExchangeError::InvalidTick(
                        _
                    ))
                ));
                Ok(())
            })
        }

        #[test]
        fn test_next_initialized_ask_tick_same_word() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Set ticks 10 and 50 (both in word 0)
                book_handler.set_tick_bit(10, false)?;
                book_handler.set_tick_bit(50, false)?;

                // From tick 0, should find tick 10
                let (next, found) = book_handler.next_initialized_tick(0, false)?;
                assert!(found);
                assert_eq!(next, 10);

                // From tick 10, should find tick 50
                let (next, found) = book_handler.next_initialized_tick(10, false)?;
                assert!(found);
                assert_eq!(next, 50);

                // From tick 50, should find nothing in bounds
                let (next, found) = book_handler.next_initialized_tick(50, false)?;
                assert!(!found);
                assert!(next > MAX_TICK);

                Ok(())
            })
        }

        #[test]
        fn test_next_initialized_ask_tick_cross_word() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Set ticks in different words: 100 (word 0), 300 (word 1), 600 (word 2)
                book_handler.set_tick_bit(100, false)?;
                book_handler.set_tick_bit(300, false)?;
                book_handler.set_tick_bit(600, false)?;

                // From tick 0, should find tick 100 (same word)
                let (next, found) = book_handler.next_initialized_tick(0, false)?;
                assert!(found);
                assert_eq!(next, 100);

                // From tick 100, should find tick 300 (cross word boundary)
                let (next, found) = book_handler.next_initialized_tick(100, false)?;
                assert!(found);
                assert_eq!(next, 300);

                // From tick 300, should find tick 600 (cross word boundary)
                let (next, found) = book_handler.next_initialized_tick(300, false)?;
                assert!(found);
                assert_eq!(next, 600);

                Ok(())
            })
        }

        #[test]
        fn test_next_initialized_bid_tick_same_word() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Set ticks 10 and 50 (both in word 0) for bids
                book_handler.set_tick_bit(10, true)?;
                book_handler.set_tick_bit(50, true)?;

                // From tick 100, should find tick 50
                let (next, found) = book_handler.next_initialized_tick(100, true)?;
                assert!(found);
                assert_eq!(next, 50);

                // From tick 50, should find tick 10
                let (next, found) = book_handler.next_initialized_tick(50, true)?;
                assert!(found);
                assert_eq!(next, 10);

                // From tick 10, should find nothing in bounds
                let (next, found) = book_handler.next_initialized_tick(10, true)?;
                assert!(!found);
                assert!(next < MIN_TICK);

                Ok(())
            })
        }

        #[test]
        fn test_next_initialized_bid_tick_cross_word() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Set ticks in different words for bids: 600 (word 2), 300 (word 1), 100 (word 0)
                book_handler.set_tick_bit(600, true)?;
                book_handler.set_tick_bit(300, true)?;
                book_handler.set_tick_bit(100, true)?;

                // From tick 700, should find tick 600 (same word)
                let (next, found) = book_handler.next_initialized_tick(700, true)?;
                assert!(found);
                assert_eq!(next, 600);

                // From tick 600, should find tick 300 (cross word boundary)
                let (next, found) = book_handler.next_initialized_tick(600, true)?;
                assert!(found);
                assert_eq!(next, 300);

                // From tick 300, should find tick 100 (cross word boundary)
                let (next, found) = book_handler.next_initialized_tick(300, true)?;
                assert!(found);
                assert_eq!(next, 100);

                Ok(())
            })
        }

        #[test]
        fn test_next_initialized_tick_negative_ticks() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Set negative ticks for asks
                book_handler.set_tick_bit(-500, false)?;
                book_handler.set_tick_bit(-100, false)?;
                book_handler.set_tick_bit(50, false)?;

                // From -600, should find -500
                let (next, found) = book_handler.next_initialized_tick(-600, false)?;
                assert!(found);
                assert_eq!(next, -500);

                // From -500, should find -100
                let (next, found) = book_handler.next_initialized_tick(-500, false)?;
                assert!(found);
                assert_eq!(next, -100);

                // From -100, should find 50
                let (next, found) = book_handler.next_initialized_tick(-100, false)?;
                assert!(found);
                assert_eq!(next, 50);

                // Set negative ticks for bids
                book_handler.set_tick_bit(-100, true)?;
                book_handler.set_tick_bit(-500, true)?;

                // From 0, should find -100
                let (next, found) = book_handler.next_initialized_tick(0, true)?;
                assert!(found);
                assert_eq!(next, -100);

                // From -100, should find -500
                let (next, found) = book_handler.next_initialized_tick(-100, true)?;
                assert!(found);
                assert_eq!(next, -500);

                Ok(())
            })
        }

        #[test]
        fn test_next_initialized_tick_at_word_boundary() -> eyre::Result<()> {
            let mut storage = HashMapStorageProvider::new(1);
            StorageCtx::enter(&mut storage, || {
                let mut exchange = StablecoinExchange::new();
                exchange.initialize()?;
                let mut book_handler = exchange.books.at(BOOK_KEY);

                // Test exact word boundaries (256, 512, -256, -512)
                book_handler.set_tick_bit(255, false)?; // Last bit of word 0
                book_handler.set_tick_bit(256, false)?; // First bit of word 1

                // From 254, should find 255
                let (next, found) = book_handler.next_initialized_tick(254, false)?;
                assert!(found);
                assert_eq!(next, 255);

                // From 255, should find 256 (cross word)
                let (next, found) = book_handler.next_initialized_tick(255, false)?;
                assert!(found);
                assert_eq!(next, 256);

                // Test bid direction at word boundary
                book_handler.set_tick_bit(256, true)?;
                book_handler.set_tick_bit(255, true)?;

                // From 257, should find 256
                let (next, found) = book_handler.next_initialized_tick(257, true)?;
                assert!(found);
                assert_eq!(next, 256);

                // From 256, should find 255 (cross word going down)
                let (next, found) = book_handler.next_initialized_tick(256, true)?;
                assert!(found);
                assert_eq!(next, 255);

                Ok(())
            })
        }
    }

    mod rounding_tests {
        use super::*;

        #[test]
        fn test_base_to_quote_rounds_down_correctly() {
            let base_amount = 1_000_003u128;
            let tick = 0i16;

            let quote_down = base_to_quote(base_amount, tick, RoundingDirection::Down).unwrap();
            let quote_up = base_to_quote(base_amount, tick, RoundingDirection::Up).unwrap();

            assert_eq!(quote_down, 1_000_003);
            assert_eq!(quote_up, 1_000_003);
        }

        #[test]
        fn test_base_to_quote_rounds_up_when_remainder_exists() {
            let base_amount = 33u128;
            let tick = 100i16;

            let price = tick_to_price(tick) as u128;
            let numerator = base_amount * price;
            let has_remainder = !numerator.is_multiple_of(PRICE_SCALE as u128);

            let quote_down = base_to_quote(base_amount, tick, RoundingDirection::Down).unwrap();
            let quote_up = base_to_quote(base_amount, tick, RoundingDirection::Up).unwrap();

            if has_remainder {
                assert_eq!(
                    quote_up,
                    quote_down + 1,
                    "Round up should be 1 more than round down when there's a remainder"
                );
            } else {
                assert_eq!(
                    quote_up, quote_down,
                    "Round up and down should be equal when there's no remainder"
                );
            }
        }

        #[test]
        fn test_quote_to_base_rounds_down_correctly() {
            let quote_amount = 1_000_003u128;
            let tick = 0i16;

            let base_down = quote_to_base(quote_amount, tick, RoundingDirection::Down).unwrap();
            let base_up = quote_to_base(quote_amount, tick, RoundingDirection::Up).unwrap();

            assert_eq!(base_down, 1_000_003);
            assert_eq!(base_up, 1_000_003);
        }

        #[test]
        fn test_quote_to_base_rounds_up_when_remainder_exists() {
            let quote_amount = 33u128;
            let tick = 100i16;

            let price = tick_to_price(tick) as u128;
            let numerator = quote_amount * PRICE_SCALE as u128;
            let has_remainder = !numerator.is_multiple_of(price);

            let base_down = quote_to_base(quote_amount, tick, RoundingDirection::Down).unwrap();
            let base_up = quote_to_base(quote_amount, tick, RoundingDirection::Up).unwrap();

            if has_remainder {
                assert_eq!(
                    base_up,
                    base_down + 1,
                    "Round up should be 1 more than round down when there's a remainder"
                );
            } else {
                assert_eq!(
                    base_up, base_down,
                    "Round up and down should be equal when there's no remainder"
                );
            }
        }

        #[test]
        fn test_rounding_favors_protocol_for_bid_escrow() {
            let base_amount = 10_000_001u128;
            let tick = 100i16;

            let escrow_floor = base_to_quote(base_amount, tick, RoundingDirection::Down).unwrap();
            let escrow_ceil = base_to_quote(base_amount, tick, RoundingDirection::Up).unwrap();

            assert!(
                escrow_ceil >= escrow_floor,
                "Ceiling should never be less than floor"
            );
        }

        #[test]
        fn test_rounding_favors_protocol_for_settlement() {
            let base_amount = 10_000_001u128;
            let tick = 100i16;

            let payout_floor = base_to_quote(base_amount, tick, RoundingDirection::Down).unwrap();
            let payout_ceil = base_to_quote(base_amount, tick, RoundingDirection::Up).unwrap();

            assert!(
                payout_floor <= payout_ceil,
                "Floor should never be more than ceiling"
            );
        }
    }
}
