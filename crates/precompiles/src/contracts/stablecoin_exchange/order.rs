//! Limit order type for the stablecoin DEX.
//!
//! This module defines the core `Order` type used in the stablecoin DEX orderbook.
//! Orders support price-time priority matching, partial fills, and flip orders that
//! automatically place opposite-side orders when filled.

use alloy::primitives::{Address, B256};

use super::error::OrderError;

/// Represents an order in the stablecoin DEX orderbook.
///
/// This struct matches the Solidity reference implementation in StablecoinExchange.sol.
///
/// # Order Types
/// - **Regular orders**: Orders with `is_flip = false`
/// - **Flip orders**: Orders with `is_flip = true` that automatically create
///   a new order on the opposite side when fully filled
///
/// # Order Lifecycle
/// 1. Order is placed via `place()` or `placeFlip()` and added to pending queue
/// 2. At end of block, pending orders are inserted into the active orderbook
/// 3. Orders can be filled (fully or partially) by taker orders
/// 4. Flip orders automatically create a new order on the opposite side when fully filled
/// 5. Orders can be cancelled, removing them from the book
///
/// # Price-Time Priority
/// Orders are sorted by price (tick), then by insertion time.
/// The doubly linked list maintains insertion order - orders are added at the tail,
/// so traversing from head to tail gives price-time priority.
///
/// # Onchain Storage
/// Orders are stored onchain in doubly linked lists organized by tick.
/// Each tick maintains a FIFO queue of orders using `prev` and `next` pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    /// Unique identifier for this order
    order_id: u128,
    /// Address of the user who placed this order
    maker: Address,
    /// Orderbook key (identifies the trading pair)
    book_key: B256,
    /// Whether this is a bid (true) or ask (false) order
    is_bid: bool,
    /// Price tick
    tick: i16,
    /// Original order amount
    amount: u128,
    /// Remaining amount to be filled
    remaining: u128,
    /// Previous order ID in the doubly linked list (0 if head)
    prev: u128,
    /// Next order ID in the doubly linked list (0 if tail)
    next: u128,
    /// Whether this is a flip order
    is_flip: bool,
    /// Tick to flip to when fully filled (for flip orders, 0 for regular orders)
    /// For bid flips: flip_tick must be > tick
    /// For ask flips: flip_tick must be < tick
    flip_tick: i16,
}

impl Order {
    /// Creates a new bid order (buying base token with quote token).
    ///
    /// Note: `prev` and `next` are initialized to 0.
    /// The orderbook will set these when inserting the order into the linked list.
    pub fn new_bid(
        order_id: u128,
        maker: Address,
        book_key: B256,
        amount: u128,
        tick: i16,
    ) -> Self {
        Self {
            order_id,
            maker,
            book_key,
            is_bid: true,
            tick,
            amount,
            remaining: amount,
            prev: 0,
            next: 0,
            is_flip: false,
            flip_tick: 0,
        }
    }

    /// Creates a new ask order (selling base token for quote token).
    ///
    /// Note: `prev` and `next` are initialized to 0.
    /// The orderbook will set these when inserting the order into the linked list.
    pub fn new_ask(
        order_id: u128,
        maker: Address,
        book_key: B256,
        amount: u128,
        tick: i16,
    ) -> Self {
        Self {
            order_id,
            maker,
            book_key,
            is_bid: false,
            tick,
            amount,
            remaining: amount,
            prev: 0,
            next: 0,
            is_flip: false,
            flip_tick: 0,
        }
    }

    /// Creates a new flip order.
    ///
    /// Note: `prev` and `next` are initialized to 0.
    /// The orderbook will set these when inserting the order into the linked list.
    ///
    /// # Errors
    /// Returns an error if flip_tick constraint is violated:
    /// - For bids: flip_tick must be > tick
    /// - For asks: flip_tick must be < tick
    pub fn new_flip(
        order_id: u128,
        maker: Address,
        book_key: B256,
        amount: u128,
        is_bid: bool,
        tick: i16,
        flip_tick: i16,
    ) -> Result<Self, OrderError> {
        // Validate flip tick constraint
        if is_bid {
            if flip_tick <= tick {
                return Err(OrderError::InvalidBidFlipTick { tick, flip_tick });
            }
        } else if flip_tick >= tick {
            return Err(OrderError::InvalidAskFlipTick { tick, flip_tick });
        }

        Ok(Self {
            order_id,
            maker,
            book_key,
            is_bid,
            tick,
            amount,
            remaining: amount,
            prev: 0,
            next: 0,
            is_flip: true,
            flip_tick,
        })
    }

    /// Returns the order ID.
    pub fn order_id(&self) -> u128 {
        self.order_id
    }

    /// Returns the maker address.
    pub fn maker(&self) -> Address {
        self.maker
    }

    /// Returns the orderbook key.
    pub fn book_key(&self) -> B256 {
        self.book_key
    }

    /// Returns whether this is a bid order.
    pub fn is_bid(&self) -> bool {
        self.is_bid
    }

    /// Returns the original amount.
    pub fn amount(&self) -> u128 {
        self.amount
    }

    /// Returns the remaining amount.
    pub fn remaining(&self) -> u128 {
        self.remaining
    }

    /// Returns a mutable reference to the remaining amount.
    fn remaining_mut(&mut self) -> &mut u128 {
        &mut self.remaining
    }

    /// Returns the tick price.
    pub fn tick(&self) -> i16 {
        self.tick
    }

    /// Returns true if this is an ask order (selling base token).
    pub fn is_ask(&self) -> bool {
        !self.is_bid
    }

    /// Returns true if this is a flip order.
    pub fn is_flip(&self) -> bool {
        self.is_flip
    }

    /// Returns the flip tick.
    ///
    /// For non-flip orders, this is always 0.
    /// For flip orders, this can be any valid tick value including 0 (peg price).
    pub fn flip_tick(&self) -> i16 {
        self.flip_tick
    }

    /// Returns the previous order ID in the doubly linked list (0 if head).
    pub fn prev(&self) -> u128 {
        self.prev
    }

    /// Returns the next order ID in the doubly linked list (0 if tail).
    pub fn next(&self) -> u128 {
        self.next
    }

    /// Sets the previous order ID in the doubly linked list.
    pub fn set_prev(&mut self, prev_id: u128) {
        self.prev = prev_id;
    }

    /// Sets the next order ID in the doubly linked list.
    pub fn set_next(&mut self, next_id: u128) {
        self.next = next_id;
    }

    /// Returns true if the order is completely filled (no remaining amount).
    pub fn is_fully_filled(&self) -> bool {
        self.remaining == 0
    }

    /// Fills the order by the specified amount.
    ///
    /// # Errors
    /// Returns an error if fill_amount exceeds remaining amount
    pub fn fill(&mut self, fill_amount: u128) -> Result<(), OrderError> {
        if fill_amount > self.remaining {
            return Err(OrderError::FillAmountExceedsRemaining {
                requested: fill_amount,
                available: self.remaining,
            });
        }
        *self.remaining_mut() = self.remaining.saturating_sub(fill_amount);
        Ok(())
    }

    /// Creates a flipped order from a fully filled flip order.
    ///
    /// When a flip order is completely filled, it creates a new order on the opposite side:
    /// - Sides are swapped (bid -> ask, ask -> bid)
    /// - New price = original flip_tick
    /// - New flip_tick = original tick
    /// - Amount is the same as original
    /// - Linked list pointers are reset to 0 (will be set by orderbook on insertion)
    ///
    /// # Errors
    /// Returns an error if called on a non-flip order or if the order is not fully filled
    pub fn create_flipped_order(&self, new_order_id: u128) -> Result<Self, OrderError> {
        // Check if this is a flip order
        if !self.is_flip {
            return Err(OrderError::NotAFlipOrder);
        }

        // Check if fully filled
        if self.remaining != 0 {
            return Err(OrderError::OrderNotFullyFilled {
                remaining: self.remaining,
            });
        }

        // Create flipped order
        Ok(Self {
            order_id: new_order_id,
            maker: self.maker,
            book_key: self.book_key,
            is_bid: !self.is_bid,   // Flip the side
            tick: self.flip_tick,   // Old flip_tick becomes new tick
            amount: self.amount,    // Same as original
            remaining: self.amount, // Reset remaining to original amount
            prev: 0,                // Reset linked list pointers
            next: 0,
            is_flip: true,        // Keep as flip order
            flip_tick: self.tick, // Old tick becomes new flip_tick
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256};

    const TEST_MAKER: Address = address!("0x1111111111111111111111111111111111111111");
    const TEST_BOOK_KEY: B256 =
        b256!("0x0000000000000000000000000000000000000000000000000000000000000001");

    #[test]
    fn test_new_bid_order() {
        let order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        assert_eq!(order.order_id(), 1);
        assert_eq!(order.maker(), TEST_MAKER);
        assert_eq!(order.book_key(), TEST_BOOK_KEY);
        assert!(order.is_bid());
        assert_eq!(order.amount(), 1000);
        assert_eq!(order.remaining(), 1000);
        assert!(order.is_bid());
        assert!(!order.is_ask());
        assert_eq!(order.tick(), 5);
        assert!(!order.is_flip());
        assert_eq!(order.flip_tick(), 0);
    }

    #[test]
    fn test_new_ask_order() {
        let order = Order::new_ask(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        assert_eq!(order.order_id(), 1);
        assert!(!order.is_bid());
        assert!(!order.is_bid());
        assert!(order.is_ask());
        assert!(!order.is_flip());
    }

    #[test]
    fn test_new_flip_order_bid() {
        let order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            true, // Bid
            5,
            10, // flip_tick > tick for bid
        )
        .unwrap();

        assert!(order.is_flip());
        assert_eq!(order.flip_tick(), 10);
        assert_eq!(order.tick(), 5);
        assert!(order.is_bid());
    }

    #[test]
    fn test_new_flip_order_ask() {
        let order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            false, // Ask
            5,
            2, // flip_tick < tick for ask
        )
        .unwrap();

        assert!(order.is_flip());
        assert_eq!(order.flip_tick(), 2);
        assert_eq!(order.tick(), 5);
        assert!(!order.is_bid());
        assert!(order.is_ask());
    }

    #[test]
    fn test_new_flip_order_bid_invalid_flip_tick() {
        let result = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            true, // Bid
            5,
            3, // Invalid: flip_tick <= tick for bid
        );

        assert!(matches!(result, Err(OrderError::InvalidBidFlipTick { .. })));
    }

    #[test]
    fn test_new_flip_order_ask_invalid_flip_tick() {
        let result = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            false, // Ask
            5,
            7, // Invalid: flip_tick >= tick for ask
        );

        assert!(matches!(result, Err(OrderError::InvalidAskFlipTick { .. })));
    }

    #[test]
    fn test_fill_bid_order_partial() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        assert!(!order.is_fully_filled());

        order.fill(400).unwrap();

        assert_eq!(order.remaining(), 600);
        assert_eq!(order.amount(), 1000);
        assert!(!order.is_fully_filled());
    }

    #[test]
    fn test_fill_ask_order_complete() {
        let mut order = Order::new_ask(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        order.fill(1000).unwrap();

        assert_eq!(order.remaining(), 0);
        assert_eq!(order.amount(), 1000);
        assert!(order.is_fully_filled());
    }

    #[test]
    fn test_fill_order_overfill() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        let result = order.fill(1001);
        assert!(matches!(
            result,
            Err(OrderError::FillAmountExceedsRemaining { .. })
        ));
    }

    #[test]
    fn test_create_flipped_order_bid_to_ask() {
        let mut order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            true, // Bid
            5,    // tick
            10,   // flip_tick
        )
        .unwrap();

        // Fully fill the order
        order.fill(1000).unwrap();
        assert!(order.is_fully_filled());

        // Create flipped order
        let flipped = order.create_flipped_order(2).unwrap();

        assert_eq!(flipped.order_id(), 2);
        assert_eq!(flipped.maker(), order.maker());
        assert_eq!(flipped.book_key(), order.book_key());
        assert_eq!(flipped.amount(), 1000); // Same as original
        assert_eq!(flipped.remaining(), 1000); // Reset to full amount
        assert!(!flipped.is_bid()); // Flipped from bid to ask
        assert!(flipped.is_ask());
        assert_eq!(flipped.tick(), 10); // Old flip_tick
        assert_eq!(flipped.flip_tick(), 5); // Old tick
        assert!(flipped.is_flip());
    }

    #[test]
    fn test_create_flipped_order_ask_to_bid() {
        let mut order = Order::new_flip(
            1,
            TEST_MAKER,
            TEST_BOOK_KEY,
            1000,
            false, // Ask
            10,    // tick
            5,     // flip_tick (< tick for ask)
        )
        .unwrap();

        order.fill(1000).unwrap();
        let flipped = order.create_flipped_order(2).unwrap();

        assert!(flipped.is_bid()); // Flipped from ask to bid
        assert!(!flipped.is_ask());
        assert_eq!(flipped.tick(), 5); // Old flip_tick
        assert_eq!(flipped.flip_tick(), 10); // Old tick
    }

    #[test]
    fn test_create_flipped_order_non_flip() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        order.fill(1000).unwrap();
        let result = order.create_flipped_order(2);
        assert!(matches!(result, Err(OrderError::NotAFlipOrder)));
    }

    #[test]
    fn test_create_flipped_order_not_filled() {
        let order = Order::new_flip(1, TEST_MAKER, TEST_BOOK_KEY, 1000, true, 5, 10).unwrap();

        let result = order.create_flipped_order(2);
        assert!(matches!(
            result,
            Err(OrderError::OrderNotFullyFilled { .. })
        ));
    }

    #[test]
    fn test_multiple_fills() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        // Multiple partial fills
        order.fill(300).unwrap();
        assert_eq!(order.remaining(), 700);

        order.fill(200).unwrap();
        assert_eq!(order.remaining(), 500);

        order.fill(500).unwrap();
        assert_eq!(order.remaining(), 0);
        assert!(order.is_fully_filled());
    }

    #[test]
    fn test_multiple_flips() {
        // Test that an order can flip multiple times
        let mut order = Order::new_flip(1, TEST_MAKER, TEST_BOOK_KEY, 1000, true, 5, 10).unwrap();

        // First flip: bid -> ask
        order.fill(1000).unwrap();
        let mut flipped1 = order.create_flipped_order(2).unwrap();

        assert!(!flipped1.is_bid());
        assert!(flipped1.is_ask());
        assert_eq!(flipped1.tick(), 10);
        assert_eq!(flipped1.flip_tick(), 5);

        // Second flip: ask -> bid
        flipped1.fill(1000).unwrap();
        let flipped2 = flipped1.create_flipped_order(3).unwrap();

        assert!(flipped2.is_bid());
        assert!(!flipped2.is_ask());
        assert_eq!(flipped2.tick(), 5);
        assert_eq!(flipped2.flip_tick(), 10);
    }

    #[test]
    fn test_tick_price_encoding() {
        // Tick represents price offset from peg

        let order_above = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 2);
        assert_eq!(order_above.tick(), 2);

        let order_below = Order::new_ask(2, TEST_MAKER, TEST_BOOK_KEY, 1000, -2);
        assert_eq!(order_below.tick(), -2);

        let order_par = Order::new_bid(3, TEST_MAKER, TEST_BOOK_KEY, 1000, 0);
        assert_eq!(order_par.tick(), 0);
    }

    #[test]
    fn test_linked_list_pointers_initialization() {
        let order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);
        // Linked list pointers should be initialized to 0
        assert_eq!(order.prev(), 0);
        assert_eq!(order.next(), 0);
    }

    #[test]
    fn test_set_linked_list_pointers() {
        let mut order = Order::new_bid(1, TEST_MAKER, TEST_BOOK_KEY, 1000, 5);

        // Set prev and next pointers
        order.set_prev(42);
        order.set_next(43);

        assert_eq!(order.prev(), 42);
        assert_eq!(order.next(), 43);
    }

    #[test]
    fn test_flipped_order_resets_linked_list_pointers() {
        let mut order = Order::new_flip(1, TEST_MAKER, TEST_BOOK_KEY, 1000, true, 5, 10).unwrap();

        // Set linked list pointers on original order
        order.set_prev(100);
        order.set_next(200);

        // Fill the order
        order.fill(1000).unwrap();

        // Create flipped order
        let flipped = order.create_flipped_order(2).unwrap();

        // Flipped order should have reset pointers
        assert_eq!(flipped.prev(), 0);
        assert_eq!(flipped.next(), 0);
    }
}
