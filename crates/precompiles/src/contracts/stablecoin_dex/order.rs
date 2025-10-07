//! Order type for the stablecoin DEX.
//!
//! This module defines the core `Order` type used in the stablecoin DEX orderbook.
//! Orders support price-time priority matching, partial fills, and flip orders that
//! automatically place opposite-side orders when filled.

use alloy::primitives::Address;

use super::error::OrderError;

/// Represents an order in the stablecoin DEX orderbook.
///
/// # Order Lifecycle
/// 1. Order is placed via `place()` or `placeFlip()` and added to pending queue
/// 2. At end of block, pending orders are inserted into the active orderbook
/// 3. Orders can be filled (fully or partially) by taker orders
/// 4. Flip orders automatically create a new order on the opposite side when fully filled
/// 5. Orders can be cancelled, removing them from the book
///
/// # Price-Time Priority
/// Orders are sorted by:
/// 1. Price (tick)
/// 2. Block number (when inserted)
/// 3. Order index within block
///
/// Special case: Orders that flipped within a block are added to the
/// book before other orders that were placed within the block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    /// Unique identifier for this order
    pub order_id: u128,

    /// Address of the user who placed this order
    pub maker: Address,

    /// Token being traded, not the linking token
    /// - For a bid: buying this token with linking token
    /// - For an ask: selling this token for linking token
    pub token: Address,

    /// Remaining amount of the token to be filled
    /// This decreases as the order is partially filled
    pub amount: u128,

    /// Original amount when the order was placed
    /// Required for flip orders to create new orders with correct size
    pub original_amount: u128,

    /// True if this is a bid (buying token), false if ask (selling token)
    pub is_bid: bool,

    /// Price tick for this order
    /// Tick = (price of token in linking token - 1) * 1000
    pub tick: i16,

    /// Whether this is a flip order
    /// Flip orders automatically create a new order on the opposite side when fully filled
    pub is_flip: bool,

    /// Tick to flip to when this order is fully filled
    /// - For bid flip orders: flip_tick must be > tick
    /// - For ask flip orders: flip_tick must be < tick
    pub flip_tick: Option<i16>,

    /// Block number when this order was inserted into the active orderbook
    /// Used for time priority in the orderbook
    pub block_number: u64,

    /// Position of this order within its block
    /// Used for ordering orders placed in the same block
    pub order_index: u64,

    /// Whether this order was created from a flip within the current block
    /// Such orders are added to the book before other orders placed in the same block
    pub was_flipped: bool,
}

impl Order {
    /// Creates a new regular (non-flip) order.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        order_id: u128,
        maker: Address,
        token: Address,
        amount: u128,
        is_bid: bool,
        tick: i16,
        block_number: u64,
        order_index: u64,
    ) -> Self {
        Self {
            order_id,
            maker,
            token,
            amount,
            original_amount: amount,
            is_bid,
            tick,
            is_flip: false,
            flip_tick: None,
            block_number,
            order_index,
            was_flipped: false,
        }
    }

    /// Creates a new flip order.
    ///
    /// # Errors
    /// Returns an error if flip_tick constraint is violated:
    /// - For bids: flip_tick must be > tick
    /// - For asks: flip_tick must be < tick
    #[allow(clippy::too_many_arguments)]
    pub fn new_flip(
        order_id: u128,
        maker: Address,
        token: Address,
        amount: u128,
        is_bid: bool,
        tick: i16,
        flip_tick: i16,
        block_number: u64,
        order_index: u64,
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
            token,
            amount,
            original_amount: amount,
            is_bid,
            tick,
            is_flip: true,
            flip_tick: Some(flip_tick),
            block_number,
            order_index,
            was_flipped: false,
        })
    }

    /// Creates a flipped order from a fully filled flip order.
    ///
    /// When a flip order is completely filled, it creates a new order on the opposite side:
    /// - Sides are swapped (bid -> ask, ask -> bid)
    /// - New price = original flip_tick
    /// - New flip_tick = original tick
    /// - Amount is the same as original
    /// - The new order is marked as `was_flipped` for priority
    ///
    /// # Errors
    /// Returns an error if called on a non-flip order or if the order is not fully filled
    pub fn create_flipped_order(
        &self,
        new_order_id: u128,
        block_number: u64,
        order_index: u64,
    ) -> Result<Self, OrderError> {
        if !self.is_flip {
            return Err(OrderError::NotAFlipOrder);
        }

        if !self.is_fully_filled() {
            return Err(OrderError::OrderNotFullyFilled {
                remaining: self.amount,
            });
        }

        let flip_tick = self.flip_tick.expect("Flip order must have flip_tick");

        Ok(Self {
            order_id: new_order_id,
            maker: self.maker,
            token: self.token,
            amount: self.original_amount,
            original_amount: self.original_amount,
            is_bid: !self.is_bid, // Flip the side
            tick: flip_tick,      // Old flip_tick becomes new tick
            is_flip: true,
            flip_tick: Some(self.tick), // Old tick becomes new flip_tick
            block_number,
            order_index,
            was_flipped: true, // Mark as flipped for priority
        })
    }

    /// Returns true if the order is completely filled
    #[inline]
    pub fn is_fully_filled(&self) -> bool {
        self.amount == 0
    }

    /// Fills the order by the specified amount.
    ///
    /// # Errors
    /// Returns an error if fill_amount exceeds remaining amount
    #[inline]
    pub fn fill(&mut self, fill_amount: u128) -> Result<(), OrderError> {
        if fill_amount > self.amount {
            return Err(OrderError::FillAmountExceedsRemaining {
                requested: fill_amount,
                available: self.amount,
            });
        }
        self.amount = self.amount.saturating_sub(fill_amount);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_new_regular_order() {
        let order = Order::new(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            100,
            0,
        );

        assert_eq!(order.order_id, 1);
        assert_eq!(
            order.maker,
            address!("0x1111111111111111111111111111111111111111")
        );
        assert_eq!(
            order.token,
            address!("0x2222222222222222222222222222222222222222")
        );
        assert_eq!(order.amount, 1000);
        assert_eq!(order.original_amount, 1000);
        assert!(order.is_bid);
        assert_eq!(order.tick, 5);
        assert!(!order.is_flip);
        assert_eq!(order.flip_tick, None);
        assert_eq!(order.block_number, 100);
        assert_eq!(order.order_index, 0);
        assert!(!order.was_flipped);
    }

    #[test]
    fn test_new_flip_order_bid() {
        let order = Order::new_flip(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            10, // flip_tick > tick for bid
            100,
            0,
        )
        .unwrap();

        assert!(order.is_flip);
        assert_eq!(order.flip_tick, Some(10));
        assert_eq!(order.tick, 5);
        assert!(order.is_bid);
    }

    #[test]
    fn test_new_flip_order_ask() {
        let order = Order::new_flip(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            false,
            5,
            2, // flip_tick < tick for ask
            100,
            0,
        )
        .unwrap();

        assert!(order.is_flip);
        assert_eq!(order.flip_tick, Some(2));
        assert_eq!(order.tick, 5);
        assert!(!order.is_bid);
    }

    #[test]
    fn test_new_flip_order_bid_invalid_flip_tick() {
        let result = Order::new_flip(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            3, // Invalid: flip_tick <= tick for bid
            100,
            0,
        );

        assert!(matches!(result, Err(OrderError::InvalidBidFlipTick { .. })));
    }

    #[test]
    fn test_new_flip_order_ask_invalid_flip_tick() {
        let result = Order::new_flip(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            false,
            5,
            7, // Invalid: flip_tick >= tick for ask
            100,
            0,
        );

        assert!(matches!(result, Err(OrderError::InvalidAskFlipTick { .. })));
    }

    #[test]
    fn test_fill_order_partial() {
        let mut order = Order::new(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            100,
            0,
        );

        assert!(!order.is_fully_filled());

        order.fill(400).unwrap();

        assert_eq!(order.amount, 600);
        assert_eq!(order.original_amount, 1000);
        assert!(!order.is_fully_filled());
    }

    #[test]
    fn test_fill_order_complete() {
        let mut order = Order::new(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            100,
            0,
        );

        order.fill(1000).unwrap();

        assert_eq!(order.amount, 0);
        assert_eq!(order.original_amount, 1000);
        assert!(order.is_fully_filled());
    }

    #[test]
    fn test_fill_order_overfill() {
        let mut order = Order::new(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            100,
            0,
        );

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
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true, // bid
            5,    // tick
            10,   // flip_tick
            100,
            0,
        )
        .unwrap();

        // Fully fill the order
        order.fill(1000).unwrap();
        assert!(order.is_fully_filled());

        // Create flipped order
        let flipped = order.create_flipped_order(2, 101, 5).unwrap();

        assert_eq!(flipped.order_id, 2);
        assert_eq!(flipped.maker, order.maker);
        assert_eq!(flipped.token, order.token);
        assert_eq!(flipped.amount, 1000); // Same as original
        assert_eq!(flipped.original_amount, 1000);
        assert!(!flipped.is_bid); // Flipped from bid to ask
        assert_eq!(flipped.tick, 10); // Old flip_tick
        assert_eq!(flipped.flip_tick, Some(5)); // Old tick
        assert_eq!(flipped.block_number, 101);
        assert_eq!(flipped.order_index, 5);
        assert!(flipped.was_flipped);
        assert!(flipped.is_flip);
    }

    #[test]
    fn test_create_flipped_order_ask_to_bid() {
        let mut order = Order::new_flip(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            false, // ask
            10,    // tick
            5,     // flip_tick (< tick for ask)
            100,
            0,
        )
        .unwrap();

        order.fill(1000).unwrap();
        let flipped = order.create_flipped_order(2, 101, 5).unwrap();

        assert!(flipped.is_bid); // Flipped from ask to bid
        assert_eq!(flipped.tick, 5); // Old flip_tick
        assert_eq!(flipped.flip_tick, Some(10)); // Old tick
        assert!(flipped.was_flipped);
    }

    #[test]
    fn test_create_flipped_order_non_flip() {
        let mut order = Order::new(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            100,
            0,
        );

        order.fill(1000).unwrap();
        let result = order.create_flipped_order(2, 101, 5);
        assert!(matches!(result, Err(OrderError::NotAFlipOrder)));
    }

    #[test]
    fn test_create_flipped_order_not_filled() {
        let order = Order::new_flip(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            10,
            100,
            0,
        )
        .unwrap();

        let result = order.create_flipped_order(2, 101, 5);
        assert!(matches!(
            result,
            Err(OrderError::OrderNotFullyFilled { .. })
        ));
    }

    #[test]
    fn test_multiple_fills() {
        let mut order = Order::new(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            100,
            0,
        );

        // Multiple partial fills
        order.fill(300).unwrap();
        assert_eq!(order.amount, 700);

        order.fill(200).unwrap();
        assert_eq!(order.amount, 500);

        order.fill(500).unwrap();
        assert_eq!(order.amount, 0);
        assert!(order.is_fully_filled());
    }

    #[test]
    fn test_multiple_flips() {
        // Test that an order can flip multiple times
        let mut order = Order::new_flip(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true, // bid
            5,
            10,
            100,
            0,
        )
        .unwrap();

        // First flip: bid -> ask
        order.fill(1000).unwrap();
        let mut flipped1 = order.create_flipped_order(2, 101, 0).unwrap();

        assert!(!flipped1.is_bid);
        assert_eq!(flipped1.tick, 10);
        assert_eq!(flipped1.flip_tick, Some(5));

        // Second flip: ask -> bid
        flipped1.fill(1000).unwrap();
        let flipped2 = flipped1.create_flipped_order(3, 102, 0).unwrap();

        assert!(flipped2.is_bid);
        assert_eq!(flipped2.tick, 5);
        assert_eq!(flipped2.flip_tick, Some(10));
    }

    #[test]
    fn test_order_priority_fields() {
        let order1 = Order::new(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            100,
            0,
        );

        let order2 = Order::new(
            2,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            100,
            1,
        );

        let order3 = Order::new(
            3,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            101,
            0,
        );

        // Same tick and block, different order_index
        assert_eq!(order1.tick, order2.tick);
        assert_eq!(order1.block_number, order2.block_number);
        assert!(order1.order_index < order2.order_index);

        // Same tick, different block
        assert_eq!(order1.tick, order3.tick);
        assert!(order1.block_number < order3.block_number);
    }

    #[test]
    fn test_flipped_order_priority_flag() {
        let mut flip_order = Order::new_flip(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            5,
            10,
            100,
            0,
        )
        .unwrap();

        assert!(!flip_order.was_flipped);

        flip_order.fill(1000).unwrap();
        let flipped = flip_order.create_flipped_order(2, 101, 0).unwrap();

        // Flipped orders are marked for priority in same block
        assert!(flipped.was_flipped);
    }

    #[test]
    fn test_tick_price_encoding() {
        // Tick = (price - 1) * 1000

        // Price = $1.002 -> tick = 2
        let order_above = Order::new(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            2,
            100,
            0,
        );
        assert_eq!(order_above.tick, 2);

        // Price = $0.998 -> tick = -2
        let order_below = Order::new(
            2,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            false,
            -2,
            100,
            0,
        );
        assert_eq!(order_below.tick, -2);

        // Price = $1.00 -> tick = 0
        let order_par = Order::new(
            3,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            true,
            0,
            100,
            0,
        );
        assert_eq!(order_par.tick, 0);
    }
}
