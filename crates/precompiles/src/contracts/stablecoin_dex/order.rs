//! Limit order type for the stablecoin DEX.
//!
//! This module defines the core `LimitOrder` type used in the stablecoin DEX orderbook.
//! Orders support price-time priority matching, partial fills, and flip orders that
//! automatically place opposite-side orders when filled.

use alloy::primitives::Address;

use super::error::OrderError;

/// Represents a limit order in the stablecoin DEX orderbook.
///
/// # Order Types
/// - **Bid**: Order to buy the token using its linking token
/// - **Ask**: Order to sell the token for its linking token
/// - **Flip**: Order that automatically creates a new order on the opposite side when fully filled
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
pub enum LimitOrder {
    /// Bid order: buying the token using its linking token
    Bid {
        /// Unique identifier for this order
        order_id: u128,
        /// Address of the user who placed this order
        maker: Address,
        /// Token being traded (not the linking token)
        token: Address,
        /// Remaining amount of the token to be filled
        amount: u128,
        /// Original amount when the order was placed
        original_amount: u128,
        /// Price tick: (price - 1) * 1000
        tick: i16,
        /// Block number when inserted into orderbook
        block_number: u64,
        /// Position within block
        order_index: u64,
    },

    /// Ask order: selling the token for its linking token
    Ask {
        /// Unique identifier for this order
        order_id: u128,
        /// Address of the user who placed this order
        maker: Address,
        /// Token being traded (not the linking token)
        token: Address,
        /// Remaining amount of the token to be filled
        amount: u128,
        /// Original amount when the order was placed
        original_amount: u128,
        /// Price tick: (price - 1) * 1000
        tick: i16,
        /// Block number when inserted into orderbook
        block_number: u64,
        /// Position within block
        order_index: u64,
    },

    /// Flip order: automatically creates a new order on the opposite side when fully filled
    Flip {
        /// Unique identifier for this order
        order_id: u128,
        /// Address of the user who placed this order
        maker: Address,
        /// Token being traded (not the linking token)
        token: Address,
        /// Remaining amount of the token to be filled
        amount: u128,
        /// Original amount when the order was placed
        original_amount: u128,
        /// True if this is a bid (buying), false if ask (selling)
        is_bid: bool,
        /// Price tick: (price - 1) * 1000
        tick: i16,
        /// Tick to flip to when fully filled
        /// For bid flips: flip_tick must be > tick
        /// For ask flips: flip_tick must be < tick
        flip_tick: i16,
        /// Block number when inserted into orderbook
        block_number: u64,
        /// Position within block
        order_index: u64,
        /// Whether this order was created from a flip within the current block
        was_flipped: bool,
    },
}

impl LimitOrder {
    /// Creates a new bid order (buying token with linking token).
    #[allow(clippy::too_many_arguments)]
    pub fn new_bid(
        order_id: u128,
        maker: Address,
        token: Address,
        amount: u128,
        tick: i16,
        block_number: u64,
        order_index: u64,
    ) -> Self {
        Self::Bid {
            order_id,
            maker,
            token,
            amount,
            original_amount: amount,
            tick,
            block_number,
            order_index,
        }
    }

    /// Creates a new ask order (selling token for linking token).
    #[allow(clippy::too_many_arguments)]
    pub fn new_ask(
        order_id: u128,
        maker: Address,
        token: Address,
        amount: u128,
        tick: i16,
        block_number: u64,
        order_index: u64,
    ) -> Self {
        Self::Ask {
            order_id,
            maker,
            token,
            amount,
            original_amount: amount,
            tick,
            block_number,
            order_index,
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

        Ok(Self::Flip {
            order_id,
            maker,
            token,
            amount,
            original_amount: amount,
            is_bid,
            tick,
            flip_tick,
            block_number,
            order_index,
            was_flipped: false,
        })
    }

    /// Returns the order ID.
    pub fn order_id(&self) -> u128 {
        match self {
            Self::Bid { order_id, .. }
            | Self::Ask { order_id, .. }
            | Self::Flip { order_id, .. } => *order_id,
        }
    }

    /// Returns the maker address.
    pub fn maker(&self) -> Address {
        match self {
            Self::Bid { maker, .. } | Self::Ask { maker, .. } | Self::Flip { maker, .. } => *maker,
        }
    }

    /// Returns the token address.
    pub fn token(&self) -> Address {
        match self {
            Self::Bid { token, .. } | Self::Ask { token, .. } | Self::Flip { token, .. } => *token,
        }
    }

    /// Returns the remaining amount.
    pub fn amount(&self) -> u128 {
        match self {
            Self::Bid { amount, .. } | Self::Ask { amount, .. } | Self::Flip { amount, .. } => {
                *amount
            }
        }
    }

    /// Returns a mutable reference to the remaining amount.
    fn amount_mut(&mut self) -> &mut u128 {
        match self {
            Self::Bid { amount, .. } | Self::Ask { amount, .. } | Self::Flip { amount, .. } => {
                amount
            }
        }
    }

    /// Returns the original amount.
    pub fn original_amount(&self) -> u128 {
        match self {
            Self::Bid {
                original_amount, ..
            }
            | Self::Ask {
                original_amount, ..
            }
            | Self::Flip {
                original_amount, ..
            } => *original_amount,
        }
    }

    /// Returns the tick price.
    pub fn tick(&self) -> i16 {
        match self {
            Self::Bid { tick, .. } | Self::Ask { tick, .. } | Self::Flip { tick, .. } => *tick,
        }
    }

    /// Returns the block number.
    pub fn block_number(&self) -> u64 {
        match self {
            Self::Bid { block_number, .. }
            | Self::Ask { block_number, .. }
            | Self::Flip { block_number, .. } => *block_number,
        }
    }

    /// Returns the order index within the block.
    pub fn order_index(&self) -> u64 {
        match self {
            Self::Bid { order_index, .. }
            | Self::Ask { order_index, .. }
            | Self::Flip { order_index, .. } => *order_index,
        }
    }

    /// Returns true if this is a bid order (buying token).
    pub fn is_bid(&self) -> bool {
        match self {
            Self::Bid { .. } => true,
            Self::Ask { .. } => false,
            Self::Flip { is_bid, .. } => *is_bid,
        }
    }

    /// Returns true if this is an ask order (selling token).
    pub fn is_ask(&self) -> bool {
        !self.is_bid()
    }

    /// Returns true if this is a flip order.
    pub fn is_flip(&self) -> bool {
        matches!(self, Self::Flip { .. })
    }

    /// Returns the flip tick if this is a flip order.
    pub fn flip_tick(&self) -> Option<i16> {
        match self {
            Self::Flip { flip_tick, .. } => Some(*flip_tick),
            _ => None,
        }
    }

    /// Returns true if this order was created from a flip.
    pub fn was_flipped(&self) -> bool {
        match self {
            Self::Flip { was_flipped, .. } => *was_flipped,
            _ => false,
        }
    }

    /// Returns true if the order is completely filled (no remaining amount).
    pub fn is_fully_filled(&self) -> bool {
        self.amount() == 0
    }

    /// Fills the order by the specified amount.
    ///
    /// # Errors
    /// Returns an error if fill_amount exceeds remaining amount
    pub fn fill(&mut self, fill_amount: u128) -> Result<(), OrderError> {
        let amount = self.amount();
        if fill_amount > amount {
            return Err(OrderError::FillAmountExceedsRemaining {
                requested: fill_amount,
                available: amount,
            });
        }
        *self.amount_mut() = amount.saturating_sub(fill_amount);
        Ok(())
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
        match self {
            Self::Flip {
                maker,
                token,
                original_amount,
                is_bid,
                tick,
                flip_tick,
                amount,
                ..
            } => {
                if *amount != 0 {
                    return Err(OrderError::OrderNotFullyFilled { remaining: *amount });
                }

                Ok(Self::Flip {
                    order_id: new_order_id,
                    maker: *maker,
                    token: *token,
                    amount: *original_amount,
                    original_amount: *original_amount,
                    is_bid: !is_bid,  // Flip the side
                    tick: *flip_tick, // Old flip_tick becomes new tick
                    flip_tick: *tick, // Old tick becomes new flip_tick
                    block_number,
                    order_index,
                    was_flipped: true, // Mark as flipped for priority
                })
            }
            _ => Err(OrderError::NotAFlipOrder),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_new_bid_order() {
        let order = LimitOrder::new_bid(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            5,
            100,
            0,
        );

        assert_eq!(order.order_id(), 1);
        assert_eq!(
            order.maker(),
            address!("0x1111111111111111111111111111111111111111")
        );
        assert_eq!(
            order.token(),
            address!("0x2222222222222222222222222222222222222222")
        );
        assert_eq!(order.amount(), 1000);
        assert_eq!(order.original_amount(), 1000);
        assert!(order.is_bid());
        assert!(!order.is_ask());
        assert_eq!(order.tick(), 5);
        assert!(!order.is_flip());
        assert_eq!(order.flip_tick(), None);
        assert_eq!(order.block_number(), 100);
        assert_eq!(order.order_index(), 0);
        assert!(!order.was_flipped());
    }

    #[test]
    fn test_new_ask_order() {
        let order = LimitOrder::new_ask(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            5,
            100,
            0,
        );

        assert_eq!(order.order_id(), 1);
        assert!(!order.is_bid());
        assert!(order.is_ask());
        assert!(!order.is_flip());
    }

    #[test]
    fn test_new_flip_order_bid() {
        let order = LimitOrder::new_flip(
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

        assert!(order.is_flip());
        assert_eq!(order.flip_tick(), Some(10));
        assert_eq!(order.tick(), 5);
        assert!(order.is_bid());
    }

    #[test]
    fn test_new_flip_order_ask() {
        let order = LimitOrder::new_flip(
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

        assert!(order.is_flip());
        assert_eq!(order.flip_tick(), Some(2));
        assert_eq!(order.tick(), 5);
        assert!(!order.is_bid());
        assert!(order.is_ask());
    }

    #[test]
    fn test_new_flip_order_bid_invalid_flip_tick() {
        let result = LimitOrder::new_flip(
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
        let result = LimitOrder::new_flip(
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
    fn test_fill_bid_order_partial() {
        let mut order = LimitOrder::new_bid(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            5,
            100,
            0,
        );

        assert!(!order.is_fully_filled());

        order.fill(400).unwrap();

        assert_eq!(order.amount(), 600);
        assert_eq!(order.original_amount(), 1000);
        assert!(!order.is_fully_filled());
    }

    #[test]
    fn test_fill_ask_order_complete() {
        let mut order = LimitOrder::new_ask(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            5,
            100,
            0,
        );

        order.fill(1000).unwrap();

        assert_eq!(order.amount(), 0);
        assert_eq!(order.original_amount(), 1000);
        assert!(order.is_fully_filled());
    }

    #[test]
    fn test_fill_order_overfill() {
        let mut order = LimitOrder::new_bid(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
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
        let mut order = LimitOrder::new_flip(
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

        assert_eq!(flipped.order_id(), 2);
        assert_eq!(flipped.maker(), order.maker());
        assert_eq!(flipped.token(), order.token());
        assert_eq!(flipped.amount(), 1000); // Same as original
        assert_eq!(flipped.original_amount(), 1000);
        assert!(!flipped.is_bid()); // Flipped from bid to ask
        assert!(flipped.is_ask());
        assert_eq!(flipped.tick(), 10); // Old flip_tick
        assert_eq!(flipped.flip_tick(), Some(5)); // Old tick
        assert_eq!(flipped.block_number(), 101);
        assert_eq!(flipped.order_index(), 5);
        assert!(flipped.was_flipped());
        assert!(flipped.is_flip());
    }

    #[test]
    fn test_create_flipped_order_ask_to_bid() {
        let mut order = LimitOrder::new_flip(
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

        assert!(flipped.is_bid()); // Flipped from ask to bid
        assert!(!flipped.is_ask());
        assert_eq!(flipped.tick(), 5); // Old flip_tick
        assert_eq!(flipped.flip_tick(), Some(10)); // Old tick
        assert!(flipped.was_flipped());
    }

    #[test]
    fn test_create_flipped_order_non_flip() {
        let mut order = LimitOrder::new_bid(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
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
        let order = LimitOrder::new_flip(
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
        let mut order = LimitOrder::new_bid(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            5,
            100,
            0,
        );

        // Multiple partial fills
        order.fill(300).unwrap();
        assert_eq!(order.amount(), 700);

        order.fill(200).unwrap();
        assert_eq!(order.amount(), 500);

        order.fill(500).unwrap();
        assert_eq!(order.amount(), 0);
        assert!(order.is_fully_filled());
    }

    #[test]
    fn test_multiple_flips() {
        // Test that an order can flip multiple times
        let mut order = LimitOrder::new_flip(
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

        assert!(!flipped1.is_bid());
        assert!(flipped1.is_ask());
        assert_eq!(flipped1.tick(), 10);
        assert_eq!(flipped1.flip_tick(), Some(5));

        // Second flip: ask -> bid
        flipped1.fill(1000).unwrap();
        let flipped2 = flipped1.create_flipped_order(3, 102, 0).unwrap();

        assert!(flipped2.is_bid());
        assert!(!flipped2.is_ask());
        assert_eq!(flipped2.tick(), 5);
        assert_eq!(flipped2.flip_tick(), Some(10));
    }

    #[test]
    fn test_order_priority_fields() {
        let order1 = LimitOrder::new_bid(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            5,
            100,
            0,
        );

        let order2 = LimitOrder::new_bid(
            2,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            5,
            100,
            1,
        );

        let order3 = LimitOrder::new_bid(
            3,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            5,
            101,
            0,
        );

        // Same tick and block, different order_index
        assert_eq!(order1.tick(), order2.tick());
        assert_eq!(order1.block_number(), order2.block_number());
        assert!(order1.order_index() < order2.order_index());

        // Same tick, different block
        assert_eq!(order1.tick(), order3.tick());
        assert!(order1.block_number() < order3.block_number());
    }

    #[test]
    fn test_flipped_order_priority_flag() {
        let mut flip_order = LimitOrder::new_flip(
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

        assert!(!flip_order.was_flipped());

        flip_order.fill(1000).unwrap();
        let flipped = flip_order.create_flipped_order(2, 101, 0).unwrap();

        // Flipped orders are marked for priority in same block
        assert!(flipped.was_flipped());
    }

    #[test]
    fn test_tick_price_encoding() {
        // Tick = (price - 1) * 1000

        // Price = $1.002 -> tick = 2
        let order_above = LimitOrder::new_bid(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            2,
            100,
            0,
        );
        assert_eq!(order_above.tick(), 2);

        // Price = $0.998 -> tick = -2
        let order_below = LimitOrder::new_ask(
            2,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            -2,
            100,
            0,
        );
        assert_eq!(order_below.tick(), -2);

        // Price = $1.00 -> tick = 0
        let order_par = LimitOrder::new_bid(
            3,
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            1000,
            0,
            100,
            0,
        );
        assert_eq!(order_par.tick(), 0);
    }
}
