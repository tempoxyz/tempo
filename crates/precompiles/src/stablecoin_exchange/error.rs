/// Errors that can occur when working with orders.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrderError {
    /// Flip tick constraint violated for a bid flip order.
    /// For bids: flip_tick must be > tick
    #[error(
        "invalid flip tick for bid order: flip_tick ({flip_tick}) must be greater than tick ({tick})"
    )]
    InvalidBidFlipTick {
        /// The order's tick
        tick: i16,
        /// The invalid flip_tick value
        flip_tick: i16,
    },

    /// Flip tick constraint violated for an ask flip order.
    /// For asks: flip_tick must be < tick
    #[error(
        "invalid flip tick for ask order: flip_tick ({flip_tick}) must be less than tick ({tick})"
    )]
    InvalidAskFlipTick {
        /// The order's tick
        tick: i16,
        /// The invalid flip_tick value
        flip_tick: i16,
    },

    /// Attempted to create a flipped order from a non-flip order
    #[error("cannot create flipped order from a non-flip order")]
    NotAFlipOrder,

    /// Attempted to create a flipped order from an order that is not fully filled
    #[error("order must be fully filled to flip, but {remaining} amount remains")]
    OrderNotFullyFilled {
        /// Remaining amount that needs to be filled
        remaining: u128,
    },

    /// Attempted to fill more than the remaining amount
    #[error("cannot fill {requested} when only {available} is available")]
    FillAmountExceedsRemaining {
        /// Amount requested to fill
        requested: u128,
        /// Amount available to fill
        available: u128,
    },

    /// Tick value is out of valid bounds
    #[error("tick {tick} is out of bounds (min: {min}, max: {max})")]
    InvalidTick {
        /// The invalid tick value
        tick: i16,
        /// Minimum valid tick
        min: i16,
        /// Maximum valid tick
        max: i16,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_flip_tick_bid() {
        let err = OrderError::InvalidBidFlipTick { tick: 5, flip_tick: 3 };
        let msg = err.to_string();
        assert!(msg.contains("bid"));
        assert!(msg.contains("greater than"));
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_invalid_flip_tick_ask() {
        let err = OrderError::InvalidAskFlipTick { tick: 5, flip_tick: 7 };
        let msg = err.to_string();
        assert!(msg.contains("ask"));
        assert!(msg.contains("less than"));
        assert!(msg.contains("5"));
        assert!(msg.contains("7"));
    }

    #[test]
    fn test_not_a_flip_order() {
        let err = OrderError::NotAFlipOrder;
        assert_eq!(err.to_string(), "cannot create flipped order from a non-flip order");
    }

    #[test]
    fn test_order_not_fully_filled() {
        let err = OrderError::OrderNotFullyFilled { remaining: 500 };
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("must be fully filled"));
    }

    #[test]
    fn test_fill_amount_exceeds_remaining() {
        let err = OrderError::FillAmountExceedsRemaining { requested: 1000, available: 600 };
        let msg = err.to_string();
        assert!(msg.contains("1000"));
        assert!(msg.contains("600"));
    }

    #[test]
    fn test_invalid_tick() {
        let err = OrderError::InvalidTick { tick: 3000, min: -2000, max: 2000 };
        let msg = err.to_string();
        assert_eq!(msg, "tick 3000 is out of bounds (min: -2000, max: 2000)");
    }
}
