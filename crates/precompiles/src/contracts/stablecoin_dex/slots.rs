//! Storage slot definitions for the StablecoinDex contract.
//!
//! This module defines the storage layout for the stablecoin DEX,
//! following the same pattern as the Solidity reference implementation.

use alloy::primitives::{U256, uint};

// Simple storage variables
/// Next order ID to be processed (last order that has been added to the active orderbook)
pub const NEXT_ORDER_ID: U256 = uint!(0_U256);

/// Latest pending order ID (last order that has been placed but not yet processed)
pub const PENDING_ORDER_ID: U256 = uint!(1_U256);

// Mappings
/// Mapping of pair key (bytes32) to Orderbook data
/// Storage layout for Orderbook struct starts at slot 2
pub const ORDERBOOKS: U256 = uint!(2_U256);

/// Mapping of order ID (u128) to Order data
/// Storage layout for Order struct starts at slot 3
pub const ORDERS: U256 = uint!(3_U256);

/// Mapping of user address => token address => balance (u128)
/// TODO: Implement balance management in follow-up work
pub const BALANCES: U256 = uint!(4_U256);

// Orderbook struct field offsets (relative to orderbook base slot)
/// Base token address field offset
pub const ORDERBOOK_BASE_OFFSET: U256 = uint!(0_U256);
/// Quote token address field offset
pub const ORDERBOOK_QUOTE_OFFSET: U256 = uint!(1_U256);
/// Minimum tick field offset
pub const ORDERBOOK_MIN_TICK_OFFSET: U256 = uint!(2_U256);
/// Maximum tick field offset
pub const ORDERBOOK_MAX_TICK_OFFSET: U256 = uint!(3_U256);
/// Best bid tick field offset
pub const ORDERBOOK_BEST_BID_TICK_OFFSET: U256 = uint!(4_U256);
/// Best ask tick field offset
pub const ORDERBOOK_BEST_ASK_TICK_OFFSET: U256 = uint!(5_U256);

// Order struct field offsets (relative to order base slot)
/// Maker address field offset
pub const ORDER_MAKER_OFFSET: U256 = uint!(0_U256);
/// Book key field offset
pub const ORDER_BOOK_KEY_OFFSET: U256 = uint!(1_U256);
/// Side (bid/ask) field offset
pub const ORDER_SIDE_OFFSET: U256 = uint!(2_U256);
/// Tick field offset
pub const ORDER_TICK_OFFSET: U256 = uint!(3_U256);
/// Amount field offset
pub const ORDER_AMOUNT_OFFSET: U256 = uint!(4_U256);
/// Remaining amount field offset
pub const ORDER_REMAINING_OFFSET: U256 = uint!(5_U256);
/// Previous order ID field offset
pub const ORDER_PREV_OFFSET: U256 = uint!(6_U256);
/// Next order ID field offset
pub const ORDER_NEXT_OFFSET: U256 = uint!(7_U256);
/// Is flip order boolean field offset
pub const ORDER_IS_FLIP_OFFSET: U256 = uint!(8_U256);
/// Flip tick field offset
pub const ORDER_FLIP_TICK_OFFSET: U256 = uint!(9_U256);
