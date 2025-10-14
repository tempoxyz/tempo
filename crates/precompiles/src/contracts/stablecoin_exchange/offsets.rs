//! Struct field offsets for StablecoinExchange storage layout.
//!
//! This module defines field offsets within structs stored in the DEX.
//! These are NOT storage slots - they are offsets added to a base storage slot
//! to access individual struct fields.
//!
//! These offsets match the Solidity reference implementation in StablecoinExchange.sol.

use alloy::primitives::{U256, uint};

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
// Matches Solidity Order struct layout
/// Maker address field offset
pub const ORDER_MAKER_OFFSET: U256 = uint!(0_U256);
/// Orderbook key field offset
pub const ORDER_BOOK_KEY_OFFSET: U256 = uint!(1_U256);
/// Is bid boolean field offset
pub const ORDER_IS_BID_OFFSET: U256 = uint!(2_U256);
/// Tick field offset
pub const ORDER_TICK_OFFSET: U256 = uint!(3_U256);
/// Original amount field offset
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

// TickLevel struct field offsets (relative to tick level base slot)
// Matches Solidity TickLevel struct layout
/// Head order ID field offset
pub const TICK_LEVEL_HEAD_OFFSET: U256 = uint!(0_U256);
/// Tail order ID field offset
pub const TICK_LEVEL_TAIL_OFFSET: U256 = uint!(1_U256);
/// Total liquidity field offset
pub const TICK_LEVEL_TOTAL_LIQUIDITY_OFFSET: U256 = uint!(2_U256);
