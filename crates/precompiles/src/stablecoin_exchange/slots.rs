//! Storage slot definitions for the StablecoinExchange contract.
//!
//! This module defines the storage layout for the stablecoin DEX,
//! following the same pattern as the Solidity reference implementation.

use alloy::primitives::{U256, uint};

// Simple storage variables
/// Next order ID to be processed (last order that has been added to the active orderbook)
pub const ACTIVE_ORDER_ID: U256 = uint!(0_U256);

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

/// Mapping of (pair_key, tick) to PriceLevel data for bid orders
/// Storage layout for PriceLevel struct starts at slot 5
pub const BID_TICK_LEVELS: U256 = uint!(5_U256);

/// Mapping of (pair_key, tick) to PriceLevel data for ask orders
/// Storage layout for PriceLevel struct starts at slot 6
pub const ASK_TICK_LEVELS: U256 = uint!(6_U256);

/// Mapping of (pair_key, word_index) to bid bitmap data
/// Used for efficient price discovery in bid direction
pub const BID_BITMAPS: U256 = uint!(7_U256);

/// Mapping of (pair_key, word_index) to ask bitmap data
/// Used for efficient price discovery in ask direction
pub const ASK_BITMAPS: U256 = uint!(8_U256);

/// Length of book keys vector
pub const BOOK_KEYS_LENGTH: U256 = uint!(9_U256);

/// Base slot for book keys vector data
/// Individual book keys are stored at BOOK_KEYS_BASE + index
pub const BOOK_KEYS_BASE: U256 = uint!(10_U256);
