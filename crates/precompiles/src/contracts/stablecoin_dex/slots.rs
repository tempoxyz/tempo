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
