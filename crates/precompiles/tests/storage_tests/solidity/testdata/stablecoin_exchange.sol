// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract for StablecoinExchange storage layout.
/// Orderbook-based DEX for stablecoin trading.
contract StablecoinExchange {
    // ========== Structs ==========

    struct TickLevel {
        uint128 head;
        uint128 tail;
        uint128 totalLiquidity;
    }

    struct Orderbook {
        address base;
        address quote;
        mapping(int16 => TickLevel) bids;
        mapping(int16 => TickLevel) asks;
        int16 bestBidTick;
        int16 bestAskTick;
        mapping(int16 => uint256) bidBitmap;
        mapping(int16 => uint256) askBitmap;
    }

    struct Order {
        uint128 orderId;
        address maker;
        bytes32 bookKey;
        bool isBid;
        int16 tick;
        uint128 amount;
        uint128 remaining;
        uint128 prev;
        uint128 next;
        bool isFlip;
        int16 flipTick;
    }

    // ========== Storage ==========

    /// Mapping of book key (hash of base/quote pair) to orderbook data
    mapping(bytes32 => Orderbook) public books;

    /// Mapping of order ID to order details
    mapping(uint128 => Order) public orders;

    /// Nested mapping for user balances: user -> token -> balance
    mapping(address => mapping(address => uint128)) public balances;

    /// Next order ID
    uint128 public nextOrderId;

    /// Dynamic array of all book keys
    bytes32[] public bookKeys;
}
