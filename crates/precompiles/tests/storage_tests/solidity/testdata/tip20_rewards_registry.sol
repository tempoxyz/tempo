// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract for TIP20RewardsRegistry storage layout.
/// Registry for tracking reward stream end times.
contract TIP20RewardsRegistry {
    // ========== Storage ==========

    /// Last updated timestamp
    uint128 public lastUpdatedTimestamp;

    /// Mapping of timestamp to dynamic array of token addresses
    /// Tracks which tokens have reward streams ending at a given timestamp
    mapping(uint128 => address[]) public endingStreams; // in the spec named `streamsEndingAt`

    /// Mapping of (timestamp, token_address) hash to index in `endingStreams` array
    /// Used for efficient removal from the array
    mapping(bytes32 => uint256) public streamIndex;
}
