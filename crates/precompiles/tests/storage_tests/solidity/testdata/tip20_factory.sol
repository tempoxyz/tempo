// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract for TIP20Factory storage layout.
/// Factory for creating TIP20 tokens.
///
/// NOTE: TIP20Factory no longer has storage fields.
/// Token addresses are now derived from keccak256(sender, salt) instead of
/// using a sequential tokenIdCounter.
contract TIP20Factory {
    // No storage fields
}
