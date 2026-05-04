// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.0;

/// Test contract for TIP1028Escrow storage layout.
contract TIP1028Escrow {
    uint64 public blockedReceiptNonce;
    mapping(bytes32 => uint256) internal blockedReceiptAmount;
}
