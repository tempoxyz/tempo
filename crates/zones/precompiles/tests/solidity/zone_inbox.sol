// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// Storage-only schema for the native ZoneInbox precompile.
contract ZoneInboxStorage {
    bytes32 public processedDepositQueueHash;
    uint64 public processedDepositNumber;
    mapping(address token => mapping(address owner => uint128 amount)) private _refunds;
    bytes32 public processedTokenEnablementHash;
}
