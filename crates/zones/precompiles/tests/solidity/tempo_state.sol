// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// Storage-only schema for the native TempoState precompile.
contract TempoStateStorage {
    bytes32 public tempoBlockHash;
    uint64 public tempoBlockNumber;
}
