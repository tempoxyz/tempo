// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Benchmark fixture for the state-call presets: spends a transaction's gas on cold
/// calls to the state bloat's synthetic contracts (generate-state-bloat --contracts).
/// Contract i lives at the last 20 bytes of keccak256(seed || uint64_be(i)) and returns
/// that hash as one word, so each call loads a cold account and its distinct bytecode.
contract StateCaller {
    uint256 public sink;
    bytes32 public cursor;

    /// The cursor starts nonzero so transactions only overwrite it, never create a new slot.
    constructor() {
        cursor = keccak256("state-call");
    }

    /// Calls pseudo-random bloat contracts with index in [start, end) until `reserve`
    /// gas is left. `salt` gives each transaction its own contracts.
    function callRandom(bytes32 seed, uint256 start, uint256 end, bytes32 salt, uint256 reserve)
        external
        returns (uint256 calls)
    {
        uint256 span = end - start;
        uint256 acc;
        while (gasleft() > reserve) {
            uint256 idx = start + (uint256(keccak256(abi.encodePacked(salt, calls))) % span);
            // forge-lint: disable-next-line(unsafe-typecast)
            address target = address(uint160(uint256(keccak256(abi.encodePacked(seed, uint64(idx))))));
            acc ^= _call(target);
            unchecked {
                ++calls;
            }
        }
        // Keeps the calls observable without writing state on the normal path.
        if (acc == type(uint256).max) sink = acc;
    }

    /// Worst case: serial, dependent calls. The first target comes from a cursor the
    /// previous transaction wrote, and each next target from the word the last contract
    /// returned, so neither prewarming nor prefetching can know a target before the call
    /// ahead of it loads its code. Writes the cursor back for the next transaction.
    function callDependent(bytes32 seed, uint256 start, uint256 end, uint256 reserve)
        external
        returns (uint256 calls)
    {
        uint256 span = end - start;
        bytes32 x = cursor;
        while (gasleft() > reserve) {
            uint256 idx = start + (uint256(x) % span);
            // forge-lint: disable-next-line(unsafe-typecast)
            address target = address(uint160(uint256(keccak256(abi.encodePacked(seed, uint64(idx))))));
            x = keccak256(abi.encodePacked(x, _call(target), calls));
            unchecked {
                ++calls;
            }
        }
        cursor = x;
    }

    /// Calls `target` with no data and returns its first returned word (zero if none).
    function _call(address target) private view returns (uint256 word) {
        assembly ("memory-safe") {
            mstore(0, 0)
            pop(staticcall(gas(), target, 0, 0, 0, 32))
            word := mload(0)
        }
    }
}
