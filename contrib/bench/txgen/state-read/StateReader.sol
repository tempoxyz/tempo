// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITIP20Balance {
    function balanceOf(address) external view returns (uint256);
}

/// Benchmark fixture for the state-read presets: spends a transaction's gas on
/// TIP20 balance reads of state-bloat accounts. Addresses follow the state-bloat
/// fast derivation: address = last 20 bytes of keccak256(seed || uint64_be(index)).
contract StateReader {
    uint256 public sink;

    /// Reads balances of pseudo-random bloat accounts with index in [start, end)
    /// until `reserve` gas is left. `salt` gives each transaction its own accounts.
    function readRandom(address token, bytes32 seed, uint256 start, uint256 end, bytes32 salt, uint256 reserve)
        external
        returns (uint256 reads)
    {
        uint256 span = end - start;
        uint256 acc;
        while (gasleft() > reserve) {
            uint256 idx = start + (uint256(keccak256(abi.encodePacked(salt, reads))) % span);
            // forge-lint: disable-next-line(unsafe-typecast)
            address account = address(uint160(uint256(keccak256(abi.encodePacked(seed, uint64(idx))))));
            acc += ITIP20Balance(token).balanceOf(account);
            unchecked {
                ++reads;
            }
        }
        // Keeps the reads observable without writing state on the normal path.
        if (acc == type(uint256).max) sink = acc;
    }
}
