// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITIP20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// Benchmark fixture for the state-write presets: spends a transaction's gas on TIP20
/// transfers of 1 unit to state-bloat accounts, each of which already holds a balance,
/// so every transfer overwrites an existing storage slot. Fund it with the token first.
/// Addresses follow the state-bloat fast derivation:
/// address = last 20 bytes of keccak256(seed || uint64_be(index)).
contract StateWriter {
    bytes32 public cursor;

    /// The cursor starts nonzero so transactions only overwrite it, never create a new slot.
    constructor() {
        cursor = keccak256("state-write");
    }

    /// Writes to pseudo-random bloat accounts with index in [start, end) until
    /// `reserve` gas is left. `salt` gives each transaction its own accounts.
    function writeRandom(address token, bytes32 seed, uint256 start, uint256 end, bytes32 salt, uint256 reserve)
        external
        returns (uint256 writes)
    {
        uint256 span = end - start;
        while (gasleft() > reserve) {
            uint256 idx = start + (uint256(keccak256(abi.encodePacked(salt, writes))) % span);
            // forge-lint: disable-next-line(unsafe-typecast)
            address account = address(uint160(uint256(keccak256(abi.encodePacked(seed, uint64(idx))))));
            ITIP20(token).transfer(account, 1);
            unchecked {
                ++writes;
            }
        }
    }

    /// Worst case: serial, dependent writes. The first account comes from a cursor the
    /// previous transaction wrote, and each next account from the balance just written,
    /// so prewarming can't know an address before the write ahead of it completes.
    function writeDependent(address token, bytes32 seed, uint256 start, uint256 end, uint256 reserve)
        external
        returns (uint256 writes)
    {
        uint256 span = end - start;
        bytes32 x = cursor;
        while (gasleft() > reserve) {
            uint256 idx = start + (uint256(x) % span);
            // forge-lint: disable-next-line(unsafe-typecast)
            address account = address(uint160(uint256(keccak256(abi.encodePacked(seed, uint64(idx))))));
            ITIP20(token).transfer(account, 1);
            x = keccak256(abi.encodePacked(x, ITIP20(token).balanceOf(account), writes));
            unchecked {
                ++writes;
            }
        }
        cursor = x;
    }
}
