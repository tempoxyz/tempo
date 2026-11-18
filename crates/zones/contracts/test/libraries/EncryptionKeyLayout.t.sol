// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    EncryptionKeyEntry,
    PORTAL_ENCRYPTION_KEYS_SLOT
} from "../../src/runtime/interfaces/IZone.sol";
import { Test } from "forge-std/Test.sol";

/// @notice Minimal harness that mirrors ZonePortal's _encryptionKeys storage layout.
/// @dev The array is placed at the same storage slot as in ZonePortal so that
///      derived slot arithmetic is identical.
contract EncryptionKeyLayoutHarness {

    // Slots 0-4: padding to match ZonePortal layout
    uint256 private _pad0;
    uint256 private _pad1;
    uint256 private _pad2;
    uint256 private _pad3;
    uint256 private _pad4;

    // Slot 5: _encryptionKeys — must be at PORTAL_ENCRYPTION_KEYS_SLOT
    EncryptionKeyEntry[] internal _encryptionKeys;

    function push(bytes32 x, uint8 yParity, uint64 activationBlock) external {
        _encryptionKeys.push(
            EncryptionKeyEntry({ x: x, yParity: yParity, activationBlock: activationBlock })
        );
    }

    function length() external view returns (uint256) {
        return _encryptionKeys.length;
    }

    function get(uint256 i) external view returns (EncryptionKeyEntry memory) {
        return _encryptionKeys[i];
    }

}

/// @title EncryptionKeyLayoutTest
/// @notice Storage layout regression test for EncryptionKeyEntry.
///         ZoneInbox._readEncryptionKey()
///         read raw storage slots and assume yParity is packed in the lowest byte
///         of the meta slot. If the struct field order ever changes, these tests fail.
contract EncryptionKeyLayoutTest is Test {

    EncryptionKeyLayoutHarness harness;

    function setUp() public {
        harness = new EncryptionKeyLayoutHarness();
    }

    /// @notice Verify x fills the first slot of each two-slot entry, yParity the lowest byte of
    ///         the meta slot and activationBlock bytes 1-8.
    function test_structPackingMultipleEntries() public {
        bytes32[3] memory xs = [keccak256("key-0"), keccak256("key-1"), keccak256("key-2")];
        uint8[3] memory yParities = [uint8(0x02), uint8(0x03), uint8(0x02)];
        uint64[3] memory blocks = [uint64(1), uint64(100_000), uint64(type(uint64).max)];

        for (uint256 i = 0; i < 3; i++) {
            harness.push(xs[i], yParities[i], blocks[i]);
        }

        uint256 base = uint256(keccak256(abi.encode(uint256(PORTAL_ENCRYPTION_KEYS_SLOT))));

        for (uint256 i = 0; i < 3; i++) {
            bytes32 rawX = vm.load(address(harness), bytes32(base + i * 2));
            bytes32 rawMeta = vm.load(address(harness), bytes32(base + i * 2 + 1));

            assertEq(rawX, xs[i], "x mismatch");
            assertEq(uint8(uint256(rawMeta) & 0xff), yParities[i], "yParity must be in lowest byte");
            assertEq(
                uint64((uint256(rawMeta) >> 8) & 0xffffffffffffffff),
                blocks[i],
                "activationBlock must be in bytes 1-8"
            );
        }
    }

}
