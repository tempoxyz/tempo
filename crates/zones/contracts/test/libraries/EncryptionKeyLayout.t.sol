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

    /// @notice Verify that _encryptionKeys lives at the expected storage slot.
    function test_arraySlot() public view {
        bytes32 lengthSlot = bytes32(uint256(PORTAL_ENCRYPTION_KEYS_SLOT));
        uint256 len = uint256(vm.load(address(harness), lengthSlot));
        assertEq(len, 0, "empty array length should be 0 at PORTAL_ENCRYPTION_KEYS_SLOT");
    }

    /// @notice Verify that yParity is stored in the lowest byte of the meta slot,
    ///         and activationBlock occupies bytes 1-8.
    function test_structPackingLayout() public {
        bytes32 keyX = keccak256("regression-key");
        uint8 yParity = 0x03;
        uint64 activationBlock = 0xDEADBEEFCAFE;

        harness.push(keyX, yParity, activationBlock);

        uint256 base = uint256(keccak256(abi.encode(uint256(PORTAL_ENCRYPTION_KEYS_SLOT))));
        uint256 slotX = base;
        uint256 slotMeta = base + 1;

        // Verify x occupies a full slot
        bytes32 rawX = vm.load(address(harness), bytes32(slotX));
        assertEq(rawX, keyX, "slot 0 of entry should store x");

        // Verify the meta slot packing
        bytes32 rawMeta = vm.load(address(harness), bytes32(slotMeta));

        // yParity must be extractable from the lowest byte — this is exactly what
        // ZoneInbox._readEncryptionKey() do
        uint8 extractedYParity = uint8(uint256(rawMeta) & 0xff);
        assertEq(extractedYParity, yParity, "yParity must be in lowest byte of meta slot");

        // activationBlock must be in bytes 1-8 (bits 8..71)
        uint64 extractedActivation = uint64((uint256(rawMeta) >> 8) & 0xffffffffffffffff);
        assertEq(
            extractedActivation,
            activationBlock,
            "activationBlock must be in bytes 1-8 of meta slot"
        );
    }

    /// @notice Same check with multiple entries at different indices.
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

    /// @notice Verify that each EncryptionKeyEntry occupies exactly 2 storage slots.
    function test_entrySizeIsTwoSlots() public {
        harness.push(keccak256("a"), 0x02, 1);
        harness.push(keccak256("b"), 0x03, 2);

        uint256 base = uint256(keccak256(abi.encode(uint256(PORTAL_ENCRYPTION_KEYS_SLOT))));

        // Entry 0 at base+0, base+1
        bytes32 x0 = vm.load(address(harness), bytes32(base));
        assertEq(x0, keccak256("a"), "entry 0 x");

        // Entry 1 at base+2, base+3 (stride of 2)
        bytes32 x1 = vm.load(address(harness), bytes32(base + 2));
        assertEq(x1, keccak256("b"), "entry 1 x at stride 2");
    }

}
