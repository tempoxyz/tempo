// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Secp256k1Lib } from "../../src/runtime/libraries/Secp256k1Lib.sol";
import { Test } from "forge-std/Test.sol";

contract Secp256k1LibHarness {

    function isValidX(bytes32 x) external view returns (bool) {
        return Secp256k1Lib.isValidX(x);
    }

    function isCompressedYParity(uint8 yParity) external pure returns (bool) {
        return Secp256k1Lib.isCompressedYParity(yParity);
    }

    function deriveAddress(bytes32 x, uint8 yParity) external view returns (address) {
        return Secp256k1Lib.deriveAddress(x, yParity);
    }

}

contract Secp256k1LibTest is Test {

    uint256 internal constant SECP256K1_P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    bytes32 internal constant GENERATOR_X =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    address internal constant PRIVATE_KEY_ONE_ADDRESS = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf;

    Secp256k1LibHarness internal harness;

    function setUp() public {
        harness = new Secp256k1LibHarness();
    }

    /// @notice Verifies the generator x-coordinate is accepted as valid.
    function test_isValidX_acceptsGeneratorX() public view {
        assertTrue(harness.isValidX(GENERATOR_X));
    }

    /// @notice Verifies zero is rejected as an invalid x-coordinate.
    function test_isValidX_rejectsZero() public view {
        assertFalse(harness.isValidX(bytes32(0)));
    }

    /// @notice Verifies x-coordinates at or above the field modulus are invalid.
    function test_isValidX_rejectsFieldModulusAndAbove() public view {
        assertFalse(harness.isValidX(bytes32(SECP256K1_P)));
        assertFalse(harness.isValidX(bytes32(SECP256K1_P + 1)));
    }

    /// @notice Verifies compressed y-parity prefixes 0x02 and 0x03 are accepted.
    function test_isCompressedYParity_acceptsCompressedPrefixes() public view {
        assertTrue(harness.isCompressedYParity(0x02));
        assertTrue(harness.isCompressedYParity(0x03));
    }

    /// @notice Verifies non-compressed y-parity prefix values are rejected.
    function test_isCompressedYParity_rejectsOtherValues() public view {
        assertFalse(harness.isCompressedYParity(0x00));
        assertFalse(harness.isCompressedYParity(0x01));
        assertFalse(harness.isCompressedYParity(0x04));
        assertFalse(harness.isCompressedYParity(type(uint8).max));
    }

    /// @notice Verifies the generator point derives the known private-key-one address.
    function test_deriveAddress_matchesKnownGeneratorAddress() public view {
        assertEq(harness.deriveAddress(GENERATOR_X, 0x02), PRIVATE_KEY_ONE_ADDRESS);
    }

    /// @notice Verifies changing y parity changes the derived address.
    function test_deriveAddress_parityChangesAddress() public view {
        address evenAddress = harness.deriveAddress(GENERATOR_X, 0x02);
        address oddAddress = harness.deriveAddress(GENERATOR_X, 0x03);

        assertEq(evenAddress, PRIVATE_KEY_ONE_ADDRESS);
        assertTrue(oddAddress != evenAddress);
    }

    /// @notice Verifies isValidX is deterministic and never reverts for any input.
    function testFuzz_isValidX_neverRevertsAndConsistent(bytes32 x) public view {
        bool first = harness.isValidX(x);
        bool second = harness.isValidX(x);
        assertEq(first, second);
    }

    /// @notice Verifies only compressed y-parity prefixes pass for any byte value.
    function testFuzz_isCompressedYParity(uint8 yParity) public view {
        assertEq(harness.isCompressedYParity(yParity), yParity == 0x02 || yParity == 0x03);
    }

}
