// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BLS12381} from "../src/BLS12381.sol";
import {BLS2} from "bls-solidity/src/libraries/BLS2.sol";

/// @title BLS12381Test
/// @notice Tests for the BLS12381 library wrapper
/// @dev Note: Full signature verification tests require EIP-2537 precompiles (Prague/Pectra)
contract BLS12381Test is Test {
    // Test DST matching the bridge (MinSig variant - hashes to G1)
    bytes constant TEST_DST = "TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

    //=============================================================
    //                    FORMAT CONVERSION TESTS
    //=============================================================

    function test_verify_invalidPublicKeyLength() public {
        // G2 public key should be 256 bytes in EIP-2537 format
        bytes memory shortPk = new bytes(128); // Wrong length
        shortPk[0] = 0x01;
        bytes memory message = "test";
        bytes memory signature = new bytes(128); // G1 signature
        signature[0] = 0x01;

        try this.callVerify(shortPk, message, TEST_DST, signature) {
            fail("Should have reverted");
        } catch {
            // Expected revert
        }
    }

    function test_verify_invalidSignatureLength() public {
        bytes memory pk = new bytes(256); // G2 public key
        pk[0] = 0x01;
        bytes memory message = "test";
        bytes memory shortSig = new bytes(256); // Wrong length (should be 128)
        shortSig[0] = 0x01;

        try this.callVerify(pk, message, TEST_DST, shortSig) {
            fail("Should have reverted");
        } catch {
            // Expected revert
        }
    }

    /// @notice External wrapper to test library function reverts
    function callVerify(
        bytes memory pk,
        bytes memory message,
        bytes memory dst,
        bytes memory signature
    ) external view returns (bool) {
        return BLS12381.verify(pk, message, dst, signature);
    }

    function test_verify_rejectsInfinityPublicKey() public {
        // Point at infinity is all zeros for G2 (256 bytes)
        bytes memory infinityPk = new bytes(256);
        bytes memory message = "test";
        // Valid length signature (128 bytes with some non-zero data)
        bytes memory signature = new bytes(128);
        signature[0] = 0x01;

        try this.callVerify(infinityPk, message, TEST_DST, signature) {
            fail("Should have reverted with PublicKeyIsInfinity");
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), BLS12381.PublicKeyIsInfinity.selector);
        }
    }

    function test_verify_rejectsInfinitySignature() public {
        // Valid length public key (G2, 256 bytes) with some non-zero data
        bytes memory pk = new bytes(256);
        pk[0] = 0x01;
        bytes memory message = "test";
        // Point at infinity is all zeros for G1 (128 bytes)
        bytes memory infinitySig = new bytes(128);

        try this.callVerify(pk, message, TEST_DST, infinitySig) {
            fail("Should have reverted with SignatureIsInfinity");
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), BLS12381.SignatureIsInfinity.selector);
        }
    }

    function test_isValidPublicKey_rejectsInfinity() public pure {
        // G2 public key (256 bytes) at infinity
        bytes memory infinityPk = new bytes(256);
        assertFalse(BLS12381.isValidPublicKey(infinityPk));
    }

    function test_isValidPublicKey_acceptsNonZero() public pure {
        bytes memory validPk = new bytes(256);
        validPk[0] = 0x01;
        assertTrue(BLS12381.isValidPublicKey(validPk));
    }

    function test_isValidPublicKey_rejectsWrongLength() public pure {
        // Wrong length (128 instead of 256)
        bytes memory shortPk = new bytes(128);
        shortPk[0] = 0x01;
        assertFalse(BLS12381.isValidPublicKey(shortPk));
    }

    //=============================================================
    //              UNDERLYING LIBRARY TESTS (BLS2)
    //=============================================================

    /// @notice Test that BLS2 library's expandMsg works correctly
    /// @dev Uses RFC 9380 test vectors
    function test_expandMsg_rfc9380_vector_empty_32() public pure {
        bytes memory dst = "QUUX-V01-CS02-with-expander-SHA256-128";
        bytes memory result = BLS2.expandMsg(dst, "", 32);

        bytes32 expected = hex"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235";
        assertEq(keccak256(result), keccak256(abi.encodePacked(expected)));
    }

    function test_expandMsg_rfc9380_vector_abc_32() public pure {
        bytes memory dst = "QUUX-V01-CS02-with-expander-SHA256-128";
        bytes memory result = BLS2.expandMsg(dst, "abc", 32);

        bytes32 expected = hex"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615";
        assertEq(keccak256(result), keccak256(abi.encodePacked(expected)));
    }

    function test_expandMsg_deterministic() public pure {
        bytes memory message = "test message";
        bytes memory result1 = BLS2.expandMsg(TEST_DST, message, 128);
        bytes memory result2 = BLS2.expandMsg(TEST_DST, message, 128);

        assertEq(result1.length, 128);
        assertEq(keccak256(result1), keccak256(result2));
    }

    function test_expandMsg_differentMessages() public pure {
        bytes memory msg1 = "message one";
        bytes memory msg2 = "message two";

        bytes memory result1 = BLS2.expandMsg(TEST_DST, msg1, 128);
        bytes memory result2 = BLS2.expandMsg(TEST_DST, msg2, 128);

        assertNotEq(keccak256(result1), keccak256(result2));
    }
}
