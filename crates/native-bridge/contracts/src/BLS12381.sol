// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLS2} from "bls-solidity/src/libraries/BLS2.sol";

/// @title BLS12381
/// @notice BLS12-381 signature verification adapter using randa-mu/bls-solidity
/// @dev Implements MinSig variant (G2 public keys, G1 signatures) to match consensus DKG.
///
/// Format conversion:
/// - Our EIP-2537 G1 (128 bytes: 2×64 with padding) → BLS2 G1 (96 bytes: 2×48)
/// - Our EIP-2537 G2 (256 bytes: 4×64 with padding) → BLS2 G2 (192 bytes: 4×48)
///
/// The underlying BLS2 library uses the correct EIP-2537 precompiles internally.
library BLS12381 {
    //=============================================================
    //                         CONSTANTS
    //=============================================================

    /// @notice G1 point length in EIP-2537 format (128 bytes: 2 × 64-byte Fp)
    uint256 internal constant G1_POINT_LENGTH = 128;

    /// @notice G2 point length in EIP-2537 format (256 bytes: 4 × 64-byte Fp)
    uint256 internal constant G2_POINT_LENGTH = 256;

    /// @notice G1 point length in BLS2 library format (96 bytes: 2 × 48-byte Fp)
    uint256 internal constant G1_BLS2_LENGTH = 96;

    /// @notice G2 point length in BLS2 library format (192 bytes: 4 × 48-byte Fp)
    uint256 internal constant G2_BLS2_LENGTH = 192;

    //=============================================================
    //                         ERRORS
    //=============================================================

    error InvalidPublicKeyLength();
    error InvalidSignatureLength();
    error PairingCheckFailed();
    error PublicKeyIsInfinity();
    error SignatureIsInfinity();

    //=============================================================
    //                    SIGNATURE VERIFICATION
    //=============================================================

    /// @notice Verify a BLS signature (MinSig variant)
    /// @param publicKey G2 public key (256 bytes EIP-2537 format)
    /// @param message The message that was signed (will be hashed to G1)
    /// @param dst Domain separation tag for hash-to-curve
    /// @param signature G1 signature (128 bytes EIP-2537 format)
    /// @return True if signature is valid
    function verify(
        bytes memory publicKey,
        bytes memory message,
        bytes memory dst,
        bytes memory signature
    ) internal view returns (bool) {
        if (publicKey.length != G2_POINT_LENGTH) revert InvalidPublicKeyLength();
        if (signature.length != G1_POINT_LENGTH) revert InvalidSignatureLength();

        // Check for point at infinity
        if (_isAllZeros(publicKey)) revert PublicKeyIsInfinity();
        if (_isAllZeros(signature)) revert SignatureIsInfinity();

        // Convert from EIP-2537 padded format to BLS2 compact format
        bytes memory sig96 = _g1FromEip2537(signature);
        bytes memory pk192 = _g2FromEip2537(publicKey);

        // Unmarshal points
        BLS2.PointG1 memory sig = BLS2.g1Unmarshal(sig96);
        BLS2.PointG2 memory pk = BLS2.g2Unmarshal(pk192);

        // Hash message to G1 point
        BLS2.PointG1 memory hm = BLS2.hashToPoint(dst, message);

        // Verify: e(sig, -G2) * e(H(m), pk) == 1
        (bool pairingSuccess, bool callSuccess) = BLS2.verifySingle(sig, pk, hm);

        return callSuccess && pairingSuccess;
    }

    /// @notice Verify a BLS signature with pre-hashed message (MinSig variant)
    /// @param publicKey G2 public key (256 bytes EIP-2537 format)
    /// @param messageHash 32-byte hash to sign (will be hashed to G1 with DST)
    /// @param dst Domain separation tag for hash-to-curve
    /// @param signature G1 signature (128 bytes EIP-2537 format)
    /// @return True if signature is valid
    function verifyHash(
        bytes memory publicKey,
        bytes32 messageHash,
        bytes memory dst,
        bytes memory signature
    ) internal view returns (bool) {
        return verify(publicKey, abi.encodePacked(messageHash), dst, signature);
    }

    //=============================================================
    //                    FORMAT CONVERSION
    //=============================================================

    /// @notice Convert G1 from EIP-2537 format (128 bytes) to BLS2 format (96 bytes)
    /// @dev Strips 16-byte padding from each 64-byte Fp element
    function _g1FromEip2537(bytes memory eip2537) internal pure returns (bytes memory) {
        require(eip2537.length == G1_POINT_LENGTH, "Invalid G1 EIP-2537 length");

        bytes memory result = new bytes(G1_BLS2_LENGTH);

        // x: bytes[16:64] (skip 16-byte padding)
        for (uint256 i = 0; i < 48; i++) {
            result[i] = eip2537[16 + i];
        }

        // y: bytes[80:128] (skip 16-byte padding)
        for (uint256 i = 0; i < 48; i++) {
            result[48 + i] = eip2537[80 + i];
        }

        return result;
    }

    /// @notice Convert G2 from EIP-2537 format (256 bytes) to BLS2 format (192 bytes)
    /// @dev Strips 16-byte padding from each 64-byte Fp element
    function _g2FromEip2537(bytes memory eip2537) internal pure returns (bytes memory) {
        require(eip2537.length == G2_POINT_LENGTH, "Invalid G2 EIP-2537 length");

        bytes memory result = new bytes(G2_BLS2_LENGTH);

        // Each of the 4 Fp elements: skip first 16 bytes (padding), copy 48 bytes
        for (uint256 elem = 0; elem < 4; elem++) {
            uint256 srcOffset = elem * 64 + 16; // Skip padding
            uint256 dstOffset = elem * 48;

            for (uint256 i = 0; i < 48; i++) {
                result[dstOffset + i] = eip2537[srcOffset + i];
            }
        }

        return result;
    }

    //=============================================================
    //                    HELPER FUNCTIONS
    //=============================================================

    /// @notice Check if all bytes are zero (point at infinity)
    function _isAllZeros(bytes memory data) private pure returns (bool) {
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] != 0) return false;
        }
        return true;
    }

    /// @notice Validate a G2 public key is not infinity
    /// @param publicKey The G2 public key to validate (256 bytes EIP-2537 format)
    /// @return True if the public key is valid (not infinity)
    function isValidPublicKey(bytes memory publicKey) internal pure returns (bool) {
        if (publicKey.length != G2_POINT_LENGTH) return false;
        return !_isAllZeros(publicKey);
    }
}
