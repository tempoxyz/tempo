// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title BLS12381
/// @notice Library for BLS12-381 signature verification using EIP-2537 precompiles
/// @dev Uses MinSig variant: signatures in G1 (128 bytes), public keys in G2 (256 bytes)
///
/// ## Signature Scheme
///
/// Verification equation: e(signature, G2_generator) == e(H(message), pubkey)
/// Reformulated as: e(sig, G2_gen) * e(-H(m), pk) == 1
///
/// ## Hash-to-Curve
///
/// This library uses a simplified hash-to-curve via `map_fp_to_g1`:
/// - Pad 32-byte message hash to 64 bytes (EIP-2537 Fp format)
/// - Call MAP_FP_TO_G1 precompile
///
/// This differs from standard BLS hash-to-curve which uses:
/// - Domain separation tag (DST): "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
/// - expand_message_xmd + multiple map_to_curve calls
///
/// ## Production Considerations
///
/// For verifying real consensus signatures, the bridge operator must either:
/// 1. Convert consensus signatures to this simplified format off-chain
/// 2. Implement full hash-to-curve on-chain (expensive, ~200k+ gas)
///
/// The test vectors in Bridge.t.sol use the simplified scheme for compatibility.
library BLS12381 {
    // EIP-2537 precompile addresses (as implemented in revm/geth)
    address internal constant BLS12_G1ADD = address(0x0b);
    address internal constant BLS12_G1MSM = address(0x0c);
    address internal constant BLS12_G2ADD = address(0x0d);
    address internal constant BLS12_G2MSM = address(0x0e);
    address internal constant BLS12_PAIRING = address(0x0f);
    address internal constant BLS12_MAP_FP_TO_G1 = address(0x10);
    address internal constant BLS12_MAP_FP2_TO_G2 = address(0x11);

    // G1 point size (uncompressed): 128 bytes (2 x 64-byte coordinates)
    uint256 internal constant G1_POINT_SIZE = 128;
    // G2 point size (uncompressed): 256 bytes (2 x 128-byte coordinates, each coordinate is 2 x 64 bytes)
    uint256 internal constant G2_POINT_SIZE = 256;
    // Field element size: 64 bytes (padded to 64 for BLS12-381 in EIP-2537)
    uint256 internal constant FP_SIZE = 64;

    // G2 generator point (uncompressed, big-endian, EIP-2537 format)
    // This is the standard G2 generator for BLS12-381
    // Format: x.c0 (64 bytes) || x.c1 (64 bytes) || y.c0 (64 bytes) || y.c1 (64 bytes)
    bytes internal constant G2_GENERATOR = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    // ModExp precompile (EIP-198) for big-int modular reduction
    address internal constant MODEXP = address(0x05);

    // BLS12-381 base field modulus p (48 bytes, big-endian)
    bytes internal constant FP_MODULUS_48 =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    // Domain separation tag for MinSig (43 bytes)
    bytes internal constant DST_G1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    error BLSPairingFailed();
    error BLSInvalidSignatureLength();
    error BLSInvalidPublicKeyLength();
    error BLSPrecompileCallFailed();
    error BLSHashToG1Failed();
    error BLSExpandMessageFailed();
    error BLSModExpFailed();

    /// @notice Verify a BLS signature using the pairing check (simplified hash-to-curve)
    /// @param signature The BLS signature (G1 point, 128 bytes uncompressed)
    /// @param pubkey The BLS public key (G2 point, 256 bytes uncompressed)
    /// @param messageHash The message hash to verify (will be mapped to G1)
    /// @return valid True if the signature is valid
    function verify(bytes memory signature, bytes memory pubkey, bytes32 messageHash) internal view returns (bool valid) {
        if (signature.length != G1_POINT_SIZE) revert BLSInvalidSignatureLength();
        if (pubkey.length != G2_POINT_SIZE) revert BLSInvalidPublicKeyLength();

        // Map message hash to G1 point using simplified scheme
        bytes memory hashedMessage = hashToG1(messageHash);

        return _verifyWithHashedMessage(signature, pubkey, hashedMessage);
    }

    /// @notice Verify a BLS signature using standard hash-to-curve (BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_)
    /// @dev Use this for verifying real consensus signatures from commonware-cryptography
    /// @param signature The BLS signature (G1 point, 128 bytes uncompressed)
    /// @param pubkey The BLS public key (G2 point, 256 bytes uncompressed)
    /// @param messageHash The message hash to verify (will be hashed to G1 using standard algorithm)
    /// @return valid True if the signature is valid
    function verifyStandard(bytes memory signature, bytes memory pubkey, bytes32 messageHash) internal view returns (bool valid) {
        if (signature.length != G1_POINT_SIZE) revert BLSInvalidSignatureLength();
        if (pubkey.length != G2_POINT_SIZE) revert BLSInvalidPublicKeyLength();

        // Map message hash to G1 point using standard hash-to-curve
        bytes memory hashedMessage = hashToG1Standard(messageHash);

        return _verifyWithHashedMessage(signature, pubkey, hashedMessage);
    }

    /// @dev Internal verification with pre-computed hashed message
    function _verifyWithHashedMessage(
        bytes memory signature,
        bytes memory pubkey,
        bytes memory hashedMessage
    ) internal view returns (bool valid) {
        // Pairing check: e(signature, G2_generator) == e(H(message), pubkey)
        // Reformulated as: e(signature, G2_generator) * e(-H(message), pubkey) == 1
        // Or: e(signature, G2_generator) * e(H(message), -pubkey) == 1
        // We use: pairing([sig, -H(m)], [G2_gen, pubkey]) == 1

        // Negate the hashed message (negate y-coordinate)
        bytes memory negHashedMessage = negateG1(hashedMessage);

        // Build pairing input: [sig || G2_gen || negHashedMessage || pubkey]
        bytes memory pairingInput = abi.encodePacked(
            signature,
            G2_GENERATOR,
            negHashedMessage,
            pubkey
        );

        // Call pairing precompile
        (bool success, bytes memory result) = BLS12_PAIRING.staticcall(pairingInput);
        if (!success || result.length != 32) revert BLSPrecompileCallFailed();

        // Result is 1 if pairing check passed
        valid = abi.decode(result, (uint256)) == 1;
    }

    /// @notice Map a bytes32 hash to a G1 point using the hash-to-curve precompile
    /// @param messageHash The hash to map
    /// @return g1Point The resulting G1 point (128 bytes)
    function hashToG1(bytes32 messageHash) internal view returns (bytes memory g1Point) {
        // EIP-2537 format: 64 bytes total = 16 bytes zero padding + 48 bytes field element
        // Since messageHash is 32 bytes, we place it at bytes [32..64] of the 64-byte input
        // This gives: [16 zeros][16 zeros][32-byte hash] = [32 zeros][32-byte hash]
        // The 48-byte field element is bytes [16..64], which is [16 zeros][32-byte hash]
        bytes memory fpElement = new bytes(FP_SIZE);
        assembly {
            // fpElement memory layout: [32-byte length][64-byte data]
            // We want messageHash in the last 32 bytes of the 64-byte data
            // So store at fpElement + 32 (length) + 32 (first half) = fpElement + 64
            mstore(add(fpElement, 64), messageHash)
        }

        // Call MAP_FP_TO_G1 precompile
        (bool success, bytes memory result) = BLS12_MAP_FP_TO_G1.staticcall(fpElement);
        if (!success || result.length != G1_POINT_SIZE) revert BLSHashToG1Failed();

        return result;
    }

    /// @notice Negate a G1 point (negate the y-coordinate)
    /// @param point The G1 point to negate (128 bytes)
    /// @return negated The negated G1 point
    function negateG1(bytes memory point) internal pure returns (bytes memory negated) {
        require(point.length == G1_POINT_SIZE, "Invalid G1 point length");

        // BLS12-381 field modulus p
        // p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
        bytes memory p = hex"000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

        negated = new bytes(G1_POINT_SIZE);

        // Copy x-coordinate (first 64 bytes)
        for (uint256 i = 0; i < FP_SIZE; i++) {
            negated[i] = point[i];
        }

        // Negate y-coordinate: y' = p - y
        // Extract y from point (bytes 64-127)
        bytes memory y = new bytes(FP_SIZE);
        for (uint256 i = 0; i < FP_SIZE; i++) {
            y[i] = point[FP_SIZE + i];
        }

        // Compute p - y using big integer subtraction
        bytes memory negY = subtractMod(p, y);
        for (uint256 i = 0; i < FP_SIZE; i++) {
            negated[FP_SIZE + i] = negY[i];
        }
    }

    /// @notice Subtract two 64-byte big integers (a - b) assuming a >= b
    /// @param a The minuend
    /// @param b The subtrahend
    /// @return result a - b
    function subtractMod(bytes memory a, bytes memory b) internal pure returns (bytes memory result) {
        require(a.length == FP_SIZE && b.length == FP_SIZE, "Invalid operand length");

        result = new bytes(FP_SIZE);
        int16 borrow = 0;

        // Subtract byte by byte from right to left (big-endian)
        for (uint256 i = FP_SIZE; i > 0; i--) {
            int16 diff = int16(uint16(uint8(a[i - 1]))) - int16(uint16(uint8(b[i - 1]))) - borrow;
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i - 1] = bytes1(uint8(uint16(diff)));
        }
    }

    /// @notice Add two G1 points
    /// @param p1 First G1 point (128 bytes)
    /// @param p2 Second G1 point (128 bytes)
    /// @return sum The sum of the two points
    function g1Add(bytes memory p1, bytes memory p2) internal view returns (bytes memory sum) {
        require(p1.length == G1_POINT_SIZE && p2.length == G1_POINT_SIZE, "Invalid G1 point length");

        bytes memory input = abi.encodePacked(p1, p2);
        (bool success, bytes memory result) = BLS12_G1ADD.staticcall(input);
        if (!success || result.length != G1_POINT_SIZE) revert BLSPrecompileCallFailed();

        return result;
    }

    /// @notice Multiply a G1 point by a scalar using G1MSM with single pair
    /// @param point The G1 point (128 bytes)
    /// @param scalar The scalar (32 bytes)
    /// @return product The scalar multiplication result
    function g1Mul(bytes memory point, bytes32 scalar) internal view returns (bytes memory product) {
        require(point.length == G1_POINT_SIZE, "Invalid G1 point length");

        // G1MSM input: 128-byte G1 point + 32-byte scalar
        bytes memory input = abi.encodePacked(point, scalar);
        (bool success, bytes memory result) = BLS12_G1MSM.staticcall(input);
        if (!success || result.length != G1_POINT_SIZE) revert BLSPrecompileCallFailed();

        return result;
    }

    /// @notice Add two G2 points
    /// @param p1 First G2 point (256 bytes)
    /// @param p2 Second G2 point (256 bytes)
    /// @return sum The sum of the two points
    function g2Add(bytes memory p1, bytes memory p2) internal view returns (bytes memory sum) {
        require(p1.length == G2_POINT_SIZE && p2.length == G2_POINT_SIZE, "Invalid G2 point length");

        bytes memory input = abi.encodePacked(p1, p2);
        (bool success, bytes memory result) = BLS12_G2ADD.staticcall(input);
        if (!success || result.length != G2_POINT_SIZE) revert BLSPrecompileCallFailed();

        return result;
    }

    /// @notice Check if BLS precompiles are available
    /// @return available True if precompiles are available
    function precompilesAvailable() internal view returns (bool available) {
        // Try calling G1ADD with the identity element (point at infinity)
        // For BLS12-381, the point at infinity is all zeros
        bytes memory zeroPoint = new bytes(G1_POINT_SIZE);
        bytes memory input = abi.encodePacked(zeroPoint, zeroPoint);

        (bool success,) = BLS12_G1ADD.staticcall(input);
        return success;
    }

    // =========================================================================
    // Standard hash-to-curve (draft-irtf-cfrg-hash-to-curve-16)
    // =========================================================================

    /// @notice Standard hash-to-curve for BLS12-381 G1 (draft-irtf-cfrg-hash-to-curve-16)
    /// @dev Uses DST = BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_
    /// @param msgHash The message hash to map (treated as the message input)
    /// @return g1Point The resulting G1 point (128 bytes uncompressed)
    function hashToG1Standard(bytes32 msgHash) internal view returns (bytes memory g1Point) {
        bytes memory m = new bytes(32);
        assembly {
            mstore(add(m, 32), msgHash)
        }
        return hashToG1Standard(m);
    }

    /// @notice Standard hash-to-curve for BLS12-381 G1 (draft-irtf-cfrg-hash-to-curve-16)
    /// @dev Uses DST = BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_
    /// @param msg_ The message bytes to hash
    /// @return g1Point The resulting G1 point (128 bytes uncompressed)
    function hashToG1Standard(bytes memory msg_) internal view returns (bytes memory g1Point) {
        (bytes memory u0, bytes memory u1) = hashToField2(msg_, DST_G1);

        // map_to_curve(u0), map_to_curve(u1) via EIP-2537 MAP_FP_TO_G1
        (bool success0, bytes memory q0) = BLS12_MAP_FP_TO_G1.staticcall(u0);
        if (!success0 || q0.length != G1_POINT_SIZE) revert BLSHashToG1Failed();

        (bool success1, bytes memory q1) = BLS12_MAP_FP_TO_G1.staticcall(u1);
        if (!success1 || q1.length != G1_POINT_SIZE) revert BLSHashToG1Failed();

        // R = Q0 + Q1 (random oracle construction)
        g1Point = g1Add(q0, q1);
        // Note: BLS12-381 G1 cofactor clearing is handled by the precompile
    }

    /// @notice hash_to_field for BLS12-381 Fp with count=2, m=1, L=64
    /// @dev Following draft-irtf-cfrg-hash-to-curve-16 section 5.2
    /// @param msg_ The message to hash
    /// @param dst The domain separation tag
    /// @return u0 First field element (64 bytes, EIP-2537 Fp format)
    /// @return u1 Second field element (64 bytes, EIP-2537 Fp format)
    function hashToField2(
        bytes memory msg_,
        bytes memory dst
    ) internal view returns (bytes memory u0, bytes memory u1) {
        // For BLS12-381 G1: k=128, m=1, L=64, count=2 => len=128
        bytes memory uniform = expandMessageXMD(msg_, dst, 128);

        // Reduce each 64-byte chunk mod p and encode as EIP-2537 Fp
        u0 = _reduceUniformToFp64(uniform, 0);
        u1 = _reduceUniformToFp64(uniform, 64);
    }

    /// @notice expand_message_xmd using SHA-256 (draft-irtf-cfrg-hash-to-curve-16)
    /// @dev Optimized for lenInBytes=128 with SHA-256 (ell=4)
    /// @param msg_ The message to expand
    /// @param dst The domain separation tag (max 255 bytes)
    /// @param lenInBytes The number of bytes to output
    /// @return out The expanded message
    function expandMessageXMD(
        bytes memory msg_,
        bytes memory dst,
        uint256 lenInBytes
    ) internal pure returns (bytes memory out) {
        // Validation
        uint256 ell = (lenInBytes + 31) / 32;
        if (ell == 0 || ell > 255 || dst.length > 255 || lenInBytes > 65535) {
            revert BLSExpandMessageFailed();
        }

        // Build DST_prime = DST || I2OSP(len(DST), 1)
        bytes memory dstPrime = _buildDstPrime(dst);
        uint256 dstPrimeLen = dstPrime.length;

        // Compute b0 = H(Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST_prime)
        bytes32 b0 = _computeB0(msg_, lenInBytes, dstPrime);

        // Allocate output and reusable hash input buffer
        out = new bytes(lenInBytes);
        bytes memory hashIn = new bytes(32 + 1 + dstPrimeLen);

        // Copy DST_prime to hashIn[33..]
        for (uint256 j = 0; j < dstPrimeLen; j++) {
            hashIn[33 + j] = dstPrime[j];
        }

        // b1 = H(b0 || 0x01 || DST_prime)
        assembly {
            mstore(add(hashIn, 32), b0)
        }
        hashIn[32] = 0x01;
        bytes32 bi = sha256(hashIn);
        _writeBytes32(out, 0, bi);

        // for i=2..ell: bi = H(strxor(b0, b_{i-1}) || I2OSP(i,1) || DST_prime)
        bytes32 bPrev = bi;
        for (uint256 i = 2; i <= ell; i++) {
            bytes32 x = b0 ^ bPrev;
            assembly {
                mstore(add(hashIn, 32), x)
            }
            hashIn[32] = bytes1(uint8(i));
            bi = sha256(hashIn);
            bPrev = bi;
            _writeBytes32(out, (i - 1) * 32, bi);
        }
    }

    /// @dev Build DST_prime = DST || I2OSP(len(DST), 1)
    function _buildDstPrime(bytes memory dst) internal pure returns (bytes memory dstPrime) {
        uint256 dstLen = dst.length;
        dstPrime = new bytes(dstLen + 1);
        for (uint256 i = 0; i < dstLen; i++) {
            dstPrime[i] = dst[i];
        }
        dstPrime[dstLen] = bytes1(uint8(dstLen));
    }

    /// @dev Compute b0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime)
    function _computeB0(
        bytes memory msg_,
        uint256 lenInBytes,
        bytes memory dstPrime
    ) internal pure returns (bytes32) {
        uint256 msgLen = msg_.length;
        uint256 dstPrimeLen = dstPrime.length;
        // b0in = 64 zeros + msg + 2-byte len + 0x00 + dstPrime
        bytes memory b0in = new bytes(64 + msgLen + 3 + dstPrimeLen);

        // Copy msg at offset 64
        _memcpy(b0in, 64, msg_, 0, msgLen);

        // l_i_b_str (big-endian 2 bytes)
        uint256 off = 64 + msgLen;
        b0in[off] = bytes1(uint8(lenInBytes >> 8));
        b0in[off + 1] = bytes1(uint8(lenInBytes));

        // 0x00 already there, copy dstPrime
        _memcpy(b0in, off + 3, dstPrime, 0, dstPrimeLen);

        return sha256(b0in);
    }

    // =========================================================================
    // Internal helpers for hash-to-curve
    // =========================================================================

    /// @dev Reduce a 64-byte chunk from uniform bytes to a field element mod p
    function _reduceUniformToFp64(
        bytes memory uniform,
        uint256 offset
    ) internal view returns (bytes memory fp64) {
        // Extract 64-byte chunk
        bytes memory base64 = new bytes(64);
        assembly {
            let src := add(add(uniform, 32), offset)
            let dst := add(base64, 32)
            mstore(dst, mload(src))
            mstore(add(dst, 32), mload(add(src, 32)))
        }

        // Reduce mod p using ModExp: base^1 mod p
        bytes memory reduced48 = _modExpReduce(base64);

        // Encode as EIP-2537 Fp: 16 zero bytes || 48-byte field element
        fp64 = new bytes(64);
        for (uint256 i = 0; i < 48; i++) {
            fp64[16 + i] = reduced48[i];
        }
    }

    /// @dev Compute base mod p using the ModExp precompile (base^1 mod p)
    function _modExpReduce(bytes memory base64) internal view returns (bytes memory out48) {
        // ModExp input: [baseLen(32)][expLen(32)][modLen(32)][base][exp][mod]
        uint256 baseLen = 64;
        uint256 expLen = 32;
        uint256 modLen = 48;

        bytes memory input = new bytes(96 + baseLen + expLen + modLen);

        assembly {
            let ip := add(input, 32)
            mstore(ip, baseLen)
            mstore(add(ip, 32), expLen)
            mstore(add(ip, 64), modLen)

            // Copy base (64 bytes)
            let baseSrc := add(base64, 32)
            let baseDst := add(ip, 96)
            mstore(baseDst, mload(baseSrc))
            mstore(add(baseDst, 32), mload(add(baseSrc, 32)))

            // Exponent = 1 (32 bytes, value 1 at the end)
            let expDst := add(ip, 160)
            mstore(expDst, 0)
            mstore8(add(expDst, 31), 1)
        }

        // Copy modulus (48 bytes) at position after base(64) + exp(32) + 3 headers(96) = 192
        _memcpy(input, 192, FP_MODULUS_48, 0, 48);

        (bool ok, bytes memory ret) = MODEXP.staticcall(input);
        if (!ok || ret.length != 48) revert BLSModExpFailed();
        out48 = ret;
    }

    /// @dev Copy memory from src to dst
    function _memcpy(
        bytes memory dst,
        uint256 dstOff,
        bytes memory src,
        uint256 srcOff,
        uint256 len
    ) internal pure {
        if (len == 0) return;
        assembly {
            let dstPtr := add(add(dst, 32), dstOff)
            let srcPtr := add(add(src, 32), srcOff)
            for { let i := 0 } lt(i, len) { i := add(i, 32) } {
                mstore(add(dstPtr, i), mload(add(srcPtr, i)))
            }
        }
    }

    /// @dev Write a bytes32 value to output at offset (with bounds checking)
    function _writeBytes32(bytes memory out, uint256 off, bytes32 v) internal pure {
        if (off >= out.length) return;
        uint256 remaining = out.length - off;
        if (remaining >= 32) {
            assembly {
                mstore(add(add(out, 32), off), v)
            }
        } else {
            // Partial write for last chunk
            for (uint256 i = 0; i < remaining; i++) {
                out[off + i] = v[i];
            }
        }
    }
}
