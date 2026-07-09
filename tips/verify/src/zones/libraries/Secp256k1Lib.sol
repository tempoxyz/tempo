// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title Secp256k1Lib
/// @notice Shared secp256k1 public-key helpers used by zone contracts.
library Secp256k1Lib {

    uint256 internal constant SECP256K1_P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    uint256 internal constant SECP256K1_HALF_PM1 =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFE17;

    uint256 internal constant SECP256K1_SQRT_EXP =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;

    /// @notice Validate that an X coordinate corresponds to a valid secp256k1 point.
    /// @dev Uses Euler's criterion via MODEXP: x^3 + 7 is a quadratic residue mod p
    ///      iff (x^3 + 7)^((p-1)/2) == 1 (mod p).
    function isValidX(bytes32 x) internal view returns (bool) {
        uint256 px = uint256(x);
        if (px == 0 || px >= SECP256K1_P) return false;

        uint256 rhs = _curveRhs(px);
        bytes memory input = abi.encodePacked(
            uint256(32), uint256(32), uint256(32), rhs, SECP256K1_HALF_PM1, SECP256K1_P
        );

        (bool success, bytes memory result) = address(0x05).staticcall(input);
        if (!success || result.length != 32) return false;

        return uint256(bytes32(result)) == 1;
    }

    /// @notice Return true for compressed secp256k1 public key y-parity prefixes.
    function isCompressedYParity(uint8 yParity) internal pure returns (bool) {
        return yParity == 0x02 || yParity == 0x03;
    }

    /// @notice Derive the Ethereum address corresponding to a compressed secp256k1 public key.
    function deriveAddress(bytes32 x, uint8 yParity) internal view returns (address addr) {
        uint256 px = uint256(x);
        uint256 rhs = _curveRhs(px);

        bytes memory input = abi.encodePacked(
            uint256(32), uint256(32), uint256(32), rhs, SECP256K1_SQRT_EXP, SECP256K1_P
        );
        (bool success, bytes memory result) = address(0x05).staticcall(input);
        require(success && result.length == 32, "modexp failed");
        uint256 y = uint256(bytes32(result));

        if ((y % 2 == 0) != (yParity == 0x02)) {
            y = SECP256K1_P - y;
        }

        addr = address(uint160(uint256(keccak256(abi.encodePacked(px, y)))));
    }

    function _curveRhs(uint256 px) private pure returns (uint256) {
        return addmod(mulmod(mulmod(px, px, SECP256K1_P), px, SECP256K1_P), 7, SECP256K1_P);
    }

}
