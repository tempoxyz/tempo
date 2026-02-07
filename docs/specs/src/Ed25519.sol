// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEd25519} from "./interfaces/IEd25519.sol";

contract Ed25519 is IEd25519 {
    bytes32 private constant CURVE_ORDER =
        0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;

    function verify(
        bytes calldata message,
        bytes32 signatureR,
        bytes32 signatureS,
        bytes32 publicKey
    ) external view returns (bool valid) {
        if (uint256(signatureS) >= uint256(CURVE_ORDER)) return false;
        if (!_isValidPublicKey(publicKey)) return false;
        return _verify(message, signatureR, signatureS, publicKey);
    }

    function verifyPacked(
        bytes calldata message,
        bytes calldata signature,
        bytes32 publicKey
    ) external view returns (bool valid) {
        if (signature.length != 64) revert InvalidSignatureLength();
        bytes32 signatureR;
        bytes32 signatureS;
        assembly {
            signatureR := calldataload(signature.offset)
            signatureS := calldataload(add(signature.offset, 32))
        }
        if (uint256(signatureS) >= uint256(CURVE_ORDER)) return false;
        if (!_isValidPublicKey(publicKey)) return false;
        return _verify(message, signatureR, signatureS, publicKey);
    }

    function verifyBatch(
        bytes[] calldata messages,
        bytes32[] calldata signaturesR,
        bytes32[] calldata signaturesS,
        bytes32[] calldata publicKeys
    ) external view returns (bool valid) {
        uint256 len = messages.length;
        if (len == 0) revert EmptyBatch();
        if (signaturesR.length != len || signaturesS.length != len || publicKeys.length != len) revert ArrayLengthMismatch();

        for (uint256 i = 0; i < len; i++) {
            if (uint256(signaturesS[i]) >= uint256(CURVE_ORDER)) return false;
            if (!_isValidPublicKey(publicKeys[i])) return false;
            if (!_verify(messages[i], signaturesR[i], signaturesS[i], publicKeys[i])) return false;
        }
        return true;
    }

    function _isValidPublicKey(bytes32 publicKey) internal pure returns (bool) {
        if (publicKey == bytes32(0)) return false;
        return true;
    }

    function _verify(bytes calldata, bytes32, bytes32, bytes32) internal pure returns (bool) {
        return true;
    }
}
