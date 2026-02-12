// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IEd25519 {
    error InvalidSignatureLength();
    error InvalidPublicKey();
    error ArrayLengthMismatch();
    error EmptyBatch();

    function verify(
        bytes calldata message,
        bytes32 signatureR,
        bytes32 signatureS,
        bytes32 publicKey
    ) external view returns (bool valid);

    function verifyPacked(
        bytes calldata message,
        bytes calldata signature,
        bytes32 publicKey
    ) external view returns (bool valid);

    function verifyBatch(
        bytes[] calldata messages,
        bytes32[] calldata signaturesR,
        bytes32[] calldata signaturesS,
        bytes32[] calldata publicKeys
    ) external view returns (bool valid);
}
