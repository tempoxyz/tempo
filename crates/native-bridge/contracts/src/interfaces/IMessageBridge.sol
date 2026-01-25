// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IMessageBridge
/// @notice Minimal cross-chain message hash bridge with BLS threshold signatures
/// @dev Uses EIP-2537 BLS12-381 precompiles for signature verification
interface IMessageBridge {
    //=============================================================
    //                          ERRORS
    //=============================================================

    error MessageAlreadySent(address sender, bytes32 messageHash);
    error MessageAlreadyReceived(uint64 originChainId, address sender, bytes32 messageHash);
    error InvalidBLSSignature();
    error ZeroMessageHash();
    error ContractPaused();
    error Unauthorized();
    error InvalidPublicKeyLength();
    error InvalidSignatureLength();
    error EpochMustIncrease(uint64 current, uint64 proposed);
    error KeyTransitionNotAuthorized();
    error NoActivePublicKey();
    error PublicKeyIsInfinity();

    //=============================================================
    //                          EVENTS
    //=============================================================

    /// @notice Emitted when a message is sent
    event MessageSent(address indexed sender, bytes32 indexed messageHash, uint64 indexed destinationChainId);

    /// @notice Emitted when a message is received
    event MessageReceived(
        uint64 indexed originChainId, address indexed sender, bytes32 indexed messageHash, uint256 receivedAt
    );

    /// @notice Emitted when the group public key is rotated
    event KeyRotated(uint64 indexed oldEpoch, uint64 indexed newEpoch, bytes oldPublicKey, bytes newPublicKey);

    /// @notice Emitted when a key rotation is authorized by the old key
    event KeyRotationAuthorized(uint64 indexed oldEpoch, uint64 indexed newEpoch, bytes newPublicKey);

    //=============================================================
    //                      SEND FUNCTION
    //=============================================================

    /// @notice Send a message hash to another chain
    /// @dev Each (sender, messageHash) pair can only be sent once
    /// @param messageHash The 32-byte hash to send
    /// @param destinationChainId The target chain ID
    function send(bytes32 messageHash, uint64 destinationChainId) external;

    //=============================================================
    //                      WRITE FUNCTION
    //=============================================================

    /// @notice Write a received message with BLS attestation
    /// @dev Called by aggregator after collecting threshold signatures
    /// @param sender The original sender on the source chain
    /// @param messageHash The 32-byte message hash
    /// @param originChainId The source chain ID
    /// @param signature Aggregated BLS threshold signature (G2 point, 256 bytes uncompressed)
    function write(address sender, bytes32 messageHash, uint64 originChainId, bytes calldata signature) external;

    //=============================================================
    //                      READ FUNCTIONS
    //=============================================================

    /// @notice Check when a message was received
    /// @return Timestamp when received (0 if not received)
    function receivedAt(uint64 originChainId, address sender, bytes32 messageHash) external view returns (uint256);

    /// @notice Check if a message has been sent
    function isSent(address sender, bytes32 messageHash) external view returns (bool);

    /// @notice Get the current epoch
    function epoch() external view returns (uint64);

    /// @notice Get the current group public key (G1 point, 128 bytes uncompressed)
    function groupPublicKey() external view returns (bytes memory);

    /// @notice Get the previous epoch
    function previousEpoch() external view returns (uint64);

    /// @notice Get the previous group public key
    function previousGroupPublicKey() external view returns (bytes memory);

    //=============================================================
    //                   KEY ROTATION FUNCTIONS
    //=============================================================

    /// @notice Rotate to a new key, authorized by the old key signing the transition
    /// @dev The old key signs: keccak256("TEMPO_BRIDGE_KEY_ROTATION_V1" || oldEpoch || newEpoch || newPublicKey)
    /// @param newEpoch The new epoch (must be > current)
    /// @param newPublicKey The new BLS group public key (G1, 128 bytes)
    /// @param authSignature Signature from OLD key authorizing this (G2, 256 bytes)
    function rotateKey(uint64 newEpoch, bytes calldata newPublicKey, bytes calldata authSignature) external;

    /// @notice Compute the hash for key rotation authorization
    /// @param oldEpoch Current epoch
    /// @param newEpoch New epoch
    /// @param newPublicKey New public key
    /// @return Hash that old key must sign
    function computeKeyRotationHash(
        uint64 oldEpoch,
        uint64 newEpoch,
        bytes calldata newPublicKey
    ) external pure returns (bytes32);

    //=============================================================
    //                      ADMIN FUNCTIONS
    //=============================================================

    /// @notice Force-set the group public key (governance only, bypasses authorization)
    /// @dev Use only for genesis setup or emergency recovery
    function forceSetGroupPublicKey(uint64 newEpoch, bytes calldata publicKey) external;

    /// @notice Pause the contract
    function pause() external;

    /// @notice Unpause the contract
    function unpause() external;

    /// @notice Transfer ownership
    function transferOwnership(address newOwner) external;
}
