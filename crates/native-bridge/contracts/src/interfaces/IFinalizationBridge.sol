// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IFinalizationBridge
/// @notice Cross-chain message bridge using finalization certificates and receipt proofs
/// @dev Verifies Tempo block finalization via BLS threshold signatures, then proves
///      MessageSent events via Merkle Patricia Trie proofs against the receiptsRoot.
interface IFinalizationBridge {
    //=============================================================
    //                          ERRORS
    //=============================================================

    error MessageAlreadySent(address sender, bytes32 messageHash);
    error MessageAlreadyReceived(uint64 originChainId, address sender, bytes32 messageHash);
    error InvalidFinalizationSignature();
    error InvalidReceiptProof();
    error InvalidBlockHeader();
    error BlockHashMismatch(bytes32 expected, bytes32 actual);
    error InvalidLogIndex();
    error InvalidMessageSentLog();
    error WrongDestinationChain(uint64 expected, uint64 actual);
    error ZeroMessageHash();
    error ContractPaused();
    error Unauthorized();
    error InvalidPublicKeyLength();
    error InvalidSignatureLength();
    error EpochMustIncrease(uint64 current, uint64 proposed);
    error KeyTransitionNotAuthorized();
    error NoActivePublicKey();
    error PublicKeyIsInfinity();
    error EmptyProof();
    error ArrayLengthMismatch();

    //=============================================================
    //                          EVENTS
    //=============================================================

    /// @notice Emitted when a message is sent
    event MessageSent(address indexed sender, bytes32 indexed messageHash, uint64 indexed destinationChainId);

    /// @notice Emitted when a message is received via finalization proof
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
    //                      WRITE FUNCTIONS
    //=============================================================

    /// @notice Write a received message proven via finalization certificate and receipt proof
    /// @dev Verifies: 1) BLS sig over blockHash, 2) header hashes to blockHash,
    ///      3) receipt exists in receiptsRoot, 4) MessageSent log in receipt
    /// @param blockHeader RLP-encoded Tempo block header
    /// @param finalizationSignature Aggregated BLS threshold signature over the block hash (G1, 128 bytes)
    /// @param receiptProof MPT proof nodes for the receipt
    /// @param receiptIndex Index of the receipt in the block
    /// @param logIndex Index of the MessageSent log in the receipt
    function write(
        bytes calldata blockHeader,
        bytes calldata finalizationSignature,
        bytes[] calldata receiptProof,
        uint256 receiptIndex,
        uint256 logIndex
    ) external;

    /// @notice Write multiple messages from the same block
    /// @dev More efficient than multiple write() calls - verifies finalization once
    /// @param blockHeader RLP-encoded Tempo block header
    /// @param finalizationSignature Aggregated BLS threshold signature (G1, 128 bytes)
    /// @param receiptProofs Array of MPT proof nodes for each receipt
    /// @param receiptIndices Array of receipt indices
    /// @param logIndices Array of log indices within each receipt
    function writeBatch(
        bytes calldata blockHeader,
        bytes calldata finalizationSignature,
        bytes[][] calldata receiptProofs,
        uint256[] calldata receiptIndices,
        uint256[] calldata logIndices
    ) external;

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

    /// @notice Get the current group public key (G2 point, 256 bytes)
    function groupPublicKey() external view returns (bytes memory);

    /// @notice Get the previous epoch
    function previousEpoch() external view returns (uint64);

    /// @notice Get the previous group public key
    function previousGroupPublicKey() external view returns (bytes memory);

    /// @notice Get the origin chain ID (Tempo chain ID)
    function originChainId() external view returns (uint64);

    //=============================================================
    //                   KEY ROTATION FUNCTIONS
    //=============================================================

    /// @notice Rotate to a new key, authorized by the old key signing the transition
    /// @param newEpoch The new epoch (must be > current)
    /// @param newPublicKey The new BLS group public key (G2, 256 bytes)
    /// @param authSignature Signature from OLD key authorizing this (G1, 128 bytes)
    function rotateKey(uint64 newEpoch, bytes calldata newPublicKey, bytes calldata authSignature) external;

    /// @notice Compute the hash for key rotation authorization
    function computeKeyRotationHash(
        uint64 oldEpoch,
        uint64 newEpoch,
        bytes calldata newPublicKey
    ) external pure returns (bytes32);

    //=============================================================
    //                      ADMIN FUNCTIONS
    //=============================================================

    /// @notice Force-set the group public key (governance only)
    function forceSetGroupPublicKey(uint64 newEpoch, bytes calldata publicKey) external;

    /// @notice Pause the contract
    function pause() external;

    /// @notice Unpause the contract
    function unpause() external;

    /// @notice Transfer ownership
    function transferOwnership(address newOwner) external;
}
