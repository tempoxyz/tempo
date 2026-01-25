// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IMessageBridge} from "./interfaces/IMessageBridge.sol";
import {BLS12381} from "./BLS12381.sol";

/// @title MessageBridge
/// @notice Minimal cross-chain messaging using BLS threshold signatures
/// @dev Uses EIP-2537 BLS12-381 precompiles for signature verification
contract MessageBridge is IMessageBridge {
    //=============================================================
    //                          CONSTANTS
    //=============================================================

    /// @notice Domain separator for bridge attestations
    bytes public constant BRIDGE_DOMAIN = "TEMPO_BRIDGE_V1";

    /// @notice Domain separator for key rotation
    bytes public constant KEY_ROTATION_DOMAIN = "TEMPO_BRIDGE_KEY_ROTATION_V1";

    /// @notice BLS Domain Separation Tag for hash-to-curve (targets G1 for MinSig variant)
    /// @dev Must match the DST used by validators when signing
    bytes public constant BLS_DST = "TEMPO_BRIDGE_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

    /// @notice Expected length for uncompressed G1 point (signature in MinSig)
    uint256 internal constant G1_POINT_LENGTH = 128;

    /// @notice Expected length for uncompressed G2 point (public key in MinSig)
    uint256 internal constant G2_POINT_LENGTH = 256;

    //=============================================================
    //                          STORAGE
    //=============================================================

    /// @notice Contract owner
    address public owner;

    /// @notice Pause state
    bool public paused;

    /// @notice This chain's ID
    uint64 public immutable chainId;

    /// @notice Current validator epoch
    uint64 public epoch;

    /// @notice Previous epoch (for grace period)
    uint64 public previousEpoch;

    /// @notice BLS group public key for current epoch (G2 point, 256 bytes for MinSig)
    bytes public groupPublicKey;

    /// @notice BLS group public key for previous epoch (G2 point)
    bytes public previousGroupPublicKey;

    /// @notice Sent messages: sender => messageHash => sent
    mapping(address => mapping(bytes32 => bool)) public sent;

    /// @notice Received messages: originChainId => sender => messageHash => timestamp
    mapping(uint64 => mapping(address => mapping(bytes32 => uint256))) public received;

    //=============================================================
    //                        MODIFIERS
    //=============================================================

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    //=============================================================
    //                       CONSTRUCTOR
    //=============================================================

    /// @param _owner Contract owner
    /// @param _initialEpoch Initial epoch number
    /// @param _initialPublicKey Initial BLS group public key (G2, 256 bytes for MinSig)
    constructor(address _owner, uint64 _initialEpoch, bytes memory _initialPublicKey) {
        if (_initialPublicKey.length != G2_POINT_LENGTH) revert InvalidPublicKeyLength();
        if (!BLS12381.isValidPublicKey(_initialPublicKey)) revert PublicKeyIsInfinity();

        owner = _owner;
        chainId = uint64(block.chainid);
        epoch = _initialEpoch;
        groupPublicKey = _initialPublicKey;
    }

    //=============================================================
    //                      SEND FUNCTION
    //=============================================================

    /// @inheritdoc IMessageBridge
    function send(bytes32 messageHash, uint64 destinationChainId) external whenNotPaused {
        if (messageHash == bytes32(0)) revert ZeroMessageHash();

        if (sent[msg.sender][messageHash]) {
            revert MessageAlreadySent(msg.sender, messageHash);
        }

        sent[msg.sender][messageHash] = true;

        emit MessageSent(msg.sender, messageHash, destinationChainId);
    }

    //=============================================================
    //                      WRITE FUNCTION
    //=============================================================

    /// @inheritdoc IMessageBridge
    function write(
        address sender,
        bytes32 messageHash,
        uint64 originChainId,
        bytes calldata signature
    ) external whenNotPaused {
        if (signature.length != G1_POINT_LENGTH) revert InvalidSignatureLength();

        if (received[originChainId][sender][messageHash] != 0) {
            revert MessageAlreadyReceived(originChainId, sender, messageHash);
        }

        // Compute attestation hash that validators signed
        bytes32 attestationHash = _computeAttestationHash(sender, messageHash, originChainId, chainId);

        // Verify BLS signature using current epoch's public key
        bool valid = _verifyBLSSignature(groupPublicKey, attestationHash, signature);

        // If failed and we have a previous key (grace period), try that
        if (!valid && previousGroupPublicKey.length > 0) {
            valid = _verifyBLSSignature(previousGroupPublicKey, attestationHash, signature);
        }

        if (!valid) revert InvalidBLSSignature();

        uint256 timestamp = block.timestamp;
        received[originChainId][sender][messageHash] = timestamp;

        emit MessageReceived(originChainId, sender, messageHash, timestamp);
    }

    //=============================================================
    //                      READ FUNCTIONS
    //=============================================================

    /// @inheritdoc IMessageBridge
    function receivedAt(uint64 originChainId, address sender, bytes32 messageHash) external view returns (uint256) {
        return received[originChainId][sender][messageHash];
    }

    /// @inheritdoc IMessageBridge
    function isSent(address sender, bytes32 messageHash) external view returns (bool) {
        return sent[sender][messageHash];
    }

    //=============================================================
    //                   KEY ROTATION FUNCTIONS
    //=============================================================

    /// @inheritdoc IMessageBridge
    function rotateKey(
        uint64 newEpoch,
        bytes calldata newPublicKey,
        bytes calldata authSignature
    ) external whenNotPaused {
        if (newPublicKey.length != G2_POINT_LENGTH) revert InvalidPublicKeyLength();
        if (authSignature.length != G1_POINT_LENGTH) revert InvalidSignatureLength();
        if (newEpoch <= epoch) revert EpochMustIncrease(epoch, newEpoch);
        if (groupPublicKey.length == 0) revert NoActivePublicKey();

        bytes32 rotationHash = _computeKeyRotationHash(epoch, newEpoch, newPublicKey);

        bool valid = _verifyBLSSignature(groupPublicKey, rotationHash, authSignature);
        if (!valid) revert KeyTransitionNotAuthorized();

        emit KeyRotationAuthorized(epoch, newEpoch, newPublicKey);

        _rotateKey(newEpoch, newPublicKey);
    }

    /// @inheritdoc IMessageBridge
    function computeKeyRotationHash(
        uint64 oldEpoch,
        uint64 newEpoch,
        bytes calldata newPublicKey
    ) external pure returns (bytes32) {
        return _computeKeyRotationHash(oldEpoch, newEpoch, newPublicKey);
    }

    //=============================================================
    //                      ADMIN FUNCTIONS
    //=============================================================

    /// @inheritdoc IMessageBridge
    function forceSetGroupPublicKey(uint64 newEpoch, bytes calldata publicKey) external onlyOwner {
        if (publicKey.length != G2_POINT_LENGTH) revert InvalidPublicKeyLength();
        if (newEpoch <= epoch) revert EpochMustIncrease(epoch, newEpoch);

        _rotateKey(newEpoch, publicKey);
    }

    /// @inheritdoc IMessageBridge
    function pause() external onlyOwner {
        paused = true;
    }

    /// @inheritdoc IMessageBridge
    function unpause() external onlyOwner {
        paused = false;
    }

    /// @inheritdoc IMessageBridge
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }

    //=============================================================
    //                      INTERNAL FUNCTIONS
    //=============================================================

    /// @notice Compute attestation hash for a message
    /// @dev Format: keccak256(domain || sender || messageHash || originChainId || destinationChainId)
    function _computeAttestationHash(
        address sender,
        bytes32 messageHash,
        uint64 originChainId,
        uint64 destinationChainId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            BRIDGE_DOMAIN,
            sender,
            messageHash,
            originChainId,
            destinationChainId
        ));
    }

    /// @notice Compute key rotation authorization hash
    function _computeKeyRotationHash(
        uint64 oldEpoch,
        uint64 newEpoch,
        bytes memory newPublicKey
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            KEY_ROTATION_DOMAIN,
            oldEpoch,
            newEpoch,
            newPublicKey
        ));
    }

    /// @notice Internal key rotation
    function _rotateKey(uint64 newEpoch, bytes memory newPublicKey) internal {
        // Reject point at infinity to prevent signature forgery attacks
        // If pk = infinity, then e(infinity, H(m)) * e(-G1, infinity) = 1 for any message
        if (!BLS12381.isValidPublicKey(newPublicKey)) revert PublicKeyIsInfinity();

        bytes memory oldKey = groupPublicKey;
        uint64 oldEpoch = epoch;

        previousEpoch = epoch;
        previousGroupPublicKey = groupPublicKey;

        epoch = newEpoch;
        groupPublicKey = newPublicKey;

        emit KeyRotated(oldEpoch, newEpoch, oldKey, newPublicKey);
    }

    /// @notice Verify a BLS signature using RFC 9380 hash-to-curve (MinSig variant)
    /// @param publicKey G2 public key (256 bytes)
    /// @param messageHash The 32-byte message hash (will be hashed to G1)
    /// @param signature G1 signature (128 bytes)
    /// @return True if signature is valid
    function _verifyBLSSignature(
        bytes memory publicKey,
        bytes32 messageHash,
        bytes calldata signature
    ) internal view returns (bool) {
        // Use the BLS12381 library for signature verification
        // This implements RFC 9380 hash-to-curve to G1 with our DST
        return BLS12381.verifyHash(
            publicKey,
            messageHash,
            BLS_DST,
            bytes(signature)
        );
    }
}
