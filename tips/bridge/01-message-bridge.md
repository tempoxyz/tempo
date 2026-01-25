# Base Message Bridge Contract Specification

This document specifies the minimal message bridge contract for cross-chain 32-byte hash passing.

## Overview

The Message Bridge provides a minimal interface for cross-chain messaging:
- **Send**: Record a message hash destined for another chain
- **Write**: Store a message hash received from another chain (with BLS verification)
- **Read**: Check if a message has been received

The contract is **completely payload agnostic** - applications encode their own data, hash it, and use this bridge for cross-chain transport.

## Storage Model

### Sent Messages (Replay Protection)

```solidity
// Prevents same (sender, messageHash) from being sent twice
mapping(address sender => mapping(bytes32 messageHash => bool)) public sent;
```

### Received Messages

```solidity
// Records when messages were received
// received[originChainId][sender][messageHash] = timestamp
mapping(uint64 originChainId => mapping(address sender => mapping(bytes32 messageHash => uint256 receivedAt))) public received;
```

## Interface Definition

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IMessageBridge
/// @notice Minimal cross-chain message hash bridge
interface IMessageBridge {
    //=============================================================
    //                          ERRORS
    //=============================================================
    
    error MessageAlreadySent(address sender, bytes32 messageHash);
    error MessageAlreadyReceived(uint64 originChainId, address sender, bytes32 messageHash);
    error InvalidBLSSignature();
    error InvalidEpoch(uint64 provided, uint64 current);
    error ZeroMessageHash();
    error ContractPaused();
    error Unauthorized();
    
    //=============================================================
    //                          EVENTS
    //=============================================================
    
    /// @notice Emitted when a message is sent
    /// @param sender The address sending the message (msg.sender)
    /// @param messageHash The 32-byte message hash
    /// @param destinationChainId The target chain ID
    event MessageSent(
        address indexed sender,
        bytes32 indexed messageHash,
        uint64 indexed destinationChainId
    );
    
    /// @notice Emitted when a message is written (received)
    /// @param originChainId The source chain ID
    /// @param sender The original sender on the source chain
    /// @param messageHash The 32-byte message hash
    /// @param receivedAt Timestamp when received
    event MessageReceived(
        uint64 indexed originChainId,
        address indexed sender,
        bytes32 indexed messageHash,
        uint256 receivedAt
    );
    
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
    /// @param signature Aggregated BLS threshold signature (96 bytes)
    function write(
        address sender,
        bytes32 messageHash,
        uint64 originChainId,
        bytes calldata signature
    ) external;
    
    //=============================================================
    //                      READ FUNCTION
    //=============================================================
    
    /// @notice Check when a message was received
    /// @param originChainId The source chain ID
    /// @param sender The original sender
    /// @param messageHash The message hash
    /// @return Timestamp when received (0 if not received)
    function receivedAt(
        uint64 originChainId,
        address sender,
        bytes32 messageHash
    ) external view returns (uint256);
    
    /// @notice Check if a message has been sent
    /// @param sender The sender address
    /// @param messageHash The message hash
    /// @return True if already sent
    function isSent(address sender, bytes32 messageHash) external view returns (bool);
    
    //=============================================================
    //                      ADMIN FUNCTIONS
    //=============================================================
    
    /// @notice Update the BLS group public key for a new epoch
    function updateGroupPublicKey(uint64 newEpoch, bytes calldata publicKey) external;
    
    /// @notice Pause the contract
    function pause() external;
    
    /// @notice Unpause the contract
    function unpause() external;
}
```

## Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IMessageBridge} from "./interfaces/IMessageBridge.sol";
import {BLSVerifier} from "./libraries/BLSVerifier.sol";

/// @title MessageBridge
/// @notice Minimal cross-chain messaging using BLS threshold signatures
contract MessageBridge is IMessageBridge {
    //=============================================================
    //                          CONSTANTS
    //=============================================================
    
    bytes public constant DOMAIN = "TEMPO_BRIDGE_V1";
    
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
    
    /// @notice Previous epoch (grace period)
    uint64 public previousEpoch;
    
    /// @notice BLS group public key for current epoch (48 bytes compressed G1)
    bytes public groupPublicKey;
    
    /// @notice BLS group public key for previous epoch
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
    
    constructor(
        address _owner,
        uint64 _initialEpoch,
        bytes memory _initialPublicKey
    ) {
        owner = _owner;
        chainId = uint64(block.chainid);
        epoch = _initialEpoch;
        groupPublicKey = _initialPublicKey;
    }
    
    //=============================================================
    //                      SEND FUNCTION
    //=============================================================
    
    /// @inheritdoc IMessageBridge
    function send(
        bytes32 messageHash,
        uint64 destinationChainId
    ) external whenNotPaused {
        if (messageHash == bytes32(0)) revert ZeroMessageHash();
        
        // Replay protection: each (sender, messageHash) can only be sent once
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
        // Check not already received
        if (received[originChainId][sender][messageHash] != 0) {
            revert MessageAlreadyReceived(originChainId, sender, messageHash);
        }
        
        // Compute attestation hash
        bytes32 attestationHash = _computeAttestationHash(
            sender,
            messageHash,
            originChainId,
            chainId
        );
        
        // Verify BLS signature (try current epoch, then previous)
        bool valid = BLSVerifier.verify(groupPublicKey, attestationHash, signature);
        
        if (!valid && previousGroupPublicKey.length > 0) {
            valid = BLSVerifier.verify(previousGroupPublicKey, attestationHash, signature);
        }
        
        if (!valid) revert InvalidBLSSignature();
        
        // Store received timestamp
        uint256 timestamp = block.timestamp;
        received[originChainId][sender][messageHash] = timestamp;
        
        emit MessageReceived(originChainId, sender, messageHash, timestamp);
    }
    
    //=============================================================
    //                      READ FUNCTION
    //=============================================================
    
    /// @inheritdoc IMessageBridge
    function receivedAt(
        uint64 originChainId,
        address sender,
        bytes32 messageHash
    ) external view returns (uint256) {
        return received[originChainId][sender][messageHash];
    }
    
    /// @inheritdoc IMessageBridge
    function isSent(address sender, bytes32 messageHash) external view returns (bool) {
        return sent[sender][messageHash];
    }
    
    //=============================================================
    //                      ADMIN FUNCTIONS
    //=============================================================
    
    /// @inheritdoc IMessageBridge
    function updateGroupPublicKey(
        uint64 newEpoch,
        bytes calldata publicKey
    ) external onlyOwner {
        require(newEpoch > epoch, "Epoch must increase");
        require(publicKey.length == 48, "Invalid public key length");
        
        previousEpoch = epoch;
        previousGroupPublicKey = groupPublicKey;
        
        epoch = newEpoch;
        groupPublicKey = publicKey;
    }
    
    /// @inheritdoc IMessageBridge
    function pause() external onlyOwner {
        paused = true;
    }
    
    /// @inheritdoc IMessageBridge
    function unpause() external onlyOwner {
        paused = false;
    }
    
    //=============================================================
    //                      INTERNAL FUNCTIONS
    //=============================================================
    
    function _computeAttestationHash(
        address sender,
        bytes32 messageHash,
        uint64 originChainId,
        uint64 destinationChainId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "TEMPO_BRIDGE_V1",
            sender,
            messageHash,
            originChainId,
            destinationChainId
        ));
    }
}
```

## Gas Estimates

| Function | Estimated Gas |
|----------|---------------|
| `send` | ~25,000 |
| `write` (BLS verify + store) | ~180,000 |
| `receivedAt` | ~2,600 |
| `isSent` | ~2,600 |

## Invariants

1. **Send Once**: Each `(sender, messageHash)` can only be sent once per origin chain
2. **Write Once**: Each `(originChainId, sender, messageHash)` can only be written once
3. **Timestamp Non-Zero**: Once written, `receivedAt` is always > 0
4. **Signature Validity**: All written messages have valid BLS threshold signatures

## File Locations

| Component | Path |
|-----------|------|
| Contract | `contracts/bridge/src/MessageBridge.sol` |
| Interface | `contracts/bridge/src/interfaces/IMessageBridge.sol` |
| BLS Library | `contracts/bridge/src/libraries/BLSVerifier.sol` |
