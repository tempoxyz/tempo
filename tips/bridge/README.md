# Tempo Native Bridge Specification

This directory contains the complete specification for the Tempo cross-chain messaging bridge.

## Overview

The Tempo Native Bridge is a **minimal cross-chain messaging layer** that enables arbitrary 32-byte message hash passing between any chains. It uses a **BLS threshold signature model** where Tempo validators collectively sign attestations using their BLS12-381 key shares from the consensus DKG.

The bridge follows a **layered architecture**:

1. **Base Messaging Layer** - Minimal 32-byte message hash passing
2. **Application Layer** - Token bridges, NFT bridges, and other apps built on top

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              APPLICATION LAYER                                   │
│  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐                     │
│  │  Token Bridge │   │   NFT Bridge  │   │  Custom Apps  │                     │
│  │  (lock/mint)  │   │  (lock/mint)  │   │  (arbitrary)  │                     │
│  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘                     │
│          │                   │                   │                              │
│          └───────────────────┼───────────────────┘                              │
│                              ▼                                                   │
│                    read receivedAt > 0?                                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                          BASE MESSAGING LAYER                                    │
│                                                                                  │
│   ┌─────────────────┐                           ┌─────────────────┐             │
│   │   Any Chain     │                           │      Tempo      │             │
│   │                 │                           │                 │             │
│   │  ┌───────────┐  │                           │  ┌───────────┐  │             │
│   │  │  Message  │  │                           │  │  Message  │  │             │
│   │  │  Bridge   │◄─┼───── BLS Attestation ─────┼──►│  Bridge   │  │             │
│   │  └───────────┘  │                           │  └───────────┘  │             │
│   │        │        │                           │        │        │             │
│   │   send(hash,    │                           │   send(hash,    │             │
│   │    destChain)   │                           │    destChain)   │             │
│   │        │        │                           │        │        │             │
│   └─────────────────┘                           └─────────────────┘             │
│                                                                                  │
│   Storage on receiving chain:                                                   │
│   mapping(originChainId => sender => messageHash => receivedAtTimestamp)        │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Core Design

### Send (Origin Chain)

```solidity
function send(bytes32 messageHash, uint64 destinationChainId) external;

// Emits:
event MessageSent(address indexed sender, bytes32 indexed messageHash, uint64 indexed destinationChainId);
```

- Sender is `msg.sender`
- Each `(sender, messageHash)` pair can only be sent once (replay protection)
- No recipient specified - applications handle routing

### Write (Destination Chain)

```solidity
function write(address sender, bytes32 messageHash, uint64 originChainId, bytes calldata blsSignature) external;
```

- Validators sign: `(sender, messageHash, originChainId, destinationChainId)`
- Stores in: `received[originChainId][sender][messageHash] = block.timestamp`

### Read (Any Application)

```solidity
function receivedAt(uint64 originChainId, address sender, bytes32 messageHash) external view returns (uint256);
```

- Returns timestamp when message was received (0 if not received)
- Applications check `receivedAt > 0` to verify message existence

## Documents

| Document | Description |
|----------|-------------|
| [01-message-bridge.md](./01-message-bridge.md) | Base messaging bridge contract specification |
| [02-message-format.md](./02-message-format.md) | Message format and BLS signing conventions |
| [03-sidecar.md](./03-sidecar.md) | Validator sidecar specification |
| [04-token-bridge.md](./04-token-bridge.md) | Token bridge application built on base layer |

## Quick Start

### Send a Message

```solidity
// Application computes its payload hash (include a nonce for uniqueness!)
bytes32 messageHash = keccak256(abi.encode(DOMAIN, data, nonce++));

// Send through bridge
bridge.send(messageHash, TEMPO_CHAIN_ID);

// Event emitted: MessageSent(msg.sender, messageHash, TEMPO_CHAIN_ID)
```

### Check if Message Received

```solidity
// On destination chain, check if message arrived
// Note: sender is the APPLICATION CONTRACT, not the user
uint256 timestamp = bridge.receivedAt(ETH_CHAIN_ID, trustedRemoteApp, messageHash);

if (timestamp > 0) {
    // Message was received at `timestamp`
    // Application can now process it
}
```

### Token Bridge Example

```solidity
// Key design points:
// 1. Include NONCE for uniqueness (prevents hash collisions)
// 2. Use CANONICAL ASSET ID (homeChainId + homeToken)
// 3. Verify sender is TRUSTED REMOTE BRIDGE
// 4. Scope claimed by ORIGIN CHAIN

// On Ethereum: lock tokens and send message
function bridgeTokens(bytes32 assetId, address recipient, uint256 amount, uint64 destChain) external {
    Asset memory asset = assets[assetId];
    IERC20(asset.localToken).transferFrom(msg.sender, address(this), amount);
    
    uint256 transferNonce = nonce++;
    bytes32 messageHash = keccak256(abi.encode(
        "TOKEN_BRIDGE_V1",
        block.chainid,        // originChainId
        destChain,            // destinationChainId
        asset.homeChainId,    // canonical asset identity
        asset.homeToken,      // canonical asset identity
        recipient,
        amount,
        transferNonce
    ));
    
    messageBridge.send(messageHash, destChain);
}

// On Tempo: check message and mint
function claimTokens(bytes32 assetId, address recipient, uint256 amount, uint256 transferNonce, uint64 originChain) external {
    address trustedBridge = remoteBridge[originChain];  // NOT user-provided!
    Asset memory asset = assets[assetId];
    
    bytes32 messageHash = keccak256(abi.encode(
        "TOKEN_BRIDGE_V1",
        originChain,
        block.chainid,
        asset.homeChainId,
        asset.homeToken,
        recipient,
        amount,
        transferNonce
    ));
    
    require(messageBridge.receivedAt(originChain, trustedBridge, messageHash) > 0, "not received");
    require(!claimed[originChain][messageHash], "already claimed");  // Scoped by origin!
    
    claimed[originChain][messageHash] = true;
    IMintable(asset.localToken).mint(recipient, amount);
}
```

## Why This Design?

### Minimal Base Layer

| Aspect | Design |
|--------|--------|
| Send interface | `send(hash, destChain)` - 2 parameters |
| Storage | Single nested mapping with timestamp |
| Verification | Check `receivedAt > 0` |
| Replay protection | Origin chain prevents duplicate sends |

### Benefits

1. **Simplicity** - Minimal interface, easy to audit
2. **Flexibility** - Applications define their own message encoding
3. **Composability** - Any app can use the same bridge
4. **Efficiency** - No redundant data storage
5. **Extensibility** - New apps don't require bridge changes
