# Token Bridge Specification

This document specifies the Token Bridge - a lock/mint bridge for ERC-20 ↔ TIP-20 transfers between Ethereum and Tempo.

## Overview

The Token Bridge enables users to:
1. **Lock USDC on Ethereum → Mint USDC.t (TIP-20) on Tempo**
2. **Burn USDC.t on Tempo → Unlock USDC on Ethereum**

Key properties:
- Built on top of the base `MessageBridge` for cross-chain attestation verification
- Uses **canonical asset IDs** for consistent token identity across chains
- Uses **per-bridge nonces** for unique transfer identification
- **Deployed at the same address on all chains** via CREATE2 for simple sender verification

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Token Bridge Flow                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ETHEREUM                              TEMPO                                 │
│  ────────                              ─────                                 │
│                                                                              │
│  ┌──────────────┐                      ┌──────────────┐                     │
│  │     USDC     │                      │   USDC.t     │                     │
│  │   (ERC-20)   │                      │   (TIP-20)   │                     │
│  └──────┬───────┘                      └──────┬───────┘                     │
│         │                                     │                              │
│         ▼                                     ▼                              │
│  ┌──────────────┐                      ┌──────────────┐                     │
│  │ TokenBridge  │◄────── BLS ────────►│ TokenBridge  │                     │
│  │  (lock/unlock)│     Attestations    │ (mint/burn)  │                     │
│  └──────┬───────┘                      └──────┬───────┘                     │
│         │                                     │                              │
│         ▼                                     ▼                              │
│  ┌──────────────┐                      ┌──────────────┐                     │
│  │MessageBridge │                      │MessageBridge │                     │
│  └──────────────┘                      └──────────────┘                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### 1. Same Address on All Chains (CREATE2)

The TokenBridge is deployed at the **same address** on all chains using CREATE2:
- No "trusted remote bridge" registry needed
- Claims verify `messageBridge.receivedAt(originChainId, address(this), hash) > 0`
- Simpler code, fewer admin functions, reduced attack surface

### 2. Unique Transfers via Nonce

Each transfer includes a monotonically increasing nonce to prevent:
- Hash collisions (two users bridging same token/amount/recipient)
- Griefing attacks (burning a hash tuple forever with dust)
- Replay of identical transfers

### 3. Canonical Asset Identity

Tokens are identified by `(homeChainId, homeToken)`:
- USDC's canonical identity is `(1, 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)` (Ethereum mainnet)
- Message hashes are consistent regardless of which chain you're on
- Supports future multi-chain expansion (e.g., bridging from Arbitrum)

### 4. TIP-20 Integration on Tempo

On Tempo, bridged tokens are TIP-20 tokens with special configuration:
- TokenBridge holds `ISSUER_ROLE` to mint tokens
- Users call `burn()` directly on the TIP-20 (no approval needed)
- TokenBridge watches for `Burn` events (not `burnFrom`)

## Data Structures

### Asset Registry

```solidity
struct Asset {
    uint64 homeChainId;      // Chain where canonical token lives (e.g., 1 for USDC)
    address homeToken;       // Token address on home chain
    address localToken;      // Token address on THIS chain
    bool isHomeChain;        // True if this chain is the home chain
    bool active;             // Can be paused per-asset
}
```

### Asset ID Computation

```solidity
// Deterministic asset ID from canonical identity
assetId = keccak256(abi.encodePacked(homeChainId, homeToken))

// Example: USDC
assetId = keccak256(abi.encodePacked(uint64(1), address(0xA0b869...)))
```

### Message Hash Format

```solidity
messageHash = keccak256(abi.encodePacked(
    "TOKEN_BRIDGE_V1",       // Domain separator (15 bytes)
    originChainId,           // uint64 - source chain
    destinationChainId,      // uint64 - destination chain
    homeChainId,             // uint64 - asset's canonical chain
    homeToken,               // address - asset's canonical address
    recipient,               // address - recipient on destination
    amount,                  // uint256 - transfer amount
    nonce                    // uint256 - unique per-bridge nonce
))
```

**Field breakdown:**
| Field | Type | Purpose |
|-------|------|---------|
| Domain | bytes15 | Protocol identification |
| originChainId | uint64 | Where the transfer started |
| destinationChainId | uint64 | Where tokens will be received |
| homeChainId | uint64 | Canonical asset identity (replay protection) |
| homeToken | address | Canonical asset identity |
| recipient | address | Who receives on destination |
| amount | uint256 | Transfer amount |
| nonce | uint256 | Uniqueness guarantee |

## Interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ITokenBridge {
    //=============================================================
    //                          TYPES
    //=============================================================
    
    struct Asset {
        uint64 homeChainId;
        address homeToken;
        address localToken;
        bool isHomeChain;
        bool active;
    }
    
    //=============================================================
    //                          ERRORS
    //=============================================================
    
    error Unauthorized();
    error ContractPaused();
    error MessageNotReceived();
    error AlreadyClaimed();
    error InvalidAmount();
    error InvalidRecipient();
    error AssetNotRegistered(bytes32 assetId);
    error AssetNotActive(bytes32 assetId);
    
    //=============================================================
    //                          EVENTS
    //=============================================================
    
    /// @notice Emitted when tokens are bridged out
    event TokensBridged(
        bytes32 indexed messageHash,
        bytes32 indexed assetId,
        uint256 indexed nonce,
        address sender,
        address recipient,
        uint256 amount,
        uint64 destinationChainId
    );
    
    /// @notice Emitted when bridged tokens are claimed
    event TokensClaimed(
        bytes32 indexed messageHash,
        bytes32 indexed assetId,
        address indexed recipient,
        uint256 amount,
        uint64 originChainId
    );
    
    /// @notice Emitted when a new asset is registered
    event AssetRegistered(
        bytes32 indexed assetId,
        uint64 homeChainId,
        address homeToken,
        address localToken,
        bool isHomeChain
    );
    
    //=============================================================
    //                      BRIDGE FUNCTIONS
    //=============================================================
    
    /// @notice Bridge tokens to another chain
    /// @param assetId The canonical asset identifier
    /// @param recipient Address to receive tokens on destination chain
    /// @param amount Amount of tokens to bridge
    /// @param destinationChainId Target chain ID
    /// @return messageHash The hash sent to MessageBridge
    /// @return transferNonce The nonce for this transfer
    function bridgeTokens(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        uint64 destinationChainId
    ) external returns (bytes32 messageHash, uint256 transferNonce);
    
    /// @notice Claim bridged tokens on destination chain
    /// @param assetId The canonical asset identifier
    /// @param recipient Address to receive tokens
    /// @param amount Amount of tokens to claim
    /// @param transferNonce The nonce from the origin chain
    /// @param originChainId Chain where tokens were bridged from
    function claimTokens(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        uint256 transferNonce,
        uint64 originChainId
    ) external;
    
    //=============================================================
    //                      VIEW FUNCTIONS
    //=============================================================
    
    /// @notice Compute the message hash for a transfer
    function computeMessageHash(
        uint64 originChainId,
        uint64 destinationChainId,
        uint64 homeChainId,
        address homeToken,
        address recipient,
        uint256 amount,
        uint256 transferNonce
    ) external pure returns (bytes32);
    
    /// @notice Get asset details by ID
    function getAsset(bytes32 assetId) external view returns (Asset memory);
    
    /// @notice Check if a transfer has been claimed
    function isClaimed(uint64 originChainId, bytes32 messageHash) external view returns (bool);
    
    /// @notice Current nonce (next transfer will use this value)
    function nonce() external view returns (uint256);
    
    //=============================================================
    //                      ADMIN FUNCTIONS
    //=============================================================
    
    /// @notice Register a new bridgeable asset
    function registerAsset(
        bytes32 assetId,
        uint64 homeChainId,
        address homeToken,
        address localToken,
        bool isHomeChain
    ) external;
    
    /// @notice Enable/disable an asset
    function setAssetActive(bytes32 assetId, bool active) external;
    
    /// @notice Pause all bridge operations
    function pause() external;
    
    /// @notice Unpause bridge operations
    function unpause() external;
}
```

## Implementation

### TokenBridge.sol (Unified for All Chains)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ITokenBridge} from "./interfaces/ITokenBridge.sol";
import {IMessageBridge} from "./interfaces/IMessageBridge.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title TokenBridge
/// @notice Lock/mint bridge deployed at same address on all chains via CREATE2
/// @dev On home chain: locks/unlocks tokens. On remote chains: mints/burns.
contract TokenBridge is ITokenBridge {
    using SafeERC20 for IERC20;
    
    //=============================================================
    //                          CONSTANTS
    //=============================================================
    
    bytes public constant DOMAIN = "TOKEN_BRIDGE_V1";
    
    //=============================================================
    //                          STORAGE
    //=============================================================
    
    address public owner;
    bool public paused;
    
    IMessageBridge public immutable messageBridge;
    uint64 public immutable chainId;
    
    /// @notice Asset registry: assetId => Asset
    mapping(bytes32 => Asset) public assets;
    
    /// @notice Claimed transfers: originChainId => messageHash => claimed
    mapping(uint64 => mapping(bytes32 => bool)) public claimed;
    
    /// @notice Global nonce for unique transfer identification
    uint256 public nonce;
    
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
    
    constructor(address _owner, address _messageBridge) {
        owner = _owner;
        messageBridge = IMessageBridge(_messageBridge);
        chainId = uint64(block.chainid);
    }
    
    //=============================================================
    //                      BRIDGE FUNCTIONS
    //=============================================================
    
    /// @inheritdoc ITokenBridge
    function bridgeTokens(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        uint64 destinationChainId
    ) external whenNotPaused returns (bytes32 messageHash, uint256 transferNonce) {
        if (amount == 0) revert InvalidAmount();
        if (recipient == address(0)) revert InvalidRecipient();
        
        Asset memory asset = assets[assetId];
        if (asset.localToken == address(0)) revert AssetNotRegistered(assetId);
        if (!asset.active) revert AssetNotActive(assetId);
        
        if (asset.isHomeChain) {
            // HOME CHAIN: Lock tokens in this contract
            uint256 balanceBefore = IERC20(asset.localToken).balanceOf(address(this));
            IERC20(asset.localToken).safeTransferFrom(msg.sender, address(this), amount);
            // Handle fee-on-transfer tokens
            amount = IERC20(asset.localToken).balanceOf(address(this)) - balanceBefore;
        } else {
            // REMOTE CHAIN: Burn wrapped tokens
            // For TIP-20: user calls burn() directly, or we call burnFrom()
            IBurnable(asset.localToken).burnFrom(msg.sender, amount);
        }
        
        transferNonce = nonce++;
        
        messageHash = _computeMessageHash(
            chainId,
            destinationChainId,
            asset.homeChainId,
            asset.homeToken,
            recipient,
            amount,
            transferNonce
        );
        
        // Send message hash to MessageBridge for cross-chain attestation
        messageBridge.send(messageHash, destinationChainId);
        
        emit TokensBridged(
            messageHash,
            assetId,
            transferNonce,
            msg.sender,
            recipient,
            amount,
            destinationChainId
        );
    }
    
    /// @inheritdoc ITokenBridge
    function claimTokens(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        uint256 transferNonce,
        uint64 originChainId
    ) external whenNotPaused {
        Asset memory asset = assets[assetId];
        if (asset.localToken == address(0)) revert AssetNotRegistered(assetId);
        
        bytes32 messageHash = _computeMessageHash(
            originChainId,
            chainId,
            asset.homeChainId,
            asset.homeToken,
            recipient,
            amount,
            transferNonce
        );
        
        // Verify message was attested by validators via MessageBridge
        // sender = address(this) because TokenBridge has same address on all chains
        if (messageBridge.receivedAt(originChainId, address(this), messageHash) == 0) {
            revert MessageNotReceived();
        }
        
        // Prevent double-claim
        if (claimed[originChainId][messageHash]) revert AlreadyClaimed();
        claimed[originChainId][messageHash] = true;
        
        if (asset.isHomeChain) {
            // HOME CHAIN: Unlock from escrow
            IERC20(asset.localToken).safeTransfer(recipient, amount);
        } else {
            // REMOTE CHAIN: Mint wrapped tokens
            IMintable(asset.localToken).mint(recipient, amount);
        }
        
        emit TokensClaimed(messageHash, assetId, recipient, amount, originChainId);
    }
    
    //=============================================================
    //                      VIEW FUNCTIONS
    //=============================================================
    
    /// @inheritdoc ITokenBridge
    function computeMessageHash(
        uint64 originChainId,
        uint64 destinationChainId,
        uint64 homeChainId,
        address homeToken,
        address recipient,
        uint256 amount,
        uint256 transferNonce
    ) external pure returns (bytes32) {
        return _computeMessageHash(
            originChainId,
            destinationChainId,
            homeChainId,
            homeToken,
            recipient,
            amount,
            transferNonce
        );
    }
    
    /// @inheritdoc ITokenBridge
    function getAsset(bytes32 assetId) external view returns (Asset memory) {
        return assets[assetId];
    }
    
    /// @inheritdoc ITokenBridge
    function isClaimed(uint64 originChainId, bytes32 messageHash) external view returns (bool) {
        return claimed[originChainId][messageHash];
    }
    
    //=============================================================
    //                      ADMIN FUNCTIONS
    //=============================================================
    
    /// @inheritdoc ITokenBridge
    function registerAsset(
        bytes32 assetId,
        uint64 homeChainId,
        address homeToken,
        address localToken,
        bool isHomeChain
    ) external onlyOwner {
        // Verify assetId matches the canonical identity
        require(
            assetId == keccak256(abi.encodePacked(homeChainId, homeToken)),
            "Asset ID mismatch"
        );
        
        assets[assetId] = Asset({
            homeChainId: homeChainId,
            homeToken: homeToken,
            localToken: localToken,
            isHomeChain: isHomeChain,
            active: true
        });
        
        emit AssetRegistered(assetId, homeChainId, homeToken, localToken, isHomeChain);
    }
    
    /// @inheritdoc ITokenBridge
    function setAssetActive(bytes32 assetId, bool active) external onlyOwner {
        assets[assetId].active = active;
    }
    
    /// @inheritdoc ITokenBridge
    function pause() external onlyOwner {
        paused = true;
    }
    
    /// @inheritdoc ITokenBridge
    function unpause() external onlyOwner {
        paused = false;
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }
    
    //=============================================================
    //                      INTERNAL FUNCTIONS
    //=============================================================
    
    function _computeMessageHash(
        uint64 originChainId,
        uint64 destinationChainId,
        uint64 homeChainId,
        address homeToken,
        address recipient,
        uint256 amount,
        uint256 transferNonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "TOKEN_BRIDGE_V1",
            originChainId,
            destinationChainId,
            homeChainId,
            homeToken,
            recipient,
            amount,
            transferNonce
        ));
    }
}

/// @notice Interface for mintable tokens (ERC-20 style)
interface IMintable {
    function mint(address to, uint256 amount) external;
}

/// @notice Interface for burnable tokens (ERC-20 style)
interface IBurnable {
    function burnFrom(address from, uint256 amount) external;
}
```

## TIP-20 Integration on Tempo

On Tempo, bridged tokens are TIP-20 tokens. The TokenBridge needs `ISSUER_ROLE` to mint tokens.

### USDC.t Token Setup

```solidity
// During genesis or via admin transaction:

// 1. Create USDC.t TIP-20 token
ITIP20Factory(TIP20_FACTORY).createToken(
    "Bridged USDC",     // name
    "USDC.t",           // symbol
    6,                  // decimals (match USDC)
    0,                  // initialSupply (minted on demand)
    type(uint256).max,  // supplyCap
    policyId            // transfer policy
);

// 2. Grant ISSUER_ROLE to TokenBridge
ITIP20(usdcTempo).grantRole(ISSUER_ROLE, tokenBridgeAddress);
```

### TIP-20 Mint Interface

TIP-20's mint function signature:
```solidity
function mint(address to, uint256 amount) external;
```

This matches `IMintable`, so no adapter needed.

### TIP-20 Burn Handling

TIP-20 has `burn(uint256 amount)` which burns from `msg.sender`. For `burnFrom`, we need the user to either:

**Option A: User calls burn directly, TokenBridge watches events**
```solidity
// User transaction:
ITIP20(usdcTempo).burn(amount);

// Then calls TokenBridge to register the burn:
tokenBridge.registerBurn(assetId, recipient, amount, destinationChainId);
```

**Option B: TokenBridge uses transferFrom + burn**
```solidity
// In bridgeTokens() for remote chain:
IERC20(asset.localToken).safeTransferFrom(msg.sender, address(this), amount);
ITIP20(asset.localToken).burn(amount);
```

**Recommendation**: Option B is simpler and atomic. The TokenBridge needs approval but provides better UX.

## Transfer Flows

### Ethereum → Tempo (Lock & Mint)

```
ETHEREUM                                       TEMPO
────────                                       ─────

1. User approves TokenBridge for USDC
   USDC.approve(TokenBridge, amount)

2. User calls bridgeTokens()
   TokenBridge.bridgeTokens(USDC_ASSET_ID, recipient, amount, TEMPO_CHAIN_ID)
   ├─► USDC.transferFrom(user, TokenBridge, amount)  [LOCK]
   ├─► nonce = 0
   ├─► hash = keccak256(TOKEN_BRIDGE_V1 || 1 || 12345 || 1 || USDC || recipient || amount || 0)
   ├─► messageBridge.send(hash, TEMPO_CHAIN_ID)
   └─► emit TokensBridged(hash, assetId, 0, user, recipient, amount, TEMPO_CHAIN_ID)

3. MessageBridge emits MessageSent
   emit MessageSent(TokenBridge, hash, TEMPO_CHAIN_ID)

4. Validators observe event, sign attestation
   attestationHash = keccak256(TEMPO_BRIDGE_V1 || TokenBridge || hash || 1 || 12345)
   σ = threshold_sign(attestationHash)

5. Aggregator submits to Tempo MessageBridge
   messageBridge.write(TokenBridge, hash, 1, σ)
   └─► received[1][TokenBridge][hash] = block.timestamp

6. Anyone calls claimTokens() on Tempo
   TokenBridge.claimTokens(USDC_ASSET_ID, recipient, amount, 0, ETH_CHAIN_ID)
   ├─► hash = keccak256(...)  [same computation]
   ├─► require(messageBridge.receivedAt(1, address(this), hash) > 0)  ✓
   ├─► claimed[1][hash] = true
   ├─► USDC_T.mint(recipient, amount)  [MINT]
   └─► emit TokensClaimed(hash, assetId, recipient, amount, 1)
```

### Tempo → Ethereum (Burn & Unlock)

```
TEMPO                                          ETHEREUM
─────                                          ────────

1. User approves TokenBridge for USDC.t
   USDC_T.approve(TokenBridge, amount)

2. User calls bridgeTokens()
   TokenBridge.bridgeTokens(USDC_ASSET_ID, recipient, amount, ETH_CHAIN_ID)
   ├─► USDC_T.transferFrom(user, TokenBridge, amount)
   ├─► USDC_T.burn(amount)  [BURN]
   ├─► nonce = 0
   ├─► hash = keccak256(TOKEN_BRIDGE_V1 || 12345 || 1 || 1 || USDC || recipient || amount || 0)
   ├─► messageBridge.send(hash, ETH_CHAIN_ID)
   └─► emit TokensBridged(...)

3. Validators sign and relay to Ethereum
   messageBridge.write(TokenBridge, hash, 12345, σ)

4. Anyone calls claimTokens() on Ethereum
   TokenBridge.claimTokens(USDC_ASSET_ID, recipient, amount, 0, TEMPO_CHAIN_ID)
   ├─► require(messageBridge.receivedAt(12345, address(this), hash) > 0)  ✓
   ├─► claimed[12345][hash] = true
   ├─► USDC.transfer(recipient, amount)  [UNLOCK]
   └─► emit TokensClaimed(...)
```

## Asset Registration

### USDC Configuration

| Chain | Role | localToken | isHomeChain |
|-------|------|------------|-------------|
| Ethereum (1) | Home | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | `true` |
| Tempo (12345) | Remote | USDC.t address | `false` |

```solidity
// Asset ID for USDC
bytes32 USDC_ASSET_ID = keccak256(abi.encodePacked(
    uint64(1),                                    // Ethereum mainnet
    address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)  // USDC address
));

// On Ethereum:
tokenBridge.registerAsset(
    USDC_ASSET_ID,
    1,                          // homeChainId
    0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48,  // homeToken
    0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48,  // localToken (same)
    true                        // isHomeChain
);

// On Tempo:
tokenBridge.registerAsset(
    USDC_ASSET_ID,
    1,                          // homeChainId
    0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48,  // homeToken
    USDC_T_ADDRESS,             // localToken (USDC.t)
    false                       // isHomeChain
);
```

## CREATE2 Deployment

Deploy TokenBridge at the same address on all chains:

```solidity
// Deployer contract (deployed at same address on all chains)
bytes32 constant SALT = keccak256("TokenBridge_v1");

function deploy(address owner, address messageBridge) external returns (address) {
    bytes memory initCode = abi.encodePacked(
        type(TokenBridge).creationCode,
        abi.encode(owner, messageBridge)
    );
    
    address bridge;
    assembly {
        bridge := create2(0, add(initCode, 0x20), mload(initCode), SALT)
    }
    require(bridge != address(0), "Deploy failed");
    return bridge;
}
```

**Requirement**: `messageBridge` must also be at the same address on all chains.

## Gas Estimates

| Function | Home Chain | Remote Chain |
|----------|------------|--------------|
| `bridgeTokens` | ~85,000 (lock) | ~95,000 (burn) |
| `claimTokens` | ~55,000 (unlock) | ~75,000 (mint) |

## Security Considerations

### Invariants

1. **Token Conservation**: `locked_on_home == minted_on_remote` at all times
2. **Unique Transfers**: Each `(originChainId, nonce)` maps to exactly one transfer
3. **Single Claim**: Each `(originChainId, messageHash)` can only be claimed once
4. **Same Address**: TokenBridge has identical address on all chains
5. **Attestation Required**: Tokens only released after BLS threshold signature verification

### Attack Vectors & Mitigations

| Attack | Mitigation |
|--------|------------|
| Double-spend | `claimed[origin][hash]` mapping prevents re-claims |
| Cross-chain replay | `originChainId` and `destinationChainId` in hash |
| Sender spoofing | Same-address deployment; `address(this)` verification |
| Griefing (dust burns) | Nonce ensures unique hashes |
| Reentrancy | SafeERC20, effects before transfers |

## File Locations

| Component | Path |
|-----------|------|
| TokenBridge | `crates/native-bridge/contracts/src/TokenBridge.sol` |
| ITokenBridge | `crates/native-bridge/contracts/src/interfaces/ITokenBridge.sol` |
| Tests | `crates/native-bridge/contracts/test/TokenBridge.t.sol` |

## Test Vectors

### Test Vector 1: USDC Ethereum → Tempo

**Input:**
```
originChainId:      1 (Ethereum)
destinationChainId: 12345 (Tempo)
homeChainId:        1
homeToken:          0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
recipient:          0x1234567890123456789012345678901234567890
amount:             1000000 (1 USDC)
nonce:              0
```

**Expected messageHash:**
```
keccak256(abi.encodePacked(
    "TOKEN_BRIDGE_V1",
    uint64(1),
    uint64(12345),
    uint64(1),
    address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48),
    address(0x1234567890123456789012345678901234567890),
    uint256(1000000),
    uint256(0)
))
```

### Test Vector 2: USDC.t Tempo → Ethereum

**Input:**
```
originChainId:      12345 (Tempo)
destinationChainId: 1 (Ethereum)
homeChainId:        1
homeToken:          0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
recipient:          0xABCDEF0123456789ABCDEF0123456789ABCDEF01
amount:             5000000 (5 USDC)
nonce:              42
```
