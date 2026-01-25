// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IMessageBridge} from "./IMessageBridge.sol";

/// @title ITokenBridge
/// @notice Lock/mint bridge for ERC-20 ↔ TIP-20 transfers between chains
/// @dev Deployed at the same address on all chains via CREATE2
interface ITokenBridge {
    //=============================================================
    //                          TYPES
    //=============================================================

    /// @notice Asset configuration
    /// @param homeChainId Chain where the canonical token lives
    /// @param homeToken Token address on the home chain
    /// @param localToken Token address on THIS chain
    /// @param isHomeChain True if this chain is the home chain (lock/unlock vs mint/burn)
    /// @param active Whether bridging is enabled for this asset
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
    error AssetIdMismatch();
    error TransferFailed();

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
        bytes32 indexed assetId, uint64 homeChainId, address homeToken, address localToken, bool isHomeChain
    );

    /// @notice Emitted when an asset's active status changes
    event AssetActiveChanged(bytes32 indexed assetId, bool active);

    //=============================================================
    //                      BRIDGE FUNCTIONS
    //=============================================================

    /// @notice Bridge tokens to another chain
    /// @param assetId The canonical asset identifier: keccak256(homeChainId, homeToken)
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
    /// @param recipient Address to receive tokens (must match what was bridged)
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

    /// @notice Compute asset ID from canonical identity
    function computeAssetId(uint64 homeChainId, address homeToken) external pure returns (bytes32);

    /// @notice Get asset details by ID
    function getAsset(bytes32 assetId) external view returns (Asset memory);

    /// @notice Check if a transfer has been claimed
    function isClaimed(uint64 originChainId, bytes32 messageHash) external view returns (bool);

    /// @notice Current nonce (next transfer will use this value)
    function nonce() external view returns (uint256);

    /// @notice Get the MessageBridge contract
    function messageBridge() external view returns (IMessageBridge);

    /// @notice Get this chain's ID
    function chainId() external view returns (uint64);

    //=============================================================
    //                      ADMIN FUNCTIONS
    //=============================================================

    /// @notice Register a new bridgeable asset
    /// @param assetId Must equal keccak256(abi.encodePacked(homeChainId, homeToken))
    /// @param homeChainId Chain where canonical token lives
    /// @param homeToken Token address on home chain
    /// @param localToken Token address on this chain
    /// @param isHomeChain True if this chain is the home chain
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

    /// @notice Transfer ownership
    function transferOwnership(address newOwner) external;
}

/// @notice Interface for mintable tokens (ERC-20 or TIP-20)
interface IMintable {
    function mint(address to, uint256 amount) external;
}

/// @notice Interface for burnable tokens that support burnFrom (ERC-20 style)
interface IBurnableFrom {
    function burnFrom(address from, uint256 amount) external;
}

/// @notice Interface for TIP-20 burn (burns from msg.sender)
interface ITIP20Burnable {
    function burn(uint256 amount) external;
}
