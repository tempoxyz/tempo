// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ITokenBridge, IMintable, ITIP20Burnable} from "./interfaces/ITokenBridge.sol";
import {IMessageBridge} from "./interfaces/IMessageBridge.sol";

/// @title TokenBridge
/// @notice Lock/mint bridge deployed at the same address on all chains via CREATE2
/// @dev On home chain: locks/unlocks tokens. On remote chains: mints/burns.
contract TokenBridge is ITokenBridge {
    //=============================================================
    //                          CONSTANTS
    //=============================================================

    /// @notice Domain separator for token bridge messages
    bytes public constant DOMAIN = "TOKEN_BRIDGE_V1";

    //=============================================================
    //                          STORAGE
    //=============================================================

    /// @notice Contract owner
    address public owner;

    /// @notice Pause state
    bool public paused;

    /// @notice The MessageBridge contract for cross-chain attestations
    IMessageBridge public immutable messageBridge;

    /// @notice This chain's ID
    uint64 public immutable chainId;

    /// @notice Asset registry: assetId => Asset
    mapping(bytes32 => Asset) internal _assets;

    /// @notice Claimed transfers: originChainId => messageHash => claimed
    mapping(uint64 => mapping(bytes32 => bool)) internal _claimed;

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

    /// @param _owner Contract owner
    /// @param _messageBridge The MessageBridge contract address
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

        Asset memory asset = _assets[assetId];
        if (asset.localToken == address(0)) revert AssetNotRegistered(assetId);
        if (!asset.active) revert AssetNotActive(assetId);

        // Transfer tokens to this contract first
        uint256 balanceBefore = _balanceOf(asset.localToken, address(this));
        _safeTransferFrom(asset.localToken, msg.sender, address(this), amount);
        // Handle fee-on-transfer tokens
        amount = _balanceOf(asset.localToken, address(this)) - balanceBefore;

        if (asset.isHomeChain) {
            // HOME CHAIN: Tokens are now locked in this contract
            // Nothing more to do - tokens stay escrowed
        } else {
            // REMOTE CHAIN: Burn the wrapped tokens we just received
            // Uses TIP-20 burn(amount) which burns from msg.sender (this contract)
            ITIP20Burnable(asset.localToken).burn(amount);
        }

        transferNonce = nonce++;

        messageHash = _computeMessageHash(
            chainId, destinationChainId, asset.homeChainId, asset.homeToken, recipient, amount, transferNonce
        );

        // Send message hash to MessageBridge for cross-chain attestation
        messageBridge.send(messageHash, destinationChainId);

        emit TokensBridged(messageHash, assetId, transferNonce, msg.sender, recipient, amount, destinationChainId);
    }

    /// @inheritdoc ITokenBridge
    function claimTokens(
        bytes32 assetId,
        address recipient,
        uint256 amount,
        uint256 transferNonce,
        uint64 originChainId
    ) external whenNotPaused {
        Asset memory asset = _assets[assetId];
        if (asset.localToken == address(0)) revert AssetNotRegistered(assetId);

        bytes32 messageHash = _computeMessageHash(
            originChainId, chainId, asset.homeChainId, asset.homeToken, recipient, amount, transferNonce
        );

        // Verify message was attested by validators via MessageBridge
        // sender = address(this) because TokenBridge has same address on all chains
        if (messageBridge.receivedAt(originChainId, address(this), messageHash) == 0) {
            revert MessageNotReceived();
        }

        // Prevent double-claim
        if (_claimed[originChainId][messageHash]) revert AlreadyClaimed();
        _claimed[originChainId][messageHash] = true;

        if (asset.isHomeChain) {
            // HOME CHAIN: Unlock from escrow
            _safeTransfer(asset.localToken, recipient, amount);
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
            originChainId, destinationChainId, homeChainId, homeToken, recipient, amount, transferNonce
        );
    }

    /// @inheritdoc ITokenBridge
    function computeAssetId(uint64 homeChainId, address homeToken) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(homeChainId, homeToken));
    }

    /// @inheritdoc ITokenBridge
    function getAsset(bytes32 assetId) external view returns (Asset memory) {
        return _assets[assetId];
    }

    /// @inheritdoc ITokenBridge
    function isClaimed(uint64 originChainId, bytes32 messageHash) external view returns (bool) {
        return _claimed[originChainId][messageHash];
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
        if (assetId != keccak256(abi.encodePacked(homeChainId, homeToken))) {
            revert AssetIdMismatch();
        }

        _assets[assetId] = Asset({
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
        _assets[assetId].active = active;
        emit AssetActiveChanged(assetId, active);
    }

    /// @inheritdoc ITokenBridge
    function pause() external onlyOwner {
        paused = true;
    }

    /// @inheritdoc ITokenBridge
    function unpause() external onlyOwner {
        paused = false;
    }

    /// @inheritdoc ITokenBridge
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid owner");
        owner = newOwner;
    }

    //=============================================================
    //                      INTERNAL FUNCTIONS
    //=============================================================

    /// @notice Compute message hash for a transfer
    function _computeMessageHash(
        uint64 originChainId,
        uint64 destinationChainId,
        uint64 homeChainId,
        address homeToken,
        address recipient,
        uint256 amount,
        uint256 transferNonce
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "TOKEN_BRIDGE_V1",
                originChainId,
                destinationChainId,
                homeChainId,
                homeToken,
                recipient,
                amount,
                transferNonce
            )
        );
    }

    /// @notice Get token balance
    function _balanceOf(address token, address account) internal view returns (uint256) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", account));
        require(success && data.length >= 32, "Balance query failed");
        return abi.decode(data, (uint256));
    }

    /// @notice Safe transferFrom that handles non-standard tokens
    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount));
        if (!success || (data.length > 0 && !abi.decode(data, (bool)))) {
            revert TransferFailed();
        }
    }

    /// @notice Safe transfer that handles non-standard tokens
    function _safeTransfer(address token, address to, uint256 amount) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        if (!success || (data.length > 0 && !abi.decode(data, (bool)))) {
            revert TransferFailed();
        }
    }
}
