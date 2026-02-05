// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.28 <0.9.0;

import { CrossChainAccount } from "./CrossChainAccount.sol";

/// @title CrossChainAccountFactory
/// @notice Factory for deploying Tempo smart wallets with deterministic CREATE2 addresses.
/// @dev Deploy this factory at the same address on all chains (via deterministic deployer)
///      to ensure wallet addresses are identical across all EVM chains.
///
/// Key design decisions (per Oracle audit):
/// 1. No proxy pattern - keeps initCode identical across chains
/// 2. Atomic deploy+initialize - prevents griefing/front-running
/// 3. Supports account index for multiple wallets per passkey
///
/// ## Cross-Chain Compatibility
/// This factory and the accounts it creates use pure Solidity signature verification
/// (via Solady's P256 and WebAuthn libraries) instead of chain-specific precompiles.
/// This ensures the same contract works identically on Tempo, Ethereum, Base, and any
/// other EVM chain without modification.
contract CrossChainAccountFactory {

    // ============ Events ============

    /// @notice Emitted when a new account is created
    event AccountCreated(
        address indexed account, bytes32 indexed passkeyX, bytes32 indexed passkeyY, uint256 index
    );

    // ============ Errors ============

    error InvalidPasskey();
    error DeploymentFailed();

    // ============ Constructor ============

    constructor() { }

    // ============ View Functions ============

    /// @notice Computes the counterfactual address for a wallet before deployment
    /// @param passkeyX The x-coordinate of the passkey public key (P-256)
    /// @param passkeyY The y-coordinate of the passkey public key (P-256)
    /// @param index Account index (0 for primary, >0 for additional wallets)
    /// @return The deterministic wallet address
    function getAddress(
        bytes32 passkeyX,
        bytes32 passkeyY,
        uint256 index
    )
        public
        view
        returns (address)
    {
        bytes32 salt = _computeSalt(passkeyX, passkeyY, index);
        bytes32 bytecodeHash = keccak256(type(CrossChainAccount).creationCode);
        return _computeCreate2Address(salt, bytecodeHash);
    }

    /// @notice Computes the counterfactual address for the primary wallet (index=0)
    /// @param passkeyX The x-coordinate of the passkey public key (P-256)
    /// @param passkeyY The y-coordinate of the passkey public key (P-256)
    /// @return The deterministic wallet address
    function getAddress(bytes32 passkeyX, bytes32 passkeyY) external view returns (address) {
        return getAddress(passkeyX, passkeyY, 0);
    }

    // ============ State-Changing Functions ============

    /// @notice Creates a new cross-chain account or returns existing one
    /// @dev Atomically deploys and initializes to prevent griefing
    /// @param passkeyX The x-coordinate of the passkey public key (P-256)
    /// @param passkeyY The y-coordinate of the passkey public key (P-256)
    /// @param index Account index (0 for primary, >0 for additional wallets)
    /// @return account The deployed or existing account
    function createAccount(
        bytes32 passkeyX,
        bytes32 passkeyY,
        uint256 index
    )
        public
        returns (CrossChainAccount account)
    {
        if (passkeyX == bytes32(0) || passkeyY == bytes32(0)) {
            revert InvalidPasskey();
        }

        address addr = getAddress(passkeyX, passkeyY, index);

        // Return existing account if already deployed
        if (addr.code.length > 0) {
            return CrossChainAccount(payable(addr));
        }

        bytes32 salt = _computeSalt(passkeyX, passkeyY, index);

        // Deploy via CREATE2
        account = new CrossChainAccount{ salt: salt }();

        if (address(account) == address(0)) {
            revert DeploymentFailed();
        }

        // Atomic initialization
        account.initialize(passkeyX, passkeyY);

        emit AccountCreated(address(account), passkeyX, passkeyY, index);
    }

    /// @notice Creates the primary account (index=0)
    /// @param passkeyX The x-coordinate of the passkey public key (P-256)
    /// @param passkeyY The y-coordinate of the passkey public key (P-256)
    /// @return The deployed or existing account
    function createAccount(bytes32 passkeyX, bytes32 passkeyY)
        external
        returns (CrossChainAccount)
    {
        return createAccount(passkeyX, passkeyY, 0);
    }

    // ============ Internal Functions ============

    /// @dev Computes the CREATE2 salt from passkey coordinates and index
    function _computeSalt(
        bytes32 passkeyX,
        bytes32 passkeyY,
        uint256 index
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(passkeyX, passkeyY, index));
    }

    /// @dev Computes the CREATE2 address
    function _computeCreate2Address(
        bytes32 salt,
        bytes32 bytecodeHash
    )
        internal
        view
        returns (address)
    {
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, bytecodeHash))
                )
            )
        );
    }

}
