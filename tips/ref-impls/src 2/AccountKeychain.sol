// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.28 <0.9.0;

import { IAccountKeychain } from "./interfaces/IAccountKeychain.sol";

/// @title AccountKeychain - Access Key Manager Precompile
/// @notice Manages authorized Access Keys for accounts, enabling Root Keys to provision
///         scoped secondary keys with expiry timestamps and per-TIP20 token spending limits.
/// @dev This precompile is deployed at address `0xaAAAaaAA00000000000000000000000000000000`
///
/// Storage Layout:
/// ```solidity
/// contract AccountKeychain {
///     mapping(address => mapping(address => AuthorizedKey)) private keys;     // slot 0
///     mapping(bytes32 => mapping(address => uint256)) private spendingLimits; // slot 1
/// }
/// ```
///
/// Transient Storage:
/// - transactionKey: The key ID that signed the current transaction (set by protocol)
///
/// The keys mapping stores packed AuthorizedKey structs:
/// - byte 0: signature_type (uint8)
/// - bytes 1-8: expiry (uint64, little-endian)
/// - byte 9: enforce_limits (bool)
/// - byte 10: is_revoked (bool)
contract AccountKeychain is IAccountKeychain {

    // ============ Storage ============

    /// @dev Internal struct for key storage
    struct AuthorizedKey {
        uint8 signatureType;
        uint64 expiry;
        bool enforceLimits;
        bool isRevoked;
    }

    /// @dev Mapping from account -> keyId -> AuthorizedKey
    mapping(address => mapping(address => AuthorizedKey)) private keys;

    /// @dev Mapping from keccak256(account || keyId) -> token -> spending limit
    mapping(bytes32 => mapping(address => uint256)) private spendingLimits;

    /// @dev Transient storage for the transaction key
    /// Set by the protocol during transaction validation to indicate which key signed the tx
    address private transient _transactionKey;

    // ============ Internal Helpers ============

    /// @dev Compute the hash key for spending limits mapping from account and keyId
    function _spendingLimitKey(address account, address keyId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(account, keyId));
    }

    /// @dev Check that caller is using the root key (transaction key == 0)
    function _requireRootKey() internal view {
        if (_transactionKey != address(0)) {
            revert UnauthorizedCaller();
        }
    }

    // ============ Management Functions ============

    /// @inheritdoc IAccountKeychain
    function authorizeKey(
        address keyId,
        SignatureType signatureType,
        uint64 expiry,
        bool enforceLimits,
        TokenLimit[] calldata limits
    ) external {
        // Check that the transaction key for this transaction is zero (main key)
        _requireRootKey();

        // Validate inputs
        if (keyId == address(0)) {
            revert ZeroPublicKey();
        }

        // Expiry must be in the future (also catches expiry == 0 which means "key doesn't exist")
        if (expiry <= block.timestamp) {
            revert ExpiryInPast();
        }

        // Check if key already exists (key exists if expiry > 0)
        AuthorizedKey storage existingKey = keys[msg.sender][keyId];
        if (existingKey.expiry > 0) {
            revert KeyAlreadyExists();
        }

        // Check if this key was previously revoked - prevents replay attacks
        if (existingKey.isRevoked) {
            revert KeyAlreadyRevoked();
        }

        // Convert SignatureType enum to uint8 for storage (enums are uint8 under the hood)
        uint8 sigType = uint8(signatureType);
        if (sigType > 2) {
            revert InvalidSignatureType();
        }

        // Store the new key
        keys[msg.sender][keyId] = AuthorizedKey({
            signatureType: sigType, expiry: expiry, enforceLimits: enforceLimits, isRevoked: false
        });

        // Set initial spending limits (only if enforce_limits is true)
        if (enforceLimits) {
            bytes32 limitKey = _spendingLimitKey(msg.sender, keyId);
            for (uint256 i = 0; i < limits.length; i++) {
                spendingLimits[limitKey][limits[i].token] = limits[i].amount;
            }
        }

        // Emit event
        emit KeyAuthorized(msg.sender, keyId, sigType, expiry);
    }

    /// @inheritdoc IAccountKeychain
    function revokeKey(address keyId) external {
        _requireRootKey();

        AuthorizedKey storage key = keys[msg.sender][keyId];

        // Key exists if expiry > 0
        if (key.expiry == 0) {
            revert KeyNotFound();
        }

        // Mark the key as revoked - this prevents replay attacks by ensuring
        // the same key_id can never be re-authorized for this account.
        // We keep isRevoked=true but clear other fields.
        keys[msg.sender][keyId] =
            AuthorizedKey({ signatureType: 0, expiry: 0, enforceLimits: false, isRevoked: true });

        // Note: We don't clear spending limits here - they become inaccessible

        // Emit event
        emit KeyRevoked(msg.sender, keyId);
    }

    /// @inheritdoc IAccountKeychain
    function updateSpendingLimit(address keyId, address token, uint256 newLimit) external {
        _requireRootKey();

        AuthorizedKey storage key = keys[msg.sender][keyId];

        // Check if key has been revoked
        if (key.isRevoked) {
            revert KeyAlreadyRevoked();
        }

        // Key exists if expiry > 0
        if (key.expiry == 0) {
            revert KeyNotFound();
        }

        // Check if key has expired
        if (block.timestamp >= key.expiry) {
            revert KeyExpired();
        }

        // If this key had unlimited spending (enforceLimits=false), enable limits now
        if (!key.enforceLimits) {
            key.enforceLimits = true;
        }

        // Update the spending limit
        bytes32 limitKey = _spendingLimitKey(msg.sender, keyId);
        spendingLimits[limitKey][token] = newLimit;

        // Emit event
        emit SpendingLimitUpdated(msg.sender, keyId, token, newLimit);
    }

    // ============ View Functions ============

    /// @inheritdoc IAccountKeychain
    function getKey(address account, address keyId) external view returns (KeyInfo memory) {
        AuthorizedKey storage key = keys[account][keyId];

        // Key doesn't exist if expiry == 0, or key has been revoked
        if (key.expiry == 0 || key.isRevoked) {
            return KeyInfo({
                signatureType: SignatureType.Secp256k1,
                keyId: address(0),
                expiry: 0,
                enforceLimits: false,
                isRevoked: key.isRevoked
            });
        }

        // Convert uint8 signature_type to SignatureType enum
        SignatureType sigType;
        if (key.signatureType == 0) {
            sigType = SignatureType.Secp256k1;
        } else if (key.signatureType == 1) {
            sigType = SignatureType.P256;
        } else if (key.signatureType == 2) {
            sigType = SignatureType.WebAuthn;
        } else {
            sigType = SignatureType.Secp256k1; // Default fallback
        }

        return KeyInfo({
            signatureType: sigType,
            keyId: keyId,
            expiry: key.expiry,
            enforceLimits: key.enforceLimits,
            isRevoked: key.isRevoked
        });
    }

    /// @inheritdoc IAccountKeychain
    function getRemainingLimit(address account, address keyId, address token)
        external
        view
        returns (uint256)
    {
        bytes32 limitKey = _spendingLimitKey(account, keyId);
        return spendingLimits[limitKey][token];
    }

    /// @inheritdoc IAccountKeychain
    function getTransactionKey() external view returns (address) {
        return _transactionKey;
    }

    // ============ Internal Protocol Functions ============

    /// @notice Internal function to set the transaction key (called during transaction validation)
    /// @dev SECURITY CRITICAL: This must be called by the transaction validation logic
    ///      BEFORE the transaction is executed, to store which key authorized the transaction.
    ///      - If keyId is address(0) (main key), this should store address(0)
    ///      - If keyId is a specific key address, this should store that key
    ///
    ///      This creates a secure channel between validation and the precompile to ensure
    ///      only the main key can authorize/revoke other keys.
    ///      Uses transient storage, so the key is automatically cleared after the transaction.
    /// @param keyId The key ID that signed the transaction
    function _setTransactionKey(address keyId) internal {
        _transactionKey = keyId;
    }

    /// @notice Internal function to verify and update spending for a token transfer
    /// @dev This would be called by the protocol during TIP20 transfers to enforce spending limits
    /// @param account The account performing the transfer
    /// @param keyId The key ID that signed the transaction
    /// @param token The token being transferred
    /// @param amount The amount being transferred
    function _verifyAndUpdateSpending(address account, address keyId, address token, uint256 amount)
        internal
    {
        // If using main key (zero address), no spending limits apply
        if (keyId == address(0)) {
            return;
        }

        AuthorizedKey storage key = keys[account][keyId];

        // Check if key has been revoked
        if (key.isRevoked) {
            revert KeyAlreadyRevoked();
        }

        // Key exists if expiry > 0
        if (key.expiry == 0) {
            revert KeyNotFound();
        }

        // If enforceLimits is false, this key has unlimited spending
        if (!key.enforceLimits) {
            return;
        }

        // Check and update spending limit
        bytes32 limitKey = _spendingLimitKey(account, keyId);
        uint256 remaining = spendingLimits[limitKey][token];

        if (amount > remaining) {
            revert SpendingLimitExceeded();
        }

        // Update remaining limit (safe due to above check)
        unchecked {
            spendingLimits[limitKey][token] = remaining - amount;
        }
    }

}
