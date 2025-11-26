pub use IAccountKeychain::{
    IAccountKeychainErrors as AccountKeychainError, IAccountKeychainEvents as AccountKeychainEvent,
};

use alloy::sol;

sol! {
    /// Account Keychain interface for managing authorized keys
    ///
    /// This precompile allows accounts to authorize secondary keys with:
    /// - Different signature types (secp256k1, P256, WebAuthn)
    /// - Expiry times for key rotation
    /// - Per-token spending limits for security
    ///
    /// Only the main account key can authorize/revoke keys, while secondary keys
    /// can be used for regular transactions within their spending limits.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface IAccountKeychain {
        enum SignatureType {
            Secp256k1,
            P256,
            WebAuthn,
        }

        /// Token spending limit structure
        struct TokenLimit {
            address token;
            uint256 amount;
        }

        /// Key information structure
        struct KeyInfo {
            SignatureType signatureType;
            address keyId;
            uint64 expiry;
            bool enforceLimits;
        }
        /// Emitted when a new key is authorized
        event KeyAuthorized(address indexed account, bytes32 indexed publicKey, uint8 signatureType, uint64 expiry);

        /// Emitted when a key is revoked
        event KeyRevoked(address indexed account, bytes32 indexed publicKey);

        /// Emitted when a spending limit is updated
        event SpendingLimitUpdated(address indexed account, bytes32 indexed publicKey, address indexed token, uint256 newLimit);

        /// Authorize a new key for the caller's account
        /// @param keyId The key identifier (address derived from public key)
        /// @param signatureType 0: secp256k1, 1: P256, 2: WebAuthn
        /// @param expiry Block timestamp when the key expires (u64::MAX for never expires)
        /// @param enforceLimits Whether to enforce spending limits for this key
        /// @param limits Initial spending limits for tokens (only used if enforceLimits is true)
        function authorizeKey(
            address keyId,
            SignatureType signatureType,
            uint64 expiry,
            bool enforceLimits,
            TokenLimit[] calldata limits
        ) external;

        /// Revoke an authorized key
        /// @param publicKey The public key to revoke
        function revokeKey(address keyId) external;

        /// Update spending limit for a key-token pair
        /// @param publicKey The public key
        /// @param token The token address
        /// @param newLimit The new spending limit
        function updateSpendingLimit(
            address keyId,
            address token,
            uint256 newLimit
        ) external;

        /// Get key information
        /// @param account The account address
        /// @param publicKey The public key
        /// @return Key information
        function getKey(address account, address keyId) external view returns (KeyInfo memory);

        /// Get remaining spending limit
        /// @param account The account address
        /// @param publicKey The public key
        /// @param token The token address
        /// @return Remaining spending amount
        function getRemainingLimit(
            address account,
            address keyId,
            address token
        ) external view returns (uint256);

        /// Get the key used in the current transaction
        /// @return The keyId used in the current transaction
        function getTransactionKey() external view returns (address);

        // Errors
        error UnauthorizedCaller();
        error KeyAlreadyExists();
        error KeyNotFound();
        error KeyExpired();
        error SpendingLimitExceeded();
        error InvalidSignatureType();
        error ZeroPublicKey();
        error ExpiryInPast();
    }
}

impl AccountKeychainError {
    /// Creates an error for unauthorized caller.
    pub const fn unauthorized_caller() -> Self {
        Self::UnauthorizedCaller(IAccountKeychain::UnauthorizedCaller {})
    }

    /// Creates an error for key already exists.
    pub const fn key_already_exists() -> Self {
        Self::KeyAlreadyExists(IAccountKeychain::KeyAlreadyExists {})
    }

    /// Creates an error for key not found.
    pub const fn key_not_found() -> Self {
        Self::KeyNotFound(IAccountKeychain::KeyNotFound {})
    }

    /// Creates an error for key expired.
    pub const fn key_expired() -> Self {
        Self::KeyExpired(IAccountKeychain::KeyExpired {})
    }

    /// Creates an error for spending limit exceeded.
    pub const fn spending_limit_exceeded() -> Self {
        Self::SpendingLimitExceeded(IAccountKeychain::SpendingLimitExceeded {})
    }

    /// Creates an error for invalid signature type.
    pub const fn invalid_signature_type() -> Self {
        Self::InvalidSignatureType(IAccountKeychain::InvalidSignatureType {})
    }

    /// Creates an error for zero public key.
    pub const fn zero_public_key() -> Self {
        Self::ZeroPublicKey(IAccountKeychain::ZeroPublicKey {})
    }

    /// Creates an error for expiry timestamp in the past.
    pub const fn expiry_in_past() -> Self {
        Self::ExpiryInPast(IAccountKeychain::ExpiryInPast {})
    }
}
