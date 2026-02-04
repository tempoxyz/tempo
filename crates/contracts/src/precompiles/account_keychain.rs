pub use IAccountKeychain::{
    IAccountKeychainErrors as AccountKeychainError, IAccountKeychainEvents as AccountKeychainEvent,
};

crate::sol! {
    /// Account Keychain interface for managing authorized keys
    ///
    /// This precompile allows accounts to authorize secondary keys with:
    /// - Different signature types (secp256k1, P256, WebAuthn)
    /// - Expiry times for key rotation
    /// - Per-token spending limits for security
    /// - Periodic spending limits that reset automatically (TIP-1011)
    /// - Destination address scoping (TIP-1011)
    ///
    /// Only the main account key can authorize/revoke keys, while secondary keys
    /// can be used for regular transactions within their spending limits.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
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

        /// Token spending limit with period info (TIP-1011)
        struct TokenLimitInfo {
            address token;
            uint256 remaining;     // Remaining allowance in current period
            uint256 limit;         // Per-period limit (or lifetime limit if period == 0)
            uint64 period;         // Period duration in seconds (0 = one-time limit)
            uint64 periodEnd;      // Timestamp when current period expires
        }

        /// Key information structure
        struct KeyInfo {
            SignatureType signatureType;
            address keyId;
            uint64 expiry;
            bool enforceLimits;
            bool isRevoked;
        }

        /// Emitted when a new key is authorized
        event KeyAuthorized(address indexed account, address indexed publicKey, uint8 signatureType, uint64 expiry);

        /// Emitted when a key is revoked
        event KeyRevoked(address indexed account, address indexed publicKey);

        /// Emitted when a spending limit is updated
        event SpendingLimitUpdated(address indexed account, address indexed publicKey, address indexed token, uint256 newLimit);

        /// Emitted when a periodic limit is set (TIP-1011)
        event PeriodicLimitSet(address indexed account, address indexed publicKey, address indexed token, uint256 limit, uint64 period);

        /// Emitted when allowed destinations are updated (TIP-1011)
        event AllowedDestinationsUpdated(address indexed account, address indexed publicKey, address[] destinations);

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

        /// Set a periodic spending limit for a key-token pair (TIP-1011, T2+)
        /// @param keyId The key identifier
        /// @param token The token address
        /// @param limit The per-period spending limit
        /// @param period The period duration in seconds
        function setPeriodicLimit(
            address keyId,
            address token,
            uint256 limit,
            uint64 period
        ) external;

        /// Set allowed destinations for a key (TIP-1011, T2+)
        /// @param keyId The key identifier
        /// @param destinations Array of allowed destination addresses (empty = unrestricted)
        function setAllowedDestinations(
            address keyId,
            address[] calldata destinations
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

        /// Get spending limit info including period data (TIP-1011, T2+)
        /// @param account The account address
        /// @param keyId The key identifier
        /// @param token The token address
        /// @return info TokenLimitInfo with remaining, limit, period, and periodEnd
        function getLimitInfo(
            address account,
            address keyId,
            address token
        ) external view returns (TokenLimitInfo memory info);

        /// Get allowed destinations for a key (TIP-1011, T2+)
        /// @param account The account address
        /// @param keyId The key identifier
        /// @return destinations Array of allowed addresses (empty = unrestricted)
        function getAllowedDestinations(
            address account,
            address keyId
        ) external view returns (address[] memory destinations);

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
        error KeyAlreadyRevoked();
        error SignatureTypeMismatch(uint8 expected, uint8 actual);
        error DestinationNotAllowed(address destination);
        error InvalidPeriod();
    }
}

impl AccountKeychainError {
    /// Creates an error for signature type mismatch.
    pub const fn signature_type_mismatch(expected: u8, actual: u8) -> Self {
        Self::SignatureTypeMismatch(IAccountKeychain::SignatureTypeMismatch { expected, actual })
    }

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

    /// Creates an error for when a key_id has already been revoked.
    /// Once revoked, a key_id can never be re-authorized for the same account.
    /// This prevents replay attacks where a revoked key's authorization is reused.
    pub const fn key_already_revoked() -> Self {
        Self::KeyAlreadyRevoked(IAccountKeychain::KeyAlreadyRevoked {})
    }

    /// Creates an error for destination not allowed (TIP-1011).
    pub const fn destination_not_allowed(destination: alloy_primitives::Address) -> Self {
        Self::DestinationNotAllowed(IAccountKeychain::DestinationNotAllowed { destination })
    }

    /// Creates an error for invalid period (TIP-1011).
    pub const fn invalid_period() -> Self {
        Self::InvalidPeriod(IAccountKeychain::InvalidPeriod {})
    }
}
