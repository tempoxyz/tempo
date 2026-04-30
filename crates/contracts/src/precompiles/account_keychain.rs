#![allow(clippy::too_many_arguments)]

pub use IAccountKeychain::{
    IAccountKeychainErrors as AccountKeychainError, IAccountKeychainEvents as AccountKeychainEvent,
    authorizeKey_0Call as legacyAuthorizeKeyCall, authorizeKey_1Call as authorizeKeyCall,
    getAllowedCallsReturn, getRemainingLimitWithPeriodCall,
    getRemainingLimitWithPeriodReturn as getRemainingLimitReturn,
};

crate::sol! {
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
    #[sol(abi)]
    interface IAccountKeychain {
        enum SignatureType {
            Secp256k1,
            P256,
            WebAuthn,
        }

        /// Legacy token spending limit structure used before T3.
        struct LegacyTokenLimit {
            address token;
            uint256 amount;
        }

        /// Token spending limit structure
        struct TokenLimit {
            address token;
            uint256 amount;
            uint64 period;
        }

        /// Selector-level recipient rule.
        struct SelectorRule {
            bytes4 selector;
            /// Empty means no recipient restriction for this selector.
            /// To block the selector entirely, remove the selector rule instead of passing `[]`.
            address[] recipients;
        }

        /// Per-target call scope.
        struct CallScope {
            address target;
            /// Empty means no selector restriction for this target.
            /// To block the target entirely, omit this scope from `allowedCalls` or call
            /// `removeAllowedCalls` for incremental updates.
            SelectorRule[] selectorRules;
        }

        /// Optional access-key restrictions configured at authorization time.
        struct KeyRestrictions {
            uint64 expiry;
            bool enforceLimits;
            TokenLimit[] limits;
            /// `true` means the key is unrestricted and `allowedCalls` must be empty.
            /// `false` means `allowedCalls` defines the full call scope (including deny-all with `[]`).
            bool allowAnyCalls;
            CallScope[] allowedCalls;
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

        event AccessKeySpend(
            address indexed account,
            address indexed publicKey,
            address indexed token,
            uint256 amount,
            uint256 remainingLimit
        );

        /// Legacy authorize-key entrypoint used before T3.
        function authorizeKey(
            address keyId,
            SignatureType signatureType,
            uint64 expiry,
            bool enforceLimits,
            LegacyTokenLimit[] calldata limits
        ) external;

        /// Authorize a new key for the caller's account with T3 extensions.
        /// @param keyId The key identifier (address derived from public key)
        /// @param signatureType 0: secp256k1, 1: P256, 2: WebAuthn
        /// @param config Access-key expiry and optional limits / call restrictions
        function authorizeKey(
            address keyId,
            SignatureType signatureType,
            KeyRestrictions calldata config
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

        /// Set or replace allowed calls for one or more key+target pairs.
        /// @dev Reverts if `scopes` is empty; use `removeAllowedCalls` to delete target scopes.
        /// @dev `scope.selectorRules = []` does NOT block the target; it allows any selector on that target.
        /// @dev To block the target entirely, call `removeAllowedCalls`. To block one selector,
        ///      omit that selector rule from `scope.selectorRules`.
        function setAllowedCalls(
            address keyId,
            CallScope[] calldata scopes
        ) external;

        /// Remove any configured call scope for a key+target pair.
        function removeAllowedCalls(address keyId, address target) external;

        /// Get key information
        /// @param account The account address
        /// @param publicKey The public key
        /// @return Key information
        function getKey(address account, address keyId) external view returns (KeyInfo memory);

        /// Get remaining spending limit using the legacy pre-T3 return shape.
        /// @param account The account address
        /// @param publicKey The public key
        /// @param token The token address
        function getRemainingLimit(
            address account,
            address keyId,
            address token
        ) external view returns (uint256 remaining);

        /// Get remaining spending limit together with the active period end.
        /// @param account The account address
        /// @param publicKey The public key
        /// @param token The token address
        /// @return remaining Remaining spending amount
        /// @return periodEnd Period end timestamp for periodic limits (0 for one-time)
        function getRemainingLimitWithPeriod(
            address account,
            address keyId,
            address token
        ) external view returns (uint256 remaining, uint64 periodEnd);

        /// Returns whether an account key is call-scoped and, if so, the configured call scopes.
        /// @dev `isScoped = false` means unrestricted. `isScoped = true && scopes.length == 0`
        ///      means scoped deny-all.
        /// @dev Missing, revoked, or expired access keys also return scoped deny-all so callers do
        ///      not observe stale persisted scope state.
        function getAllowedCalls(
            address account,
            address keyId
        ) external view returns (bool isScoped, CallScope[] memory scopes);

        /// Get the key used in the current transaction
        /// @return The keyId used in the current transaction
        function getTransactionKey() external view returns (address);

        // Errors
        error UnauthorizedCaller();
        error KeyAlreadyExists();
        error KeyNotFound();
        error KeyExpired();
        error SpendingLimitExceeded();
        error InvalidSpendingLimit();
        error InvalidSignatureType();
        error ZeroPublicKey();
        error ExpiryInPast();
        error KeyAlreadyRevoked();
        error SignatureTypeMismatch(uint8 expected, uint8 actual);
        error CallNotAllowed();
        error InvalidCallScope();
        error LegacyAuthorizeKeySelectorChanged(bytes4 newSelector);
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

    /// Creates an error for spending limits that exceed the TIP-20 u128 supply cap.
    pub const fn invalid_spending_limit() -> Self {
        Self::InvalidSpendingLimit(IAccountKeychain::InvalidSpendingLimit {})
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

    /// Creates an error for disallowed call attempts by scoped access keys.
    pub const fn call_not_allowed() -> Self {
        Self::CallNotAllowed(IAccountKeychain::CallNotAllowed {})
    }

    /// Creates an error for invalid scope configuration.
    pub const fn invalid_call_scope() -> Self {
        Self::InvalidCallScope(IAccountKeychain::InvalidCallScope {})
    }

    /// Creates an error for the legacy authorize-key selector being unavailable on T3+.
    pub fn legacy_authorize_key_selector_changed(new_selector: [u8; 4]) -> Self {
        Self::LegacyAuthorizeKeySelectorChanged(
            IAccountKeychain::LegacyAuthorizeKeySelectorChanged {
                newSelector: new_selector.into(),
            },
        )
    }
}
