// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/**
 * @title Account Keychain Precompile Interface
 * @notice Interface for the Account Keychain precompile that manages authorized access keys
 * @dev This precompile is deployed at address `0xaAAAaaAA00000000000000000000000000000000`
 *
 * The Account Keychain allows accounts to authorize secondary keys (Access Keys) that can sign
 * transactions on behalf of the account. Access Keys can be scoped by:
 * - Expiry timestamp (when the key becomes invalid)
 * - Per-TIP20 token spending limits (one-time or periodic) that deplete as the key spends
 * - Call scopes restricting which contracts/selectors the key may call (T3+)
 *
 * Only the Root Key can call authorizeKey, revokeKey, updateSpendingLimit, setAllowedCalls,
 * and removeAllowedCalls.
 * This restriction is enforced by the protocol at transaction validation time.
 * Access Keys attempting to call these functions will fail with UnauthorizedCaller.
 *
 * This design is inspired by session key and access control patterns,
 * enshrined at the protocol level for better UX and reduced gas costs.
 */
interface IAccountKeychain {

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Signature type enumeration
    enum SignatureType {
        Secp256k1,
        P256,
        WebAuthn
    }

    /// @notice Legacy token spending limit structure used before T3
    struct LegacyTokenLimit {
        address token; // TIP20 token address
        uint256 amount; // Spending limit amount
    }

    /// @notice Token spending limit structure
    struct TokenLimit {
        address token; // TIP20 token address
        uint256 amount; // Spending limit amount
        uint64 period; // Period duration in seconds (0 = one-time limit, >0 = periodic reset)
    }

    /// @notice Selector-level recipient rule
    struct SelectorRule {
        bytes4 selector; // 4-byte function selector
        address[] recipients; // Empty means no recipient restriction for this selector
    }

    /// @notice Per-target call scope
    struct CallScope {
        address target; // Target contract address
        SelectorRule[] selectorRules; // Empty means any selector is allowed for this target
    }

    /// @notice Optional access-key restrictions configured at authorization time
    struct KeyRestrictions {
        uint64 expiry; // Unix timestamp when key expires (use type(uint64).max for never)
        bool enforceLimits; // Whether spending limits are enforced for this key
        TokenLimit[] limits; // Token spending limits
        bool allowAnyCalls; // true = unrestricted calls (allowedCalls must be empty)
        CallScope[] allowedCalls; // Call scopes when allowAnyCalls is false
    }

    /// @notice Key information structure
    struct KeyInfo {
        SignatureType signatureType; // Signature type of the key
        address keyId; // The key identifier (address)
        uint64 expiry; // Unix timestamp when key expires (use type(uint64).max for never)
        bool enforceLimits; // Whether spending limits are enforced for this key
        bool isRevoked; // Whether this key has been revoked
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a new key is authorized
    event KeyAuthorized(
        address indexed account, address indexed publicKey, uint8 signatureType, uint64 expiry
    );

    /// @notice Emitted when a key is revoked
    event KeyRevoked(address indexed account, address indexed publicKey);

    /// @notice Emitted when a spending limit is updated
    event SpendingLimitUpdated(
        address indexed account, address indexed publicKey, address indexed token, uint256 newLimit
    );

    /// @notice Emitted when an access key spends tokens
    event AccessKeySpend(
        address indexed account,
        address indexed publicKey,
        address indexed token,
        uint256 amount,
        uint256 remainingLimit
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

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

    /*//////////////////////////////////////////////////////////////
                        MANAGEMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Legacy authorize-key entrypoint used before T3
     * @param keyId The key identifier (address) to authorize
     * @param signatureType Signature type of the key
     * @param expiry Unix timestamp when key expires
     * @param enforceLimits Whether to enforce spending limits for this key
     * @param limits Initial spending limits for tokens
     */
    function authorizeKey(
        address keyId,
        SignatureType signatureType,
        uint64 expiry,
        bool enforceLimits,
        LegacyTokenLimit[] calldata limits
    )
        external;

    /**
     * @notice Authorize a new key for the caller's account with T3 extensions
     * @param keyId The key identifier (address derived from public key)
     * @param signatureType Signature type of the key
     * @param config Access-key expiry and optional limits / call restrictions
     */
    function authorizeKey(
        address keyId,
        SignatureType signatureType,
        KeyRestrictions calldata config
    )
        external;

    /**
     * @notice Revoke an authorized key
     * @param keyId The key ID to revoke
     */
    function revokeKey(address keyId) external;

    /**
     * @notice Update spending limit for a specific token on an authorized key
     * @param keyId The key ID to update
     * @param token The token address
     * @param newLimit The new spending limit
     */
    function updateSpendingLimit(address keyId, address token, uint256 newLimit) external;

    /**
     * @notice Set or replace allowed calls for one or more key+target pairs
     * @param keyId The key ID to configure
     * @param scopes The call scopes to set
     */
    function setAllowedCalls(address keyId, CallScope[] calldata scopes) external;

    /**
     * @notice Remove any configured call scope for a key+target pair
     * @param keyId The key ID to update
     * @param target The target contract to remove from allowed calls
     */
    function removeAllowedCalls(address keyId, address target) external;

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get key information
     * @param account The account address
     * @param keyId The key ID
     * @return Key information (returns default values if key doesn't exist)
     */
    function getKey(address account, address keyId) external view returns (KeyInfo memory);

    /**
     * @notice Get remaining spending limit for a key-token pair (legacy)
     * @param account The account address
     * @param keyId The key ID
     * @param token The token address
     * @return remaining Remaining spending amount
     */
    function getRemainingLimit(
        address account,
        address keyId,
        address token
    )
        external
        view
        returns (uint256 remaining);

    /**
     * @notice Get remaining spending limit together with the active period end
     * @param account The account address
     * @param keyId The key ID
     * @param token The token address
     * @return remaining Remaining spending amount
     * @return periodEnd Period end timestamp for periodic limits (0 for one-time)
     */
    function getRemainingLimitWithPeriod(
        address account,
        address keyId,
        address token
    )
        external
        view
        returns (uint256 remaining, uint64 periodEnd);

    /**
     * @notice Returns whether an account key is call-scoped and the configured call scopes
     * @param account The account address
     * @param keyId The key ID
     * @return isScoped Whether the key is call-scoped
     * @return scopes The configured call scopes
     */
    function getAllowedCalls(
        address account,
        address keyId
    )
        external
        view
        returns (bool isScoped, CallScope[] memory scopes);

    /**
     * @notice Get the transaction key used in the current transaction
     * @return The key ID that signed the transaction
     */
    function getTransactionKey() external view returns (address);

}
