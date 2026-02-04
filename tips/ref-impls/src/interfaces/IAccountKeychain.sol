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
 * - Per-TIP20 token spending limits that deplete as the key spends
 * - Periodic spending limits that reset automatically (TIP-1011, T2+)
 * - Destination address scoping (TIP-1011, T2+)
 *
 * Only the Root Key can call authorizeKey, revokeKey, and updateSpendingLimit.
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

    /// @notice Token spending limit structure
    struct TokenLimit {
        address token; // TIP20 token address
        uint256 amount; // Spending limit amount
    }

    /// @notice Token spending limit info with period data (TIP-1011)
    struct TokenLimitInfo {
        address token;      // TIP20 token address
        uint256 remaining;  // Remaining allowance in current period
        uint256 limit;      // Per-period limit (or lifetime limit if period == 0)
        uint64 period;      // Period duration in seconds (0 = one-time limit)
        uint64 periodEnd;   // Timestamp when current period expires
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

    /// @notice Emitted when a periodic limit is set (TIP-1011, T2+)
    event PeriodicLimitSet(
        address indexed account, address indexed publicKey, address indexed token, uint256 limit, uint64 period
    );

    /// @notice Emitted when allowed destinations are updated (TIP-1011, T2+)
    event AllowedDestinationsUpdated(
        address indexed account, address indexed publicKey, address[] destinations
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error KeyAlreadyExists();
    error KeyNotFound();
    error KeyInactive();
    error KeyExpired();
    error KeyAlreadyRevoked();
    error SpendingLimitExceeded();
    error InvalidSignatureType();
    error ZeroPublicKey();
    error ExpiryInPast();
    error UnauthorizedCaller();
    error DestinationNotAllowed(address destination);
    error InvalidPeriod();

    /*//////////////////////////////////////////////////////////////
                        MANAGEMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Authorize a new key for the caller's account
     * @dev MUST only be called in transactions signed by the Root Key
     *      The protocol enforces this restriction by checking transactionKey[msg.sender]
     * @param keyId The key identifier (address) to authorize
     * @param signatureType Signature type of the key (0: Secp256k1, 1: P256, 2: WebAuthn)
     * @param expiry Unix timestamp when key expires (use type(uint64).max for never expires)
     * @param enforceLimits Whether to enforce spending limits for this key
     * @param limits Initial spending limits for tokens (only used if enforceLimits is true)
     */
    function authorizeKey(
        address keyId,
        SignatureType signatureType,
        uint64 expiry,
        bool enforceLimits,
        TokenLimit[] calldata limits
    ) external;

    /**
     * @notice Revoke an authorized key
     * @dev MUST only be called in transactions signed by the Root Key
     *      The protocol enforces this restriction by checking transactionKey[msg.sender]
     * @param keyId The key ID to revoke
     */
    function revokeKey(address keyId) external;

    /**
     * @notice Update spending limit for a specific token on an authorized key
     * @dev MUST only be called in transactions signed by the Root Key
     *      The protocol enforces this restriction by checking transactionKey[msg.sender]
     * @param keyId The key ID to update
     * @param token The token address
     * @param newLimit The new spending limit
     */
    function updateSpendingLimit(address keyId, address token, uint256 newLimit) external;

    /**
     * @notice Set a periodic spending limit for a key-token pair (TIP-1011, T2+)
     * @dev MUST only be called in transactions signed by the Root Key
     * @param keyId The key identifier
     * @param token The token address
     * @param limit The per-period spending limit
     * @param period The period duration in seconds (must be > 0)
     */
    function setPeriodicLimit(address keyId, address token, uint256 limit, uint64 period) external;

    /**
     * @notice Set allowed destinations for a key (TIP-1011, T2+)
     * @dev MUST only be called in transactions signed by the Root Key
     * @param keyId The key identifier
     * @param destinations Array of allowed destination addresses (empty = unrestricted)
     */
    function setAllowedDestinations(address keyId, address[] calldata destinations) external;

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
     * @notice Get remaining spending limit for a key-token pair
     * @param account The account address
     * @param keyId The key ID
     * @param token The token address
     * @return Remaining spending amount
     */
    function getRemainingLimit(address account, address keyId, address token)
        external
        view
        returns (uint256);

    /**
     * @notice Get spending limit info including period data (TIP-1011, T2+)
     * @param account The account address
     * @param keyId The key identifier
     * @param token The token address
     * @return info TokenLimitInfo with remaining, limit, period, and periodEnd
     */
    function getLimitInfo(address account, address keyId, address token)
        external
        view
        returns (TokenLimitInfo memory info);

    /**
     * @notice Get allowed destinations for a key (TIP-1011, T2+)
     * @param account The account address
     * @param keyId The key identifier
     * @return destinations Array of allowed addresses (empty = unrestricted)
     */
    function getAllowedDestinations(address account, address keyId)
        external
        view
        returns (address[] memory destinations);

    /**
     * @notice Get the transaction key used in the current transaction
     * @dev Returns address(0) if the Root Key is being used
     * @return The key ID that signed the transaction
     */
    function getTransactionKey() external view returns (address);

}
