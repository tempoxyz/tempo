// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
 * @title Account Keychain Precompile Interface
 * @notice Interface for the Account Keychain precompile that manages authorized access keys
 * @dev This precompile is deployed at address `0xaAAAaaAA00000000000000000000000000000000`
 *
 * The Account Keychain allows accounts to authorize secondary keys (Access Keys) that can sign
 * transactions on behalf of the account. Access Keys can be scoped by:
 * - Expiry timestamp (when the key becomes invalid)
 * - Per-TIP20 token spending limits that deplete as the key spends
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
     * @notice Get the transaction key used in the current transaction
     * @dev Returns address(0) if the Root Key is being used
     * @return The key ID that signed the transaction
     */
    function getTransactionKey() external view returns (address);

}
