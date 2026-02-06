// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/**
 * @title Account Keychain Subaccount Extension Interface
 * @notice Extension to IAccountKeychain for TIP-1017 subaccount primitives
 * @dev These functions are added to the AccountKeychain precompile at
 *      address `0xaAAAaaAA00000000000000000000000000000000`
 */
interface IAccountKeychainSubaccounts {

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Auto-funding rule for a subaccount
    struct AutoFundRule {
        address token;         // TIP-20 token address
        uint256 minBalance;    // Trigger auto-fund when sub-balance drops below this
        uint256 refillAmount;  // Amount to transfer from root to subaccount
    }

    /// @notice Subaccount configuration for an access key
    struct SubaccountConfig {
        bool enabled;             // Whether this key operates as a subaccount
        AutoFundRule[] autoFund;  // Auto-funding rules
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when tokens are deposited into a subaccount
    event SubaccountDeposit(
        address indexed account,
        address indexed keyId,
        address indexed token,
        uint256 amount
    );

    /// @notice Emitted when tokens are withdrawn from a subaccount
    event SubaccountWithdrawal(
        address indexed account,
        address indexed keyId,
        address indexed token,
        uint256 amount
    );

    /// @notice Emitted when auto-funding is triggered
    event SubaccountAutoFunded(
        address indexed account,
        address indexed keyId,
        address indexed token,
        uint256 amount
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error SubaccountNotEnabled();
    error InsufficientSubBalance();
    error InsufficientRootBalance();
    error AutoFundFailed();

    /*//////////////////////////////////////////////////////////////
                        MANAGEMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit tokens from root account balance into a key's subaccount
     * @dev MUST only be called in transactions signed by the Root Key.
     *      Debits the root account's TIP-20 balance and credits the sub-balance.
     * @param keyId The access key identifier
     * @param token The TIP-20 token address
     * @param amount The amount to deposit
     */
    function depositToSubaccount(address keyId, address token, uint256 amount) external;

    /**
     * @notice Withdraw tokens from a key's subaccount back to the root account
     * @dev MUST only be called in transactions signed by the Root Key.
     *      Debits the sub-balance and credits the root account's TIP-20 balance.
     *      Can be called even after the key is revoked (to recover remaining funds).
     * @param keyId The access key identifier
     * @param token The TIP-20 token address
     * @param amount The amount to withdraw
     */
    function withdrawFromSubaccount(address keyId, address token, uint256 amount) external;

    /**
     * @notice Update auto-funding rules for a key's subaccount
     * @dev MUST only be called in transactions signed by the Root Key.
     *      Replaces all existing auto-fund rules for the key.
     * @param keyId The access key identifier
     * @param rules The new auto-funding rules
     */
    function updateAutoFundRules(address keyId, AutoFundRule[] calldata rules) external;

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Returns the deterministic subaccount address for a given account and key
     * @dev Derived as: address(uint160(uint256(keccak256(
     *      abi.encodePacked(bytes1(0xff), account, keyId)
     *      ))))
     * @param account The root account address
     * @param keyId The access key identifier
     * @return The deterministic subaccount address
     */
    function getSubaccountAddress(address account, address keyId)
        external pure returns (address);

    /**
     * @notice Returns the sub-balance of a token for a specific key's subaccount
     * @param account The root account address
     * @param keyId The access key identifier
     * @param token The TIP-20 token address
     * @return The sub-balance amount
     */
    function getSubBalance(address account, address keyId, address token)
        external view returns (uint256);

    /**
     * @notice Returns the subaccount configuration for a key
     * @param account The root account address
     * @param keyId The access key identifier
     * @return config The subaccount configuration
     */
    function getSubaccountConfig(address account, address keyId)
        external view returns (SubaccountConfig memory config);
}
