use alloy::sol;

sol! {
    /// TipAccountRegistrar interface for managing account registration and metadata.
    ///
    /// The account registrar provides services for:
    /// - Account registration and validation
    /// - Metadata management for registered accounts
    /// - Account status tracking and updates
    /// - Integration with other Tempo protocol components
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITipAccountRegistrar {
        /// Account registration status
        enum AccountStatus {
            Unregistered,
            Active,
            Suspended,
            Banned
        }

        /// Account information structure
        struct AccountInfo {
            address account;
            AccountStatus status;
            string metadata;
            uint256 registrationTime;
            address registrar;
        }

        /// Register a new account
        /// @param account The account address to register
        /// @param metadata Initial metadata for the account
        function registerAccount(address account, string calldata metadata) external;

        /// Update account metadata
        /// @param account The account address
        /// @param metadata The new metadata
        function updateAccountMetadata(address account, string calldata metadata) external;

        /// Update account status
        /// @param account The account address
        /// @param status The new status
        function updateAccountStatus(address account, AccountStatus status) external;

        /// Get account information
        /// @param account The account address
        /// @return info The account information
        function getAccountInfo(address account) external view returns (AccountInfo memory info);

        /// Check if an account is registered and active
        /// @param account The account address
        /// @return active Whether the account is active
        function isAccountActive(address account) external view returns (bool active);

        /// Get the total number of registered accounts
        /// @return count The total account count
        function accountCount() external view returns (uint256 count);

        /// Get account address by registration index
        /// @param index The registration index
        /// @return account The account address
        function accountByIndex(uint256 index) external view returns (address account);

        /// Batch register multiple accounts
        /// @param accounts The account addresses to register
        /// @param metadata The metadata for each account
        function batchRegisterAccounts(
            address[] calldata accounts,
            string[] calldata metadata
        ) external;

        // Events
        event AccountRegistered(
            address indexed account,
            address indexed registrar,
            string metadata,
            uint256 timestamp
        );
        event AccountMetadataUpdated(address indexed account, string metadata);
        event AccountStatusUpdated(
            address indexed account,
            AccountStatus oldStatus,
            AccountStatus newStatus
        );

        // Errors
        error AccountAlreadyRegistered();
        error AccountNotRegistered();
        error Unauthorized();
        error InvalidStatus();
        error InvalidMetadata();
        error ArrayLengthMismatch();
    }
}

