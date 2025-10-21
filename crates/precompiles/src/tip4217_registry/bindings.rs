use alloy::sol;

sol! {
    /// TIP4217Registry interface for managing currency definitions and metadata.
    ///
    /// TIP4217 extends the ISO 4217 standard for currency codes to support:
    /// - Registration of new currency definitions
    /// - Metadata management for supported currencies  
    /// - Currency validation and lookup services
    /// - Integration with token denomination systems
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface ITIP4217Registry {
        /// Currency information structure
        struct CurrencyInfo {
            string code;        // 3-letter currency code (e.g., "USD", "EUR")
            string name;        // Full currency name
            uint8 decimals;     // Number of decimal places
            bool active;        // Whether currency is active
            address admin;      // Currency admin address
        }

        /// Register a new currency
        /// @param code The 3-letter currency code
        /// @param name The full currency name
        /// @param decimals The number of decimal places
        /// @param admin The admin address for this currency
        function registerCurrency(
            string calldata code,
            string calldata name,
            uint8 decimals,
            address admin
        ) external;

        /// Update currency information
        /// @param code The currency code
        /// @param name The new currency name
        /// @param decimals The new decimal places
        function updateCurrency(
            string calldata code,
            string calldata name,
            uint8 decimals
        ) external;

        /// Activate or deactivate a currency
        /// @param code The currency code
        /// @param active The new active status
        function setCurrencyStatus(string calldata code, bool active) external;

        /// Get currency information
        /// @param code The currency code
        /// @return info The currency information
        function getCurrency(string calldata code) external view returns (CurrencyInfo memory info);

        /// Check if a currency is registered and active
        /// @param code The currency code
        /// @return valid Whether the currency is valid
        function isValidCurrency(string calldata code) external view returns (bool valid);

        /// Get the number of registered currencies
        /// @return count The total currency count
        function currencyCount() external view returns (uint256 count);

        /// Get currency code by index
        /// @param index The index
        /// @return code The currency code at that index
        function currencyByIndex(uint256 index) external view returns (string memory code);

        /// Transfer admin rights for a currency
        /// @param code The currency code
        /// @param newAdmin The new admin address
        function transferCurrencyAdmin(string calldata code, address newAdmin) external;

        // Events
        event CurrencyRegistered(
            string indexed code,
            string name,
            uint8 decimals,
            address indexed admin
        );
        event CurrencyUpdated(string indexed code, string name, uint8 decimals);
        event CurrencyStatusChanged(string indexed code, bool active);
        event CurrencyAdminTransferred(
            string indexed code,
            address indexed oldAdmin,
            address indexed newAdmin
        );

        // Errors
        error CurrencyAlreadyExists();
        error CurrencyDoesNotExist();
        error InvalidCurrencyCode();
        error Unauthorized();
        error CurrencyInactive();
    }
}