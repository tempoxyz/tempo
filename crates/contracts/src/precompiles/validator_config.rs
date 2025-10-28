use alloy::sol;

pub use IValidatorConfig::IValidatorConfigErrors as ValidatorConfigError;

sol! {
    /// Validator config interface for managing consensus validators.
    ///
    /// This precompile manages the set of validators that participate in consensus.
    /// Validators can update their own information, rotate their identity to a new address,
    /// and the owner can manage validator status.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc)]
    interface IValidatorConfig {
        /// Validator information
        struct Validator {
            bytes32 key;
            bool active;
            uint64 index;
            address validatorAddress;
            string inboundAddress;
            string outboundAddress;
        }

        /// Get the complete set of validators
        /// @return validators Array of all validators with their information
        function getValidators() external view returns (Validator[] memory validators);

        /// Add a new validator (owner only)
        /// @param newValidatorAddress The address of the new validator
        /// @param key The validator's communication public key
        /// @param ipAddressOrDns The validator's IP address
        /// @param outboundAddress The validator's outbound address
        /// @param outboundPort The validator's outbound port
        function addValidator(address newValidatorAddress, bytes32 key, bool active, string calldata inboundAddress, string calldata outboundAddress) external;

        /// Update validator information (only validator)
        /// @param newValidatorAddress The new address for this validator
        /// @param key The validator's new communication public key
        /// @param ipAddressOrDns The validator's new IP address
        /// @param outboundAddress The validator's outbound address
        /// @param outboundPort The validator's outbound port
        function updateValidator(address newValidatorAddress, bytes32 key, string calldata ipAddressOrDns, string calldata outboundAddress, uint16 outboundPort) external;

        /// Change validator active status (owner only)
        /// @param validator The validator address
        /// @param active Whether the validator should be active
        function changeValidatorStatus(address validator, bool active) external;

        /// Get the owner of the precompile
        /// @return owner The owner address
        function owner() external view returns (address);

        /// Change owner
        /// @param newOwner The new owner address
        function changeOwner(address newOwner) external;

        // Errors
        error Unauthorized();
        error ValidatorAlreadyExists();
        error ValidatorNotFound();

        error NotHostPort(string field, string backtrace);
    }
}

impl ValidatorConfigError {
    /// Creates an error for unauthorized access.
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(IValidatorConfig::Unauthorized {})
    }

    /// Creates an error when validator already exists.
    pub const fn validator_already_exists() -> Self {
        Self::ValidatorAlreadyExists(IValidatorConfig::ValidatorAlreadyExists {})
    }

    /// Creates an error when validator is not found.
    pub const fn validator_not_found() -> Self {
        Self::ValidatorNotFound(IValidatorConfig::ValidatorNotFound {})
    }

    pub fn not_host_port(field: String, backtrace: String) -> Self {
        Self::NotHostPort(IValidatorConfig::NotHostPort { field, backtrace })
    }
}
