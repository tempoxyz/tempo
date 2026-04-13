use alloc::string::String;

pub use IValidatorConfig::IValidatorConfigErrors as ValidatorConfigError;

crate::sol! {
    /// Validator config interface for managing consensus validators.
    ///
    /// This precompile manages the set of validators that participate in consensus.
    /// Validators can update their own information, rotate their identity to a new address,
    /// and the owner can manage validator status.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IValidatorConfig {
        /// Validator information
        struct Validator {
            bytes32 publicKey;
            bool active;
            uint64 index;
            address validatorAddress;
            /// Address where other validators can connect to this validator.
            /// Format: `<hostname|ip>:<port>`
            string inboundAddress;
            /// IP address for firewall whitelisting by other validators.
            /// Format: `<ip>:<port>` - must be an IP address, not a hostname.
            string outboundAddress;
        }

        /// Get the complete set of validators
        /// @return validators Array of all validators with their information
        function getValidators() external view returns (Validator[] memory validators);

        /// Add a new validator (owner only)
        /// @param newValidatorAddress The address of the new validator
        /// @param publicKey The validator's communication public publicKey
        /// @param inboundAddress The validator's inbound address `<hostname|ip>:<port>` for incoming connections
        /// @param outboundAddress The validator's outbound IP address `<ip>:<port>` for firewall whitelisting (IP only, no hostnames)
        function addValidator(address newValidatorAddress, bytes32 publicKey, bool active, string calldata inboundAddress, string calldata outboundAddress) external;

        /// Update validator information (only validator)
        /// @param newValidatorAddress The new address for this validator
        /// @param publicKey The validator's new communication public publicKey
        /// @param inboundAddress The validator's inbound address `<hostname|ip>:<port>` for incoming connections
        /// @param outboundAddress The validator's outbound IP address `<ip>:<port>` for firewall whitelisting (IP only, no hostnames)
        function updateValidator(address newValidatorAddress, bytes32 publicKey, string calldata inboundAddress, string calldata outboundAddress) external;

        /// Change validator active status (owner only)
        /// @param validator The validator address
        /// @param active Whether the validator should be active
        /// @dev Deprecated: Use changeValidatorStatusByIndex to prevent front-running attacks
        function changeValidatorStatus(address validator, bool active) external;

        /// Change validator active status by index (owner only) - T1+
        /// @param index The validator index in the validators array
        /// @param active Whether the validator should be active
        /// @dev Added in T1 to prevent front-running attacks where a validator changes its address
        function changeValidatorStatusByIndex(uint64 index, bool active) external;

        /// Get the owner of the precompile
        /// @return owner The owner address
        function owner() external view returns (address);

        /// Change owner
        /// @param newOwner The new owner address
        function changeOwner(address newOwner) external;

        /// Get the epoch at which a fresh DKG ceremony will be triggered
        ///
        /// @return The epoch number. The fresh DKG ceremony runs in epoch N, and epoch N+1 uses the new DKG polynomial.
        function getNextFullDkgCeremony() external view returns (uint64);

        /// Set the epoch at which a fresh DKG ceremony will be triggered (owner only)
        ///
        /// @param epoch The epoch in which to run the fresh DKG ceremony. Epoch N runs the ceremony, and epoch N+1 uses the new DKG polynomial.
        function setNextFullDkgCeremony(uint64 epoch) external;

        /// Get validator address at a specific index in the validators array
        /// @param index The index in the validators array
        /// @return The validator address at the given index
        function validatorsArray(uint256 index) external view returns (address);

        /// Get validator information by address
        /// @param validator The validator address to look up
        /// @return The validator struct for the given address
        function validators(address validator) external view returns (Validator memory);

        /// Get the total number of validators
        /// @return The count of validators
        function validatorCount() external view returns (uint64);

        // Errors
        error Unauthorized();
        error ValidatorAlreadyExists();
        error ValidatorNotFound();
        error InvalidPublicKey();

        error NotHostPort(string field, string input, string backtrace);
        error NotIpPort(string field, string input, string backtrace);
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

    /// Creates an error when public key is invalid (zero).
    pub const fn invalid_public_key() -> Self {
        Self::InvalidPublicKey(IValidatorConfig::InvalidPublicKey {})
    }

    pub fn not_host_port(field: String, input: String, backtrace: String) -> Self {
        Self::NotHostPort(IValidatorConfig::NotHostPort {
            field,
            input,
            backtrace,
        })
    }

    pub fn not_ip_port(field: String, input: String, backtrace: String) -> Self {
        Self::NotIpPort(IValidatorConfig::NotIpPort {
            field,
            input,
            backtrace,
        })
    }
}
