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

        /// Pending validator information for two-step addition/rotation
        struct PendingValidator {
            bytes32 publicKey;
            bool active;
            address fromValidator;
            string inboundAddress;
            string outboundAddress;
        }

        /// Get the complete set of validators
        /// @return validators Array of all validators with their information
        function getValidators() external view returns (Validator[] memory validators);

        /// Get pending validator information
        /// @param pendingAddress The pending validator address to query
        /// @return pending The pending validator information
        function getPendingValidator(address pendingAddress) external view returns (PendingValidator memory pending);

        /// Add a new validator (owner only) - creates pending entry requiring acceptance
        /// @param newValidatorAddress The address of the new validator
        /// @param publicKey The validator's communication public publicKey
        /// @param inboundAddress The validator's inbound address `<hostname|ip>:<port>` for incoming connections
        /// @param outboundAddress The validator's outbound IP address `<ip>:<port>` for firewall whitelisting (IP only, no hostnames)
        function addValidator(address newValidatorAddress, bytes32 publicKey, bool active, string calldata inboundAddress, string calldata outboundAddress) external;

        /// Update validator information (only validator) - rotations create pending entry requiring acceptance
        /// @param newValidatorAddress The new address for this validator
        /// @param publicKey The validator's new communication public publicKey
        /// @param inboundAddress The validator's inbound address `<hostname|ip>:<port>` for incoming connections
        /// @param outboundAddress The validator's outbound IP address `<ip>:<port>` for firewall whitelisting (IP only, no hostnames)
        function updateValidator(address newValidatorAddress, bytes32 publicKey, string calldata inboundAddress, string calldata outboundAddress) external;

        /// Accept pending validator addition or rotation (called by the new validator address)
        function acceptValidator() external;

        /// Cancel a pending validator addition or rotation (owner only)
        /// @param pendingAddress The pending validator address to cancel
        function cancelPendingValidator(address pendingAddress) external;

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
        error InvalidPublicKey();
        error PendingValidatorNotFound();
        error PendingValidatorAlreadyExists();

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

    /// Creates an error when pending validator is not found.
    pub const fn pending_validator_not_found() -> Self {
        Self::PendingValidatorNotFound(IValidatorConfig::PendingValidatorNotFound {})
    }

    /// Creates an error when pending validator already exists.
    pub const fn pending_validator_already_exists() -> Self {
        Self::PendingValidatorAlreadyExists(IValidatorConfig::PendingValidatorAlreadyExists {})
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
