pub use IValidatorConfigV2::IValidatorConfigV2Errors as ValidatorConfigV2Error;

crate::sol! {
    /// Validator Config V2 interface for managing consensus validators with append-only,
    /// delete-once semantics.
    ///
    /// V2 uses an append-only design that eliminates the need for historical state access
    /// during node recovery. Validators are immutable after creation and can only be deleted once.
    ///
    /// Key differences from V1:
    /// - `active` bool replaced by `addedAtHeight` and `deactivatedAtHeight`
    /// - No `updateValidator` - validators are immutable after creation
    /// - Requires Ed25519 signature on `addValidator` to prove key ownership
    /// - Both address and public key must be unique across all validators (including deleted)
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IValidatorConfigV2 {
        /// Validator information
        struct Validator {
            bytes32 publicKey;
            address validatorAddress;
            string ingress;
            string egress;
            uint64 index;
            uint64 addedAtHeight;
            uint64 deactivatedAtHeight;
        }

        // =====================================================================
        // View functions
        // =====================================================================

        /// Get the complete set of validators (including deleted)
        function getAllValidators() external view returns (Validator[] memory validators);

        /// Get only active validators (deactivatedAtHeight == 0)
        function getActiveValidators() external view returns (Validator[] memory validators);

        /// Get the block height at which the contract was initialized
        function getInitializedAtHeight() external view returns (uint64);

        /// Get the contract owner
        function owner() external view returns (address);

        /// Get total count of validators ever added (including deleted)
        function validatorCount() external view returns (uint64);

        /// Get validator by index
        function validatorByIndex(uint64 index) external view returns (Validator memory);

        /// Get validator by address
        function validatorByAddress(address validatorAddress) external view returns (Validator memory);

        /// Get validator by public key
        function validatorByPublicKey(bytes32 publicKey) external view returns (Validator memory);

        /// Get the epoch for next full DKG ceremony
        function getNextFullDkgCeremony() external view returns (uint64);

        /// Check if V2 has been initialized
        function isInitialized() external view returns (bool);

        // =====================================================================
        // Mutate functions
        // =====================================================================

        /// Add a new validator (owner only)
        function addValidator(
            address validatorAddress,
            bytes32 publicKey,
            string calldata ingress,
            string calldata egress,
            bytes calldata signature
        ) external;

        /// Deactivate a validator (owner or validator)
        function deactivateValidator(address validatorAddress) external;

        /// Rotate a validator to new identity (owner or validator)
        function rotateValidator(
            address validatorAddress,
            bytes32 publicKey,
            string calldata ingress,
            string calldata egress,
            bytes calldata signature
        ) external;

        /// Update IP addresses (owner or validator)
        function setIpAddresses(
            address validatorAddress,
            string calldata ingress,
            string calldata egress
        ) external;

        /// Transfer validator ownership to new address (owner or validator)
        function transferValidatorOwnership(
            address currentAddress,
            address newAddress
        ) external;

        /// Transfer contract ownership (owner only)
        function transferOwnership(address newOwner) external;

        /// Set the epoch for next full DKG ceremony (owner only)
        function setNextFullDkgCeremony(uint64 epoch) external;

        /// Migrate a single validator from V1 (owner only)
        function migrateValidator(uint64 idx) external;

        /// Initialize V2 after migration (owner only)
        function initializeIfMigrated() external;

        // =====================================================================
        // Errors
        // =====================================================================

        error Unauthorized();
        error ValidatorAlreadyExists();
        error PublicKeyAlreadyExists();
        error ValidatorNotFound();
        error ValidatorAlreadyDeleted();
        error InvalidPublicKey();
        error InvalidSignature();
        error InvalidSignatureFormat();
        error InvalidValidatorAddress();
        error NotInitialized();
        error AlreadyInitialized();
        error MigrationNotComplete();
        error InvalidMigrationIndex();

        error NotIp(string input, string backtrace);
        error NotIpPort(string input, string backtrace);
    }
}

impl ValidatorConfigV2Error {
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(IValidatorConfigV2::Unauthorized {})
    }

    pub const fn validator_already_exists() -> Self {
        Self::ValidatorAlreadyExists(IValidatorConfigV2::ValidatorAlreadyExists {})
    }

    pub const fn public_key_already_exists() -> Self {
        Self::PublicKeyAlreadyExists(IValidatorConfigV2::PublicKeyAlreadyExists {})
    }

    pub const fn validator_not_found() -> Self {
        Self::ValidatorNotFound(IValidatorConfigV2::ValidatorNotFound {})
    }

    pub const fn validator_already_deleted() -> Self {
        Self::ValidatorAlreadyDeleted(IValidatorConfigV2::ValidatorAlreadyDeleted {})
    }

    pub const fn invalid_public_key() -> Self {
        Self::InvalidPublicKey(IValidatorConfigV2::InvalidPublicKey {})
    }

    pub const fn invalid_signature() -> Self {
        Self::InvalidSignature(IValidatorConfigV2::InvalidSignature {})
    }

    pub const fn invalid_signature_format() -> Self {
        Self::InvalidSignatureFormat(IValidatorConfigV2::InvalidSignatureFormat {})
    }

    pub const fn invalid_validator_address() -> Self {
        Self::InvalidValidatorAddress(IValidatorConfigV2::InvalidValidatorAddress {})
    }

    pub const fn not_initialized() -> Self {
        Self::NotInitialized(IValidatorConfigV2::NotInitialized {})
    }

    pub const fn already_initialized() -> Self {
        Self::AlreadyInitialized(IValidatorConfigV2::AlreadyInitialized {})
    }

    pub const fn migration_not_complete() -> Self {
        Self::MigrationNotComplete(IValidatorConfigV2::MigrationNotComplete {})
    }

    pub const fn invalid_migration_index() -> Self {
        Self::InvalidMigrationIndex(IValidatorConfigV2::InvalidMigrationIndex {})
    }

    pub fn not_ip(input: String, backtrace: String) -> Self {
        Self::NotIp(IValidatorConfigV2::NotIp { input, backtrace })
    }

    pub fn not_ip_port(input: String, backtrace: String) -> Self {
        Self::NotIpPort(IValidatorConfigV2::NotIpPort { input, backtrace })
    }
}
