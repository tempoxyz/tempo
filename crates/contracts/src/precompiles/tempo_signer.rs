pub use ITempoSigner::{
    ITempoSignerErrors as TempoSignerError, ITempoSignerEvents as TempoSignerEvent,
};

crate::sol! {
    /// ITempoSigner interface for contract-based access key verification
    ///
    /// Contracts implementing this interface can be used as verifiers for
    /// EvmContract-type access keys. The AccountKeychain precompile will call
    /// isValidSignatureWithKeyHash to validate authorization.
    ///
    /// This is inspired by Porto's ISigner interface with additional account parameter
    /// to enable proper namespacing of configurations per account.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITempoSigner {
        /// ERC-1271 magic value indicating valid signature
        /// bytes4(keccak256("isValidSignature(bytes32,bytes)"))
        function MAGIC_VALUE() external pure returns (bytes4);

        /// Validate a signature for contract-based access keys
        ///
        /// @param account The Tempo account being authorized
        /// @param digest The bound digest (includes domain, chainId, account, keyHash)
        /// @param keyHash Identifies the key configuration within this contract
        /// @param signature Opaque authorization data (e.g., aggregated signatures)
        /// @return magicValue 0x1626ba7e if valid, any other value if invalid
        function isValidSignatureWithKeyHash(
            address account,
            bytes32 digest,
            bytes32 keyHash,
            bytes calldata signature
        ) external view returns (bytes4 magicValue);

        // Events
        event ConfigInitialized(address indexed account, bytes32 indexed keyHash);
        event ConfigUpdated(address indexed account, bytes32 indexed keyHash);

        // Errors
        error ConfigAlreadyExists();
        error ConfigNotFound();
        error InvalidSignature();
        error BelowThreshold();
        error InvalidThreshold();
        error DuplicateSigner();
        error SignerNotOwner();
        error InvalidSignerOrder();
    }
}

impl TempoSignerError {
    pub const fn config_already_exists() -> Self {
        Self::ConfigAlreadyExists(ITempoSigner::ConfigAlreadyExists {})
    }

    pub const fn config_not_found() -> Self {
        Self::ConfigNotFound(ITempoSigner::ConfigNotFound {})
    }

    pub const fn invalid_signature() -> Self {
        Self::InvalidSignature(ITempoSigner::InvalidSignature {})
    }

    pub const fn below_threshold() -> Self {
        Self::BelowThreshold(ITempoSigner::BelowThreshold {})
    }

    pub const fn invalid_threshold() -> Self {
        Self::InvalidThreshold(ITempoSigner::InvalidThreshold {})
    }

    pub const fn duplicate_signer() -> Self {
        Self::DuplicateSigner(ITempoSigner::DuplicateSigner {})
    }

    pub const fn signer_not_owner() -> Self {
        Self::SignerNotOwner(ITempoSigner::SignerNotOwner {})
    }

    pub const fn invalid_signer_order() -> Self {
        Self::InvalidSignerOrder(ITempoSigner::InvalidSignerOrder {})
    }
}

/// ERC-1271 magic value for valid signature
pub const ERC1271_MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];
