pub use ITipAccountRegistrar::ITipAccountRegistrarErrors as TIPAccountRegistrarError;
use alloy_sol_types::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface ITipAccountRegistrar {
        /// Pre-Moderato: accepts arbitrary hash (vulnerable to signature forgery)
        /// Only works pre-Moderato. Returns UnknownSelector post-Moderato.
        function delegateToDefault(bytes32 hash, bytes calldata signature) external returns (address authority);

        /// Post-Moderato: accepts arbitrary message bytes, computes keccak256(bytes) internally
        /// Only works post-Moderato. Returns UnknownSelector pre-Moderato.
        function delegateToDefault(bytes calldata message, bytes calldata signature) external returns (address authority);

        // Errors
        error InvalidSignature();
        error CodeNotEmpty();
        error NonceNotZero();
    }
}

impl TIPAccountRegistrarError {
    /// Creates an error for invalid cryptographic signature.
    pub const fn invalid_signature() -> Self {
        Self::InvalidSignature(ITipAccountRegistrar::InvalidSignature {})
    }

    /// Creates an error when account code is not empty.
    pub const fn code_not_empty() -> Self {
        Self::CodeNotEmpty(ITipAccountRegistrar::CodeNotEmpty {})
    }

    /// Creates an error when nonce is not zero.
    pub const fn nonce_not_zero() -> Self {
        Self::NonceNotZero(ITipAccountRegistrar::NonceNotZero {})
    }
}
