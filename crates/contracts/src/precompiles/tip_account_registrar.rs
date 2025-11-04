pub use ITipAccountRegistrar::ITipAccountRegistrarErrors as TIPAccountRegistrarError;
use alloy::sol;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(rpc, abi)]
    interface ITipAccountRegistrar {
        function delegateToDefault(bytes32 hash, bytes calldata signature) external returns (address authority);
        function getDelegationMessage() external pure returns (string memory);

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
