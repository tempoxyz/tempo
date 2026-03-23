pub use ISignatureVerifier::ISignatureVerifierErrors as SignatureVerifierError;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ISignatureVerifier {
        /// @notice Verifies a Tempo signature (secp256k1, P256, WebAuthn).
        /// @param hash The message hash that was signed
        /// @param signature The encoded signature (see Tempo Transaction spec for formats)
        /// @return signer Address of the signer if valid, reverts otherwise
        function verify(bytes32 hash, bytes calldata signature) external view returns (address signer);

        error InvalidSignatureFormat();
        error SignatureVerificationFailed();
    }
}

impl SignatureVerifierError {
    pub const fn invalid_signature_format() -> Self {
        Self::InvalidSignatureFormat(ISignatureVerifier::InvalidSignatureFormat {})
    }

    pub const fn signature_verification_failed() -> Self {
        Self::SignatureVerificationFailed(ISignatureVerifier::SignatureVerificationFailed {})
    }
}
