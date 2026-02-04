pub use ISignatureVerification::ISignatureVerificationErrors as SignatureVerificationError;

crate::sol! {
    /// Signature Verification precompile interface (TIP-1020)
    ///
    /// This precompile enables contracts to verify Tempo signature types
    /// (secp256k1, P256, WebAuthn, Keychain) using the same verification
    /// logic as Tempo transaction processing.
    ///
    /// For signature encoding formats, see:
    /// https://docs.tempo.xyz/protocol/transactions/spec-tempo-transaction#signature-types
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ISignatureVerification {
        /// Verifies a Tempo signature
        /// @param signer The expected signer address
        /// @param hash The message hash that was signed
        /// @param signature The encoded signature (secp256k1, P256, WebAuthn, or Keychain)
        /// @return True if valid, reverts otherwise
        function verify(address signer, bytes32 hash, bytes calldata signature) external view returns (bool);

        /// The signature is invalid or could not be parsed
        error InvalidSignature();

        /// The recovered signer does not match the expected signer
        error SignerMismatch(address expected, address recovered);

        /// The keychain access key is not authorized, expired, or revoked
        error UnauthorizedKeychainKey();
    }
}

impl SignatureVerificationError {
    /// Creates an error for invalid signature
    pub const fn invalid_signature() -> Self {
        Self::InvalidSignature(ISignatureVerification::InvalidSignature {})
    }

    /// Creates an error for signer mismatch
    pub const fn signer_mismatch(expected: alloy_primitives::Address, recovered: alloy_primitives::Address) -> Self {
        Self::SignerMismatch(ISignatureVerification::SignerMismatch { expected, recovered })
    }

    /// Creates an error for unauthorized keychain key
    pub const fn unauthorized_keychain_key() -> Self {
        Self::UnauthorizedKeychainKey(ISignatureVerification::UnauthorizedKeychainKey {})
    }
}
