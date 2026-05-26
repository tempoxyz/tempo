pub use ISignatureVerifier::ISignatureVerifierErrors as SignatureVerifierError;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ISignatureVerifier {

        /// @notice Recovers the signer of a Tempo signature (secp256k1, P256, WebAuthn).
        /// @param hash The message hash that was signed
        /// @param signature The encoded signature (see Tempo Transaction spec for formats)
        /// @return Address of the signer if valid, reverts otherwise
        function recover(bytes32 hash, bytes calldata signature) external view returns (address signer);

        /// @notice Verifies a signer against a Tempo signature (secp256k1, P256, WebAuthn).
        /// @param signer The input address verified against the recovered signer
        /// @param hash The message hash that was signed
        /// @param signature The encoded signature (see Tempo Transaction spec for formats)
        /// @return True if the input address signed, false otherwise. Reverts on invalid signatures.
        function verify(address signer, bytes32 hash, bytes calldata signature) external view returns (bool);

        /// @notice Verifies whether a Tempo signature was produced by an account root or admin key.
        /// @param account The account whose root/admin key set is checked
        /// @param hash The message hash that was signed
        /// @param signature The encoded signature (see Tempo Transaction spec for formats)
        /// @return True if the recovered signer is the root or an active admin key for account.
        function verifyAdmin(address account, bytes32 hash, bytes calldata signature) external view returns (bool);

        error InvalidFormat();
        error InvalidSignature();
    }
}
