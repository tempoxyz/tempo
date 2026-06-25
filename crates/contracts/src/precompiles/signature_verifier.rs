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

        /// @notice Verifies whether a keychain signature was produced by an active key.
        /// @param account The expected embedded root account
        /// @param hash The message hash that was signed
        /// @param signature The encoded keychain signature
        /// @dev Does not compare the inner signature type against the stored key type.
        /// @return True if the keychain access key is active on account.
        #[since(TempoHardfork::T6)]
        function verifyKeychain(address account, bytes32 hash, bytes calldata signature) external view returns (bool);

        /// @notice Verifies whether a keychain signature was produced by a root or active admin key.
        /// @param account The expected embedded root account
        /// @param hash The message hash that was signed
        /// @param signature The encoded keychain signature
        /// @dev Does not compare the inner signature type against the stored key type.
        /// @return True if the recovered key is account or an active admin key on account.
        #[since(TempoHardfork::T6)]
        function verifyKeychainAdmin(address account, bytes32 hash, bytes calldata signature) external view returns (bool);

        error InvalidFormat();
        error InvalidSignature();
    }
}
