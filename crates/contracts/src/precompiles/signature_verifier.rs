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

        /// @notice Verifies whether a Tempo signature approves a hash for an account.
        /// @param account Before T15, the expected signer. From T15, the account expected to approve
        /// hash under its current state (TIP-1168).
        /// @param hash The message hash that was signed
        /// @param signature Before T15, a primitive signature. From T15, a primitive, keychain or
        /// configurable account signature.
        /// @dev From T15, a primitive signature counts only while account has no configuration
        /// commitment (TIP-1113), a keychain signature follows `verifyKeychainAdmin`, and a
        /// configurable account signature follows `verifyConfigurableAccount`. Use `recover` for a
        /// stateless check of which key signed.
        /// @return True if the signature approves hash for account, false otherwise. Reverts for
        /// malformed or invalid signatures.
        function verify(address account, bytes32 hash, bytes calldata signature) external view returns (bool);

        /// @notice Verifies whether a keychain signature was produced by an active key.
        /// @param account The expected embedded root account
        /// @param hash The message hash that was signed
        /// @param signature The encoded keychain signature
        /// @dev From T14, false if a primitive inner signature's key has a nonzero configuration
        /// commitment (TIP-1113), and the inner signature type must match the stored key type.
        /// @return True if the keychain access key is active on account.
        function verifyKeychain(address account, bytes32 hash, bytes calldata signature) external view returns (bool);

        /// @notice Verifies whether a keychain signature was produced by a root or active admin key.
        /// @param account The expected embedded root account
        /// @param hash The message hash that was signed
        /// @param signature The encoded keychain signature
        /// @dev From T14, false if the recovered key has a nonzero configuration commitment (TIP-1113),
        /// including account itself, and the inner signature type of an access key must match the
        /// stored key type.
        /// @return True if the recovered key is account or an active admin key on account.
        function verifyKeychainAdmin(address account, bytes32 hash, bytes calldata signature) external view returns (bool);

        /// @notice Verifies a configurable account signature against current account state.
        /// @return False for an account or configuration mismatch; reverts for malformed or invalid approvals.
        function verifyConfigurableAccount(address account, bytes32 hash, bytes calldata signature) external view returns (bool);

        error InvalidFormat();
        error InvalidSignature();
    }
}
