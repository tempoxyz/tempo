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

        /// @notice Verifies whether a signature approves a hash for an account.
        /// @param account The account expected to approve
        /// @param hash The message hash that was signed
        /// @param signature The encoded signature
        /// @dev Before T15, whether a primitive signature recovers to account.
        /// From T15, by signature type, against account's current state (TIP-1168):
        /// - primitive: recovers to account, and account has no configuration commitment
        /// - keychain: same as `verifyKeychainAdmin`
        /// - configurable account: same as `verifyConfigurableAccount`
        /// Use `recover` for a stateless check.
        /// @return True if the signature approves hash for account. Reverts on malformed or invalid
        /// signatures.
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
