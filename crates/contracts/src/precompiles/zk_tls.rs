pub use IZkTlsVerifier::{
    IZkTlsVerifierErrors as ZkTlsVerifierError, IZkTlsVerifierEvents as ZkTlsVerifierEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IZkTlsVerifier {
        /// @notice Tempo-native zkTLS claim emitted after off-chain TEE attestation validation.
        /// @dev Fixed-width fields intentionally keep on-chain verification deterministic.
        struct TempoZkTlsClaim {
            address subject;
            bytes32 providerHash;
            bytes32 claimType;
            bytes32 extractedHash;
            bytes32 nonce;
            bytes32 sessionId;
            uint64 issuedAt;
            uint64 expiresAt;
            bytes32 sourceHash;
            bytes32 measurement;
            bytes32 imageDigest;
            bytes32 evidenceHash;
        }

        /// @notice Application policy checked atomically with the attestor signature.
        /// @dev Set expectedImageDigest or expectedEvidenceHash to zero to skip that exact match.
        struct VerificationPolicy {
            address expectedSubject;
            bytes32 expectedProviderHash;
            bytes32 expectedClaimType;
            bytes32 expectedNonce;
            bytes32 expectedSourceHash;
            bytes32 expectedMeasurement;
            bytes32 expectedImageDigest;
            bytes32 expectedEvidenceHash;
            bytes32 attestorPublicKey;
            uint64 maxClaimAgeSeconds;
            uint64 maxFutureSkewSeconds;
        }

        /// @notice Verifies an attestor-signed Tempo zkTLS claim without mutating nonce state.
        /// @param claim The fixed-width claim preimage.
        /// @param policy The expected verifier policy for this app/session.
        /// @param signature Ed25519 signature over the EIP-712 digest returned by `hashTempoClaim(claim)`.
        /// @return claimHash EIP-712 signing digest for the claim.
        function verifyTempoClaim(TempoZkTlsClaim calldata claim, VerificationPolicy calldata policy, bytes calldata signature)
            external
            view
            returns (bytes32 claimHash);

        /// @notice Verifies an attestor-signed Tempo zkTLS claim and marks its subject/nonce as used.
        /// @param claim The fixed-width claim preimage.
        /// @param policy The expected verifier policy for this app/session.
        /// @param signature Ed25519 signature over the EIP-712 digest returned by `hashTempoClaim(claim)`.
        /// @return claimHash EIP-712 signing digest for the claim.
        function verifyAndMarkTempoClaim(TempoZkTlsClaim calldata claim, VerificationPolicy calldata policy, bytes calldata signature)
            external
            returns (bytes32 claimHash);

        /// @notice Returns the EIP-712 signing digest signed by the Tempo zkTLS attestor.
        function hashTempoClaim(TempoZkTlsClaim calldata claim) external view returns (bytes32 claimHash);

        /// @notice Returns whether a subject/nonce pair has been consumed through `verifyAndMarkTempoClaim`.
        function isNonceUsed(address subject, bytes32 nonce) external view returns (bool used);

        /// @notice Returns the verifier registry owner.
        function owner() external view returns (address owner);

        /// @notice Returns whether an attestor public key is approved in verifier state.
        function isAttestorApproved(bytes32 attestorPublicKey) external view returns (bool approved);

        /// @notice Returns whether a provider schema/policy hash is approved in verifier state.
        function isProviderHashApproved(bytes32 providerHash) external view returns (bool approved);

        /// @notice Returns whether a TEE measurement is approved in verifier state.
        function isMeasurementApproved(bytes32 measurement) external view returns (bool approved);

        /// @notice Updates an attestor public key approval. Owner only.
        function setAttestorApproved(bytes32 attestorPublicKey, bool approved) external;

        /// @notice Updates a provider schema/policy hash approval. Owner only.
        function setProviderHashApproved(bytes32 providerHash, bool approved) external;

        /// @notice Updates a TEE measurement approval. Owner only.
        function setMeasurementApproved(bytes32 measurement, bool approved) external;

        /// @notice Transfers verifier registry ownership. Owner only.
        function transferOwnership(address newOwner) external;

        event TempoZkTlsClaimVerified(
            address indexed subject,
            bytes32 indexed providerHash,
            bytes32 indexed nonce,
            bytes32 claimType,
            bytes32 extractedHash,
            bytes32 sessionId,
            bytes32 sourceHash,
            bytes32 measurement,
            bytes32 imageDigest,
            bytes32 evidenceHash,
            bytes32 attestorPublicKey,
            bytes32 claimHash
        );
        event AttestorApprovalUpdated(bytes32 indexed attestorPublicKey, bool approved);
        event ProviderHashApprovalUpdated(bytes32 indexed providerHash, bool approved);
        event MeasurementApprovalUpdated(bytes32 indexed measurement, bool approved);
        event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

        error Unauthorized();
        error InvalidOwner();
        error SubjectMismatch();
        error NonceMismatch();
        error ProviderHashMismatch();
        error ClaimTypeMismatch();
        error SourceHashMismatch();
        error MeasurementMismatch();
        error ImageDigestMismatch();
        error EvidenceHashMismatch();
        error AttestorNotApproved();
        error ProviderHashNotApproved();
        error MeasurementNotApproved();
        error AttestorPublicKeyZero();
        error InvalidPublicKey();
        error InvalidSignatureLength();
        error InvalidSignature();
        error NonceAlreadyUsed();
        error ClaimExpired();
        error ClaimStale();
        error ClaimIssuedFromFuture();
    }
}
