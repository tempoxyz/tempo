pub use IZkTlsVerifier::{
    IZkTlsVerifierErrors as ZkTlsVerifierError, IZkTlsVerifierEvents as ZkTlsVerifierEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IZkTlsVerifier {
        /// @notice Tempo-native zkTLS claim emitted by a Phala dstack CVM.
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
            address dstackApp;
            bytes32 composeHash;
            bytes32 deviceId;
            bytes32 quoteHash;
        }

        /// @notice Application policy checked atomically with the dstack signature.
        /// @dev Set expectedDeviceId or expectedTeeSigner to zero to rely on registry approval only.
        struct VerificationPolicy {
            address expectedSubject;
            bytes32 expectedProviderHash;
            bytes32 expectedClaimType;
            bytes32 expectedNonce;
            bytes32 expectedSourceHash;
            address expectedDstackApp;
            bytes32 expectedComposeHash;
            bytes32 expectedDeviceId;
            address expectedTeeSigner;
            uint64 maxClaimAgeSeconds;
            uint64 maxFutureSkewSeconds;
        }

        /// @notice Verifies a Phala dstack-signed Tempo zkTLS claim without mutating nonce state.
        /// @param claim The fixed-width claim preimage.
        /// @param policy The expected verifier policy for this app/session.
        /// @param rawQuote Phala dstack TDX quote whose reportData binds the signer and nonce.
        /// @param signature secp256k1 signature over `toEthSignedMessageHash(hashTempoClaim(claim))`.
        /// @return claimHash Solidity-compatible claim hash signed by the dstack signer.
        /// @return teeSigner signer recovered from the TDX quote reportData and signature.
        function verifyTempoClaim(TempoZkTlsClaim calldata claim, VerificationPolicy calldata policy, bytes calldata rawQuote, bytes calldata signature)
            external
            view
            returns (bytes32 claimHash, address teeSigner);

        /// @notice Verifies a Phala dstack-signed Tempo zkTLS claim and marks its subject/nonce as used.
        /// @param claim The fixed-width claim preimage.
        /// @param policy The expected verifier policy for this app/session.
        /// @param rawQuote Phala dstack TDX quote whose reportData binds the signer and nonce.
        /// @param signature secp256k1 signature over `toEthSignedMessageHash(hashTempoClaim(claim))`.
        /// @return claimHash Solidity-compatible claim hash signed by the dstack signer.
        /// @return teeSigner signer recovered from the TDX quote reportData and signature.
        function verifyAndMarkTempoClaim(TempoZkTlsClaim calldata claim, VerificationPolicy calldata policy, bytes calldata rawQuote, bytes calldata signature)
            external
            returns (bytes32 claimHash, address teeSigner);

        /// @notice Returns the Solidity-compatible claim hash signed by the Phala dstack signer.
        function hashTempoClaim(TempoZkTlsClaim calldata claim) external view returns (bytes32 claimHash);

        /// @notice Returns the EIP-191 digest signed by the Phala dstack signer.
        function toEthSignedMessageHash(bytes32 claimHash) external view returns (bytes32 digest);

        /// @notice Returns whether a subject/nonce pair has been consumed through `verifyAndMarkTempoClaim`.
        function isNonceUsed(address subject, bytes32 nonce) external view returns (bool used);

        /// @notice Returns the verifier registry owner.
        function owner() external view returns (address owner);

        /// @notice Returns whether a provider schema/policy hash is approved in verifier state.
        function isProviderHashApproved(bytes32 providerHash) external view returns (bool approved);

        /// @notice Returns the only claim type approved for a provider hash, or zero when unapproved.
        function claimTypeForProviderHash(bytes32 providerHash) external view returns (bytes32 claimType);

        /// @notice Returns whether a dstack app identity is approved in verifier state.
        function isDstackAppApproved(address dstackApp) external view returns (bool approved);

        /// @notice Returns whether a dstack app compose hash is approved in verifier state.
        function isDstackComposeHashApproved(address dstackApp, bytes32 composeHash) external view returns (bool approved);

        /// @notice Returns whether a dstack app device id is approved in verifier state.
        function isDstackDeviceApproved(address dstackApp, bytes32 deviceId) external view returns (bool approved);

        /// @notice Returns whether any device id is allowed for a dstack app.
        function isDstackAnyDeviceAllowed(address dstackApp) external view returns (bool approved);

        /// @notice Returns whether a dstack signer is approved for a dstack app.
        function isDstackSignerApproved(address dstackApp, address teeSigner) external view returns (bool approved);

        /// @notice Updates a provider schema/policy hash approval. Owner only.
        function setProviderHashApproved(bytes32 providerHash, bytes32 claimType, bool approved) external;

        /// @notice Updates dstack app approval. Owner only.
        function setDstackAppApproved(address dstackApp, bool approved) external;

        /// @notice Updates dstack compose-hash approval for an approved app. Owner only.
        function setDstackComposeHashApproved(address dstackApp, bytes32 composeHash, bool approved) external;

        /// @notice Updates dstack device approval for an approved app. Owner only.
        function setDstackDeviceApproved(address dstackApp, bytes32 deviceId, bool approved) external;

        /// @notice Allows or disallows any device for an approved dstack app. Owner only.
        function setDstackAllowAnyDevice(address dstackApp, bool approved) external;

        /// @notice Updates dstack signer approval for an approved app. Owner only.
        function setDstackSignerApproved(address dstackApp, address teeSigner, bool approved) external;

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
            address dstackApp,
            bytes32 composeHash,
            bytes32 deviceId,
            bytes32 quoteHash,
            address teeSigner,
            bytes32 claimHash,
            bytes32 digest
        );
        event ProviderHashApprovalUpdated(bytes32 indexed providerHash, bytes32 indexed claimType, bool approved);
        event DstackAppApprovalUpdated(address indexed dstackApp, bool approved);
        event DstackComposeHashApprovalUpdated(address indexed dstackApp, bytes32 indexed composeHash, bool approved);
        event DstackDeviceApprovalUpdated(address indexed dstackApp, bytes32 indexed deviceId, bool approved);
        event DstackAllowAnyDeviceUpdated(address indexed dstackApp, bool approved);
        event DstackSignerApprovalUpdated(address indexed dstackApp, address indexed teeSigner, bool approved);
        event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

        error Unauthorized();
        error InvalidOwner();
        error DstackAppZero();
        error DstackSignerZero();
        error ProviderHashZero();
        error ClaimTypeZero();
        error SubjectMismatch();
        error NonceMismatch();
        error ProviderHashMismatch();
        error ClaimTypeMismatch();
        error SourceHashMismatch();
        error DstackAppMismatch();
        error DstackComposeHashMismatch();
        error DstackDeviceMismatch();
        error DstackSignerMismatch();
        error ProviderHashNotApproved();
        error DstackAppNotApproved();
        error DstackComposeHashNotApproved();
        error DstackDeviceNotApproved();
        error DstackSignerNotApproved();
        error QuoteHashMismatch();
        error QuoteReportDataSignerMismatch();
        error QuoteReportDataNonceMismatch();
        error QuoteComposeHashMismatch();
        error QuoteTooShort();
        error QuoteVersionUnsupported(uint16 quoteVersion);
        error QuoteBodyTypeUnsupported(uint16 quoteBodyType);
        error InvalidSignatureLength();
        error InvalidSignature();
        error NonceAlreadyUsed();
        error ClaimExpired();
        error ClaimStale();
        error ClaimIssuedFromFuture();
    }
}
