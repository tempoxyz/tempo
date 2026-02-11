pub use ITLSEmailOwnership::ITLSEmailOwnershipErrors as TLSEmailOwnershipError;

crate::sol! {
    /// TLS Email Ownership verification interface.
    ///
    /// Verifies email ownership using TLSNotary attestations signed by trusted Notaries.
    /// Users submit a Notary-signed attestation of their Google userinfo response,
    /// and the precompile verifies the signature, extracts the email, and stores the claim.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITLSEmailOwnership {
        /// A verified email claim stored on-chain.
        struct EmailClaim {
            string email;
            bytes32 emailHash;
            uint64 verifiedAt;
            bytes32 notaryKeyId;
        }

        /// Verify a Google userinfo email attestation and store the claim.
        ///
        /// The attestation must be signed by a trusted Notary over the digest:
        ///   keccak256(abi.encodePacked(
        ///     "TempoEmailAttestationV1",
        ///     subject,
        ///     serverName,
        ///     endpoint,
        ///     responseBodyHash,
        ///     emailHash,
        ///     notaryKeyId
        ///   ))
        ///
        /// The signature uses secp256k1 ECDSA (same as Ethereum's ecrecover).
        ///
        /// @param notaryKeyId Key ID selecting which trusted Notary to verify against
        /// @param subject Must equal msg.sender
        /// @param serverName Must be "www.googleapis.com"
        /// @param endpoint Must be "/oauth2/v3/userinfo"
        /// @param responseBody The disclosed HTTP response body (JSON containing "email" field)
        /// @param v ECDSA recovery id
        /// @param r ECDSA r value
        /// @param s ECDSA s value
        /// @return email The verified email address
        function verifyEmail(
            bytes32 notaryKeyId,
            address subject,
            string calldata serverName,
            string calldata endpoint,
            bytes calldata responseBody,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) external returns (string memory email);

        /// Get the verified email claim for an address.
        /// @param user The address to look up
        /// @return claim The email claim (empty if not verified)
        function getVerifiedEmail(address user) external view returns (EmailClaim memory claim);

        /// Check if an address has a verified email.
        /// @param user The address to check
        /// @return Whether the address has a verified email claim
        function isVerified(address user) external view returns (bool);

        /// Get the owner of the precompile.
        function owner() external view returns (address);

        /// Change the owner (owner only).
        /// @param newOwner The new owner address
        function changeOwner(address newOwner) external;

        /// Register a trusted Notary public key (owner only).
        /// @param notaryKeyId Unique identifier for this Notary key
        /// @param notaryAddress The Ethereum address of the Notary (derived from its secp256k1 pubkey)
        function setNotaryKey(bytes32 notaryKeyId, address notaryAddress) external;

        /// Remove a trusted Notary key (owner only).
        /// @param notaryKeyId The key to remove
        function removeNotaryKey(bytes32 notaryKeyId) external;

        /// Get a Notary's address by key ID.
        /// @param notaryKeyId The key ID to look up
        /// @return notaryAddress The Notary's Ethereum address (zero if not set)
        function getNotaryKey(bytes32 notaryKeyId) external view returns (address notaryAddress);

        /// Revoke your own email claim.
        function revokeMyEmail() external;

        // Errors
        error Unauthorized();
        error InvalidSubject();
        error InvalidServerName();
        error InvalidEndpoint();
        error ResponseBodyMismatch();
        error EmailNotFound();
        error InvalidSignature();
        error NotaryKeyNotFound();
        error AlreadyVerified();
        error NotVerified();
    }
}

impl TLSEmailOwnershipError {
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(ITLSEmailOwnership::Unauthorized {})
    }

    pub const fn invalid_subject() -> Self {
        Self::InvalidSubject(ITLSEmailOwnership::InvalidSubject {})
    }

    pub const fn invalid_server_name() -> Self {
        Self::InvalidServerName(ITLSEmailOwnership::InvalidServerName {})
    }

    pub const fn invalid_endpoint() -> Self {
        Self::InvalidEndpoint(ITLSEmailOwnership::InvalidEndpoint {})
    }

    pub const fn response_body_mismatch() -> Self {
        Self::ResponseBodyMismatch(ITLSEmailOwnership::ResponseBodyMismatch {})
    }

    pub const fn email_not_found() -> Self {
        Self::EmailNotFound(ITLSEmailOwnership::EmailNotFound {})
    }

    pub const fn invalid_signature() -> Self {
        Self::InvalidSignature(ITLSEmailOwnership::InvalidSignature {})
    }

    pub const fn notary_key_not_found() -> Self {
        Self::NotaryKeyNotFound(ITLSEmailOwnership::NotaryKeyNotFound {})
    }

    pub const fn already_verified() -> Self {
        Self::AlreadyVerified(ITLSEmailOwnership::AlreadyVerified {})
    }

    pub const fn not_verified() -> Self {
        Self::NotVerified(ITLSEmailOwnership::NotVerified {})
    }
}
