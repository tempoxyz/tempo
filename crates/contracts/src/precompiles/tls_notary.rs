pub use ITLSNotary::{
    ITLSNotaryErrors as TLSNotaryError, ITLSNotaryEvents as TLSNotaryEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITLSNotary {
        // ──── Notary Management (owner only) ────

        /// Add a trusted notary address.
        function addNotary(address notary) external;

        /// Remove a trusted notary address.
        function removeNotary(address notary) external;

        /// Check if an address is a registered notary.
        function isNotary(address notary) external view returns (bool);

        /// Get the owner of the precompile.
        function owner() external view returns (address);

        /// Transfer ownership.
        function transferOwnership(address newOwner) external;

        // ──── Attestation Registration ────

        /// Register an attestation signed by a quorum of notaries.
        /// @param proofHash keccak256 of the full TLSNotary proof blob
        /// @param statementHash keccak256 of the proven statement (e.g., email ownership)
        /// @param serverNameHash keccak256 of the TLS server name (e.g., "accounts.google.com")
        /// @param signatures Concatenated ECDSA sigs from notaries (65 bytes each: r‖s‖v)
        /// @return sessionId Unique ID for this attestation
        function registerAttestation(
            bytes32 proofHash,
            bytes32 statementHash,
            bytes32 serverNameHash,
            bytes calldata signatures
        ) external returns (bytes32 sessionId);

        // ──── Email Ownership Claims ────

        /// Register a TLSNotary-attested email ownership claim.
        /// After verification, maps keccak256(email) → claimant on-chain.
        /// @param email The email address being claimed (e.g., "user@example.com")
        /// @param serverNameHash keccak256 of the TLS server (e.g., keccak256("accounts.google.com"))
        /// @param proofHash keccak256 of the TLSNotary proof
        /// @param signatures Notary signatures over the claim
        function claimEmail(
            string calldata email,
            bytes32 serverNameHash,
            bytes32 proofHash,
            bytes calldata signatures
        ) external returns (bytes32 claimId);

        /// Look up who has proven ownership of an email.
        /// @param emailHash keccak256 of the email address
        /// @return claimant The address that proved ownership (address(0) if unclaimed)
        /// @return timestamp When the claim was registered
        function emailOwner(bytes32 emailHash) external view returns (address claimant, uint64 timestamp);

        // ──── Session Queries ────

        /// Get a registered session.
        function getSession(bytes32 sessionId) external view returns (
            bytes32 proofHash,
            bytes32 statementHash,
            bytes32 serverNameHash,
            address submitter,
            uint64 timestamp
        );

        /// Check if a proof has been registered.
        function isProofRegistered(bytes32 proofHash) external view returns (bool);

        // ──── Events ────

        event NotaryAdded(address indexed notary, address indexed addedBy);
        event NotaryRemoved(address indexed notary, address indexed removedBy);
        event AttestationRegistered(
            bytes32 indexed sessionId,
            bytes32 indexed proofHash,
            bytes32 statementHash,
            bytes32 serverNameHash,
            address indexed submitter
        );
        event EmailClaimed(
            bytes32 indexed emailHash,
            address indexed claimant,
            bytes32 proofHash,
            bytes32 serverNameHash
        );

        // ──── Errors ────

        error Unauthorized();
        error NotaryAlreadyRegistered(address notary);
        error NotaryNotFound(address notary);
        error InsufficientSignatures(uint256 provided, uint256 required);
        error InvalidSignatureLength();
        error SignatureVerificationFailed(uint256 index);
        error ProofAlreadyRegistered(bytes32 proofHash);
        error SessionNotFound(bytes32 sessionId);
        error EmailAlreadyClaimed(bytes32 emailHash, address existingClaimant);
    }
}

impl TLSNotaryError {
    pub const fn unauthorized() -> Self {
        Self::Unauthorized(ITLSNotary::Unauthorized {})
    }

    pub fn notary_already_registered(notary: alloy_primitives::Address) -> Self {
        Self::NotaryAlreadyRegistered(ITLSNotary::NotaryAlreadyRegistered { notary })
    }

    pub fn notary_not_found(notary: alloy_primitives::Address) -> Self {
        Self::NotaryNotFound(ITLSNotary::NotaryNotFound { notary })
    }

    pub fn insufficient_signatures(provided: alloy_primitives::U256, required: alloy_primitives::U256) -> Self {
        Self::InsufficientSignatures(ITLSNotary::InsufficientSignatures { provided, required })
    }

    pub const fn invalid_signature_length() -> Self {
        Self::InvalidSignatureLength(ITLSNotary::InvalidSignatureLength {})
    }

    pub fn signature_verification_failed(index: alloy_primitives::U256) -> Self {
        Self::SignatureVerificationFailed(ITLSNotary::SignatureVerificationFailed { index })
    }

    pub fn proof_already_registered(proof_hash: alloy_primitives::B256) -> Self {
        Self::ProofAlreadyRegistered(ITLSNotary::ProofAlreadyRegistered { proofHash: proof_hash })
    }

    pub fn session_not_found(session_id: alloy_primitives::B256) -> Self {
        Self::SessionNotFound(ITLSNotary::SessionNotFound { sessionId: session_id })
    }

    pub fn email_already_claimed(email_hash: alloy_primitives::B256, existing_claimant: alloy_primitives::Address) -> Self {
        Self::EmailAlreadyClaimed(ITLSNotary::EmailAlreadyClaimed {
            emailHash: email_hash,
            existingClaimant: existing_claimant,
        })
    }
}
