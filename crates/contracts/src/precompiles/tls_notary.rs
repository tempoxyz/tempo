pub use ITLSNotary::{
    ITLSNotaryErrors as TLSNotaryError, ITLSNotaryEvents as TLSNotaryEvent,
};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface ITLSNotary {
        /// Verify a validator quorum attestation over a TLSNotary proof.
        /// @param attestation ABI-encoded attestation (epoch, proofHash, statementHash, serverNameHash, bitmap, signatures)
        /// @return ok Whether the attestation is valid and meets quorum
        /// @return epoch The epoch at which the attestation was created
        /// @return signedPower The total voting power that signed
        /// @return totalPower The total voting power of the validator set
        function verifyAttestation(bytes calldata attestation) external view returns (bool ok, uint64 epoch, uint256 signedPower, uint256 totalPower);

        /// Register an attestation on-chain for indexing and replay prevention.
        /// @param epoch The epoch at which the attestation was created
        /// @param proofHash The keccak256 hash of the TLSNotary proof body
        /// @param statementHash The keccak256 hash of the revealed/proven statement
        /// @param serverNameHash The keccak256 hash of the TLS server name
        /// @param signatures Concatenated ECDSA signatures from validators (65 bytes each: r[32] || s[32] || v[1])
        /// @param bitmap Packed bitmap indicating which validators signed (bit i = validator at index i)
        /// @return sessionId A unique session identifier derived from epoch and proofHash
        function registerAttestation(
            uint64 epoch,
            bytes32 proofHash,
            bytes32 statementHash,
            bytes32 serverNameHash,
            bytes calldata signatures,
            bytes calldata bitmap
        ) external returns (bytes32 sessionId);

        /// Get a registered session by its ID.
        /// @param sessionId The session identifier
        /// @return epoch The epoch at which the session was attested
        /// @return proofHash The proof hash
        /// @return statementHash The statement hash
        /// @return serverNameHash The server name hash
        /// @return submitter The address that registered the session
        /// @return timestamp The block timestamp when it was registered
        function getSession(bytes32 sessionId) external view returns (
            uint64 epoch,
            bytes32 proofHash,
            bytes32 statementHash,
            bytes32 serverNameHash,
            address submitter,
            uint64 timestamp
        );

        /// Check if a proof hash has been registered.
        /// @param proofHash The proof hash to check
        /// @return Whether the proof has been registered
        function isProofRegistered(bytes32 proofHash) external view returns (bool);

        /// Get the session ID for a given epoch and proof hash.
        /// @param epoch The epoch
        /// @param proofHash The proof hash
        /// @return sessionId The derived session ID
        function getSessionId(uint64 epoch, bytes32 proofHash) external pure returns (bytes32 sessionId);

        // Events
        event AttestationRegistered(
            bytes32 indexed sessionId,
            bytes32 indexed proofHash,
            uint64 epoch,
            bytes32 statementHash,
            bytes32 serverNameHash,
            address indexed submitter
        );

        // Errors
        error InvalidAttestation();
        error InsufficientQuorum(uint256 signedPower, uint256 requiredPower);
        error SessionAlreadyRegistered(bytes32 sessionId);
        error SessionNotFound(bytes32 sessionId);
        error InvalidSignatureLength();
        error InvalidBitmapLength();
        error SignatureVerificationFailed(uint64 validatorIndex);
    }
}

impl TLSNotaryError {
    pub const fn invalid_attestation() -> Self {
        Self::InvalidAttestation(ITLSNotary::InvalidAttestation {})
    }

    pub fn insufficient_quorum(signed_power: alloy_primitives::U256, required_power: alloy_primitives::U256) -> Self {
        Self::InsufficientQuorum(ITLSNotary::InsufficientQuorum {
            signedPower: signed_power,
            requiredPower: required_power,
        })
    }

    pub fn session_already_registered(session_id: alloy_primitives::B256) -> Self {
        Self::SessionAlreadyRegistered(ITLSNotary::SessionAlreadyRegistered {
            sessionId: session_id,
        })
    }

    pub fn session_not_found(session_id: alloy_primitives::B256) -> Self {
        Self::SessionNotFound(ITLSNotary::SessionNotFound {
            sessionId: session_id,
        })
    }

    pub const fn invalid_signature_length() -> Self {
        Self::InvalidSignatureLength(ITLSNotary::InvalidSignatureLength {})
    }

    pub const fn invalid_bitmap_length() -> Self {
        Self::InvalidBitmapLength(ITLSNotary::InvalidBitmapLength {})
    }

    pub fn signature_verification_failed(validator_index: u64) -> Self {
        Self::SignatureVerificationFailed(ITLSNotary::SignatureVerificationFailed {
            validatorIndex: validator_index,
        })
    }
}
