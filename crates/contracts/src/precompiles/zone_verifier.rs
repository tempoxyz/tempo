//! ABI for the TIP-1098 native Zone verifier.

pub use crate::zones::IZoneVerifier;

/// Canonical one-byte configuration selecting the first Nitro-backed verifier policy.
pub const NITRO_VERIFIER_CONFIG_V1: &[u8] = &[1];
/// Canonical one-byte configuration selecting temporary proofless fallback settlement.
pub const NO_PROOF_FALLBACK_VERIFIER: &[u8] = &[2];

crate::sol! {
    /// EIP-712 statement committed to a Nitro attestation's `user_data`.
    #[derive(Debug, PartialEq, Eq)]
    struct NitroBatchAttestation {
        uint256 parentChainId;
        address verifier;
        uint32 zoneId;
        uint64 tempoBlockNumber;
        uint64 anchorBlockNumber;
        bytes32 anchorBlockHash;
        uint64 expectedWithdrawalBatchIndex;
        uint256 nextZoneHeight;
        bytes32 prevBlockHash;
        bytes32 nextBlockHash;
        bytes32 prevProcessedHash;
        bytes32 nextProcessedHash;
        uint64 prevDepositNumber;
        uint64 nextDepositNumber;
        uint64 prevProcessedTokenCount;
        uint64 nextProcessedTokenCount;
        bytes32 withdrawalQueueHash;
        bytes32 verifierConfigHash;
    }
}
