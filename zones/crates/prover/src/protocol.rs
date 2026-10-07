use alloy_primitives::{B256, Bytes};
use alloy_sol_types::{SolStruct as _, sol};
use keccak_const::Keccak256;
use serde::{Deserialize, Serialize};
use tempo_zone_contracts::ZONE_VERIFIER_ADDRESS;
use zone_spf::{BatchOutput, BatchWitness, PublicInputs};

/// Current version of the prover request and response wire format.
pub const PROTOCOL_VERSION: u16 = 1;

/// Canonical one-byte configuration selecting the first Nitro-backed verifier policy.
pub const NITRO_VERIFIER_CONFIG_V1: &[u8] = &[1];
/// Compile-time Keccak-256 hash of [`NITRO_VERIFIER_CONFIG_V1`].
pub const NITRO_VERIFIER_CONFIG_V1_HASH: B256 =
    B256::new(Keccak256::new().update(NITRO_VERIFIER_CONFIG_V1).finalize());
/// Canonical one-byte configuration selecting temporary proofless fallback settlement.
pub const NO_PROOF_FALLBACK_VERIFIER: &[u8] = &[2];
/// Compile-time Keccak-256 hash of [`NO_PROOF_FALLBACK_VERIFIER`].
pub const NO_PROOF_FALLBACK_VERIFIER_HASH: B256 = B256::new(
    Keccak256::new()
        .update(NO_PROOF_FALLBACK_VERIFIER)
        .finalize(),
);

/// Canonical verifier configurations supported by T13 settlement.
///
/// Each mode owns both the bytes passed to the on-chain verifier and the proof shape accepted for
/// those bytes. Decoding rejects unknown and non-canonical configurations rather than treating
/// them as fallback.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum VerifierMode {
    /// Nitro verification using a non-empty attestation document.
    #[default]
    NitroV1,
    /// Temporary fallback verification requiring an empty proof.
    NoProof,
}

impl VerifierMode {
    /// Exact bytes passed to the on-chain verifier.
    pub const fn config(self) -> &'static [u8] {
        match self {
            Self::NitroV1 => NITRO_VERIFIER_CONFIG_V1,
            Self::NoProof => NO_PROOF_FALLBACK_VERIFIER,
        }
    }

    /// Hash committed by settlement attestations.
    pub const fn config_hash(self) -> B256 {
        match self {
            Self::NitroV1 => NITRO_VERIFIER_CONFIG_V1_HASH,
            Self::NoProof => NO_PROOF_FALLBACK_VERIFIER_HASH,
        }
    }

    /// Validate that `proof` has the shape required by this verifier mode.
    ///
    /// Nitro requires a non-empty proof, while [`Self::NoProof`] requires an empty proof.
    pub fn validate_proof_shape(self, proof: &[u8]) -> Result<(), VerifierModeError> {
        match (self, proof.is_empty()) {
            (Self::NitroV1, true) => Err(VerifierModeError::InvalidProofShape),
            (Self::NoProof, false) => Err(VerifierModeError::InvalidProofShape),
            _ => Ok(()),
        }
    }
}

impl TryFrom<&[u8]> for VerifierMode {
    type Error = VerifierModeError;

    /// Decode an exact configuration. Unknown and non-canonical encodings are rejected.
    fn try_from(config: &[u8]) -> Result<Self, Self::Error> {
        match config {
            NITRO_VERIFIER_CONFIG_V1 => Ok(Self::NitroV1),
            NO_PROOF_FALLBACK_VERIFIER => Ok(Self::NoProof),
            _ => Err(VerifierModeError::UnknownConfig),
        }
    }
}

impl TryFrom<B256> for VerifierMode {
    type Error = VerifierModeError;

    /// Decode the hash committed by a settlement attestation.
    fn try_from(hash: B256) -> Result<Self, Self::Error> {
        match hash {
            NITRO_VERIFIER_CONFIG_V1_HASH => Ok(Self::NitroV1),
            NO_PROOF_FALLBACK_VERIFIER_HASH => Ok(Self::NoProof),
            _ => Err(VerifierModeError::UnknownConfigHash),
        }
    }
}

/// Failure to decode or validate a verifier mode.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifierModeError {
    /// Raw configuration bytes are not one of the canonical encodings.
    #[error("unknown verifier configuration")]
    UnknownConfig,
    /// A settlement commitment does not match any canonical configuration hash.
    #[error("unknown verifier configuration hash")]
    UnknownConfigHash,
    /// The proof is empty for Nitro or non-empty for proofless fallback.
    #[error("proof shape does not match verifier configuration")]
    InvalidProofShape,
}

sol! {
    /// Data placed in the Nitro attestation document's `user_data` field.
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

/// Proof material returned by an attesting prover.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofBundle {
    /// Opaque configuration passed to `IVerifier` and committed by the settlement certificate.
    pub verifier_config: Bytes,
    /// Raw COSE/CBOR Nitro attestation document.
    pub proof: Bytes,
}

/// Request to verify a Zone batch witness against a trusted Tempo chain.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyRequest {
    /// Wire-format version expected by the sender.
    pub version: u16,
    /// Caller-selected identifier echoed in the corresponding response.
    pub request_id: String,
    /// Complete input to the Zone stateless proof function.
    pub witness: BatchWitness,
}

/// Result of processing a [`VerifyRequest`].
#[derive(Debug, Deserialize, Serialize)]
#[serde(
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum VerifyResponse {
    /// The witness was verified successfully.
    #[serde(rename = "ok")]
    Ok {
        /// Wire-format version used by the prover.
        version: u16,
        /// Identifier copied from the request.
        request_id: String,
        /// Output produced by the Zone stateless proof function.
        output: Box<BatchOutput>,
        /// Nitro proof material returned by the attesting prover.
        proof_bundle: ProofBundle,
    },
    /// The request could not be decoded, accepted, or verified.
    #[serde(rename = "error")]
    Error {
        /// Wire-format version used by the prover.
        version: u16,
        /// Request identifier, when it could be recovered from the request.
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        /// Stable, machine-readable error category.
        code: ErrorCode,
        /// Human-readable diagnostic detail.
        message: String,
    },
}

/// Stable error categories returned by the prover protocol.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request is not valid CBOR or does not match the request schema.
    MalformedRequest,
    /// The request uses a wire-format version unsupported by the prover.
    UnsupportedVersion,
    /// The requested Tempo chain is not trusted by the prover.
    UnsupportedChain,
    /// Stateless proof execution rejected the supplied witness.
    VerificationFailed,
    /// The prover could not obtain an attestation from the Nitro Secure Module.
    AttestationUnavailable,
    /// The framed request exceeds the configured size limit.
    RequestTooLarge,
    /// The connection ended before the complete frame was received.
    TruncatedFrame,
    /// An unexpected transport or prover failure occurred.
    InternalError,
}

/// Construct the exact digest committed as Nitro attestation `user_data`.
///
/// The parent chain, verifier, and Zone ID prevent cross-domain replay. The verifier must
/// require its caller to be the canonical portal derived from the Zone ID. Every portal-facing
/// commitment prevents reuse for a different batch.
pub fn nitro_batch_attestation_hash(public_inputs: &PublicInputs, output: &BatchOutput) -> B256 {
    let attestation = NitroBatchAttestation {
        parentChainId: alloy_primitives::U256::from(public_inputs.parent_chain_id),
        verifier: ZONE_VERIFIER_ADDRESS,
        zoneId: public_inputs.zone_id,
        tempoBlockNumber: public_inputs.tempo_block_number,
        anchorBlockNumber: public_inputs.anchor_block_number,
        anchorBlockHash: public_inputs.anchor_block_hash,
        expectedWithdrawalBatchIndex: public_inputs.expected_withdrawal_batch_index,
        nextZoneHeight: alloy_primitives::U256::from(output.next_zone_height),
        prevBlockHash: output.block_transition.prevBlockHash,
        nextBlockHash: output.block_transition.nextBlockHash,
        prevProcessedHash: output.deposit_queue_transition.prevProcessedHash,
        nextProcessedHash: output.deposit_queue_transition.nextProcessedHash,
        prevDepositNumber: output.deposit_queue_transition.prevDepositNumber,
        nextDepositNumber: output.deposit_queue_transition.nextDepositNumber,
        prevProcessedTokenCount: output.token_enablement_transition.prevProcessedTokenCount,
        nextProcessedTokenCount: output.token_enablement_transition.nextProcessedTokenCount,
        withdrawalQueueHash: output.withdrawal_queue_hash,
        verifierConfigHash: NITRO_VERIFIER_CONFIG_V1_HASH,
    };
    attestation.eip712_hash_struct()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use zone_spf::{
        BatchOutput, BlockTransition, DepositQueueTransition, LastBatchCommitment,
        TokenEnablementTransition,
    };

    #[test]
    fn error_variant_uses_the_wire_field_names() {
        let encoded = serde_json::to_vec(&VerifyResponse::Error {
            version: PROTOCOL_VERSION,
            request_id: Some("wire-test".into()),
            code: ErrorCode::UnsupportedChain,
            message: "unsupported".into(),
        })
        .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let error = &json["error"];

        assert_eq!(error["version"], PROTOCOL_VERSION);
        assert_eq!(error["requestId"], "wire-test");
        assert_eq!(error["code"], "unsupported_chain");
    }

    #[test]
    fn verifier_config_is_versioned_and_non_empty() {
        assert_eq!(NITRO_VERIFIER_CONFIG_V1, [1]);
        assert_eq!(
            NITRO_VERIFIER_CONFIG_V1_HASH,
            keccak256(NITRO_VERIFIER_CONFIG_V1)
        );
        assert_eq!(
            NO_PROOF_FALLBACK_VERIFIER_HASH,
            keccak256(NO_PROOF_FALLBACK_VERIFIER)
        );
        assert_ne!(
            NITRO_VERIFIER_CONFIG_V1_HASH,
            alloy_consensus::constants::KECCAK_EMPTY
        );
    }

    #[test]
    fn verifier_modes_enforce_canonical_config_and_proof_shape() {
        assert_eq!(VerifierMode::try_from(&[1][..]), Ok(VerifierMode::NitroV1));
        assert_eq!(VerifierMode::try_from(&[2][..]), Ok(VerifierMode::NoProof));
        assert!(VerifierMode::try_from(&[][..]).is_err());
        assert!(VerifierMode::try_from(&[1, 2][..]).is_err());
        assert!(VerifierMode::try_from(&[3][..]).is_err());

        assert!(VerifierMode::NitroV1.validate_proof_shape(&[42]).is_ok());
        assert_eq!(
            VerifierMode::NitroV1.validate_proof_shape(&[]),
            Err(VerifierModeError::InvalidProofShape)
        );
        assert!(VerifierMode::NoProof.validate_proof_shape(&[]).is_ok());
        assert_eq!(
            VerifierMode::NoProof.validate_proof_shape(&[42]),
            Err(VerifierModeError::InvalidProofShape)
        );
        assert_eq!(
            VerifierMode::try_from(VerifierMode::NoProof.config_hash()),
            Ok(VerifierMode::NoProof)
        );
    }

    #[test]
    fn batch_attestation_hash_matches_solidity_golden_vector() {
        let output = BatchOutput {
            next_zone_height: 14,
            block_transition: BlockTransition {
                prevBlockHash: B256::with_last_byte(1),
                nextBlockHash: B256::with_last_byte(2),
            },
            deposit_queue_transition: DepositQueueTransition {
                prevProcessedHash: B256::with_last_byte(3),
                nextProcessedHash: B256::with_last_byte(4),
                prevDepositNumber: 5,
                nextDepositNumber: 6,
            },
            token_enablement_transition: TokenEnablementTransition {
                prevProcessedTokenCount: 7,
                nextProcessedTokenCount: 8,
            },
            withdrawal_queue_hash: B256::with_last_byte(9),
            last_batch_commitment: LastBatchCommitment {
                withdrawal_batch_index: 10,
            },
        };

        let public_inputs = PublicInputs {
            parent_chain_id: 42_431,
            zone_id: 12,
            tempo_block_number: 9,
            anchor_block_number: 10,
            anchor_block_hash: B256::with_last_byte(11),
            expected_withdrawal_batch_index: 13,
        };
        assert!(
            serde_json::to_value(&public_inputs)
                .unwrap()
                .get("portal")
                .is_none()
        );
        let digest = nitro_batch_attestation_hash(&public_inputs, &output);
        let mut other_height = output.clone();
        other_height.next_zone_height += 1;
        assert_ne!(
            nitro_batch_attestation_hash(&public_inputs, &other_height),
            digest
        );
        let mut other_zone = public_inputs.clone();
        other_zone.zone_id += 1;
        assert_ne!(nitro_batch_attestation_hash(&other_zone, &output), digest);
        let mut other_parent = public_inputs.clone();
        other_parent.parent_chain_id += 1;
        assert_ne!(nitro_batch_attestation_hash(&other_parent, &output), digest);
        assert_eq!(
            nitro_batch_attestation_hash(&public_inputs, &output),
            alloy_primitives::b256!(
                "0x1a703e80dd395e4720d1c88c877ed9f7d77c03052a985133b25cbf3e2b745b9d"
            ),
        );
    }

    #[test]
    fn batch_attestation_hash_binds_token_enablement_progress() {
        let mut output = BatchOutput {
            next_zone_height: 1,
            block_transition: BlockTransition {
                prevBlockHash: B256::ZERO,
                nextBlockHash: B256::ZERO,
            },
            deposit_queue_transition: DepositQueueTransition {
                prevProcessedHash: B256::ZERO,
                nextProcessedHash: B256::ZERO,
                prevDepositNumber: 0,
                nextDepositNumber: 0,
            },
            token_enablement_transition: TokenEnablementTransition {
                prevProcessedTokenCount: 0,
                nextProcessedTokenCount: 0,
            },
            withdrawal_queue_hash: B256::ZERO,
            last_batch_commitment: LastBatchCommitment {
                withdrawal_batch_index: 0,
            },
        };
        let public_inputs = PublicInputs {
            parent_chain_id: 1,
            zone_id: 1,
            tempo_block_number: 1,
            anchor_block_number: 1,
            anchor_block_hash: B256::ZERO,
            expected_withdrawal_batch_index: 1,
        };
        let expected = nitro_batch_attestation_hash(&public_inputs, &output);

        output.token_enablement_transition.prevProcessedTokenCount = 1;
        assert_ne!(
            nitro_batch_attestation_hash(&public_inputs, &output),
            expected
        );

        output.token_enablement_transition.prevProcessedTokenCount = 0;
        output.token_enablement_transition.nextProcessedTokenCount = 1;
        assert_ne!(
            nitro_batch_attestation_hash(&public_inputs, &output),
            expected
        );
    }
}
