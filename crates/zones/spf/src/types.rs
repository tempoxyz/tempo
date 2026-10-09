//! Public witness and commitment types for the Zone SPF.

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, U256};
use tempo_primitives::TempoHeader;

pub use tempo_zone_contracts::{
    BlockTransition, ChaumPedersenProof, DecryptionData, DepositQueueTransition, DepositType,
    EnabledToken, QueuedDeposit, TokenEnablementTransition,
};
use zone_chainspec::ZoneChainSpec;
use zone_evm::ZoneEvmConfig;
use zone_precompiles::L1StorageReader;

/// Trusted network configuration for Zone execution.
///
/// This is deliberately separate from [`BatchWitness`]: it is selected by the
/// verifier for the Zone it serves, not supplied by the prover. The chain
/// specification contains the actual Zone genesis and the parent Tempo hard-fork
/// schedule. Block gas limits and other inherited execution fields come from the
/// canonical parent Tempo header carried by the witness.
#[derive(Debug, Clone)]
pub struct SpfConfig {
    chain_spec: Arc<ZoneChainSpec>,
}

impl SpfConfig {
    /// Creates a new [`SpfConfig`] with the given composed chainspec.
    /// The portal is derived from the zone ID encoded in the chainspec.
    pub fn new(chain_spec: Arc<ZoneChainSpec>) -> Self {
        Self { chain_spec }
    }

    /// Returns a reference to the [`ZoneChainSpec`].
    pub fn chain_spec(&self) -> &Arc<ZoneChainSpec> {
        &self.chain_spec
    }

    /// Returns the canonical TIP-1091 portal address for this zone.
    pub fn portal(&self) -> Address {
        tempo_precompiles::zone_factory::portal_address(self.chain_spec.zone_id())
    }

    /// Crates a [`ZoneEvmConfig`] for the given L1 storage reader.
    pub fn evm_config<L1: L1StorageReader>(&self, l1_provider: L1) -> ZoneEvmConfig<L1> {
        ZoneEvmConfig::new(self.chain_spec.clone(), l1_provider, self.portal())
    }
}

/// Public values that the verifier binds to a submitted batch proof.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct PublicInputs {
    /// Parent Tempo chain ID used to domain-separate the Zone EVM chain ID.
    pub parent_chain_id: u64,
    /// Zone identifier from which the SPF derives the EVM chain ID.
    pub zone_id: u32,
    /// Tempo block number committed by the submitted batch.
    pub tempo_block_number: u64,
    /// Tempo block number used to anchor this batch.
    pub anchor_block_number: u64,
    /// Block hash for `anchor_block_number`.
    pub anchor_block_hash: B256,
    /// Withdrawal batch index expected by the portal.
    pub expected_withdrawal_batch_index: u64,
}

/// Complete prover input for one Zone batch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct BatchWitness {
    /// Values committed by the verifier.
    pub public_inputs: PublicInputs,
    /// Canonical Tempo header of the first Zone block's parent. Its hash and
    /// state root anchor the batch and its execution fields seed replay.
    #[cfg_attr(feature = "serde", serde(with = "zone_primitives::serde_rlp"))]
    pub parent_header: TempoHeader,
    /// Zone blocks in execution order.
    pub zone_blocks: Vec<ZoneBlock>,
    /// Stateless witness for the Zone state at the start of the batch.
    pub zone_state_witness: ZoneStateWitness,
    /// Stateless witness for Tempo state reads performed during the batch.
    pub tempo_state_witness: TempoStateWitness,
    /// RLP-encoded headers ordered from `tempo_block_number + 1` through the
    /// anchor block when ancestry verification is needed.
    pub tempo_ancestry_headers: Vec<Bytes>,
}

/// Typed inputs for the opening ZoneInbox system transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub enum TempoImport {
    Full {
        header_rlp: Bytes,
        deposits: Vec<QueuedDeposit>,
        decryptions: Vec<DecryptionData>,
        enabled_tokens: Vec<EnabledToken>,
    },
    CheckpointOnly {
        headers_rlp: Vec<Bytes>,
    },
}

impl TempoImport {
    pub fn headers_rlp(&self) -> &[Bytes] {
        match self {
            Self::Full { header_rlp, .. } => core::slice::from_ref(header_rlp),
            Self::CheckpointOnly { headers_rlp } => headers_rlp,
        }
    }

    pub fn deposits(&self) -> &[QueuedDeposit] {
        match self {
            Self::Full { deposits, .. } => deposits,
            Self::CheckpointOnly { .. } => &[],
        }
    }
}

/// Zone block input, including its system-call inputs and raw user transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct ZoneBlock {
    pub number: u64,
    pub parent_hash: B256,
    pub timestamp: u64,
    pub timestamp_millis_part: u64,
    pub beneficiary: Address,
    pub tempo_import: TempoImport,
    /// Withdrawal count passed to finalization in this block, if any.
    pub finalize_withdrawal_batch_count: Option<U256>,
    /// Encrypted sender payloads passed to withdrawal finalization.
    pub finalize_withdrawal_batch_encrypted_senders: Vec<Bytes>,
    /// Raw signed user transactions in execution order.
    pub transactions: Vec<Bytes>,
}

/// Stateless Zone state input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct ZoneStateWitness {
    /// Deduplicated RLP-encoded nodes used for Zone state reads.
    pub node_pool: Vec<Bytes>,
    /// Deduplicated bytecode preimages, indexed by `keccak256(bytecode)`.
    pub bytecodes: Vec<Bytes>,
}

/// Stateless Tempo state input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct TempoStateWitness {
    /// RLP-encoded header for the Tempo checkpoint bound in the initial Zone
    /// state. Its decoded state root anchors initial Tempo reads.
    pub initial_tempo_header_rlp: Bytes,
    /// Deduplicated RLP-encoded MPT nodes used for Tempo state reads.
    pub node_pool: Vec<Bytes>,
}

/// Commitments returned by a successful Zone batch transition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct BatchOutput {
    /// Number of the final executed Zone header committed by `block_transition.nextBlockHash`.
    pub next_zone_height: u64,
    /// Hash transition covering every Zone block in the batch.
    pub block_transition: BlockTransition,
    /// Progress of the ZoneInbox deposit queue during the batch.
    pub deposit_queue_transition: DepositQueueTransition,
    /// Progress of the append-only portal token-enablement prefix during the batch.
    pub token_enablement_transition: TokenEnablementTransition,
    /// Hash chain created by finalizing the batch's withdrawals.
    pub withdrawal_queue_hash: B256,
    /// Batch index committed by `ZoneOutbox.lastBatch`.
    pub last_batch_commitment: LastBatchCommitment,
}

/// The portion of `ZoneOutbox.lastBatch` independently committed by the SPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
pub struct LastBatchCommitment {
    pub withdrawal_batch_index: u64,
}
