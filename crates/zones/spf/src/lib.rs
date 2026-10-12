//! Stateless state transition function for Tempo Zones.
//!
//! The implementation is built incrementally around strict witness-backed
//! execution. It is presently a normal Rust verifier rather than a `no_std`
//! proving guest.

use alloy_consensus::{BlockHeader as _, Sealable as _};
use alloy_primitives::{B256, U256, keccak256};
use reth_chainspec::EthChainSpec as _;
use reth_evm::execute::BlockAssemblerInput;
use reth_primitives_traits::SealedHeader;
use reth_storage_api::noop::NoopProvider;
use revm::{Database as _, database::State, database_interface::bal::EvmDatabaseError};
use tempo_evm::{TempoBlockAssembler, TempoEvmConfig};
use tempo_primitives::{TempoHeader, TempoPrimitives};
use zone_precompiles::{inbox, outbox, tempo_state};
use zone_primitives::constants::{
    MAX_UNPROCESSED_DEPOSITS, MAX_UNPROCESSED_TOKEN_ENABLEMENTS, TEMPO_STATE_ADDRESS,
    ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
};

mod execution;
mod mpt;
mod types;

pub use execution::database::{TempoWitnessDatabase, WitnessDatabase, WitnessDatabaseError};
pub use mpt::StatelessSparseTrieError;
pub use types::*;

/// Execute a Zone batch witness and return its public commitments.
///
/// `config` is trusted network configuration chosen by the verifier. Every
/// other value is prover supplied and must be validated against witness-backed
/// execution. The prover launches with TIP-1096, so every batch must end at a full
/// block's withdrawal finalization boundary.
pub fn prove_zone_batch(config: &SpfConfig, witness: BatchWitness) -> Result<BatchOutput, Error> {
    // The parent header is the committed starting point for this batch. Its
    // hash binds the witness to the previously submitted Zone block, and its
    // state root selects the initial Zone state.
    if witness.zone_blocks.is_empty() {
        return Err(Error::EmptyZoneBatch);
    }
    let expected_chain_id = zone_primitives::constants::zone_chain_id(
        witness.public_inputs.parent_chain_id,
        witness.public_inputs.zone_id,
    )?;
    let configured_chain_id = config.chain_spec().chain_id();
    if configured_chain_id != expected_chain_id {
        return Err(Error::ChainIdMismatch {
            expected: configured_chain_id,
            actual: expected_chain_id,
        });
    }

    // The Zone database is backed by the parent state root and the supplied
    // trie nodes. Reads performed during execution are therefore limited to
    // state proven by the witness, while writes remain in REVM's overlay.
    let zone_database = WitnessDatabase::from_zone_state_witness(
        witness.zone_state_witness,
        witness.parent_header.state_root(),
    )?;
    let mut zone_state = State::builder()
        .with_database(zone_database)
        .with_bundle_update()
        .build();

    // Capture the pre-batch deposit state from the parent Zone state. The
    // transition output commits to this exact pair.
    let previous_processed_hash = B256::from(read_zone_storage(
        &mut zone_state,
        ZONE_INBOX_ADDRESS,
        inbox::slots::PROCESSED_DEPOSIT_QUEUE_HASH,
    )?);
    let previous_processed_number = read_zone_storage(
        &mut zone_state,
        ZONE_INBOX_ADDRESS,
        inbox::slots::PROCESSED_DEPOSIT_NUMBER,
    )?
    .to::<u64>();
    // Keep the public transition anchored to the physical pre-state. On the first T13 batch this
    // is zero; ZoneInbox authenticates the legacy hash prefix internally before writing the
    // migrated count, so rewriting this value would diverge from settlement attestations.
    let previous_processed_token_count = read_zone_storage(
        &mut zone_state,
        ZONE_INBOX_ADDRESS,
        inbox::slots::PROCESSED_ENABLED_TOKEN_COUNT,
    )?
    .to::<u64>();

    // The initial Tempo header supplies the root for Tempo-side reads. The
    // Zone's own TempoState must already contain the same number and hash;
    // otherwise the witness would describe a different L1 checkpoint.
    let mut tempo_database =
        TempoWitnessDatabase::from_tempo_state_witness(witness.tempo_state_witness)?;
    let (witnessed_tempo_number, witnessed_tempo_hash) = tempo_database.checkpoint();
    let zone_tempo_hash = B256::from(read_zone_storage(
        &mut zone_state,
        TEMPO_STATE_ADDRESS,
        tempo_state::slots::TEMPO_BLOCK_HASH,
    )?);
    let zone_tempo_number = read_zone_storage(
        &mut zone_state,
        TEMPO_STATE_ADDRESS,
        tempo_state::slots::TEMPO_BLOCK_NUMBER,
    )?
    .to::<u64>();
    if (zone_tempo_number, zone_tempo_hash) != (witnessed_tempo_number, witnessed_tempo_hash) {
        return Err(Error::InitialTempoCheckpointMismatch {
            expected_number: zone_tempo_number,
            expected_hash: zone_tempo_hash,
            actual_number: witnessed_tempo_number,
            actual_hash: witnessed_tempo_hash,
        });
    }

    // Each block is checked against the canonical Tempo header produced by its
    // predecessor. Replay feeds the execution result through Tempo's block
    // assembler, which derives the aggregate logs bloom from the receipts.
    let initial_parent_hash = witness.parent_header.hash_slow();
    // ZonePortal represents the parent of the first submitted batch with the
    // zero pre-genesis sentinel, even though block 1 executes on top of the
    // canonical (non-zero) genesis block hash.
    let output_parent_hash = if witness.zone_blocks[0].number == 1 {
        B256::ZERO
    } else {
        initial_parent_hash
    };
    let mut previous_header = witness.parent_header.clone();
    for (block_index, block) in witness.zone_blocks.iter().enumerate() {
        let expected_parent_hash = previous_header.hash_slow();
        if block.parent_hash != expected_parent_hash {
            return Err(Error::BlockParentHashMismatch {
                block_index,
                block_number: block.number,
                expected: expected_parent_hash,
                actual: block.parent_hash,
            });
        }

        let expected_number = previous_header
            .number()
            .checked_add(1)
            .ok_or(Error::BlockNumberOverflow)?;
        if block.number != expected_number {
            return Err(Error::BlockNumberMismatch {
                expected: expected_number,
                actual: block.number,
            });
        }
        validate_zone_block_timestamp(block, block_index, &previous_header)?;

        validate_system_inputs(block, block_index)?;
        let is_last = block_index + 1 == witness.zone_blocks.len();
        validate_batch_block_shape(block, is_last)?;

        // The EVM environment uses the verifier-selected fork schedule at this
        // block's timestamp. An imported Tempo header changes the L1 reader
        // used by the subsequent system and user execution in this block.
        let final_imported_header = block
            .tempo_import
            .headers_rlp()
            .last()
            .expect("validated nonempty Tempo headers");
        tempo_database = tempo_database.with_imported_checkpoint(final_imported_header)?;
        let executed_block = execution::evm::execute_zone_block(
            &mut zone_state,
            config.evm_config(tempo_database.clone()),
            execution::evm::BlockReplayContext {
                parent: &previous_header,
                block_index,
            },
            block,
        );
        let executed_block = match executed_block {
            Ok(executed_block) => executed_block,
            Err(error) => {
                if let Some(missing) = tempo_database.missing_read() {
                    return Err(Error::MissingTempoStorage {
                        account: missing.account,
                        slot: missing.slot,
                        block_number: missing.block_number,
                    });
                }
                return Err(error);
            }
        };

        let bundle_state = zone_state.take_bundle();
        let state_root = zone_state.database.state_root(bundle_state)?;
        let gas_limit = executed_block.evm_env.block_env.inner.gas_limit;
        let execution_context =
            execution::evm::next_block_execution_context(config.chain_spec(), block, gas_limit);
        let state_provider = NoopProvider::<tempo_chainspec::TempoChainSpec, TempoPrimitives>::new(
            config.chain_spec().inner.clone(),
        );
        let sealed_parent = SealedHeader::new_unhashed(previous_header.clone());
        let assembled = TempoBlockAssembler::new(config.chain_spec().inner.clone())
            .assemble_block(
                BlockAssemblerInput::<TempoEvmConfig, TempoHeader>::new(
                    executed_block.evm_env,
                    execution_context,
                    &sealed_parent,
                    executed_block.transactions,
                    &executed_block.output,
                    &zone_state.bundle_state,
                    &state_provider,
                    state_root,
                    None,
                ),
                None,
                None,
                None,
            )
            .map_err(|_| Error::BlockAssembly { block_index })?;
        previous_header = assembled.header;
    }

    // These reads see the final execution overlay rather than just the parent
    // witness. They are the contract state values committed by the batch
    // output: inbox progress, the finalized withdrawal batch, and TempoState.
    let next_processed_hash = B256::from(read_zone_storage(
        &mut zone_state,
        ZONE_INBOX_ADDRESS,
        inbox::slots::PROCESSED_DEPOSIT_QUEUE_HASH,
    )?);
    let next_processed_number = read_zone_storage(
        &mut zone_state,
        ZONE_INBOX_ADDRESS,
        inbox::slots::PROCESSED_DEPOSIT_NUMBER,
    )?
    .to::<u64>();
    let next_processed_token_count = read_zone_storage(
        &mut zone_state,
        ZONE_INBOX_ADDRESS,
        inbox::slots::PROCESSED_ENABLED_TOKEN_COUNT,
    )?
    .to::<u64>();
    let has_withdrawal_finalization = witness
        .zone_blocks
        .iter()
        .any(|block| block.finalize_withdrawal_batch_count.is_some());
    let (withdrawal_queue_hash, withdrawal_batch_index) = if has_withdrawal_finalization {
        let hash = B256::from(read_zone_storage(
            &mut zone_state,
            ZONE_OUTBOX_ADDRESS,
            outbox::slots::WITHDRAWAL_QUEUE_HASH,
        )?);
        let index_slot = read_zone_storage(
            &mut zone_state,
            ZONE_OUTBOX_ADDRESS,
            outbox::slots::WITHDRAWAL_BATCH_INDEX,
        )?;
        // The index occupies the low 64 bits of a packed Solidity slot.
        (hash, index_slot.as_limbs()[0])
    } else {
        (
            B256::ZERO,
            witness.public_inputs.expected_withdrawal_batch_index,
        )
    };
    let final_tempo_hash = B256::from(read_zone_storage(
        &mut zone_state,
        TEMPO_STATE_ADDRESS,
        tempo_state::slots::TEMPO_BLOCK_HASH,
    )?);
    let final_tempo_number = read_zone_storage(
        &mut zone_state,
        TEMPO_STATE_ADDRESS,
        tempo_state::slots::TEMPO_BLOCK_NUMBER,
    )?
    .to::<u64>();

    // The final Tempo checkpoint must be the publicly declared target. When
    // the anchor is newer, the supplied headers extend that checkpoint to the
    // public anchor hash.
    if final_tempo_number != witness.public_inputs.tempo_block_number {
        return Err(Error::FinalTempoBlockNumberMismatch {
            expected: witness.public_inputs.tempo_block_number,
            actual: final_tempo_number,
        });
    }
    validate_tempo_anchor(
        final_tempo_number,
        final_tempo_hash,
        &witness.public_inputs,
        &witness.tempo_ancestry_headers,
    )?;

    // The result links the public parent hash to the final carried header and
    // exposes the state transitions the portal will commit on successful proof
    // verification.
    if withdrawal_batch_index != witness.public_inputs.expected_withdrawal_batch_index {
        return Err(Error::WithdrawalBatchIndexMismatch {
            expected: witness.public_inputs.expected_withdrawal_batch_index,
            actual: withdrawal_batch_index,
        });
    }
    Ok(BatchOutput {
        next_zone_height: previous_header.number(),
        block_transition: BlockTransition {
            prevBlockHash: output_parent_hash,
            nextBlockHash: previous_header.hash_slow(),
        },
        deposit_queue_transition: DepositQueueTransition {
            prevProcessedHash: previous_processed_hash,
            nextProcessedHash: next_processed_hash,
            prevDepositNumber: previous_processed_number,
            nextDepositNumber: next_processed_number,
        },
        token_enablement_transition: TokenEnablementTransition {
            prevProcessedTokenCount: previous_processed_token_count,
            nextProcessedTokenCount: next_processed_token_count,
        },
        withdrawal_queue_hash,
        last_batch_commitment: LastBatchCommitment {
            withdrawal_batch_index,
        },
    })
}

/// Validates witness-controlled timestamp fields before they select fork rules or enter the EVM.
fn validate_zone_block_timestamp(
    block: &ZoneBlock,
    block_index: usize,
    parent: &TempoHeader,
) -> Result<(), Error> {
    if block.timestamp_millis_part >= 1000 {
        return Err(Error::InvalidTimestampMillisPart {
            block_index,
            actual: block.timestamp_millis_part,
        });
    }

    let actual = block
        .timestamp
        .checked_mul(1000)
        .and_then(|timestamp| timestamp.checked_add(block.timestamp_millis_part))
        .ok_or(Error::BlockTimestampOverflow { block_index })?;
    let previous = parent
        .timestamp()
        .checked_mul(1000)
        .and_then(|timestamp| timestamp.checked_add(parent.timestamp_millis_part))
        .ok_or(Error::ParentTimestampOverflow { block_index })?;
    if actual < previous {
        return Err(Error::BlockTimestampRegression { previous, actual });
    }

    Ok(())
}

fn read_zone_storage(
    zone_state: &mut State<WitnessDatabase>,
    address: alloy_primitives::Address,
    slot: U256,
) -> Result<U256, Error> {
    match zone_state.storage(address, slot) {
        Ok(value) => Ok(value),
        Err(EvmDatabaseError::Database(error)) => Err(error.into()),
        Err(EvmDatabaseError::Bal(_)) => Err(Error::UnexpectedBalancedAccess { address, slot }),
    }
}

fn validate_tempo_anchor(
    tempo_block_number: u64,
    tempo_block_hash: B256,
    public_inputs: &PublicInputs,
    ancestry_headers: &[alloy_primitives::Bytes],
) -> Result<(), Error> {
    if public_inputs.anchor_block_number < tempo_block_number {
        return Err(Error::AnchorBlockNumberBeforeTempo {
            tempo_block_number,
            anchor_block_number: public_inputs.anchor_block_number,
        });
    }

    if public_inputs.anchor_block_number == tempo_block_number {
        if !ancestry_headers.is_empty() {
            return Err(Error::UnexpectedTempoAncestryHeaders);
        }
        if tempo_block_hash != public_inputs.anchor_block_hash {
            return Err(Error::TempoAnchorHashMismatch {
                expected: public_inputs.anchor_block_hash,
                actual: tempo_block_hash,
            });
        }
        return Ok(());
    }

    let expected_len = (public_inputs.anchor_block_number - tempo_block_number) as usize;
    if ancestry_headers.len() != expected_len {
        return Err(Error::TempoAncestryLengthMismatch {
            expected: expected_len,
            actual: ancestry_headers.len(),
        });
    }

    let mut previous_number = tempo_block_number;
    let mut previous_hash = tempo_block_hash;
    for (index, encoded_header) in ancestry_headers.iter().enumerate() {
        let header: TempoHeader = alloy_rlp::decode_exact(encoded_header)
            .map_err(|_| Error::TempoAncestryHeaderDecoding { index })?;
        let expected_number = previous_number
            .checked_add(1)
            .ok_or(Error::TempoAncestryBlockNumberOverflow)?;
        if header.number() != expected_number {
            return Err(Error::TempoAncestryHeaderNumberMismatch {
                index,
                expected: expected_number,
                actual: header.number(),
            });
        }
        if header.parent_hash() != previous_hash {
            return Err(Error::TempoAncestryParentHashMismatch {
                index,
                expected: previous_hash,
                actual: header.parent_hash(),
            });
        }
        previous_number = header.number();
        previous_hash = keccak256(encoded_header);
    }

    if previous_hash != public_inputs.anchor_block_hash {
        return Err(Error::TempoAnchorHashMismatch {
            expected: public_inputs.anchor_block_hash,
            actual: previous_hash,
        });
    }
    Ok(())
}

fn validate_batch_block_shape(block: &ZoneBlock, is_last: bool) -> Result<(), Error> {
    let valid = match (&block.tempo_import, is_last) {
        (TempoImport::CheckpointOnly { .. }, false) => true,
        (TempoImport::Full { .. }, false) => block.finalize_withdrawal_batch_count.is_none(),
        (TempoImport::Full { .. }, true) => block.finalize_withdrawal_batch_count.is_some(),
        (TempoImport::CheckpointOnly { .. }, true) => false,
    };
    if !valid {
        return Err(Error::InvalidBatchShape);
    }
    Ok(())
}

fn validate_system_inputs(block: &ZoneBlock, index: usize) -> Result<(), Error> {
    if block.tempo_import.headers_rlp().is_empty() {
        return Err(Error::MissingTempoHeaders { block_index: index });
    }
    match &block.tempo_import {
        TempoImport::Full {
            deposits,
            enabled_tokens,
            ..
        } => {
            if deposits.len() > MAX_UNPROCESSED_DEPOSITS
                || enabled_tokens.len() > MAX_UNPROCESSED_TOKEN_ENABLEMENTS
            {
                return Err(Error::PortalWorkCapacityExceeded { block_index: index });
            }
        }
        TempoImport::CheckpointOnly { .. } => {
            if !block.transactions.is_empty()
                || block.finalize_withdrawal_batch_count.is_some()
                || !block.finalize_withdrawal_batch_encrypted_senders.is_empty()
            {
                return Err(Error::InvalidCheckpointOnlyBlock { block_index: index });
            }
        }
    }
    match block.finalize_withdrawal_batch_count {
        Some(count)
            if count != U256::from(block.finalize_withdrawal_batch_encrypted_senders.len()) =>
        {
            return Err(Error::FinalizationEncryptedSenderCountMismatch {
                block_index: index,
                expected: count,
                actual: block.finalize_withdrawal_batch_encrypted_senders.len(),
            });
        }
        None if !block.finalize_withdrawal_batch_encrypted_senders.is_empty() => {
            return Err(Error::FinalizationEncryptedSendersWithoutCount { block_index: index });
        }
        _ => {}
    }

    Ok(())
}

/// Errors emitted by the stateless state transition function.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The verifier-bound parent and Zone IDs cannot produce a valid chain ID.
    #[error(transparent)]
    ZoneChainId(#[from] zone_primitives::constants::ZoneChainIdError),
    /// The Zone MPT witness did not prove one of its supplied reads.
    #[error(transparent)]
    MptValidation(#[from] StatelessSparseTrieError),
    /// A read against the provided state witness failed.
    #[error(transparent)]
    WitnessDatabase(#[from] WitnessDatabaseError),
    /// The Tempo witness omitted an L1 storage proof required by execution.
    #[error("Tempo witness is missing account {account:?} slot {slot:?} at block {block_number}")]
    MissingTempoStorage {
        account: alloy_primitives::Address,
        slot: B256,
        block_number: u64,
    },
    /// A batch must execute at least one Zone block.
    #[error("zone batch contains no blocks")]
    EmptyZoneBatch,
    /// A checkpoint-only block carried operational inputs or transactions.
    #[error("checkpoint-only zone block {block_index} contains operational inputs")]
    InvalidCheckpointOnlyBlock { block_index: usize },
    /// A block did not import any Tempo headers.
    #[error("zone block {block_index} contains no Tempo headers")]
    MissingTempoHeaders { block_index: usize },
    /// A full block exceeded a protocol-wide outstanding portal-work bound.
    #[error("zone block {block_index} exceeds portal-work capacity")]
    PortalWorkCapacityExceeded { block_index: usize },
    /// A batch must end in a full operational block that finalizes withdrawals. Intermediate
    /// blocks may use either Tempo import variant, but must not finalize withdrawals.
    #[error("invalid batch shape")]
    InvalidBatchShape,
    /// The witness identifies a Zone other than the verifier-selected chain specification.
    #[error("Zone chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },
    /// The initial Tempo witness header is not the checkpoint stored in the
    /// parent Zone state.
    #[error(
        "initial Tempo checkpoint mismatch: expected ({expected_number}, {expected_hash:?}), got ({actual_number}, {actual_hash:?})"
    )]
    InitialTempoCheckpointMismatch {
        expected_number: u64,
        expected_hash: B256,
        actual_number: u64,
        actual_hash: B256,
    },
    /// A Zone block is not chained to the replayed preceding header.
    #[error(
        "zone block {block_number} (batch index {block_index}) parent hash mismatch: expected {expected:?}, got {actual:?}"
    )]
    BlockParentHashMismatch {
        block_index: usize,
        block_number: u64,
        expected: B256,
        actual: B256,
    },
    /// A Zone block number does not increment by one.
    #[error("zone block number mismatch: expected {expected}, got {actual}")]
    BlockNumberMismatch { expected: u64, actual: u64 },
    /// Zone block numbering cannot advance past `u64::MAX`.
    #[error("zone block number overflow")]
    BlockNumberOverflow,
    /// A witness supplied a value outside the millisecond component's canonical domain.
    #[error("zone block {block_index} has invalid timestamp millisecond component {actual}")]
    InvalidTimestampMillisPart { block_index: usize, actual: u64 },
    /// A witness-controlled Zone timestamp could not be represented in milliseconds.
    #[error("zone block {block_index} timestamp overflows milliseconds")]
    BlockTimestampOverflow { block_index: usize },
    /// A parent Zone timestamp could not be represented in milliseconds.
    #[error("parent of zone block {block_index} has a timestamp that overflows milliseconds")]
    ParentTimestampOverflow { block_index: usize },
    /// A Zone block's full millisecond timestamp regressed from its predecessor.
    #[error("zone block millisecond timestamp regressed: previous {previous}, got {actual}")]
    BlockTimestampRegression { previous: u64, actual: u64 },
    /// Tempo-dependent inputs appeared without a Tempo header import.
    #[error("zone block {block_index} has Tempo inputs without a Tempo header")]
    TempoInputsWithoutHeader { block_index: usize },
    /// Finalization sender data was supplied without a finalization count.
    #[error("zone block {block_index} has finalization senders without a count")]
    FinalizationEncryptedSendersWithoutCount { block_index: usize },
    /// Finalization sender data has a different length than its declared count.
    #[error(
        "zone block {block_index} finalization sender count mismatch: expected {expected}, got {actual}"
    )]
    FinalizationEncryptedSenderCountMismatch {
        block_index: usize,
        expected: alloy_primitives::U256,
        actual: usize,
    },
    /// A raw user transaction was not a complete Tempo EIP-2718 envelope.
    #[error("failed to decode transaction {transaction_index} in zone block {block_index}")]
    TransactionDecoding {
        block_index: usize,
        transaction_index: usize,
    },
    /// A system transaction appeared in the user-transaction list.
    #[error(
        "system transaction {transaction_index} appeared in zone block {block_index} user transactions"
    )]
    SystemTransactionInUserList {
        block_index: usize,
        transaction_index: usize,
    },
    /// Production block pre-execution changes could not be applied.
    #[error("failed to apply pre-execution changes in zone block {block_index}")]
    BlockPreExecution { block_index: usize },
    /// A canonical parent Zone header must carry its zero base fee.
    #[error("zone block {block_index} parent header is missing its base fee")]
    MissingParentBaseFee { block_index: usize },
    /// The ZoneInbox system transaction failed while advancing Tempo.
    #[error("failed to execute advanceTempo in zone block {block_index}")]
    AdvanceTempoExecution { block_index: usize },
    /// The ZoneInbox system transaction reverted while advancing Tempo.
    #[error("advanceTempo reverted in zone block {block_index}: {reason}; data: {output}")]
    AdvanceTempoRevert {
        block_index: usize,
        reason: String,
        output: alloy_primitives::Bytes,
    },
    /// The ZoneOutbox system transaction failed while finalizing withdrawals.
    #[error("failed to execute finalizeWithdrawalBatch in zone block {block_index}")]
    FinalizeWithdrawalBatchExecution { block_index: usize },
    /// A decoded user transaction had an invalid sender signature.
    #[error("invalid signature for transaction {transaction_index} in zone block {block_index}")]
    TransactionSignature {
        block_index: usize,
        transaction_index: usize,
    },
    /// The Tempo EVM rejected or failed to execute a user transaction.
    #[error("failed to execute transaction {transaction_index} in zone block {block_index}")]
    TransactionExecution {
        block_index: usize,
        transaction_index: usize,
    },
    /// Production block post-execution changes could not be finalized.
    #[error("failed to finalize execution of zone block {block_index}")]
    BlockPostExecution { block_index: usize },
    /// The canonical Tempo block header could not be assembled.
    #[error("failed to assemble canonical header for zone block {block_index}")]
    BlockAssembly { block_index: usize },
    /// The production Tempo EVM environment could not be constructed.
    #[error("failed to construct Zone EVM environment")]
    EvmEnvironment,
    /// An internal post-execution state read unexpectedly hit BAL state.
    #[error("unexpected balanced access while reading {address:?} slot {slot:?}")]
    UnexpectedBalancedAccess {
        address: alloy_primitives::Address,
        slot: U256,
    },
    /// The final Tempo checkpoint number differs from the public value.
    #[error("final Tempo block number mismatch: expected {expected}, got {actual}")]
    FinalTempoBlockNumberMismatch { expected: u64, actual: u64 },
    /// The requested anchor predates the proven Tempo checkpoint.
    #[error("Tempo anchor block {anchor_block_number} precedes checkpoint {tempo_block_number}")]
    AnchorBlockNumberBeforeTempo {
        tempo_block_number: u64,
        anchor_block_number: u64,
    },
    /// Direct Tempo anchoring must not include ancestry headers.
    #[error("direct Tempo anchor included ancestry headers")]
    UnexpectedTempoAncestryHeaders,
    /// The supplied ancestry chain has the wrong number of headers.
    #[error("Tempo ancestry length mismatch: expected {expected}, got {actual}")]
    TempoAncestryLengthMismatch { expected: usize, actual: usize },
    /// An ancestry header is not complete Tempo header RLP.
    #[error("invalid Tempo ancestry header at index {index}")]
    TempoAncestryHeaderDecoding { index: usize },
    /// An ancestry header number is not consecutive.
    #[error("Tempo ancestry header {index} number mismatch: expected {expected}, got {actual}")]
    TempoAncestryHeaderNumberMismatch {
        index: usize,
        expected: u64,
        actual: u64,
    },
    /// Tempo block numbering overflowed while validating ancestry.
    #[error("Tempo ancestry block number overflow")]
    TempoAncestryBlockNumberOverflow,
    /// An ancestry header does not point to the preceding Tempo block.
    #[error(
        "Tempo ancestry header {index} parent hash mismatch: expected {expected:?}, got {actual:?}"
    )]
    TempoAncestryParentHashMismatch {
        index: usize,
        expected: B256,
        actual: B256,
    },
    /// The direct Tempo checkpoint or ancestry chain did not reach the anchor.
    #[error("Tempo anchor hash mismatch: expected {expected:?}, got {actual:?}")]
    TempoAnchorHashMismatch { expected: B256, actual: B256 },
    /// The final withdrawal batch index does not match the public value.
    #[error("withdrawal batch index mismatch: expected {expected}, got {actual}")]
    WithdrawalBatchIndexMismatch { expected: u64, actual: u64 },
}

#[cfg(test)]
mod tests {
    use crate::execution::evm::next_block_env_attributes;

    use super::*;
    use alloy_consensus::Header;
    use alloy_eips::eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
    use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
    use reth_evm::ConfigureEvm;
    use reth_trie_common::{
        EMPTY_ROOT_HASH, LeafNode, Nibbles, TrieAccount, TrieNode, root::state_root_unhashed,
    };
    use revm::{
        DatabaseCommit as _,
        database::{State, states::bundle_state::BundleRetention},
    };
    use std::sync::Arc;
    use tempo_chainspec::TempoHardfork;
    use tempo_evm::TempoBlockEnv;
    use tempo_primitives::TempoHeader;
    use zone_evm::ZoneEvmConfig;
    use zone_precompiles::L1StorageReader as _;
    use zone_primitives::constants::zone_chain_id;

    fn test_config() -> SpfConfig {
        let tempo_chain_spec = tempo_chainspec::spec::MODERATO.clone();
        let mut genesis = tempo_chain_spec.genesis().clone();
        genesis.config.chain_id = zone_chain_id(tempo_chain_spec.chain_id(), 1).unwrap();
        let zone_chain_spec =
            Arc::new(zone_chainspec::ZoneChainSpec::from_genesis(genesis).unwrap());
        SpfConfig::new(zone_chain_spec)
    }

    #[test]
    fn derives_portal_from_the_chain_spec_zone_id() {
        let parent = tempo_chainspec::spec::MODERATO.clone();
        let mut genesis = parent.genesis().clone();
        genesis.config.chain_id = zone_chain_id(parent.chain_id(), 0x0102_0304).unwrap();
        let spec = Arc::new(zone_chainspec::ZoneChainSpec::from_genesis(genesis).unwrap());
        assert_eq!(
            SpfConfig::new(spec).portal(),
            alloy_primitives::address!("5ad0000000000000000000000000000001020304")
        );
    }

    fn minimal_batch_witness() -> BatchWitness {
        let parent_header = TempoHeader {
            inner: Header {
                state_root: EMPTY_ROOT_HASH,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            shared_gas_limit: 0,
            ..Default::default()
        };

        BatchWitness {
            public_inputs: PublicInputs {
                parent_chain_id: tempo_chainspec::spec::MODERATO.chain_id(),
                zone_id: 1,
                tempo_block_number: 2,
                anchor_block_number: 2,
                anchor_block_hash: B256::ZERO,
                expected_withdrawal_batch_index: 3,
            },
            parent_header,
            zone_blocks: Vec::new(),
            zone_state_witness: ZoneStateWitness {
                node_pool: Vec::new(),
                bytecodes: Vec::new(),
            },
            tempo_state_witness: empty_tempo_witness(2),
            tempo_ancestry_headers: Vec::new(),
        }
    }

    fn empty_tempo_witness(number: u64) -> TempoStateWitness {
        let header = TempoHeader {
            inner: Header {
                number,
                state_root: EMPTY_ROOT_HASH,
                ..Default::default()
            },
            ..Default::default()
        };

        TempoStateWitness {
            initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(header)),
            node_pool: Vec::new(),
        }
    }

    fn full_import(header_rlp: Bytes) -> TempoImport {
        TempoImport::Full {
            header_rlp,
            deposits: Vec::new(),
            decryptions: Vec::new(),
            enabled_tokens: Vec::new(),
        }
    }

    fn checkpoint_import(headers_rlp: Vec<Bytes>) -> TempoImport {
        TempoImport::CheckpointOnly { headers_rlp }
    }

    fn empty_zone_block(timestamp: u64, timestamp_millis_part: u64) -> ZoneBlock {
        ZoneBlock {
            number: 1,
            parent_hash: B256::ZERO,
            timestamp,
            timestamp_millis_part,
            beneficiary: Address::ZERO,
            tempo_import: checkpoint_import(vec![Bytes::from([0x01])]),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        }
    }

    fn witnessed_account_state(
        address: Address,
        nonce: u64,
        balance: U256,
        code_hash: B256,
        bytecodes: Vec<Bytes>,
        storage: Option<(U256, U256)>,
    ) -> (B256, ZoneStateWitness) {
        let mut node_pool = Vec::new();
        let storage_root = match storage {
            Some((slot, value)) => {
                let storage_node = TrieNode::Leaf(LeafNode::new(
                    Nibbles::unpack(keccak256(slot.to_be_bytes::<32>())),
                    alloy_rlp::encode(value),
                ));
                let encoded = alloy_rlp::encode(&storage_node);
                let root = keccak256(&encoded);
                node_pool.push(Bytes::from(encoded));
                root
            }
            None => EMPTY_ROOT_HASH,
        };
        let account = TrieAccount {
            nonce,
            balance,
            storage_root,
            code_hash,
        };
        let account_node = TrieNode::Leaf(LeafNode::new(
            Nibbles::unpack(keccak256(address)),
            alloy_rlp::encode(account),
        ));
        let encoded = alloy_rlp::encode(&account_node);
        let state_root = keccak256(&encoded);
        node_pool.push(Bytes::from(encoded));

        (
            state_root,
            ZoneStateWitness {
                node_pool,
                bytecodes,
            },
        )
    }

    #[test]
    fn constructs_a_minimal_batch_witness() {
        let witness = minimal_batch_witness();

        assert_eq!(witness.public_inputs.zone_id, 1);
        assert!(witness.zone_blocks.is_empty());
    }

    #[test]
    fn rejects_an_empty_zone_batch() {
        let witness = minimal_batch_witness();

        assert_eq!(
            prove_zone_batch(&test_config(), witness),
            Err(Error::EmptyZoneBatch)
        );
    }

    #[test]
    fn validates_complete_millisecond_timestamps_before_execution() {
        let parent = TempoHeader {
            inner: Header {
                timestamp: 100,
                ..Default::default()
            },
            timestamp_millis_part: 500,
            ..Default::default()
        };

        assert_eq!(
            validate_zone_block_timestamp(&empty_zone_block(100, 1000), 3, &parent),
            Err(Error::InvalidTimestampMillisPart {
                block_index: 3,
                actual: 1000,
            })
        );
        assert_eq!(
            validate_zone_block_timestamp(&empty_zone_block(100, 499), 3, &parent),
            Err(Error::BlockTimestampRegression {
                previous: 100_500,
                actual: 100_499,
            })
        );
        assert_eq!(
            validate_zone_block_timestamp(&empty_zone_block(u64::MAX, 0), 3, &parent),
            Err(Error::BlockTimestampOverflow { block_index: 3 })
        );

        // Zone consensus permits equal full-millisecond timestamps.
        assert_eq!(
            validate_zone_block_timestamp(&empty_zone_block(100, 500), 3, &parent),
            Ok(())
        );
        assert_eq!(
            validate_zone_block_timestamp(&empty_zone_block(100, 501), 3, &parent),
            Ok(())
        );
    }

    #[test]
    fn batch_shape_rejects_intermediate_finalization() {
        let mut witness = minimal_batch_witness();
        for number in 1..=2 {
            witness.zone_blocks.push(ZoneBlock {
                number,
                parent_hash: B256::ZERO,
                timestamp: 100,
                timestamp_millis_part: 0,
                beneficiary: Address::ZERO,
                tempo_import: full_import(Bytes::from([0x01])),
                finalize_withdrawal_batch_count: Some(U256::ZERO),
                finalize_withdrawal_batch_encrypted_senders: Vec::new(),
                transactions: Vec::new(),
            });
        }
        validate_system_inputs(&witness.zone_blocks[0], 0).unwrap();
        assert_eq!(
            validate_batch_block_shape(&witness.zone_blocks[0], false),
            Err(Error::InvalidBatchShape)
        );
    }

    #[test]
    fn batch_shape_accepts_intermediate_full_block_without_finalization() {
        let block = ZoneBlock {
            number: 1,
            parent_hash: B256::ZERO,
            timestamp: 100,
            timestamp_millis_part: 0,
            beneficiary: Address::ZERO,
            tempo_import: full_import(Bytes::from([0x01])),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        };

        validate_system_inputs(&block, 0).unwrap();
        assert_eq!(validate_batch_block_shape(&block, false), Ok(()));
    }

    #[test]
    fn batch_shape_rejects_checkpoint_only_batch() {
        let mut witness = minimal_batch_witness();
        witness.zone_blocks.push(ZoneBlock {
            number: 1,
            parent_hash: B256::ZERO,
            timestamp: 100,
            timestamp_millis_part: 0,
            beneficiary: Address::ZERO,
            tempo_import: checkpoint_import(vec![Bytes::from([0x01]), Bytes::from([0x02])]),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        });
        validate_system_inputs(&witness.zone_blocks[0], 0).unwrap();
        assert_eq!(
            validate_batch_block_shape(&witness.zone_blocks[0], true),
            Err(Error::InvalidBatchShape)
        );
    }

    #[test]
    fn rejects_a_witness_for_a_different_zone_chain() {
        let config = test_config();
        let mut witness = minimal_batch_witness();
        witness.public_inputs.zone_id = 2;
        witness.zone_blocks.push(ZoneBlock {
            number: 1,
            parent_hash: witness.parent_header.hash_slow(),
            timestamp: 0,
            timestamp_millis_part: 0,
            beneficiary: Address::ZERO,
            tempo_import: checkpoint_import(Vec::new()),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        });

        assert_eq!(
            prove_zone_batch(&config, witness),
            Err(Error::ChainIdMismatch {
                expected: config.chain_spec().chain_id(),
                actual: zone_chain_id(tempo_chainspec::spec::MODERATO.chain_id(), 2).unwrap(),
            })
        );
    }

    #[test]
    fn rejects_a_zone_witness_without_the_parent_state_root_node() {
        let database = WitnessDatabase::from_zone_state_witness(
            ZoneStateWitness {
                node_pool: Vec::new(),
                bytecodes: Vec::new(),
            },
            B256::repeat_byte(1),
        );

        assert!(matches!(
            database,
            Err(Error::MptValidation(
                StatelessSparseTrieError::MissingStateRootNode { state_root }
            )) if state_root == B256::repeat_byte(1)
        ));
    }

    #[test]
    fn resolves_zone_state_reads_from_trie_leaves() {
        let account = Address::repeat_byte(0x11);
        let code = Bytes::from([0x60, 0x00]);
        let code_hash = keccak256(&code);
        let (state_root, witness) = witnessed_account_state(
            account,
            7,
            U256::from(42),
            code_hash,
            vec![code.clone()],
            Some((U256::from(3), U256::from(9))),
        );
        let mut database = WitnessDatabase::from_zone_state_witness(witness, state_root).unwrap();

        let info = database.basic(account).unwrap().unwrap();
        assert_eq!(info.nonce, 7);
        assert_eq!(info.balance, U256::from(42));
        assert_eq!(
            database
                .code_by_hash(code_hash)
                .unwrap()
                .original_byte_slice(),
            code.as_ref()
        );
        assert_eq!(
            database.storage(account, U256::from(3)).unwrap(),
            U256::from(9)
        );
    }

    #[test]
    fn resolves_block_hash_from_eip2935_storage_witness() {
        let number = 42;
        let hash = B256::repeat_byte(0x42);
        let slot = U256::from(number % HISTORY_SERVE_WINDOW as u64);
        let (state_root, witness) = witnessed_account_state(
            HISTORY_STORAGE_ADDRESS,
            1,
            U256::ZERO,
            alloy_consensus::constants::KECCAK_EMPTY,
            Vec::new(),
            Some((slot, hash.into())),
        );
        let mut database = WitnessDatabase::from_zone_state_witness(witness, state_root).unwrap();

        assert_eq!(database.block_hash(number).unwrap(), hash);
    }

    fn next_block_evm_env(
        config: &SpfConfig,
        tempo_database: TempoWitnessDatabase,
        parent: &TempoHeader,
        block: &ZoneBlock,
    ) -> Result<alloy_evm::EvmEnv<TempoHardfork, TempoBlockEnv>, Error> {
        let attributes = next_block_env_attributes(config.chain_spec().as_ref(), parent, block)?;
        let env = ZoneEvmConfig::new(config.chain_spec().clone(), tempo_database, config.portal())
            .next_evm_env(parent, &attributes)
            .map_err(|_| Error::EvmEnvironment)?;
        Ok(env)
    }

    #[test]
    fn keeps_evm_state_in_the_bundle_overlay() {
        let address = Address::repeat_byte(0x22);
        let database = WitnessDatabase::from_zone_state_witness(
            ZoneStateWitness {
                node_pool: Vec::new(),
                bytecodes: Vec::new(),
            },
            EMPTY_ROOT_HASH,
        )
        .unwrap();
        let mut state = State::builder()
            .with_database(database)
            .with_bundle_update()
            .build();
        let mut changes = revm::primitives::AddressMap::default();
        let mut account = revm::state::Account::default();
        account.info.balance = U256::from(42);
        account.mark_touch();
        changes.insert(address, account);

        state.commit(changes);
        state.merge_transitions(BundleRetention::PlainState);

        assert_eq!(
            state.basic(address).unwrap().unwrap().balance,
            U256::from(42)
        );
        assert_eq!(state.database.basic(address).unwrap(), None);
        assert!(state.bundle_state.state.contains_key(&address));

        let expected_account = TrieAccount {
            nonce: 0,
            balance: U256::from(42),
            storage_root: EMPTY_ROOT_HASH,
            code_hash: alloy_consensus::constants::KECCAK_EMPTY,
        };
        let expected_root = state_root_unhashed([(address, expected_account)]);
        assert_eq!(
            state.database.state_root(state.bundle_state).unwrap(),
            expected_root
        );
    }

    #[test]
    fn ignores_stale_nodes_outside_the_bound_state_root() {
        let address = Address::repeat_byte(0x23);
        let stale_node = TrieNode::Leaf(LeafNode::new(
            Nibbles::unpack(keccak256(address)),
            alloy_rlp::encode(TrieAccount::default()),
        ));
        let mut database = WitnessDatabase::from_zone_state_witness(
            ZoneStateWitness {
                node_pool: vec![Bytes::from(alloy_rlp::encode(stale_node))],
                bytecodes: Vec::new(),
            },
            EMPTY_ROOT_HASH,
        )
        .unwrap();

        assert_eq!(database.basic(address).unwrap(), None);
    }

    #[test]
    fn rejects_zone_bytecode_absent_from_the_bytecode_pool() {
        let account = Address::repeat_byte(0x44);
        let code_hash = keccak256([0x60, 0x00]);
        let (state_root, witness) =
            witnessed_account_state(account, 1, U256::from(2), code_hash, Vec::new(), None);
        let mut database = WitnessDatabase::from_zone_state_witness(witness, state_root).unwrap();

        assert_eq!(
            database.code_by_hash(code_hash),
            Err(WitnessDatabaseError::MissingCode { code_hash })
        );
    }

    #[test]
    fn resolves_tempo_state_from_its_initial_header() {
        let account = Address::repeat_byte(0x33);
        let slot = B256::repeat_byte(0x07);
        let database =
            TempoWitnessDatabase::from_tempo_state_witness(empty_tempo_witness(9)).unwrap();

        assert_eq!(
            database.read_l1_storage(account, slot, 9).unwrap(),
            B256::ZERO
        );
        assert!(database.read_l1_storage(account, slot, 8).is_err());
        assert_eq!(database.missing_read(), None);
    }

    #[test]
    fn reports_the_exact_missing_tempo_storage_proof() {
        let account = Address::repeat_byte(0x33);
        let slot = B256::repeat_byte(0x07);
        let block_number = 9;
        let header = TempoHeader {
            inner: Header {
                number: block_number,
                state_root: B256::repeat_byte(0x44),
                ..Default::default()
            },
            ..Default::default()
        };
        let database = TempoWitnessDatabase::from_tempo_state_witness(TempoStateWitness {
            initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(header)),
            node_pool: Vec::new(),
        })
        .unwrap();

        assert!(
            database
                .read_l1_storage(account, slot, block_number)
                .is_err()
        );
        let missing = database.missing_read().unwrap();
        assert_eq!(missing.account, account);
        assert_eq!(missing.slot, slot);
        assert_eq!(missing.block_number, block_number);
    }

    #[test]
    fn fully_reveals_the_active_tempo_checkpoint() {
        let account = Address::repeat_byte(0x34);
        let slot = U256::from(7);
        let value = U256::from(11);
        let (state_root, zone_witness) = witnessed_account_state(
            account,
            0,
            U256::ZERO,
            alloy_consensus::constants::KECCAK_EMPTY,
            Vec::new(),
            Some((slot, value)),
        );
        let header = TempoHeader {
            inner: Header {
                number: 9,
                state_root,
                ..Default::default()
            },
            ..Default::default()
        };
        let database = TempoWitnessDatabase::from_tempo_state_witness(TempoStateWitness {
            initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(header)),
            node_pool: zone_witness.node_pool,
        })
        .unwrap();

        assert_eq!(
            database.read_l1_storage(account, slot.into(), 9).unwrap(),
            B256::from(value)
        );
    }

    #[test]
    fn prepares_zone_next_block_environment() {
        let witness = minimal_batch_witness();
        let block = ZoneBlock {
            number: 1,
            parent_hash: witness.parent_header.hash_slow(),
            timestamp: 0,
            timestamp_millis_part: 321,
            beneficiary: Address::ZERO,
            tempo_import: full_import(witness.tempo_state_witness.initial_tempo_header_rlp.clone()),
            finalize_withdrawal_batch_count: Some(U256::ZERO),
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        };

        let config = test_config();
        let attributes = execution::evm::next_block_env_attributes(
            config.chain_spec().as_ref(),
            &witness.parent_header,
            &block,
        )
        .unwrap();

        assert_eq!(attributes.timestamp, 0);
        assert_eq!(attributes.suggested_fee_recipient, Address::ZERO);
        assert_eq!(attributes.gas_limit, 30_000_000);
        assert_eq!(attributes.general_gas_limit, 0);
        assert_eq!(attributes.shared_gas_limit, 0);
        assert_eq!(attributes.timestamp_millis_part, 321);

        let tempo_database =
            TempoWitnessDatabase::from_tempo_state_witness(witness.tempo_state_witness.clone())
                .unwrap();
        let env =
            next_block_evm_env(&config, tempo_database, &witness.parent_header, &block).unwrap();
        assert_eq!(env.cfg_env.chain_id, config.chain_spec().chain_id());
        assert_eq!(env.block_env.inner.basefee, 0);
    }

    #[test]
    fn rejects_portal_work_above_capacity() {
        for (deposit_count, token_count) in [
            (MAX_UNPROCESSED_DEPOSITS + 1, 0),
            (0, MAX_UNPROCESSED_TOKEN_ENABLEMENTS + 1),
        ] {
            let block = ZoneBlock {
                number: 1,
                parent_hash: B256::ZERO,
                timestamp: 0,
                timestamp_millis_part: 0,
                beneficiary: Address::ZERO,
                tempo_import: TempoImport::Full {
                    header_rlp: Bytes::from([0x01]),
                    deposits: vec![
                        tempo_contracts::zones::QueuedDeposit {
                            depositType: tempo_contracts::zones::DepositType::Deposit,
                            depositData: Bytes::new(),
                            rejected: false,
                        };
                        deposit_count
                    ],
                    decryptions: Vec::new(),
                    enabled_tokens: vec![
                        tempo_contracts::zones::EnabledToken {
                            token: Address::ZERO,
                            name: String::new(),
                            symbol: String::new(),
                            currency: String::new(),
                        };
                        token_count
                    ],
                },
                finalize_withdrawal_batch_count: None,
                finalize_withdrawal_batch_encrypted_senders: Vec::new(),
                transactions: Vec::new(),
            };
            assert_eq!(
                validate_system_inputs(&block, 0),
                Err(Error::PortalWorkCapacityExceeded { block_index: 0 })
            );
        }
    }

    #[test]
    fn final_full_block_requires_withdrawal_finalization() {
        let witness = minimal_batch_witness();
        let mut block = ZoneBlock {
            number: 1,
            parent_hash: witness.parent_header.hash_slow(),
            timestamp: 0,
            timestamp_millis_part: 0,
            beneficiary: Address::ZERO,
            tempo_import: full_import(Bytes::from([0x01])),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        };

        assert_eq!(validate_system_inputs(&block, 0), Ok(()));
        assert_eq!(
            validate_batch_block_shape(&block, true),
            Err(Error::InvalidBatchShape)
        );
        block.finalize_withdrawal_batch_count = Some(U256::ZERO);
        assert_eq!(validate_batch_block_shape(&block, true), Ok(()));
        block.tempo_import = checkpoint_import(Vec::new());
        assert_eq!(
            validate_system_inputs(&block, 0),
            Err(Error::MissingTempoHeaders { block_index: 0 })
        );
    }

    #[test]
    fn accepts_one_header_checkpoint_only_input() {
        let witness = minimal_batch_witness();
        let block = ZoneBlock {
            number: 1,
            parent_hash: witness.parent_header.hash_slow(),
            timestamp: 0,
            timestamp_millis_part: 0,
            beneficiary: Address::ZERO,
            tempo_import: checkpoint_import(vec![Bytes::from([0x01])]),
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        };

        assert_eq!(validate_system_inputs(&block, 0), Ok(()));
    }

    #[test]
    fn binds_the_initial_tempo_checkpoint_before_block_execution() {
        let mut witness = minimal_batch_witness();
        witness.zone_blocks.push(ZoneBlock {
            number: 1,
            parent_hash: witness.parent_header.hash_slow(),
            timestamp: 0,
            timestamp_millis_part: 0,
            beneficiary: Address::ZERO,
            tempo_import: full_import(Bytes::from([0x01])),
            finalize_withdrawal_batch_count: Some(U256::ZERO),
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: vec![Bytes::from([0x01])],
        });

        assert!(matches!(
            prove_zone_batch(&test_config(), witness),
            Err(Error::InitialTempoCheckpointMismatch {
                expected_number: 0,
                expected_hash: B256::ZERO,
                actual_number: 2,
                ..
            })
        ));
    }

    #[test]
    fn initial_tempo_checkpoint_binding_precedes_header_import_validation() {
        let mut witness = minimal_batch_witness();
        witness.zone_blocks.push(ZoneBlock {
            number: 1,
            parent_hash: witness.parent_header.hash_slow(),
            timestamp: 0,
            timestamp_millis_part: 0,
            beneficiary: Address::ZERO,
            tempo_import: full_import(Bytes::from([0x01])),
            finalize_withdrawal_batch_count: Some(U256::ZERO),
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: vec![Bytes::from([0x01])],
        });

        assert!(matches!(
            prove_zone_batch(&test_config(), witness),
            Err(Error::InitialTempoCheckpointMismatch {
                expected_number: 0,
                expected_hash: B256::ZERO,
                actual_number: 2,
                ..
            })
        ));
    }

    #[test]
    fn validates_a_tempo_ancestry_anchor() {
        let checkpoint = TempoHeader {
            inner: Header {
                number: 7,
                ..Default::default()
            },
            ..Default::default()
        };
        let checkpoint_hash = checkpoint.hash_slow();
        let anchor = TempoHeader {
            inner: Header {
                parent_hash: checkpoint_hash,
                number: 8,
                ..Default::default()
            },
            ..Default::default()
        };
        let anchor_rlp = Bytes::from(alloy_rlp::encode(anchor));
        let anchor_hash = keccak256(&anchor_rlp);
        let mut public_inputs = minimal_batch_witness().public_inputs;
        public_inputs.tempo_block_number = 7;
        public_inputs.anchor_block_number = 8;
        public_inputs.anchor_block_hash = anchor_hash;

        assert_eq!(
            validate_tempo_anchor(
                7,
                checkpoint_hash,
                &public_inputs,
                std::slice::from_ref(&anchor_rlp)
            ),
            Ok(())
        );

        for len in 0..anchor_rlp.len() {
            assert_eq!(
                validate_tempo_anchor(
                    7,
                    checkpoint_hash,
                    &public_inputs,
                    &[anchor_rlp.slice(..len)]
                ),
                Err(Error::TempoAncestryHeaderDecoding { index: 0 })
            );
        }
        let trailing = Bytes::from([anchor_rlp.as_ref(), &[0x80]].concat());
        assert_eq!(
            validate_tempo_anchor(7, checkpoint_hash, &public_inputs, &[trailing]),
            Err(Error::TempoAncestryHeaderDecoding { index: 0 })
        );
    }
}
