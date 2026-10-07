//! Tempo EVM setup and Zone-block execution.

use std::borrow::Cow;

use alloy_consensus::{
    Signed, TxLegacy,
    transaction::{Recovered, SignerRecoverable as _},
};
use alloy_eips::{eip2718::Decodable2718 as _, eip4895::Withdrawals};
use alloy_evm::{
    EvmFactory as _,
    block::{BlockExecutionResult, BlockExecutor as _, BlockExecutorFactory, TxResult as _},
    eth::EthBlockExecutionCtx,
};
use alloy_primitives::{B256, Bytes, U256};
use alloy_sol_types::{ContractError, SolCall as _, SolInterface as _};
use reth_chainspec::EthereumHardforks as _;
use reth_evm::{ConfigureEvm as _, NextBlockEnvAttributes};
use revm::{
    database::{State, states::bundle_state::BundleRetention},
    database_interface::bal::EvmDatabaseError,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoBlockEnv, TempoBlockExecutionCtx, TempoNextBlockEnvAttributes};
use tempo_primitives::{
    TempoHeader, TempoReceipt, TempoTxEnvelope,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use tempo_zone_contracts::{
    IZoneInbox, IZoneOutbox, TempoState, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
};
use zone_evm::{L1OverlayDB, ZoneBlockExecutor, ZoneEvmConfig};

use crate::{
    Error, TempoImport, ZoneBlock,
    execution::database::{TempoWitnessDatabase, WitnessDatabase},
};

type ZoneState = State<WitnessDatabase>;
type WitnessOverlay<'db> = L1OverlayDB<&'db mut ZoneState, TempoWitnessDatabase>;
type WitnessContext<'db> = tempo_revm::evm::TempoContext<WitnessOverlay<'db>>;
type WitnessExecutor<'a, 'db, I> =
    ZoneBlockExecutor<'a, &'db mut ZoneState, I, TempoWitnessDatabase>;

/// Execution artifacts committed by one Zone block header.
#[derive(Debug)]
pub(crate) struct ExecutedZoneBlock {
    pub(crate) transactions: Vec<TempoTxEnvelope>,
    pub(crate) output: BlockExecutionResult<TempoReceipt>,
    pub(crate) evm_env: alloy_evm::EvmEnv<TempoHardfork, TempoBlockEnv>,
}

pub(crate) struct BlockReplayContext<'a> {
    pub(crate) parent: &'a TempoHeader,
    pub(crate) block_index: usize,
}

/// Execute a complete Zone block in system-then-user order.
///
/// When a Tempo header is present, `ZoneInbox.advanceTempo` executes first.
/// That call invokes `TempoState.finalizeTempo`, then processes deposits and
/// enabled tokens. User transactions run only after that system transition.
pub(crate) fn execute_zone_block(
    zone_state: &mut ZoneState,
    evm_config: ZoneEvmConfig<TempoWitnessDatabase>,
    replay: BlockReplayContext<'_>,
    block: &ZoneBlock,
) -> Result<ExecutedZoneBlock, Error> {
    let BlockReplayContext {
        parent,
        block_index: zone_block_index,
    } = replay;
    let user_transactions = decode_user_transactions(zone_block_index, &block.transactions)?;
    let mut transactions = Vec::with_capacity(
        1 // advanceTempo system transaction
            + user_transactions.len()
            + usize::from(block.finalize_withdrawal_batch_count.is_some()),
    );
    let parent_number = block
        .number
        .checked_sub(1)
        .ok_or(Error::BlockNumberOverflow)?;
    if let Some(existing) = zone_state.block_hashes.get(parent_number)
        && existing != block.parent_hash
    {
        return Err(crate::WitnessDatabaseError::ConflictingBlockHash {
            number: parent_number,
            expected: existing,
            actual: block.parent_hash,
        }
        .into());
    }
    zone_state
        .block_hashes
        .insert(parent_number, block.parent_hash);

    if parent.inner.base_fee_per_gas.is_none() {
        return Err(Error::MissingParentBaseFee {
            block_index: zone_block_index,
        });
    }

    let attributes = next_block_env_attributes(evm_config.chain_spec(), parent, block)?;
    let env = evm_config
        .next_evm_env(parent, &attributes)
        .map_err(|_| Error::EvmEnvironment)?;
    let chain_id = env.cfg_env.chain_id;
    let assembly_env = env.clone();
    let block_gas_limit = env.block_env.inner.gas_limit;
    let evm = BlockExecutorFactory::evm_factory(&evm_config).create_evm(&mut *zone_state, env);
    let mut executor = BlockExecutorFactory::create_executor(
        &evm_config,
        evm,
        next_block_execution_context(evm_config.chain_spec().as_ref(), block, block_gas_limit),
    );

    executor.apply_pre_execution_changes().map_err(|error| {
        map_block_execution_error(
            error,
            Error::BlockPreExecution {
                block_index: zone_block_index,
            },
        )
    })?;

    match &block.tempo_import {
        TempoImport::Full {
            header_rlp,
            deposits,
            decryptions,
            enabled_tokens,
        } => transactions.push(execute_advance_tempo(
            &mut executor,
            header_rlp,
            deposits,
            decryptions,
            enabled_tokens,
            zone_block_index,
            chain_id,
        )?),
        TempoImport::CheckpointOnly { headers_rlp } => transactions.push(
            execute_advance_tempo_headers(&mut executor, headers_rlp, zone_block_index, chain_id)?,
        ),
    }
    transactions.extend(execute_user_transactions(
        &mut executor,
        zone_block_index,
        user_transactions,
    )?);
    if let Some(count) = block.finalize_withdrawal_batch_count {
        transactions.push(execute_finalize_withdrawal_batch(
            &mut executor,
            count,
            block.number,
            block.finalize_withdrawal_batch_encrypted_senders.clone(),
            zone_block_index,
            chain_id,
        )?);
    }

    let (_, output) = executor.finish().map_err(|error| {
        map_block_execution_error(
            error,
            Error::BlockPostExecution {
                block_index: zone_block_index,
            },
        )
    })?;
    zone_state.merge_transitions(BundleRetention::Reverts);

    Ok(ExecutedZoneBlock {
        transactions,
        output,
        evm_env: assembly_env,
    })
}

/// Construct the same next-block attributes supplied by the production Zone
/// payload builder.
pub(crate) fn next_block_env_attributes(
    chain_spec: &zone_chainspec::ZoneChainSpec,
    parent: &TempoHeader,
    block: &ZoneBlock,
) -> Result<TempoNextBlockEnvAttributes, Error> {
    let block_gas_limit = parent.inner.gas_limit;

    Ok(TempoNextBlockEnvAttributes {
        inner: NextBlockEnvAttributes {
            timestamp: block.timestamp,
            suggested_fee_recipient: block.beneficiary,
            prev_randao: B256::ZERO,
            gas_limit: block_gas_limit,
            parent_beacon_block_root: chain_spec
                .is_cancun_active_at_timestamp(block.timestamp)
                .then_some(B256::ZERO),
            withdrawals: chain_spec
                .is_shanghai_active_at_timestamp(block.timestamp)
                .then_some(Withdrawals::default()),
            extra_data: Bytes::new(),
            slot_number: None,
        },
        general_gas_limit: 0,
        shared_gas_limit: 0,
        timestamp_millis_part: block.timestamp_millis_part,
        consensus_context: None,
    })
}

pub(crate) fn next_block_execution_context(
    chain_spec: &zone_chainspec::ZoneChainSpec,
    block: &ZoneBlock,
    _gas_limit: u64,
) -> TempoBlockExecutionCtx<'static> {
    TempoBlockExecutionCtx {
        inner: EthBlockExecutionCtx {
            parent_hash: block.parent_hash,
            parent_beacon_block_root: chain_spec
                .is_cancun_active_at_timestamp(block.timestamp)
                .then_some(B256::ZERO),
            ommers: &[],
            withdrawals: chain_spec
                .is_shanghai_active_at_timestamp(block.timestamp)
                .then_some(Cow::Borrowed(&[])),
            extra_data: Bytes::new(),
            tx_count_hint: None,
            slot_number: None,
        },
        general_gas_limit: 0,
        shared_gas_limit: 0,
        consensus_context: None,
    }
}

fn execute_advance_tempo<'a, 'db, I>(
    executor: &mut WitnessExecutor<'a, 'db, I>,
    header: &Bytes,
    deposits: &[tempo_zone_contracts::QueuedDeposit],
    decryptions: &[tempo_zone_contracts::DecryptionData],
    enabled_tokens: &[tempo_zone_contracts::EnabledToken],
    block_index: usize,
    chain_id: u64,
) -> Result<TempoTxEnvelope, Error>
where
    I: alloy_evm::revm::Inspector<WitnessContext<'db>>,
{
    let calldata = IZoneInbox::advanceTempoCall {
        header: header.clone(),
        deposits: deposits.to_vec(),
        decryptions: decryptions.to_vec(),
        enabledTokens: enabled_tokens.to_vec(),
    }
    .abi_encode();
    let transaction = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: ZONE_INBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };
    let transaction =
        TempoTxEnvelope::Legacy(Signed::new_unhashed(transaction, TEMPO_SYSTEM_TX_SIGNATURE));
    let recovered = Recovered::new_unchecked(transaction.clone(), TEMPO_SYSTEM_TX_SENDER);

    execute_recovered_transaction(
        executor,
        recovered,
        Error::AdvanceTempoExecution { block_index },
        true,
    )?;
    Ok(transaction)
}

fn execute_advance_tempo_headers<'a, 'db, I>(
    executor: &mut WitnessExecutor<'a, 'db, I>,
    headers: &[Bytes],
    block_index: usize,
    chain_id: u64,
) -> Result<TempoTxEnvelope, Error>
where
    I: alloy_evm::revm::Inspector<WitnessContext<'db>>,
{
    let calldata = IZoneInbox::advanceTempoHeadersCall {
        headers: headers.to_vec(),
    }
    .abi_encode();
    let transaction = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: ZONE_INBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };
    let transaction =
        TempoTxEnvelope::Legacy(Signed::new_unhashed(transaction, TEMPO_SYSTEM_TX_SIGNATURE));
    let recovered = Recovered::new_unchecked(transaction.clone(), TEMPO_SYSTEM_TX_SENDER);
    execute_recovered_transaction(
        executor,
        recovered,
        Error::AdvanceTempoExecution { block_index },
        true,
    )?;
    Ok(transaction)
}

fn execute_finalize_withdrawal_batch<'a, 'db, I>(
    executor: &mut WitnessExecutor<'a, 'db, I>,
    count: U256,
    block_number: u64,
    encrypted_senders: Vec<Bytes>,
    block_index: usize,
    chain_id: u64,
) -> Result<TempoTxEnvelope, Error>
where
    I: alloy_evm::revm::Inspector<WitnessContext<'db>>,
{
    let calldata = IZoneOutbox::finalizeWithdrawalBatchCall {
        count,
        blockNumber: block_number,
        encryptedSenders: encrypted_senders,
    }
    .abi_encode();
    let transaction = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: ZONE_OUTBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };
    let transaction =
        TempoTxEnvelope::Legacy(Signed::new_unhashed(transaction, TEMPO_SYSTEM_TX_SIGNATURE));
    let recovered = Recovered::new_unchecked(transaction.clone(), TEMPO_SYSTEM_TX_SENDER);

    execute_recovered_transaction(
        executor,
        recovered,
        Error::FinalizeWithdrawalBatchExecution { block_index },
        true,
    )?;
    Ok(transaction)
}

fn decode_user_transactions(
    block_index: usize,
    transactions: &[Bytes],
) -> Result<Vec<Recovered<TempoTxEnvelope>>, Error> {
    // Not using with_capacity because input is untrusted.
    let mut decoded = Vec::new();
    for (transaction_index, encoded_transaction) in transactions.iter().enumerate() {
        let transaction =
            TempoTxEnvelope::decode_2718_exact(encoded_transaction).map_err(|_| {
                Error::TransactionDecoding {
                    block_index,
                    transaction_index,
                }
            })?;
        if transaction.is_system_tx() {
            return Err(Error::SystemTransactionInUserList {
                block_index,
                transaction_index,
            });
        }
        decoded.push(transaction.try_into_recovered().map_err(|_| {
            Error::TransactionSignature {
                block_index,
                transaction_index,
            }
        })?);
    }
    Ok(decoded)
}

fn execute_user_transactions<'a, 'db, I>(
    executor: &mut WitnessExecutor<'a, 'db, I>,
    block_index: usize,
    transactions: Vec<Recovered<TempoTxEnvelope>>,
) -> Result<Vec<TempoTxEnvelope>, Error>
where
    I: alloy_evm::revm::Inspector<WitnessContext<'db>>,
{
    let mut executed = Vec::with_capacity(transactions.len());
    for (transaction_index, transaction) in transactions.into_iter().enumerate() {
        let envelope = transaction.clone_inner();
        execute_recovered_transaction(
            executor,
            transaction,
            Error::TransactionExecution {
                block_index,
                transaction_index,
            },
            false,
        )?;
        executed.push(envelope);
    }

    Ok(executed)
}

fn execute_recovered_transaction<'a, 'db, I>(
    executor: &mut WitnessExecutor<'a, 'db, I>,
    transaction: Recovered<TempoTxEnvelope>,
    execution_error: Error,
    require_success: bool,
) -> Result<(), Error>
where
    I: alloy_evm::revm::Inspector<WitnessContext<'db>>,
{
    let result = match executor.execute_transaction_without_commit(transaction) {
        Ok(result) => result,
        Err(error) => return Err(map_block_execution_error(error, execution_error)),
    };
    if require_success && !result.result().result.is_success() {
        return Err(match (execution_error, &result.result().result) {
            (
                Error::AdvanceTempoExecution { block_index },
                revm::context::result::ExecutionResult::Revert { output, .. },
            ) => Error::AdvanceTempoRevert {
                block_index,
                reason: decode_advance_tempo_revert(output),
                output: output.clone(),
            },
            (error, _) => error,
        });
    }
    executor.commit_transaction(result);
    Ok(())
}

fn decode_advance_tempo_revert(output: &Bytes) -> String {
    if output.is_empty() {
        return "empty revert data".to_owned();
    }
    if let Ok(error) = ContractError::<IZoneInbox::IZoneInboxErrors>::abi_decode(output.as_ref()) {
        return format!("{error:?}");
    }
    if let Ok(error) = ContractError::<TempoState::TempoStateErrors>::abi_decode(output.as_ref()) {
        return format!("{error:?}");
    }
    "unknown revert".to_owned()
}

fn map_block_execution_error(
    error: alloy_evm::block::BlockExecutionError,
    execution_error: Error,
) -> Error {
    type WitnessEvmError = revm::context::result::EVMError<
        EvmDatabaseError<crate::WitnessDatabaseError>,
        tempo_evm::TempoInvalidTransaction,
    >;

    if let Some(revm::context::result::EVMError::Database(EvmDatabaseError::Database(error))) =
        error
            .as_internal()
            .and_then(|error| error.downcast_evm::<WitnessEvmError>())
    {
        return (*error).into();
    }

    execution_error
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::SolError as _;

    use super::*;

    #[test]
    fn decodes_zone_inbox_advance_tempo_revert() {
        let output = Bytes::from(IZoneInbox::InvalidDepositQueueHash {}.abi_encode());

        assert!(decode_advance_tempo_revert(&output).contains("InvalidDepositQueueHash"));
    }

    #[test]
    fn decodes_tempo_state_advance_tempo_revert() {
        let output = Bytes::from(TempoState::InvalidParentHash {}.abi_encode());

        assert!(decode_advance_tempo_revert(&output).contains("InvalidParentHash"));
    }

    #[test]
    fn retains_unknown_advance_tempo_revert_data() {
        let output = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
        let error = Error::AdvanceTempoRevert {
            block_index: 7,
            reason: decode_advance_tempo_revert(&output),
            output,
        };

        assert_eq!(
            error.to_string(),
            "advanceTempo reverted in zone block 7: unknown revert; data: 0xdeadbeef"
        );
    }
}
