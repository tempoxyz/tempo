//! Minimal Tempo execution harness.

mod invariants;

use alloy_consensus::{
    Block, BlockBody, Header, constants::EMPTY_ROOT_HASH, proofs::calculate_transaction_root,
    transaction::Transaction,
};
use alloy_eips::Decodable2718;
use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, Log, U256};
use core::ffi::c_int;
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, CacheDB, InMemoryDB},
};
use reth_chainspec::ForkCondition;
use reth_consensus::{Consensus as _, HeaderValidator as _};
use reth_evm::{
    BlockExecutionError, BlockExecutionOutput, BlockExecutor, BlockExecutorFactory,
    ConfigureEngineEvm, ConfigureEvm, ConvertTx, ExecutableTxTuple,
};
use reth_primitives_traits::{
    RecoveredBlock, SealedHeader, transaction::signed::SignedTransaction,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus, evm::TempoEvm};
use tempo_fuzz_types::{
    AccountInput, BlockContextInput, ChainSpecInput, ErrorClass, FUZZ_ACCEPT, FUZZ_REJECT,
    HarnessInputKind, InvariantFailure, InvariantScope, LogOutput, NonEmpty, StateDiff, StateInput,
    StorageInput, TYPED_HARNESS_SCHEMA_VERSION, TempoExecutionOutcome, TempoHarnessCapabilities,
    TempoHarnessInput, TempoHarnessOutcome, TransactionOutcome, TxReceiptOutput,
};
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{TempoHeader, TempoReceipt, TempoTxEnvelope};

const PINNED_CHAIN_ID: u64 = 42431;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BlockInput {
    chain_spec: ChainSpecInput,
    pre_state: StateInput,
    blocks: Vec<BlockPayload>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
struct BlockPayload {
    context: BlockContextInput,
    txs: Vec<Vec<u8>>,
    senders: Vec<[u8; 20]>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct BlockResult {
    receipts: Vec<TxReceiptOutput>,
    final_state: StateInput,
    state_diff: StateDiff,
    error: ErrorClass,
    invariant_failures: Vec<InvariantFailure>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct BlockExecutionResultOutput {
    blocks: Vec<ExecutedBlockOutput>,
    storage_changes: Vec<tempo_fuzz_types::StorageChangeOutput>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ExecutedBlockOutput {
    block_index: u64,
    receipts: Vec<TxReceiptOutput>,
    gas_used: u64,
    blob_gas_used: u64,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tempo_fuzz_execute_with_result_v1(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
    in_ptr: *const u8,
    in_len: usize,
) -> c_int {
    if in_ptr.is_null() {
        return FUZZ_REJECT;
    }
    let input = unsafe { core::slice::from_raw_parts(in_ptr, in_len) };
    let Ok(request) = bincode::deserialize::<TempoHarnessInput>(input) else {
        return FUZZ_REJECT;
    };
    let Ok(response) = execute_typed_input(request) else {
        return FUZZ_REJECT;
    };
    let output = match bincode::serialize(&response) {
        Ok(output) => output,
        Err(_) => return FUZZ_REJECT,
    };
    unsafe { write_fuzz_output(out_ptr, out_len, out_written, &output) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tempo_fuzz_capabilities_v1(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> c_int {
    let capabilities = TempoHarnessCapabilities {
        schema_version: TYPED_HARNESS_SCHEMA_VERSION,
        implementation: "tempo".to_string(),
        git_revision: option_env!("TEMPO_GIT_REVISION")
            .unwrap_or("unknown")
            .to_string(),
        supported_hardforks: NonEmpty::new(supported_hardforks())
            .expect("Tempo harness supports at least one hardfork"),
        supported_inputs: NonEmpty::new(vec![
            HarnessInputKind::Transaction,
            HarnessInputKind::State,
            HarnessInputKind::Blockchain,
        ])
        .expect("Tempo harness supports at least one input kind"),
    };
    let output = match bincode::serialize(&capabilities) {
        Ok(output) => output,
        Err(_) => return FUZZ_REJECT,
    };
    unsafe { write_fuzz_output(out_ptr, out_len, out_written, &output) }
}

fn execute_typed_input(input: TempoHarnessInput) -> Result<TempoHarnessOutcome, ErrorClass> {
    match input {
        TempoHarnessInput::Transaction(input) => {
            let tx = decode_tx(&input.tx)?;
            let sender = input
                .sender
                .map(Address::new)
                .or_else(|| tx.try_recover().ok())
                .ok_or(ErrorClass::Rejected)?;
            Ok(TempoHarnessOutcome::Transaction(TransactionOutcome {
                error: ErrorClass::None,
                sender: Some(address_bytes(sender)),
                tx_type: Some(tx.tx_type() as u8),
                intrinsic_gas: None,
            }))
        }
        TempoHarnessInput::State(input) => {
            let response = execute_concrete_block(&BlockInput {
                chain_spec: input.chain_spec,
                pre_state: input.pre_state,
                blocks: vec![BlockPayload {
                    context: input.block_context,
                    txs: vec![input.tx],
                    senders: input.sender.into_iter().collect(),
                }],
            })?;
            Ok(TempoHarnessOutcome::State(tempo_execution_outcome(
                response,
            )))
        }
        TempoHarnessInput::Blockchain(input) => {
            let blocks = input
                .blocks
                .as_slice()
                .iter()
                .map(|block| BlockPayload {
                    context: block.context.clone(),
                    txs: block.txs.clone(),
                    senders: block.senders.clone(),
                })
                .collect();
            let response = execute_concrete_block(&BlockInput {
                chain_spec: input.chain_spec,
                pre_state: input.pre_state,
                blocks,
            })?;
            Ok(TempoHarnessOutcome::Blockchain(tempo_execution_outcome(
                response,
            )))
        }
    }
}

fn tempo_execution_outcome(response: BlockResult) -> TempoExecutionOutcome {
    TempoExecutionOutcome {
        error: response.error,
        receipts: response.receipts,
        // An in-memory execution database does not expose the provider-backed trie root used by
        // block import. The canonical final state remains comparable; do not substitute a hash of
        // the diagnostic serialization and label it an Ethereum state root.
        state_root: None,
        final_state: Some(response.final_state),
        state_diff: response.state_diff,
        invariant_failures: response.invariant_failures,
    }
}

fn decode_tx(input: &[u8]) -> Result<TempoTxEnvelope, ErrorClass> {
    let mut tx_slice = input;
    let tx = TempoTxEnvelope::decode_2718(&mut tx_slice).map_err(|_| ErrorClass::RlpDecode)?;
    if !tx_slice.is_empty() {
        return Err(ErrorClass::RlpDecode);
    }
    if tx.chain_id() != Some(PINNED_CHAIN_ID) {
        return Err(ErrorClass::Rejected);
    }
    Ok(tx)
}

unsafe fn write_fuzz_output(
    dst: *mut u8,
    dst_len: usize,
    written: *mut usize,
    bytes: &[u8],
) -> c_int {
    if written.is_null() {
        return FUZZ_REJECT;
    }
    unsafe { *written = bytes.len() };
    if dst.is_null() || dst_len < bytes.len() {
        return FUZZ_REJECT;
    }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    FUZZ_ACCEPT
}

#[derive(Clone, Debug)]
struct InputDecodeError {
    class: ErrorClass,
}

impl From<ErrorClass> for InputDecodeError {
    fn from(class: ErrorClass) -> Self {
        Self { class }
    }
}

#[cfg(test)]
fn decode_block_input(input: &[u8]) -> Result<BlockInput, InputDecodeError> {
    let request: BlockInput = bincode::deserialize(input)
        .map_err(|_| InputDecodeError::from(ErrorClass::InvalidInput))?;
    if request.blocks.is_empty() {
        return Err(InputDecodeError::from(ErrorClass::InvalidInput));
    }
    Ok(request)
}

fn decode_blocks(input: &[BlockPayload]) -> Result<Vec<ExecutionBlock>, InputDecodeError> {
    let mut blocks = Vec::with_capacity(input.len());
    for block in input {
        blocks.push(ExecutionBlock {
            context: block.context.clone(),
            txs: decode_txs(&block.txs)?,
            senders: block.senders.clone(),
        });
    }
    Ok(blocks)
}

fn decode_txs(input: &[Vec<u8>]) -> Result<Vec<TempoTxEnvelope>, InputDecodeError> {
    let mut txs = Vec::with_capacity(input.len());
    for tx_bytes in input {
        let mut tx_slice = tx_bytes.as_slice();
        let tx = TempoTxEnvelope::decode_2718(&mut tx_slice)
            .map_err(|_| InputDecodeError::from(ErrorClass::RlpDecode))?;
        if !tx_slice.is_empty() {
            return Err(InputDecodeError::from(ErrorClass::RlpDecode));
        }
        if tx.chain_id() != Some(PINNED_CHAIN_ID) {
            return Err(InputDecodeError::from(ErrorClass::Rejected));
        }
        txs.push(tx);
    }
    Ok(txs)
}

fn execute_concrete_block(request: &BlockInput) -> Result<BlockResult, ErrorClass> {
    if request.blocks.is_empty() {
        return Err(ErrorClass::InvalidInput);
    }
    let blocks = decode_blocks(&request.blocks).map_err(|err| err.class)?;
    let execution = execute_blocks(&request.chain_spec, &request.pre_state, &blocks);

    let mut receipts = Vec::new();
    for (executed, requested) in execution.output.blocks.into_iter().zip(&request.blocks) {
        receipts.extend(executed.receipts.into_iter().take(requested.txs.len()));
    }

    Ok(BlockResult {
        receipts,
        final_state: execution.final_state,
        state_diff: execution.state_diff,
        error: if execution.accepted {
            ErrorClass::None
        } else {
            execution.error
        },
        invariant_failures: execution.invariant_failures,
    })
}

#[derive(Clone)]
struct ExecutionBlock {
    context: BlockContextInput,
    txs: Vec<TempoTxEnvelope>,
    senders: Vec<[u8; 20]>,
}

#[cfg(test)]
fn execute_block_input(request: &BlockInput) -> ExecutionResult {
    let blocks = match decode_blocks(&request.blocks) {
        Ok(blocks) => blocks,
        Err(err) => {
            return ExecutionResult {
                accepted: false,
                error: err.class,
                output: BlockExecutionResultOutput::default(),
                state_diff: StateDiff::default(),
                final_state: StateInput::default(),
                invariant_failures: Vec::new(),
            };
        }
    };
    execute_blocks(&request.chain_spec, &request.pre_state, &blocks)
}

fn execute_blocks(
    chain_spec: &ChainSpecInput,
    pre_state: &StateInput,
    blocks: &[ExecutionBlock],
) -> ExecutionResult {
    if !hardforks_are_monotonic(blocks) {
        return ExecutionResult {
            accepted: false,
            error: ErrorClass::Rejected,
            output: BlockExecutionResultOutput::default(),
            state_diff: StateDiff::default(),
            final_state: pre_state.clone(),
            invariant_failures: Vec::new(),
        };
    }

    let chainspec = Arc::new(fuzz_dev_chainspec(chain_spec));
    if pre_state.accounts.iter().any(|account| {
        chainspec
            .inner
            .genesis
            .alloc
            .contains_key(&Address::from(account.address))
    }) {
        return ExecutionResult {
            accepted: false,
            error: ErrorClass::Rejected,
            output: BlockExecutionResultOutput::default(),
            state_diff: StateDiff::default(),
            final_state: pre_state.clone(),
            invariant_failures: Vec::new(),
        };
    }

    let mut db = InMemoryDB::default();
    if let Err(error_class) = seed_genesis_state(&mut db, &chainspec) {
        return ExecutionResult {
            accepted: false,
            error: error_class,
            output: BlockExecutionResultOutput::default(),
            state_diff: StateDiff::default(),
            final_state: pre_state.clone(),
            invariant_failures: Vec::new(),
        };
    }
    if let Err(error_class) = seed_state(&mut db, pre_state) {
        return ExecutionResult {
            accepted: false,
            error: error_class,
            output: BlockExecutionResultOutput::default(),
            state_diff: StateDiff::default(),
            final_state: pre_state.clone(),
            invariant_failures: Vec::new(),
        };
    }

    let initial_state = encode_state(&db);
    let evm_config = TempoEvmConfig::new(Arc::clone(&chainspec));
    let consensus = TempoConsensus::new(chainspec);
    let mut executed_blocks = Vec::new();
    let mut previous_header: Option<SealedHeader<TempoHeader>> = None;

    for (block_idx, block) in blocks.iter().enumerate() {
        let hardfork = match hardfork_from_u8(block.context.hardfork) {
            Ok(hardfork) => hardfork,
            Err(error_class) => {
                return finish_execution_result(
                    false,
                    error_class,
                    db,
                    &initial_state,
                    executed_blocks,
                );
            }
        };

        let pre_block_state = encode_state(&db);
        let context = context_for_hardfork(&block.context, block.context.hardfork, chain_spec);
        let recovered = match recovered_block_from_context(
            &context,
            hardfork,
            &block.txs,
            &block.senders,
            previous_header.as_ref().map(SealedHeader::hash),
        ) {
            Ok(recovered) => recovered,
            Err(_) => {
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    executed_blocks,
                );
            }
        };
        if let Some(parent) = &previous_header
            && consensus
                .validate_header_against_parent(recovered.sealed_block().sealed_header(), parent)
                .is_err()
        {
            return finish_execution_result_from_state(
                false,
                ErrorClass::Rejected,
                pre_block_state,
                executed_blocks,
            );
        }
        if consensus
            .validate_block_pre_execution(recovered.sealed_block())
            .is_err()
        {
            return finish_execution_result_from_state(
                false,
                ErrorClass::Rejected,
                pre_block_state,
                executed_blocks,
            );
        }

        // Enter through Tempo's production Engine Tree adapter. Because this is a recovered block,
        // `tx_iterator_for_payload` reuses the ingress-verified signer pool.
        let current_header = recovered.sealed_block().clone_sealed_header();
        let payload = TempoExecutionData {
            block: recovered.into(),
            block_access_list: None,
        };
        let env = match evm_config.evm_env_for_payload(&payload) {
            Ok(env) => env,
            Err(_) => {
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    executed_blocks,
                );
            }
        };
        let ctx = match evm_config.context_for_payload(&payload) {
            Ok(ctx) => ctx,
            Err(_) => {
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    executed_blocks,
                );
            }
        };
        let executable = match evm_config.tx_iterator_for_payload(&payload) {
            Ok(executable) => executable,
            Err(_) => {
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    executed_blocks,
                );
            }
        };
        let evm =
            BlockExecutorFactory::evm_with_env(evm_config.block_executor_factory(), &mut db, env);
        let mut executor =
            BlockExecutorFactory::create_executor(evm_config.block_executor_factory(), evm, ctx);
        let (raw_transactions, convert) = executable.into_parts();

        let transaction_execution = (|| {
            executor.apply_pre_execution_changes()?;
            let post_pre_execution_state =
                encode_state_overlay(executor.evm().overlay_db(), &pre_block_state);
            validate_executor_state_invariants(
                executor.evm(),
                "post-pre-execution",
                &post_pre_execution_state,
            )?;

            let mut outputs = Vec::with_capacity(block.txs.len());
            for (tx_index, raw) in raw_transactions.into_iter().enumerate() {
                let tx = convert
                    .convert(raw)
                    .map_err(|_| HarnessBlockExecutionError::Conversion)?;
                let mut output = TxExecutionOutput::default();
                let gas_output =
                    executor.execute_transaction_with_result_closure(tx, |result| {
                        output.output = result.result().output.to_vec();
                    })?;
                let post_tx_state =
                    encode_state_overlay(executor.evm().overlay_db(), &pre_block_state);
                validate_executor_state_invariants(executor.evm(), "post-tx", &post_tx_state)?;

                let original = block
                    .txs
                    .get(tx_index)
                    .ok_or(HarnessBlockExecutionError::Conversion)?;
                output.gas_used = gas_output.tx_gas_used();
                output.effective_gas_price = original.effective_gas_price(Some(context.basefee));
                invariants::validate_transaction_invariants(original, output.gas_used).map_err(
                    |detail| HarnessBlockExecutionError::Invariant {
                        state: post_tx_state,
                        detail,
                    },
                )?;
                outputs.push(output);
            }
            if outputs.len() != block.txs.len() {
                return Err(HarnessBlockExecutionError::Conversion);
            }
            Ok(outputs)
        })();

        match transaction_execution {
            Ok(tx_outputs) => {
                let block_result = match executor.finish() {
                    Ok(output) => output,
                    Err(_) => {
                        return finish_execution_result_from_state(
                            false,
                            ErrorClass::Rejected,
                            pre_block_state,
                            executed_blocks,
                        );
                    }
                };
                executed_blocks.push(block_execution_result_output(
                    block_idx as u64,
                    &block_result,
                    &tx_outputs,
                ));
                db.commit_source(&block_result.state);
                previous_header = Some(current_header);
            }
            Err(HarnessBlockExecutionError::Invariant { state, detail }) => {
                return ExecutionResult {
                    accepted: false,
                    error: ErrorClass::Invariant,
                    output: BlockExecutionResultOutput {
                        blocks: executed_blocks,
                        storage_changes: Vec::new(),
                    },
                    state_diff: StateDiff::default(),
                    final_state: state,
                    invariant_failures: vec![InvariantFailure {
                        id: "tempo-state-invariant".to_string(),
                        message: detail,
                        scope: InvariantScope::Execution,
                    }],
                };
            }
            Err(HarnessBlockExecutionError::Execution) => {
                let _ = match executor.finish() {
                    Ok(output) => output,
                    Err(_) => {
                        return finish_execution_result_from_state(
                            false,
                            ErrorClass::Rejected,
                            pre_block_state,
                            executed_blocks,
                        );
                    }
                };
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    executed_blocks,
                );
            }
            Err(HarnessBlockExecutionError::Conversion) => {
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    executed_blocks,
                );
            }
        }
    }

    finish_execution_result(true, ErrorClass::None, db, &initial_state, executed_blocks)
}

fn hardforks_are_monotonic(blocks: &[ExecutionBlock]) -> bool {
    let mut previous = None;
    for block in blocks {
        let hardfork = block.context.hardfork;
        if previous.is_some_and(|previous| hardfork < previous) {
            return false;
        }
        previous = Some(hardfork);
    }
    true
}

fn validate_executor_state_invariants(
    evm: &TempoEvm<'_>,
    side: &'static str,
    state: &StateInput,
) -> Result<(), HarnessBlockExecutionError> {
    let evm_env = tempo_evm::TempoEvmEnv {
        tempo_spec: evm.config_spec_id(),
        version: *evm.version(),
        block: *evm.block(),
    };
    let mut db = InMemoryDB::default();
    seed_state(&mut db, state).map_err(|error| HarnessBlockExecutionError::Invariant {
        state: state.clone(),
        detail: format!("TEMPO-INVARIANT-STATE-SEED side={side} error={error:?}"),
    })?;
    let mut evm = BlockExecutorFactory::evm_with_env(
        TempoEvmConfig::moderato().block_executor_factory(),
        &mut db,
        evm_env,
    );

    invariants::validate_state_invariants(&mut evm, side, state).map_err(|detail| {
        HarnessBlockExecutionError::Invariant {
            state: state.clone(),
            detail,
        }
    })
}

#[derive(Debug)]
enum HarnessBlockExecutionError {
    Execution,
    Conversion,
    Invariant { state: StateInput, detail: String },
}

impl From<BlockExecutionError> for HarnessBlockExecutionError {
    fn from(_: BlockExecutionError) -> Self {
        Self::Execution
    }
}

fn finish_execution_result(
    accepted: bool,
    error_class: ErrorClass,
    db: InMemoryDB,
    initial_state: &StateInput,
    blocks: Vec<ExecutedBlockOutput>,
) -> ExecutionResult {
    let final_state = encode_state_overlay(&db, initial_state);
    finish_execution_result_from_state(accepted, error_class, final_state, blocks)
}

fn finish_execution_result_from_state(
    accepted: bool,
    error_class: ErrorClass,
    final_state: StateInput,
    blocks: Vec<ExecutedBlockOutput>,
) -> ExecutionResult {
    let execution_result = BlockExecutionResultOutput {
        blocks,
        storage_changes: Vec::new(),
    };
    ExecutionResult {
        accepted,
        error: error_class,
        output: execution_result,
        state_diff: StateDiff::default(),
        final_state,
        invariant_failures: Vec::new(),
    }
}

fn context_for_hardfork(
    context: &BlockContextInput,
    hardfork_id: u8,
    chain_spec: &ChainSpecInput,
) -> BlockContextInput {
    let mut context = context.clone();
    context.timestamp = timestamp_for_hardfork(context.timestamp, hardfork_id, chain_spec);
    context
}

fn supported_hardforks() -> Vec<u8> {
    (0..=13).collect()
}

fn fuzz_dev_chainspec(input: &ChainSpecInput) -> TempoChainSpec {
    let mut chainspec = tempo_chainspec::spec::DEV.as_ref().clone();
    chainspec.inner.chain = PINNED_CHAIN_ID.into();
    for hardfork in TempoHardfork::VARIANTS {
        chainspec.inner.hardforks.remove(hardfork);
    }
    chainspec
        .inner
        .hardforks
        .insert(TempoHardfork::Genesis, ForkCondition::Timestamp(0));
    chainspec
        .inner
        .hardforks
        .extend((0..=13).filter_map(|value| {
            hardfork_from_u8(value)
                .ok()
                .map(|hardfork| (hardfork, ForkCondition::Timestamp(u64::from(value) + 1)))
        }));
    chainspec
        .inner
        .hardforks
        .extend(input.hardforks.iter().filter_map(|activation| {
            hardfork_from_u8(activation.hardfork)
                .ok()
                .map(|hardfork| (hardfork, ForkCondition::Timestamp(activation.timestamp)))
        }));
    chainspec
}

fn timestamp_for_hardfork(timestamp: u64, hardfork_id: u8, chain_spec: &ChainSpecInput) -> u64 {
    let activation = chain_spec_activation_timestamp(chain_spec, hardfork_id).unwrap_or(1);
    let timestamp = timestamp.max(activation);
    match next_chain_spec_activation_timestamp(chain_spec, hardfork_id) {
        Some(next_activation) => timestamp.min(next_activation.saturating_sub(1)),
        None => timestamp,
    }
}

fn chain_spec_activation_timestamp(chain_spec: &ChainSpecInput, hardfork_id: u8) -> Option<u64> {
    chain_spec
        .hardforks
        .iter()
        .filter(|activation| activation.hardfork == hardfork_id)
        .map(|activation| activation.timestamp)
        .min()
}

fn next_chain_spec_activation_timestamp(
    chain_spec: &ChainSpecInput,
    hardfork_id: u8,
) -> Option<u64> {
    chain_spec
        .hardforks
        .iter()
        .filter(|activation| activation.hardfork > hardfork_id)
        .map(|activation| activation.timestamp)
        .min()
}

fn recovered_block_from_context(
    context: &BlockContextInput,
    hardfork: TempoHardfork,
    txs: &[TempoTxEnvelope],
    verified_senders: &[[u8; 20]],
    parent_hash: Option<B256>,
) -> Result<RecoveredBlock<Block<TempoTxEnvelope, TempoHeader>>, String> {
    let transactions = txs.to_vec();
    let senders = if verified_senders.is_empty() {
        let mut recovered = Vec::with_capacity(transactions.len());
        for (idx, tx) in transactions.iter().enumerate() {
            let sender = tx.try_recover().map_err(|err| format!("tx[{idx}]={err}"))?;
            recovered.push(sender);
        }
        recovered
    } else if verified_senders.len() == transactions.len() {
        verified_senders.iter().copied().map(Address::new).collect()
    } else {
        return Err(format!(
            "sender_count={} tx_count={}",
            verified_senders.len(),
            transactions.len()
        ));
    };

    let mut header = TempoHeader {
        general_gas_limit: hardfork.general_gas_limit().unwrap_or(context.gas_limit),
        shared_gas_limit: shared_gas_limit_for_hardfork(hardfork, context.gas_limit),
        timestamp_millis_part: context.timestamp_millis_part,
        inner: Header {
            parent_hash: parent_hash.unwrap_or_default(),
            number: context.block_number,
            timestamp: context.timestamp,
            gas_limit: context.gas_limit,
            base_fee_per_gas: Some(context.basefee),
            beneficiary: Address::from(context.beneficiary),
            parent_beacon_block_root: Some(B256::ZERO),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            ..Default::default()
        },
        consensus_context: None,
    };
    header.inner.transactions_root = calculate_transaction_root(&transactions);

    let block = Block::new(
        header,
        BlockBody {
            transactions,
            ommers: Vec::new(),
            // Matches `TempoPayloadAttributes::new`, which supplies an empty
            // withdrawals list for the Ethereum execution context.
            withdrawals: Some(Default::default()),
        },
    );

    Ok(RecoveredBlock::new_unhashed(block, senders))
}

fn shared_gas_limit_for_hardfork(hardfork: TempoHardfork, block_gas_limit: u64) -> u64 {
    if hardfork.is_t4() {
        0
    } else {
        block_gas_limit / 10
    }
}

struct ExecutionResult {
    accepted: bool,
    error: ErrorClass,
    output: BlockExecutionResultOutput,
    state_diff: StateDiff,
    final_state: StateInput,
    invariant_failures: Vec<InvariantFailure>,
}

fn hardfork_from_u8(value: u8) -> Result<TempoHardfork, ErrorClass> {
    Ok(match value {
        0 => TempoHardfork::T0,
        1 => TempoHardfork::T1,
        2 => TempoHardfork::T2,
        3 => TempoHardfork::T3,
        4 => TempoHardfork::T4,
        5 => TempoHardfork::T5,
        6 => TempoHardfork::T6,
        7 => TempoHardfork::T7,
        8 => TempoHardfork::T8,
        9 => TempoHardfork::T9,
        10 => TempoHardfork::T10,
        11 => TempoHardfork::T11,
        12 => TempoHardfork::T12,
        13 => TempoHardfork::T13,
        _ => return Err(ErrorClass::InvalidInput),
    })
}

#[derive(Clone, Debug, Default)]
struct TxExecutionOutput {
    output: Vec<u8>,
    gas_used: u64,
    effective_gas_price: u128,
}

fn receipt_output_from_tempo(
    block_index: u64,
    tx_index: u64,
    receipt: &TempoReceipt,
    execution_output: Option<&TxExecutionOutput>,
) -> TxReceiptOutput {
    TxReceiptOutput {
        block_index,
        tx_index,
        success: receipt.success,
        cumulative_gas_used: receipt.cumulative_gas_used,
        gas_used: match execution_output {
            Some(output) => output.gas_used,
            None => 0,
        },
        effective_gas_price: match execution_output {
            Some(output) => output.effective_gas_price,
            None => 0,
        },
        output: match execution_output {
            Some(output) => output.output.clone(),
            None => Vec::new(),
        },
        logs: receipt.logs.iter().map(log_output).collect(),
    }
}

fn block_execution_result_output(
    block_index: u64,
    result: &BlockExecutionOutput<TempoReceipt>,
    execution_outputs: &[TxExecutionOutput],
) -> ExecutedBlockOutput {
    ExecutedBlockOutput {
        block_index,
        receipts: result
            .receipts
            .iter()
            .enumerate()
            .map(|(tx_idx, receipt)| {
                receipt_output_from_tempo(
                    block_index,
                    tx_idx as u64,
                    receipt,
                    execution_outputs.get(tx_idx),
                )
            })
            .collect(),
        gas_used: result.gas_used,
        blob_gas_used: result.blob_gas_used,
    }
}

fn log_output(log: &Log) -> LogOutput {
    LogOutput {
        address: address_bytes(log.address),
        topics: log.data.topics().iter().map(b256_bytes).collect(),
        data: log.data.data.as_ref().to_vec(),
    }
}

fn b256_bytes(value: &B256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(value.as_slice());
    bytes
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AccountView {
    balance: U256,
    nonce: u64,
    code: Vec<u8>,
    storage: BTreeMap<[u8; 32], [u8; 32]>,
}

fn canonical_state(input: &StateInput) -> BTreeMap<[u8; 20], AccountView> {
    let mut accounts = BTreeMap::new();
    for account in &input.accounts {
        let mut storage = BTreeMap::new();
        for entry in &account.storage {
            if entry.value != [0; 32] {
                storage.insert(entry.slot, entry.value);
            }
        }
        let account_view = AccountView {
            balance: U256::from_be_bytes(account.balance),
            nonce: account.nonce,
            code: account.code.clone(),
            storage,
        };
        if !is_empty_account(&account_view) {
            accounts.insert(account.address, account_view);
        }
    }
    accounts
}

fn is_empty_account(account: &AccountView) -> bool {
    account.balance.is_zero()
        && account.nonce == 0
        && account.code.is_empty()
        && account.storage.is_empty()
}

fn address_bytes(address: Address) -> [u8; 20] {
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(address.as_slice());
    bytes
}
fn seed_state(db: &mut InMemoryDB, input: &StateInput) -> Result<(), ErrorClass> {
    for account in &input.accounts {
        let address = Address::from(account.address);
        let balance = U256::from_be_bytes(account.balance);
        let nonce = account.nonce;
        let mut info = AccountInfo {
            balance,
            nonce,
            ..Default::default()
        };
        if !account.code.is_empty() {
            let bytecode = Bytecode::new_raw(Bytes::from(account.code.clone()));
            info.code_hash = bytecode.hash_slow();
            info.code = Some(bytecode);
        }
        db.insert_account_info(&address, info);

        for storage in &account.storage {
            let slot = U256::from_be_bytes(storage.slot);
            let value = U256::from_be_bytes(storage.value);
            db.insert_account_storage(&address, &slot, &value);
        }
    }
    Ok(())
}

fn seed_genesis_state(db: &mut InMemoryDB, chain_spec: &TempoChainSpec) -> Result<(), ErrorClass> {
    for (address, account) in &chain_spec.inner.genesis.alloc {
        let mut info = AccountInfo {
            balance: account.balance,
            nonce: account.nonce.unwrap_or_default(),
            ..Default::default()
        };
        if let Some(code) = &account.code {
            let bytecode = Bytecode::new_raw(code.clone());
            info.code_hash = bytecode.hash_slow();
            info.code = Some(bytecode);
        }
        db.insert_account_info(address, info);

        if let Some(storage) = &account.storage {
            for (slot, value) in storage {
                db.insert_account_storage(
                    address,
                    &U256::from_be_bytes(slot.0),
                    &U256::from_be_bytes(value.0),
                );
            }
        }
    }
    Ok(())
}

fn encode_state<DB>(db: &CacheDB<DB>) -> StateInput {
    encode_state_overlay(db, &StateInput::default())
}

fn encode_state_overlay<DB>(db: &CacheDB<DB>, base: &StateInput) -> StateInput {
    let mut account_views = canonical_state(base);
    let addresses: BTreeSet<_> = db
        .cache
        .accounts
        .keys()
        .chain(db.cache.storage.keys())
        .copied()
        .collect();

    for address in addresses {
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(address.as_slice());

        if let Some(info) = db.cache.accounts.get(&address) {
            match info {
                Some(info) => {
                    let view = account_views.entry(address_bytes).or_default();
                    view.balance = info.balance;
                    view.nonce = info.nonce;
                    if let Some(code) = info
                        .code
                        .as_ref()
                        .or_else(|| db.cache.contracts.get(&info.code_hash))
                    {
                        view.code = code.original_byte_slice().to_vec();
                    } else if info.code_hash == KECCAK256_EMPTY {
                        view.code.clear();
                    }
                }
                None => {
                    account_views.remove(&address_bytes);
                }
            }
        }

        if let Some(storage) = db.cache.storage.get(&address) {
            let view = account_views.entry(address_bytes).or_default();
            if storage.wiped {
                view.storage.clear();
            }
            for (slot, value) in &storage.slots {
                if value.is_zero() {
                    view.storage.remove(&slot.to_be_bytes());
                } else {
                    view.storage.insert(slot.to_be_bytes(), value.to_be_bytes());
                }
            }
        }
    }

    let accounts = account_views
        .into_iter()
        .filter(|(_, view)| *view != AccountView::default())
        .map(|(address, view)| {
            let storage = view
                .storage
                .into_iter()
                .map(|(slot, value)| StorageInput { slot, value })
                .collect();
            AccountInput {
                address,
                balance: view.balance.to_be_bytes(),
                nonce: view.nonce,
                code: view.code,
                storage,
            }
        })
        .collect();

    StateInput { accounts }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, Transaction, TxLegacy};
    use alloy_eips::Encodable2718;
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use tempo_chainspec::hardfork::TempoHardforks;

    fn legacy_tx(nonce: u64, gas_price: u128) -> TempoTxEnvelope {
        legacy_tx_with_gas_limit(nonce, gas_price, 500_000)
    }

    fn legacy_tx_with_gas_limit(nonce: u64, gas_price: u128, gas_limit: u64) -> TempoTxEnvelope {
        let signed = Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(PINNED_CHAIN_ID),
                nonce,
                gas_price,
                gas_limit,
                to: TxKind::Call(Address::repeat_byte(0x11)),
                value: U256::ZERO,
                input: Bytes::new(),
            },
            Signature::test_signature(),
        );
        TempoTxEnvelope::Legacy(signed)
    }

    fn encoded_txs(txs: &[TempoTxEnvelope]) -> Vec<Vec<u8>> {
        txs.iter()
            .map(|tx| {
                let mut tx_bytes = Vec::new();
                tx.encode_2718(&mut tx_bytes);
                tx_bytes
            })
            .collect()
    }

    fn block_input_with_txs(txs: &[TempoTxEnvelope]) -> BlockInput {
        BlockInput {
            chain_spec: ChainSpecInput::default(),
            pre_state: StateInput::default(),
            blocks: vec![BlockPayload {
                context: BlockContextInput {
                    hardfork: 4,
                    ..Default::default()
                },
                txs: encoded_txs(txs),
                senders: Vec::new(),
            }],
        }
    }

    fn serialized_block_input_with_txs(txs: &[TempoTxEnvelope]) -> Vec<u8> {
        bincode::serialize(&block_input_with_txs(txs)).expect("block input serializes")
    }

    #[test]
    fn block_input_decodes_real_tempo_transaction_envelope() {
        let tx = legacy_tx(7, 1);
        let input = serialized_block_input_with_txs(&[tx]);

        let request = decode_block_input(&input).expect("block input decodes");
        let decoded_blocks = decode_blocks(&request.blocks).expect("blocks decode");
        assert_eq!(decoded_blocks.len(), 1);
        assert_eq!(decoded_blocks[0].txs.len(), 1);
        assert_eq!(decoded_blocks[0].txs[0].nonce(), 7);
    }

    #[test]
    fn protocol_genesis_accounts_cannot_be_overwritten_by_fuzz_prestate() {
        let mut request = block_input_with_txs(&[legacy_tx(0, 0)]);
        request.pre_state.accounts.push(AccountInput {
            address: address_bytes(tempo_contracts::precompiles::PATH_USD_ADDRESS),
            balance: [0; 32],
            nonce: 0,
            code: vec![0xef],
            storage: Vec::new(),
        });

        let result = execute_block_input(&request);

        assert!(!result.accepted);
        assert_eq!(result.error, ErrorClass::Rejected);
    }

    #[test]
    fn encode_state_recovers_seeded_code_from_contract_cache() {
        let input = StateInput {
            accounts: vec![AccountInput {
                address: [0x22; 20],
                balance: [0; 32],
                nonce: 0,
                code: vec![0x60, 0x00, 0x56],
                storage: Vec::new(),
            }],
        };
        let mut db = InMemoryDB::default();
        seed_state(&mut db, &input).expect("state seeds");

        assert_eq!(encode_state(&db), input);
    }

    #[test]
    fn encode_state_overlay_retains_provider_backed_code() {
        let address = Address::repeat_byte(0x23);
        let code = vec![0xef];
        let base = StateInput {
            accounts: vec![AccountInput {
                address: address_bytes(address),
                balance: [0; 32],
                nonce: 0,
                code: code.clone(),
                storage: Vec::new(),
            }],
        };
        let mut overlay = InMemoryDB::default();
        overlay.insert_account_info(
            &address,
            AccountInfo {
                code_hash: Bytecode::new_raw(Bytes::from(code)).hash_slow(),
                code: None,
                ..Default::default()
            },
        );

        let materialized = encode_state_overlay(&overlay, &base);

        assert_eq!(materialized.accounts[0].code, vec![0xef]);
    }

    #[test]
    fn encode_state_overlay_retains_untouched_base_storage() {
        let address = Address::repeat_byte(0x20);
        let untouched_slot = U256::from(8);
        let touched_slot = U256::from(9);
        let base = StateInput {
            accounts: vec![AccountInput {
                address: address_bytes(address),
                balance: [0; 32],
                nonce: 0,
                code: vec![0xef],
                storage: vec![
                    StorageInput {
                        slot: untouched_slot.to_be_bytes(),
                        value: U256::from(14_000_000).to_be_bytes(),
                    },
                    StorageInput {
                        slot: touched_slot.to_be_bytes(),
                        value: U256::from(1_000_000).to_be_bytes(),
                    },
                ],
            }],
        };
        let mut overlay = InMemoryDB::default();
        let bytecode = Bytecode::new_raw(Bytes::from(vec![0xef]));
        overlay.insert_account_info(
            &address,
            AccountInfo {
                code_hash: bytecode.hash_slow(),
                code: Some(bytecode),
                ..Default::default()
            },
        );
        overlay.insert_account_storage(&address, &touched_slot, &U256::from(2_000_000));

        let materialized = encode_state_overlay(&overlay, &base);
        let storage = &materialized.accounts[0].storage;

        assert!(storage.iter().any(|entry| {
            entry.slot == untouched_slot.to_be_bytes()
                && entry.value == U256::from(14_000_000).to_be_bytes()
        }));
        assert!(storage.iter().any(|entry| {
            entry.slot == touched_slot.to_be_bytes()
                && entry.value == U256::from(2_000_000).to_be_bytes()
        }));
    }

    #[test]
    fn encode_state_overlay_includes_storage_only_cache_addresses() {
        let address = Address::repeat_byte(0x44);
        let slot = U256::from(7);
        let value = U256::from(9);
        let mut db = InMemoryDB::default();
        db.insert_account_storage(&address, &slot, &value);

        let materialized = encode_state(&db);

        assert_eq!(materialized.accounts.len(), 1);
        assert_eq!(materialized.accounts[0].address, address_bytes(address));
        assert_eq!(materialized.accounts[0].storage.len(), 1);
        assert_eq!(materialized.accounts[0].storage[0].slot, slot.to_be_bytes());
        assert_eq!(
            materialized.accounts[0].storage[0].value,
            value.to_be_bytes()
        );
    }

    #[test]
    fn encode_state_overlay_removes_zero_cached_storage() {
        let address = Address::repeat_byte(0x55);
        let slot = U256::from(7);
        let base = StateInput {
            accounts: vec![AccountInput {
                address: address_bytes(address),
                balance: [0; 32],
                nonce: 0,
                code: Vec::new(),
                storage: vec![StorageInput {
                    slot: slot.to_be_bytes(),
                    value: U256::from(9).to_be_bytes(),
                }],
            }],
        };
        let mut db = InMemoryDB::default();
        db.insert_account_storage(&address, &slot, &U256::ZERO);

        let materialized = encode_state_overlay(&db, &base);

        assert!(materialized.accounts.is_empty());
    }

    #[test]
    fn execute_block_input_runs_transaction_in_tempo_evm() {
        let tx = legacy_tx(0, 0);
        let request = block_input_with_txs(&[tx]);

        let result = execute_block_input(&request);
        let receipts: Vec<_> = result
            .output
            .blocks
            .iter()
            .flat_map(|block| block.receipts.iter())
            .collect();

        assert!(result.accepted);
        assert!(matches!(result.error, ErrorClass::None));
        assert_eq!(result.output.blocks.len(), 1);
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].success);
        assert!(result.output.storage_changes.is_empty());
    }

    #[test]
    fn fsm_gas_cap_boundary_respects_block3() {
        // An FSM mutator walks the semantic boundary instead of regenerating arbitrary bytes:
        // below-cap -> at-cap -> over-cap.
        for (gas_limit, expected_accepted) in
            [(29_999_999, true), (30_000_000, true), (30_000_001, false)]
        {
            let tx = legacy_tx_with_gas_limit(0, 0, gas_limit);
            let result = execute_block_input(&block_input_with_txs(&[tx]));
            assert_eq!(result.accepted, expected_accepted, "gas_limit={gas_limit}");
            assert_ne!(result.error, ErrorClass::Invariant);
        }
    }

    #[test]
    fn fsm_rejects_decreasing_block_timestamps() {
        let chain_spec = ChainSpecInput {
            hardforks: vec![tempo_fuzz_types::HardforkActivationInput {
                hardfork: 13,
                timestamp: 1,
            }],
            ..Default::default()
        };
        let block = |block_number, timestamp| BlockPayload {
            context: BlockContextInput {
                block_number,
                timestamp,
                hardfork: 13,
                ..Default::default()
            },
            txs: Vec::new(),
            senders: Vec::new(),
        };
        let request = BlockInput {
            chain_spec,
            pre_state: StateInput::default(),
            blocks: vec![block(1, 100), block(2, 99)],
        };

        let result = execute_block_input(&request);

        assert!(!result.accepted);
        assert_eq!(result.error, ErrorClass::Rejected);
    }

    #[test]
    fn execute_block_input_runs_transactions() {
        let tx = legacy_tx(0, 0);
        let txs = encoded_txs(&[tx]);
        let response = execute_typed_input(TempoHarnessInput::Blockchain(
            tempo_fuzz_types::TempoBlockchainInput {
                chain_spec: ChainSpecInput::default(),
                pre_state: StateInput::default(),
                blocks: NonEmpty::new(vec![tempo_fuzz_types::TempoBlock {
                    context: BlockContextInput {
                        hardfork: 4,
                        ..Default::default()
                    },
                    txs,
                    senders: Vec::new(),
                }])
                .expect("test blockchain input has one block"),
            },
        ))
        .expect("typed blockchain input executes");
        let TempoHarnessOutcome::Blockchain(response) = response else {
            panic!("expected blockchain outcome");
        };

        assert!(matches!(response.error, ErrorClass::None));
        assert_eq!(response.receipts.len(), 1);
        assert!(response.receipts[0].success);
    }

    #[test]
    fn engine_payload_adapter_reuses_verified_sender() {
        let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(PINNED_CHAIN_ID),
                nonce: 0,
                gas_price: 0,
                gas_limit: 500_000,
                to: TxKind::Call(Address::repeat_byte(0x11)),
                value: U256::ZERO,
                input: Bytes::new(),
            },
            Signature::new(U256::MAX, U256::MAX, false),
        ));
        assert!(tx.try_recover().is_err());

        let mut request = block_input_with_txs(&[tx]);
        request.blocks[0].senders = vec![[0x42; 20]];
        let result = execute_block_input(&request);

        assert!(result.accepted);
        assert_eq!(result.output.blocks[0].receipts.len(), 1);
    }

    #[test]
    fn non_monotonic_hardfork_sequence_is_rejected_without_panicking() {
        let txs = [legacy_tx(0, 0), legacy_tx(1, 0)];
        let mut request = block_input_with_txs(&txs[..1]);
        request.blocks.push(BlockPayload {
            context: BlockContextInput {
                hardfork: 3,
                ..Default::default()
            },
            txs: encoded_txs(&txs[1..]),
            senders: Vec::new(),
        });

        let result = execute_block_input(&request);
        assert!(!result.accepted);
        assert_eq!(result.error, ErrorClass::Rejected);
    }

    #[test]
    fn context_for_hardfork_caps_timestamp_before_next_fork() {
        let chain_spec = tempo_fuzz_types::ChainSpecInput::default();
        let mut context = BlockContextInput {
            hardfork: 5,
            timestamp: TempoHardfork::T4
                .moderato_activation_timestamp()
                .expect("T4 has a moderato activation"),
            ..Default::default()
        };

        let t3_context = context_for_hardfork(&context, 3, &chain_spec);
        assert_eq!(
            TempoHardfork::from_chain_and_timestamp(PINNED_CHAIN_ID, t3_context.timestamp),
            Some(TempoHardfork::T3)
        );

        context.timestamp = 0;
        let t3_context = context_for_hardfork(&context, 3, &chain_spec);
        assert_eq!(
            TempoHardfork::from_chain_and_timestamp(PINNED_CHAIN_ID, t3_context.timestamp),
            Some(TempoHardfork::T3)
        );

        context.timestamp = u64::MAX;
        let t3_context = context_for_hardfork(&context, 3, &chain_spec);
        assert_eq!(t3_context.timestamp, 1_778_767_199);
        assert_eq!(
            TempoHardfork::from_chain_and_timestamp(PINNED_CHAIN_ID, t3_context.timestamp),
            Some(TempoHardfork::T3)
        );
    }

    #[test]
    fn fuzz_chainspec_pins_requested_t4_boundary() {
        let chainspec = fuzz_dev_chainspec(&tempo_fuzz_types::ChainSpecInput::default());
        assert_eq!(chainspec.tempo_hardfork_at(1), TempoHardfork::T0);
        assert_eq!(chainspec.tempo_hardfork_at(2), TempoHardfork::T1);
        assert_eq!(chainspec.tempo_hardfork_at(3), TempoHardfork::T2);
        assert_eq!(
            chainspec.tempo_hardfork_at(tempo_fuzz_types::MODERATO_T4_TIMESTAMP.saturating_sub(1)),
            TempoHardfork::T3
        );
        assert_eq!(
            chainspec.tempo_hardfork_at(tempo_fuzz_types::MODERATO_T4_TIMESTAMP),
            TempoHardfork::T4
        );
    }

    #[test]
    fn zone_hardforks_are_mapped_and_advertised() {
        assert_eq!(hardfork_from_u8(9), Ok(TempoHardfork::T9));
        assert_eq!(hardfork_from_u8(10), Ok(TempoHardfork::T10));
        assert_eq!(hardfork_from_u8(11), Ok(TempoHardfork::T11));
        assert_eq!(hardfork_from_u8(12), Ok(TempoHardfork::T12));
        assert_eq!(hardfork_from_u8(13), Ok(TempoHardfork::T13));
        assert_eq!(supported_hardforks(), (0..=13).collect::<Vec<_>>());
    }
}
