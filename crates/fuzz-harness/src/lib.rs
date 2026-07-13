//! Minimal Tempo execution harness.

mod invariants;

use alloy_consensus::{
    Block, BlockBody, Header, constants::EMPTY_ROOT_HASH, proofs::calculate_transaction_root,
    transaction::Transaction,
};
use alloy_eips::Decodable2718;
use alloy_evm::{
    Evm as _, EvmEnv,
    block::{BlockExecutionResult, BlockExecutor, BlockExecutorFactory, TxResult as AlloyTxResult},
};
use alloy_primitives::{Address, B256, Bytes, Log, U256, keccak256};
use core::ffi::c_int;
use reth_chainspec::ForkCondition;
use reth_consensus::Consensus as _;
use reth_evm::ConfigureEvm;
use reth_primitives_traits::{RecoveredBlock, transaction::signed::SignedTransaction};
use revm::{
    bytecode::Bytecode,
    database::{EmptyDB, in_memory_db::CacheDB},
    state::AccountInfo,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_consensus::TempoConsensus;
use tempo_evm::{TempoEvmConfig, evm::TempoEvm};
use tempo_fuzz_types::{
    AccountInput, BlockContextInput, ChainSpecInput, ErrorClass, FUZZ_ACCEPT, FUZZ_REJECT,
    HarnessInputKind, LogOutput, NonEmpty, StateDiff, StateInput, StorageInput,
    TYPED_HARNESS_SCHEMA_VERSION, TempoExecutionOutcome, TempoHarnessCapabilities,
    TempoHarnessInput, TempoHarnessOutcome, TransactionOutcome, TxReceiptOutput,
};
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
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct BlockResult {
    receipts: Vec<TxReceiptOutput>,
    final_state: StateInput,
    state_diff: StateDiff,
    error: ErrorClass,
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

struct DecodedBlock {
    context: BlockContextInput,
    txs: Vec<TempoTxEnvelope>,
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
            let sender = tx.try_recover().map_err(|_| ErrorClass::Rejected)?;
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
    let state_root = state_root(&response.final_state);
    TempoExecutionOutcome {
        error: response.error,
        receipts: response.receipts,
        state_root: Some(state_root),
        final_state: Some(response.final_state),
        state_diff: response.state_diff,
        invariant_failures: Vec::new(),
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

fn state_root(state: &StateInput) -> [u8; 32] {
    let encoded = bincode::serialize(state).expect("StateInput serialization should not fail");
    let hash = keccak256(encoded);
    let mut root = [0u8; 32];
    root.copy_from_slice(hash.as_slice());
    root
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

fn decode_blocks(input: &[BlockPayload]) -> Result<Vec<DecodedBlock>, InputDecodeError> {
    let mut blocks = Vec::with_capacity(input.len());
    for block in input {
        blocks.push(DecodedBlock {
            context: block.context.clone(),
            txs: decode_txs(&block.txs)?,
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
    let decoded_blocks = decode_blocks(&request.blocks).map_err(|err| err.class)?;
    let execution_blocks = decoded_blocks
        .iter()
        .map(|block| ExecutionBlock {
            context: block.context.clone(),
            txs: block.txs.clone(),
        })
        .collect::<Vec<_>>();
    let execution = execute_blocks(&request.chain_spec, &request.pre_state, &execution_blocks);

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
    })
}

fn make_evm(
    db: CacheDB<EmptyDB>,
    evm_config: &TempoEvmConfig,
    header: &TempoHeader,
) -> Result<TempoEvm<CacheDB<EmptyDB>>, String> {
    let env = evm_config
        .evm_env(header)
        .map_err(|err| format!("evm_env_error={err}"))?;
    Ok(TempoEvm::new(db, env))
}

#[derive(Clone)]
struct ExecutionBlock {
    context: BlockContextInput,
    txs: Vec<TempoTxEnvelope>,
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
            };
        }
    };
    let blocks: Vec<_> = blocks
        .iter()
        .map(|block| ExecutionBlock {
            context: block.context.clone(),
            txs: block.txs.clone(),
        })
        .collect();
    execute_blocks(&request.chain_spec, &request.pre_state, &blocks)
}

fn execute_blocks(
    chain_spec: &ChainSpecInput,
    pre_state: &StateInput,
    blocks: &[ExecutionBlock],
) -> ExecutionResult {
    assert_monotonic_hardforks(blocks);

    let mut db = CacheDB::new(EmptyDB::default());
    if let Err(error_class) = seed_state(&mut db, pre_state) {
        return ExecutionResult {
            accepted: false,
            error: error_class,
            output: BlockExecutionResultOutput::default(),
            state_diff: StateDiff::default(),
            final_state: pre_state.clone(),
        };
    }

    let initial_state = encode_state(&db);
    let chainspec = Arc::new(fuzz_moderato_chainspec(chain_spec));
    let evm_config = TempoEvmConfig::new(Arc::clone(&chainspec));
    let consensus = TempoConsensus::new(chainspec);
    let mut body = format!(
        "blocks={} pre_state_accounts={}",
        blocks.len(),
        pre_state.accounts.len(),
    );
    let mut executed_blocks = Vec::new();

    for (block_idx, block) in blocks.iter().enumerate() {
        let hardfork = match hardfork_from_u8(block.context.hardfork) {
            Ok(hardfork) => hardfork,
            Err(error_class) => {
                return finish_execution_result(
                    false,
                    error_class,
                    db,
                    &initial_state,
                    format!("{body} block[{block_idx}]={{invalid_context=true}}"),
                    executed_blocks,
                );
            }
        };

        let pre_block_state = encode_state(&db);
        let context = context_for_hardfork(&block.context, block.context.hardfork, chain_spec);
        let recovered = match recovered_block_from_context(&context, hardfork, &block.txs) {
            Ok(recovered) => recovered,
            Err(err) => {
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    &initial_state,
                    format!("{body} block[{block_idx}]={{recover_error={err}}}"),
                    executed_blocks,
                );
            }
        };
        if let Err(err) = consensus.validate_block_pre_execution(recovered.sealed_block()) {
            return finish_execution_result_from_state(
                false,
                ErrorClass::Rejected,
                pre_block_state,
                &initial_state,
                format!("{body} block[{block_idx}]={{pre_execution_validation_error={err}}}"),
                executed_blocks,
            );
        }

        body.push_str(&format!(" block[{block_idx}]={{txs={}}}", block.txs.len()));

        let evm = match make_evm(db, &evm_config, recovered.sealed_block().header()) {
            Ok(evm) => evm,
            Err(err) => {
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    &initial_state,
                    format!("{body} block[{block_idx}]={{{err}}}"),
                    executed_blocks,
                );
            }
        };
        let ctx = match evm_config.context_for_block(recovered.sealed_block()) {
            Ok(ctx) => ctx,
            Err(err) => {
                let _ = evm.finish();
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    &initial_state,
                    format!("{body} block[{block_idx}]={{context_error={err}}}"),
                    executed_blocks,
                );
            }
        };
        let mut executor =
            BlockExecutorFactory::create_executor(evm_config.block_executor_factory(), evm, ctx);

        match execute_recovered_block(&mut executor, &recovered, &context, hardfork) {
            Ok(tx_outputs) => {
                let (evm, block_result) = match executor.finish() {
                    Ok(output) => output,
                    Err(err) => {
                        return finish_execution_result_from_state(
                            false,
                            ErrorClass::Rejected,
                            pre_block_state,
                            &initial_state,
                            format!("{body} block[{block_idx}]={{finish_error={err}}}"),
                            executed_blocks,
                        );
                    }
                };
                let (next_db, _) = evm.finish();
                executed_blocks.push(block_execution_result_output(
                    block_idx as u64,
                    &block_result,
                    &tx_outputs,
                ));
                db = next_db;
            }
            Err(HarnessBlockExecutionError::Invariant { state, detail }) => {
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Invariant,
                    state,
                    &initial_state,
                    format!("{body} block[{block_idx}]={{invariant_error={detail}}}"),
                    executed_blocks,
                );
            }
            Err(HarnessBlockExecutionError::Execution(err)) => {
                let (evm, _) = match executor.finish() {
                    Ok(output) => output,
                    Err(finish_err) => {
                        return finish_execution_result_from_state(
                            false,
                            ErrorClass::Rejected,
                            pre_block_state,
                            &initial_state,
                            format!(
                                "{body} block[{block_idx}]={{execution_error={err}; finish_error={finish_err}}}"
                            ),
                            executed_blocks,
                        );
                    }
                };
                let _ = evm.finish();
                return finish_execution_result_from_state(
                    false,
                    ErrorClass::Rejected,
                    pre_block_state,
                    &initial_state,
                    format!("{body} block[{block_idx}]={{execution_error={err}}}"),
                    executed_blocks,
                );
            }
        }
    }

    finish_execution_result(
        true,
        ErrorClass::None,
        db,
        &initial_state,
        body,
        executed_blocks,
    )
}

fn assert_monotonic_hardforks(blocks: &[ExecutionBlock]) {
    let mut previous = None;
    for (block_index, block) in blocks.iter().enumerate() {
        let hardfork = block.context.hardfork;
        if let Some(previous) = previous {
            assert!(
                hardfork >= previous,
                "hardfork sequence is not monotonic at block {block_index}: T{previous} -> T{hardfork}"
            );
        }
        previous = Some(hardfork);
    }
}

fn execute_recovered_block<E>(
    executor: &mut E,
    block: &RecoveredBlock<Block<TempoTxEnvelope, TempoHeader>>,
    context: &BlockContextInput,
    _hardfork: TempoHardfork,
) -> Result<Vec<TxExecutionOutput>, HarnessBlockExecutionError>
where
    E: BlockExecutor<
            Transaction = TempoTxEnvelope,
            Receipt = TempoReceipt,
            Evm = TempoEvm<CacheDB<EmptyDB>>,
        >,
{
    executor.apply_pre_execution_changes()?;
    let post_pre_execution_state = encode_state(executor.evm().components().0);
    validate_executor_state_invariants(
        executor.evm(),
        "post-pre-execution",
        &post_pre_execution_state,
    )?;

    let mut outputs = Vec::new();
    for tx in block.transactions_recovered() {
        let mut output = TxExecutionOutput::default();
        let gas_output = executor.execute_transaction_with_result_closure(tx, |result| {
            output.output = match result.result().result.output() {
                Some(bytes) => bytes.to_vec(),
                None => Vec::new(),
            };
        })?;
        let post_tx_state = encode_state(executor.evm().components().0);
        validate_executor_state_invariants(executor.evm(), "post-tx", &post_tx_state)?;

        output.gas_used = gas_output.tx_gas_used();
        output.effective_gas_price = (*tx.inner()).effective_gas_price(Some(context.basefee));
        outputs.push(output);
    }
    Ok(outputs)
}

fn validate_executor_state_invariants(
    evm: &TempoEvm<CacheDB<EmptyDB>>,
    side: &'static str,
    state: &StateInput,
) -> Result<(), HarnessBlockExecutionError> {
    let evm_env = EvmEnv {
        cfg_env: evm.ctx().cfg.clone(),
        block_env: evm.ctx().block.clone(),
    };
    let mut db = CacheDB::new(EmptyDB::default());
    seed_state(&mut db, state).map_err(|error_class| HarnessBlockExecutionError::Invariant {
        state: state.clone(),
        detail: format!("TEMPO-INVARIANT-STATE-SEED side={side} error={error_class:?}"),
    })?;
    let mut evm = TempoEvm::new(db, evm_env);

    invariants::validate_state_invariants(&mut evm, side, state).map_err(|detail| {
        HarnessBlockExecutionError::Invariant {
            state: state.clone(),
            detail,
        }
    })
}

#[derive(Debug)]
enum HarnessBlockExecutionError {
    Execution(alloy_evm::block::BlockExecutionError),
    Invariant { state: StateInput, detail: String },
}

impl From<alloy_evm::block::BlockExecutionError> for HarnessBlockExecutionError {
    fn from(value: alloy_evm::block::BlockExecutionError) -> Self {
        Self::Execution(value)
    }
}

fn finish_execution_result(
    accepted: bool,
    error_class: ErrorClass,
    db: CacheDB<EmptyDB>,
    initial_state: &StateInput,
    _body: String,
    blocks: Vec<ExecutedBlockOutput>,
) -> ExecutionResult {
    let final_state = encode_state_overlay(&db, initial_state);
    finish_execution_result_from_state(
        accepted,
        error_class,
        final_state,
        initial_state,
        _body,
        blocks,
    )
}

fn finish_execution_result_from_state(
    accepted: bool,
    error_class: ErrorClass,
    final_state: StateInput,
    _initial_state: &StateInput,
    _body: String,
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
    vec![0, 1, 2, 3, 4, 5]
}

fn fuzz_moderato_chainspec(input: &ChainSpecInput) -> TempoChainSpec {
    let mut chainspec = TempoChainSpec::moderato();
    chainspec.inner.chain = PINNED_CHAIN_ID.into();
    chainspec.inner.hardforks.remove(&TempoHardfork::Genesis);
    chainspec
        .inner
        .hardforks
        .insert(TempoHardfork::Genesis, ForkCondition::Timestamp(0));
    chainspec
        .inner
        .hardforks
        .extend((0..=6).filter_map(|value| {
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
) -> Result<RecoveredBlock<Block<TempoTxEnvelope, TempoHeader>>, String> {
    let transactions = txs.to_vec();
    let mut senders = Vec::with_capacity(transactions.len());
    for (idx, tx) in transactions.iter().enumerate() {
        let sender = tx.try_recover().map_err(|err| format!("tx[{idx}]={err}"))?;
        senders.push(sender);
    }

    let mut header = TempoHeader {
        general_gas_limit: hardfork.general_gas_limit().unwrap_or(context.gas_limit),
        shared_gas_limit: shared_gas_limit_for_hardfork(hardfork, context.gas_limit),
        timestamp_millis_part: context.timestamp_millis_part,
        inner: Header {
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
}

fn hardfork_from_u8(value: u8) -> Result<TempoHardfork, ErrorClass> {
    Ok(match value {
        0 => TempoHardfork::T0,
        1 => TempoHardfork::T1,
        2 => TempoHardfork::T2,
        3 => TempoHardfork::T3,
        4 => TempoHardfork::T4,
        5 => TempoHardfork::T5,
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
    result: &BlockExecutionResult<TempoReceipt>,
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
fn seed_state(db: &mut CacheDB<EmptyDB>, input: &StateInput) -> Result<(), ErrorClass> {
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
        db.insert_account_info(address, info);

        for storage in &account.storage {
            let slot = U256::from_be_bytes(storage.slot);
            let value = U256::from_be_bytes(storage.value);
            db.insert_account_storage(address, slot, value)
                .map_err(|_| ErrorClass::Internal)?;
        }
    }
    Ok(())
}

fn encode_state(db: &CacheDB<EmptyDB>) -> StateInput {
    encode_state_overlay(db, &StateInput::default())
}

fn encode_state_overlay(db: &CacheDB<EmptyDB>, base: &StateInput) -> StateInput {
    let mut account_views = canonical_state(base);
    let mut accounts: Vec<_> = db
        .cache
        .accounts
        .iter()
        .filter_map(|(address, account)| account.info().map(|info| (*address, info, account)))
        .collect();
    accounts.sort_by_key(|(address, _, _)| *address);

    for (address, info, account) in accounts {
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(address.as_slice());
        let view = match account_views.entry(address_bytes) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(AccountView::default())
            }
        };
        view.balance = info.balance;
        view.nonce = info.nonce;
        view.code = match info.code.as_ref() {
            Some(code) => code.original_byte_slice().to_vec(),
            None => Vec::new(),
        };

        for (slot, value) in &account.storage {
            view.storage.insert(slot.to_be_bytes(), value.to_be_bytes());
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
        let signed = Signed::new_unhashed(
            TxLegacy {
                chain_id: Some(PINNED_CHAIN_ID),
                nonce,
                gas_price,
                gas_limit: 500_000,
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
    fn fuzz_chainspec_pins_moderato_t4_boundary() {
        let chainspec = fuzz_moderato_chainspec(&tempo_fuzz_types::ChainSpecInput::default());
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
}
