//! Executing a harness input.

use std::sync::Arc;

use alloy_consensus::{
    BlockHeader as _, proofs::calculate_transaction_root, transaction::Transaction as _,
};
use alloy_eips::Decodable2718 as _;
use alloy_evm::{
    Evm as _, EvmEnv,
    block::{BlockExecutionError, BlockExecutor, TxResult as _},
};
use alloy_primitives::Address;
use reth_consensus::{Consensus as _, HeaderValidator as _};
use reth_evm::ConfigureEvm;
use reth_primitives_traits::{RecoveredBlock, transaction::signed::SignedTransaction as _};
use revm::{
    context::result::ExecutionResult,
    database::{BundleState, states::bundle_state::BundleRetention},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus, evm::TempoEvm};
use tempo_fuzz_types::{
    BlockChanges, BlockHeaderInput, ChainSpecInput, ErrorClass, InvariantFailure, InvariantScope,
    PreState, StateChanges, TempoBlock, TempoExecutionOutcome, TempoHarnessInput,
    TempoHarnessOutcome, TempoTransactionInput, TransactionOutcome, TxOutcome, TxReceiptOutput,
};
use tempo_primitives::{Block, BlockBody, TempoBlockEnv, TempoReceipt, TempoTxEnvelope};

use crate::{
    chain, invariants,
    state::{self, Db},
};

type ExecutionBlock = RecoveredBlock<Block>;

/// Executes `input`.
pub(crate) fn run(input: TempoHarnessInput) -> TempoHarnessOutcome {
    match input {
        TempoHarnessInput::Transaction(input) => {
            TempoHarnessOutcome::Transaction(transaction(&input))
        }
        TempoHarnessInput::State(input) => {
            let block = TempoBlock {
                header: BlockHeaderInput::Context(input.block_context),
                txs: vec![input.tx],
                senders: input.sender.into_iter().collect(),
            };
            TempoHarnessOutcome::State(execute(
                &input.chain_spec,
                &PreState::Genesis(input.pre_state),
                std::slice::from_ref(&block),
            ))
        }
        TempoHarnessInput::Blockchain(input) => TempoHarnessOutcome::Blockchain(execute(
            &input.chain_spec,
            &input.pre_state,
            input.blocks.as_slice(),
        )),
    }
}

/// Decodes a transaction and finds its sender, without executing it.
fn transaction(input: &TempoTransactionInput) -> TransactionOutcome {
    let tx = match decode_tx(&input.tx) {
        Ok(tx) => tx,
        Err(error) => {
            return TransactionOutcome {
                error,
                ..Default::default()
            };
        }
    };
    let sender = input.sender.or_else(|| tx.try_recover().ok());
    TransactionOutcome {
        error: if sender.is_some() {
            ErrorClass::None
        } else {
            ErrorClass::Rejected
        },
        sender,
        tx_type: Some(tx.tx_type() as u8),
    }
}

fn decode_tx(bytes: &[u8]) -> Result<TempoTxEnvelope, ErrorClass> {
    TempoTxEnvelope::decode_2718_exact(bytes).map_err(|_| ErrorClass::RlpDecode)
}

/// Executes `blocks` in order on `pre_state`, stopping at the first block that fails. An input that
/// is not executable at all leaves an empty outcome with only its error set.
fn execute(
    chain: &ChainSpecInput,
    pre_state: &PreState,
    blocks: &[TempoBlock],
) -> TempoExecutionOutcome {
    let prepared = chain::chain_spec(chain).and_then(|spec| {
        let blocks = blocks
            .iter()
            .map(|block| recover_block(&spec, block))
            .collect::<Result<Vec<_>, _>>()?;
        if !blocks.is_sorted_by_key(|block| block.header().timestamp()) {
            return Err(ErrorClass::InvalidInput);
        }
        let db = state::seed(pre_state)?;
        Ok((Arc::new(spec), blocks, db))
    });
    let (spec, blocks, mut db) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return TempoExecutionOutcome {
                error,
                ..Default::default()
            };
        }
    };

    let pre = db.cache.clone();
    let evm_config = TempoEvmConfig::new(Arc::clone(&spec));
    let consensus = TempoConsensus::new(spec);
    let mut outcome = TempoExecutionOutcome::default();
    let applied = execute_blocks(&evm_config, &consensus, &mut db, &blocks, &mut outcome);

    let contracts = &db.cache.contracts;
    let after = state::after(&pre, &applied);
    outcome.state_diff.total = state::bundle_changes(&applied, contracts);
    outcome.state_root =
        matches!(pre_state, PreState::Genesis(_)).then(|| state::state_root(&after));
    outcome.final_state = state::encode(&after, contracts);
    outcome
}

/// `block` with its header resolved, its transactions decoded and their senders known.
pub(crate) fn recover_block(
    spec: &TempoChainSpec,
    block: &TempoBlock,
) -> Result<ExecutionBlock, ErrorClass> {
    let mut header = chain::header(spec, &block.header)?;
    let txs = block
        .txs
        .iter()
        .map(|tx| decode_tx(tx))
        .collect::<Result<Vec<_>, _>>()?;
    let senders = if block.senders.is_empty() {
        txs.iter()
            .map(|tx| tx.try_recover().map_err(|_| ErrorClass::Rejected))
            .collect::<Result<Vec<_>, _>>()?
    } else if block.senders.len() == txs.len() {
        block.senders.clone()
    } else {
        return Err(ErrorClass::InvalidInput);
    };
    if matches!(block.header, BlockHeaderInput::Context(_)) {
        header.inner.transactions_root = calculate_transaction_root(&txs);
    }
    let body = BlockBody {
        transactions: txs,
        ommers: Vec::new(),
        // `TempoPayloadAttributes` gives every block an empty withdrawals list.
        withdrawals: Some(Default::default()),
    };
    Ok(RecoveredBlock::new_unhashed(
        Block::new(header, body),
        senders,
    ))
}

/// Executes `blocks` on `db`, appending each applied block's outputs to `outcome` and setting its
/// error at the first block that fails. Returns the changes of the blocks that applied.
pub(crate) fn execute_blocks(
    evm_config: &TempoEvmConfig,
    consensus: &TempoConsensus,
    db: &mut Db,
    blocks: &[ExecutionBlock],
    outcome: &mut TempoExecutionOutcome,
) -> BundleState {
    let mut applied = BundleState::default();
    for (index, block) in blocks.iter().enumerate() {
        let executed = execute_block(evm_config, consensus, db, block, index as u64);
        // A read the pre-state could not answer makes the result meaningless,
        // even when the error was swallowed on its way up.
        let executed = match executed {
            _ if db.database.0.missed() => Err(ErrorClass::IncompletePreState),
            executed => executed,
        };
        match executed {
            Ok((changes, outputs)) => {
                applied.extend(changes);
                outcome.receipts.extend(outputs.receipts);
                outcome.state_diff.blocks.push(outputs.changes);
                outcome
                    .invariant_failures
                    .extend(outputs.invariant_failures);
            }
            Err(error) => {
                outcome.error = error;
                break;
            }
        }
    }
    applied
}

/// What one block produced.
#[derive(Default)]
struct BlockOutputs {
    receipts: Vec<TxReceiptOutput>,
    changes: BlockChanges,
    invariant_failures: Vec<InvariantFailure>,
}

/// Executes `block` on `db`. Returns its changes and what it produced.
fn execute_block(
    evm_config: &TempoEvmConfig,
    consensus: &TempoConsensus,
    db: &mut Db,
    block: &ExecutionBlock,
    block_index: u64,
) -> Result<(BundleState, BlockOutputs), ErrorClass> {
    consensus
        .validate_header(block.sealed_block().sealed_header())
        .map_err(|_| ErrorClass::Rejected)?;
    consensus
        .validate_block_pre_execution(block.sealed_block())
        .map_err(|_| ErrorClass::Rejected)?;
    let evm = evm_config
        .evm_for_block(&mut *db, block.header())
        .map_err(|_| ErrorClass::Rejected)?;
    let ctx = evm_config
        .context_for_block(block.sealed_block())
        .map_err(|_| ErrorClass::Rejected)?;
    let mut executor = evm_config.create_executor(evm, ctx);

    let mut outputs = BlockOutputs::default();
    let mut changes = BundleState::default();
    execute_txs(
        &mut executor,
        block,
        block_index,
        &mut changes,
        &mut outputs,
    )
    .map_err(|err| class(&err))?;
    let (mut evm, _) = executor.finish().map_err(|err| class(&err))?;
    let post_block = state::drain(evm.db_mut());
    outputs.changes.post_block = state::transition_changes(&post_block, &evm.db().cache.contracts);
    changes.apply_transitions_and_create_reverts(post_block, BundleRetention::PlainState);
    Ok((changes, outputs))
}

/// Applies the block's pre-execution changes and its transactions, recording each transaction's
/// receipt and each step's changes, and checking invariants after each step.
fn execute_txs<'db, E>(
    executor: &mut E,
    block: &ExecutionBlock,
    block_index: u64,
    changes: &mut BundleState,
    outputs: &mut BlockOutputs,
) -> Result<(), BlockExecutionError>
where
    E: BlockExecutor<
            Transaction = TempoTxEnvelope,
            Receipt = TempoReceipt,
            Evm = TempoEvm<&'db mut Db>,
        >,
{
    let env = executor.evm().evm_env();
    executor.apply_pre_execution_changes()?;
    outputs.changes.pre_block = step(
        executor,
        &env,
        InvariantScope::Block { block_index },
        false,
        changes,
        &mut outputs.invariant_failures,
    );

    let basefee = block.header().base_fee_per_gas();
    for (tx_index, tx) in block.transactions_recovered().enumerate() {
        let tx_index = tx_index as u64;
        let effective_gas_price = tx.effective_gas_price(basefee);
        let result = executor.execute_transaction_without_commit(tx)?;
        let execution = &result.result().result;
        let outcome = match execution {
            ExecutionResult::Success { .. } => TxOutcome::Success,
            ExecutionResult::Revert { .. } => TxOutcome::Revert,
            ExecutionResult::Halt { reason, .. } => TxOutcome::Halt(reason.clone()),
        };
        let gas = *execution.gas();
        let output = execution.output().cloned().unwrap_or_default();
        executor.commit_transaction(result);
        // `finish` returns the receipts the executor records here, unchanged.
        let receipt = executor
            .receipts()
            .last()
            .expect("committing a transaction records its receipt");
        outputs.receipts.push(TxReceiptOutput {
            block_index,
            tx_index,
            outcome,
            gas,
            cumulative_gas_used: receipt.cumulative_gas_used,
            effective_gas_price,
            output,
            logs: receipt.logs.clone(),
        });
        let scope = InvariantScope::Transaction {
            block_index,
            tx_index,
        };
        let tx_changes = step(
            executor,
            &env,
            scope,
            true,
            changes,
            &mut outputs.invariant_failures,
        );
        outputs.changes.txs.push(tx_changes);
    }
    Ok(())
}

/// Ends an execution step: applies its transitions to `changes`, checks invariants at `scope` (only
/// for contracts the step changed, if `changed_only`), and returns the step's changes.
fn step<'db, E>(
    executor: &mut E,
    env: &EvmEnv<TempoHardfork, TempoBlockEnv>,
    scope: InvariantScope,
    changed_only: bool,
    changes: &mut BundleState,
    failures: &mut Vec<InvariantFailure>,
) -> StateChanges
where
    E: BlockExecutor<Evm = TempoEvm<&'db mut Db>>,
{
    let db: &mut Db = executor.evm_mut().db_mut();
    let step = state::drain(db);
    let step_changes = state::transition_changes(&step, &db.cache.contracts);
    let selected = |contract: &Address| !changed_only || step.transitions.contains_key(contract);
    invariants::check(db, env, &scope, selected, failures);
    changes.apply_transitions_and_create_reverts(step, BundleRetention::PlainState);
    step_changes
}

/// A block the node would reject is `Rejected`; anything else went wrong in the executor.
fn class(err: &BlockExecutionError) -> ErrorClass {
    match err {
        BlockExecutionError::Validation(_) => ErrorClass::Rejected,
        BlockExecutionError::Internal(_) => ErrorClass::Internal,
    }
}
