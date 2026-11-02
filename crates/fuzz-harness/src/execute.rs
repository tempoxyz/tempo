//! Executing a harness input.

use std::sync::{Arc, Mutex};

use alloy_consensus::{
    BlockHeader as _, proofs::calculate_transaction_root, transaction::Transaction as _,
};
use alloy_eips::Decodable2718 as _;
use alloy_primitives::Address;
use evm2::bytecode::Bytecode;
use reth_consensus::{Consensus as _, HeaderValidator as _};
use reth_evm::{
    BlockExecutionError, BlockExecutor as _, BlockExecutorFactory as _, ConfigureEvm as _,
};
use reth_execution_types::StateUpdate;
use reth_primitives_traits::{RecoveredBlock, transaction::signed::SignedTransaction as _};
use tempo_chainspec::TempoChainSpec;
use tempo_evm::{TempoBlockExecutor, TempoEvmConfig, TempoEvmEnv, consensus::TempoConsensus};
use tempo_fuzz_types::{
    BlockChanges, BlockHeaderInput, ChainSpecInput, ErrorClass, InvariantFailure, InvariantScope,
    PreState, ResultGas, StateChanges, TempoBlock, TempoExecutionOutcome, TempoHarnessInput,
    TempoHarnessOutcome, TempoTransactionInput, TransactionOutcome, TxOutcome, TxReceiptOutput,
};
use tempo_primitives::{Block, BlockBody, TempoTxEnvelope};

use crate::{
    chain, invariants,
    state::{self, Contracts, Db, Net},
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
    let (spec, blocks, db) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return TempoExecutionOutcome {
                error,
                ..Default::default()
            };
        }
    };

    let pre = db.cache.borrow().clone();
    let evm_config = TempoEvmConfig::new(Arc::clone(&spec));
    let consensus = TempoConsensus::new(spec);
    let mut outcome = TempoExecutionOutcome::default();
    let applied = execute_blocks(&evm_config, &consensus, &db, &blocks, &mut outcome);
    if !outcome.invariant_failures.is_empty() {
        let invariant_failures = broken_start(&evm_config, pre_state, &blocks[0], &db, &outcome);
        if !invariant_failures.is_empty() {
            return TempoExecutionOutcome {
                error: ErrorClass::InvalidInput,
                invariant_failures,
                ..Default::default()
            };
        }
    }

    let cache = db.cache.borrow();
    let contracts = Contracts(&[&cache.contracts]);
    let after = state::after(&pre, &applied);
    outcome.state_diff.total = state::changes(&applied, &contracts);
    outcome.state_root =
        matches!(pre_state, PreState::Genesis(_)).then(|| state::state_root(&after));
    outcome.final_state = state::encode(&after, &contracts);
    outcome
}

/// The invariants `pre_state` already breaks, summing balances over every account `db` came to hold
/// after execution and every address in a log topic of `outcome`'s receipts (such as a holder whose
/// balance only a transaction touched, or one `transferFrom` or `burnBlocked` moved without loading
/// it). A pre-state that breaks one is not a reachable state, so nothing executed on it is a
/// finding: the input is invalid, and these failures are reported at `Execution` scope. Only the
/// accounts it lists can break one.
fn broken_start(
    evm_config: &TempoEvmConfig,
    pre_state: &PreState,
    block: &ExecutionBlock,
    db: &Db,
    outcome: &TempoExecutionOutcome,
) -> Vec<InvariantFailure> {
    let (Ok(env), Ok(start)) = (evm_config.evm_env(block.header()), state::seed(pre_state)) else {
        return Vec::new();
    };
    let (PreState::Genesis(listed) | PreState::Exact { state: listed, .. }) = pre_state;
    let logged = outcome.receipts.iter().flat_map(|receipt| &receipt.logs);
    let topics = logged
        .flat_map(|log| log.topics())
        .filter(|topic| topic[..12] == [0; 12]);
    let holders: Vec<Address> = db
        .cache
        .borrow()
        .accounts
        .keys()
        .copied()
        .chain(topics.map(|topic| Address::from_word(*topic)))
        .collect();
    let mut failures = Vec::new();
    invariants::check(
        &start,
        evm_config,
        env,
        &InvariantScope::Execution,
        |address| listed.accounts.contains_key(address),
        &holders,
        &mut failures,
    );
    failures
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
    db: &Db,
    blocks: &[ExecutionBlock],
    outcome: &mut TempoExecutionOutcome,
) -> Net {
    let mut applied = Net::default();
    for (index, block) in blocks.iter().enumerate() {
        let executed = execute_block(evm_config, consensus, db, block, index as u64);
        // A read the pre-state could not answer makes the result meaningless,
        // even when the error was swallowed on its way up.
        let executed = match executed {
            _ if db.pre.missed() => Err(ErrorClass::IncompletePreState),
            executed => executed,
        };
        match executed {
            Ok((updates, outputs)) => {
                for update in &updates {
                    applied.apply(update);
                }
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

/// The state updates an executor has emitted since they were last taken.
type Updates = Arc<Mutex<Vec<StateUpdate>>>;

/// Executes `block` on `db`. Returns the updates it made to state and what it produced.
fn execute_block(
    evm_config: &TempoEvmConfig,
    consensus: &TempoConsensus,
    db: &Db,
    block: &ExecutionBlock,
    block_index: u64,
) -> Result<(Vec<StateUpdate>, BlockOutputs), ErrorClass> {
    consensus
        .validate_header(block.sealed_block().sealed_header())
        .map_err(|_| ErrorClass::Rejected)?;
    consensus
        .validate_block_pre_execution(block.sealed_block())
        .map_err(|_| ErrorClass::Rejected)?;
    let evm = evm_config
        .evm_for_block(db.reader(), block.header())
        .map_err(|_| ErrorClass::Rejected)?;
    let ctx = evm_config
        .context_for_block(block.sealed_block())
        .map_err(|_| ErrorClass::Rejected)?;
    let mut executor = evm_config.create_executor(evm, ctx);
    let hooked = Updates::default();
    let installed = executor.set_state_hook({
        let hooked = Arc::clone(&hooked);
        move |update| hooked.lock().expect("the hook does not panic").push(update)
    });
    assert!(installed, "Tempo's block executor takes a state hook");

    let mut outputs = BlockOutputs::default();
    let mut updates = Vec::new();
    execute_txs(
        evm_config,
        &mut executor,
        db,
        &hooked,
        block,
        block_index,
        &mut updates,
        &mut outputs,
    )
    .map_err(|err| class(&err))?;
    let output = executor.finish().map_err(|err| class(&err))?;
    let post_block = take(&hooked);
    let net = Net::of(&post_block);
    let cache = db.cache.borrow();
    let contracts = Contracts(&[&output.state.contracts, &cache.contracts]);
    outputs.changes.post_block = state::changes(&net, &contracts);
    drop(cache);
    db.commit(&net, |hash| output.state.contracts.get(hash).cloned());
    updates.extend(post_block);
    Ok((updates, outputs))
}

/// Applies the block's pre-execution changes and its transactions, recording each transaction's
/// receipt and each step's changes, and checking invariants after each step.
#[allow(clippy::too_many_arguments)]
fn execute_txs(
    evm_config: &TempoEvmConfig,
    executor: &mut TempoBlockExecutor<'_>,
    db: &Db,
    hooked: &Updates,
    block: &ExecutionBlock,
    block_index: u64,
    updates: &mut Vec<StateUpdate>,
    outputs: &mut BlockOutputs,
) -> Result<(), BlockExecutionError> {
    executor.apply_pre_execution_changes()?;
    outputs.changes.pre_block = step(
        evm_config,
        executor,
        db,
        hooked,
        InvariantScope::Block { block_index },
        false,
        updates,
        &mut outputs.invariant_failures,
    );

    let basefee = block.header().base_fee_per_gas();
    for (tx_index, tx) in block.transactions_recovered().enumerate() {
        let tx_index = tx_index as u64;
        let effective_gas_price = tx.effective_gas_price(basefee);
        let result = executor.execute_transaction_without_commit(tx)?;
        let execution = result.result();
        let outcome = if execution.status {
            TxOutcome::Success
        } else if execution.is_revert() {
            TxOutcome::Revert
        } else {
            TxOutcome::Halt(execution.stop)
        };
        let gas = ResultGas {
            total_gas_spent: execution.total_gas_spent,
            state_gas_spent: execution.state_gas_spent,
            refunded: execution.refunded,
            floor_gas: execution.floor_gas,
        };
        let output = execution.output.clone();
        executor.commit_transaction(result)?;
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
            evm_config,
            executor,
            db,
            hooked,
            scope,
            true,
            updates,
            &mut outputs.invariant_failures,
        );
        outputs.changes.txs.push(tx_changes);
    }
    Ok(())
}

/// The updates `hooked` holds, which it then no longer does.
fn take(hooked: &Updates) -> Vec<StateUpdate> {
    std::mem::take(&mut *hooked.lock().expect("the hook does not panic"))
}

/// Ends an execution step: writes its changes to `db`, checks invariants at `scope` (only for
/// contracts the step changed, if `changed_only`), and returns the step's changes.
#[allow(clippy::too_many_arguments)]
fn step(
    evm_config: &TempoEvmConfig,
    executor: &TempoBlockExecutor<'_>,
    db: &Db,
    hooked: &Updates,
    scope: InvariantScope,
    changed_only: bool,
    updates: &mut Vec<StateUpdate>,
    failures: &mut Vec<InvariantFailure>,
) -> StateChanges {
    let step = take(hooked);
    let net = Net::of(&step);
    let overlay = &executor.evm().overlay_db().cache;
    let contracts = |hash: &_| -> Option<Bytecode> { overlay.contracts.get(hash).cloned() };
    db.commit(&net, contracts);
    let changes = {
        let cache = db.cache.borrow();
        state::changes(&net, &Contracts(&[&overlay.contracts, &cache.contracts]))
    };
    let selected = |contract: &_| !changed_only || net.contains(contract);
    let evm = executor.evm();
    let env = TempoEvmEnv::new_with_version(evm.config_spec_id(), *evm.block(), *evm.version());
    invariants::check(db, evm_config, env, &scope, selected, &[], failures);
    updates.extend(step);
    changes
}

/// A block the node would reject is `Rejected`; anything else went wrong in the executor.
fn class(err: &BlockExecutionError) -> ErrorClass {
    match err {
        BlockExecutionError::Validation(_) => ErrorClass::Rejected,
        BlockExecutionError::Internal(_) => ErrorClass::Internal,
    }
}
