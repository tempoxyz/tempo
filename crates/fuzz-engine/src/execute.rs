//! Executing a harness input.

use std::{
    fmt::{Debug, Display},
    mem,
    sync::{Arc, Mutex},
};

use alloy_consensus::{
    BlockHeader as _, Sealable as _,
    proofs::calculate_transaction_root,
    transaction::{Recovered, Transaction as _},
};
use alloy_eips::Decodable2718 as _;
use alloy_primitives::{Address, Log};
use evm2::{block::BlockTransactionResult as _, bytecode::Bytecode};
use invariants_core::{Effects, Frame, Report};
use reth_chainspec::EthChainSpec as _;
use reth_consensus::{Consensus as _, HeaderValidator as _};
use reth_evm::{
    BlockExecutionError, BlockExecutor, BlockExecutorFactory as _, BlockValidationError,
    ConfigureEvm as _,
};
use reth_execution_types::StateUpdate;
use reth_primitives_traits::{RecoveredBlock, transaction::signed::SignedTransaction as _};
use tempo_chainspec::{
    hardfork::{TempoHardfork, TempoHardforks as _},
    spec::TempoConsensusSpec,
};
use tempo_evm::{TempoEvm, TempoEvmEnv, TempoInvalidTransaction};
use tempo_fuzz_types::{
    BlockChanges, BlockHeaderInput, ChainSpecInput, ErrorClass, HarnessInputKind, InvariantFailure,
    InvariantScope, PreState, ResultGas, StateChanges, TempoBlock, TempoExecutionOutcome,
    TempoHarnessInput, TempoHarnessOutcome, TempoTransactionInput, TransactionOutcome, TxIndex,
    TxOutcome, TxReceiptOutput,
};
use tempo_invariants::{Ran, Tx};
use tempo_primitives::{Block, BlockBody, TempoHeader, TempoReceipt, TempoTxEnvelope};

use crate::{
    anchor::Anchor,
    chain,
    engine::{Chain, Engine, Tempo},
    invariants,
    rejection::{Check, Rejection},
    state::{self, Contracts, Db, Net},
    step::{self, StepState},
    trace::Calls,
};

/// The state updates an executor has emitted since they were last taken.
type Updates = Arc<Mutex<Vec<StateUpdate>>>;

/// A block executor on Tempo's EVM.
trait TempoExecutor<'e>:
    BlockExecutor<Evm = TempoEvm<'e>, Transaction = TempoTxEnvelope, Receipt = TempoReceipt>
{
}

impl<'e, T> TempoExecutor<'e> for T where
    T: BlockExecutor<Evm = TempoEvm<'e>, Transaction = TempoTxEnvelope, Receipt = TempoReceipt>
{
}

/// Executes `input` on `engine`'s chain. Returns the outcome and, unless its error is
/// [`ErrorClass::None`], why it stopped short.
pub fn run<E: Engine>(
    engine: &E,
    input: TempoHarnessInput,
) -> (TempoHarnessOutcome, Option<Rejection>) {
    crate::crypto::settle();
    match input {
        TempoHarnessInput::Transaction(input) => {
            let (outcome, rejection) = transaction::<E>(&input);
            (TempoHarnessOutcome::Transaction(outcome), rejection)
        }
        TempoHarnessInput::State(input) => {
            let block = TempoBlock {
                header: BlockHeaderInput::Context(input.block_context),
                txs: vec![input.tx],
                senders: input.sender.into_iter().collect(),
            };
            let (outcome, rejection) = execute(
                engine,
                HarnessInputKind::State,
                &input.chain_spec,
                &PreState::Genesis(input.pre_state),
                std::slice::from_ref(&block),
            );
            (TempoHarnessOutcome::State(outcome), rejection)
        }
        TempoHarnessInput::Blockchain(input) => {
            let (outcome, rejection) = execute(
                engine,
                HarnessInputKind::Blockchain,
                &input.chain_spec,
                &input.pre_state,
                input.blocks.as_slice(),
            );
            (TempoHarnessOutcome::Blockchain(outcome), rejection)
        }
    }
}

/// An outcome that executed nothing, with `error`.
fn stopped(error: ErrorClass) -> TempoExecutionOutcome {
    TempoExecutionOutcome {
        error,
        ..Default::default()
    }
}

/// `InvalidInput` unless `E`'s harness executes inputs of `kind`.
fn supported<E: Engine>(kind: HarnessInputKind) -> Result<(), Rejection> {
    if E::INPUTS.contains(&kind) {
        return Ok(());
    }
    Err(Rejection::new(
        ErrorClass::InvalidInput,
        Check::UnsupportedInput { kind },
    ))
}

/// Decodes a transaction and finds its sender, without executing it.
fn transaction<E: Engine>(
    input: &TempoTransactionInput,
) -> (TransactionOutcome, Option<Rejection>) {
    let tx = match supported::<E>(HarnessInputKind::Transaction).and_then(|()| decode_tx(&input.tx))
    {
        Ok(tx) => tx,
        Err(rejection) => {
            let outcome = TransactionOutcome {
                error: rejection.class(),
                ..Default::default()
            };
            return (outcome, Some(rejection));
        }
    };
    let sender = input
        .sender
        .map(Ok)
        .unwrap_or_else(|| tx.try_recover())
        .map_err(|err| Rejection::new(ErrorClass::Rejected, err));
    let outcome = TransactionOutcome {
        error: sender
            .as_ref()
            .err()
            .map_or(ErrorClass::None, Rejection::class),
        sender: sender.as_ref().ok().copied(),
        tx_type: Some(tx.tx_type() as u8),
    };
    (outcome, sender.err())
}

fn decode_tx(bytes: &[u8]) -> Result<TempoTxEnvelope, Rejection> {
    TempoTxEnvelope::decode_2718_exact(bytes)
        .map_err(|err| Rejection::new(ErrorClass::RlpDecode, err))
}

/// Executes `blocks` in order on `pre_state` on `engine`'s chain, stopping at the first block that
/// fails. An input that is not executable at all leaves an empty outcome with only its error set.
fn execute<E: Engine>(
    engine: &E,
    kind: HarnessInputKind,
    chain: &ChainSpecInput,
    pre_state: &PreState,
    blocks: &[TempoBlock],
) -> (TempoExecutionOutcome, Option<Rejection>) {
    execute_with(engine, kind, chain, pre_state, blocks, None)
}

/// Executes `blocks` as a Tempo chain from its genesis: they are numbered from 1 and each header's
/// parent hash links it to the one before, from the genesis header. Returns the outcome, why it
/// stopped short, and the genesis header with the pre-state and each block that applied with the
/// state after it, which a chain built on Tempo, such as a zone, reads Tempo at.
///
/// The pre-state must be [`PreState::Genesis`] and every header [`BlockHeaderInput::Context`],
/// whose `block_number` is ignored; otherwise the input is `InvalidInput` and nothing is anchored.
pub fn execute_anchored(
    chain: &ChainSpecInput,
    pre_state: &PreState,
    blocks: &[TempoBlock],
) -> (TempoExecutionOutcome, Option<Rejection>, Vec<Anchor>) {
    let anchorable = matches!(pre_state, PreState::Genesis(_))
        && blocks
            .iter()
            .all(|block| matches!(block.header, BlockHeaderInput::Context(_)));
    if !anchorable {
        let rejection = Rejection::new(ErrorClass::InvalidInput, Check::AnchoredChain);
        return (stopped(rejection.class()), Some(rejection), Vec::new());
    }
    let mut anchors = Vec::new();
    let kind = HarnessInputKind::Blockchain;
    let (outcome, rejection) =
        execute_with(&Tempo, kind, chain, pre_state, blocks, Some(&mut anchors));
    (outcome, rejection, anchors)
}

/// Executes `blocks`, anchoring them to `anchors` as [`execute_anchored`] describes when given.
fn execute_with<E: Engine>(
    engine: &E,
    kind: HarnessInputKind,
    chain: &ChainSpecInput,
    pre_state: &PreState,
    blocks: &[TempoBlock],
    mut anchors: Option<&mut Vec<Anchor>>,
) -> (TempoExecutionOutcome, Option<Rejection>) {
    let linked = anchors.is_some();
    let (chain, blocks, db) = match prepare(engine, kind, chain, pre_state, blocks, linked) {
        Ok(prepared) => prepared,
        Err(rejection) => return (stopped(rejection.class()), Some(rejection)),
    };

    let pre = db.cache.borrow().clone();
    let spec = Arc::clone(&chain.spec);
    let mut anchor = |header: &TempoHeader, db: &Db| {
        if let Some(anchors) = anchors.as_deref_mut() {
            let fork = spec.tempo_hardfork_at(header.inner.timestamp);
            anchors.push(Anchor::new(header.clone(), fork, db.cache.borrow().clone()));
        }
    };
    anchor(spec.genesis_header(), &db);
    let mut outcome = TempoExecutionOutcome::default();
    let (applied, failed_logs, rejection) = execute_blocks(
        engine,
        &chain.evm_config,
        &chain.consensus,
        &db,
        &blocks,
        &mut outcome,
        &mut anchor,
    );
    if !outcome.invariant_failures.is_empty() {
        let invariant_failures = broken_start(
            engine,
            &chain.evm_config,
            pre_state,
            &blocks[0],
            &db,
            &outcome,
            &failed_logs,
        );
        if !invariant_failures.is_empty() {
            let rejection = Rejection::new(ErrorClass::BrokenPreState, Check::PreStateInvariants);
            let outcome = TempoExecutionOutcome {
                invariant_failures,
                ..stopped(rejection.class())
            };
            return (outcome, Some(rejection));
        }
    }

    let cache = db.cache.borrow();
    let contracts = Contracts(&[&cache.contracts]);
    let after = state::after(&pre, &applied);
    outcome.state_diff.total = state::changes(&applied, &contracts);
    outcome.state_root =
        matches!(pre_state, PreState::Genesis(_)).then(|| state::state_root(&after));
    outcome.final_state = state::encode(&after, &contracts);
    (outcome, rejection)
}

/// `engine`'s chain for `chain`, `blocks` ready to execute on it, and `pre_state` seeded, or why
/// the input, of `kind`, is not executable.
/// With `linked`, context headers are numbered from 1 and linked from the genesis header.
fn prepare<E: Engine>(
    engine: &E,
    kind: HarnessInputKind,
    chain: &ChainSpecInput,
    pre_state: &PreState,
    blocks: &[TempoBlock],
    linked: bool,
) -> Result<(Chain<E>, Vec<PreparedBlock>, Db), Rejection> {
    supported::<E>(kind)?;
    let chain = engine.chain(chain)?;
    let spec = chain.spec.as_ref();
    let mut parent = linked.then(|| spec.genesis_header().clone());
    let blocks = blocks
        .iter()
        .map(|block| recover_block(spec, block, parent.as_mut()))
        .collect::<Result<Vec<_>, _>>()?;
    let timestamps = || {
        blocks
            .iter()
            .map(|block| block.recovered.header().timestamp())
    };
    if !timestamps().is_sorted() {
        return Err(Rejection::new(
            ErrorClass::InvalidInput,
            Check::TimestampOrder,
        ));
    }
    if let Some(hardfork) = timestamps()
        .map(|timestamp| spec.tempo_hardfork_at(timestamp))
        .find(|hardfork| !E::HARDFORKS.contains(hardfork))
    {
        return Err(Rejection::new(
            ErrorClass::InvalidInput,
            Check::UnsupportedHardfork { hardfork },
        ));
    }
    let db = state::seed(pre_state, engine.genesis())
        .map_err(|class| Rejection::new(class, Check::PreState))?;
    Ok((chain, blocks, db))
}

/// The invariants `pre_state` already breaks, summing balances over every account `db` came to hold
/// after execution and every address in a log topic of `outcome`'s receipts (such as a holder whose
/// balance only a transaction touched, or one `transferFrom` or `burnBlocked` moved without loading
/// it). A pre-state that breaks one is not a reachable state, so nothing executed on it is a
/// finding: the outcome is `BrokenPreState`, with these failures at `Execution` scope. Only the
/// accounts it lists can break one.
fn broken_start<E: Engine>(
    engine: &E,
    evm_config: &E::EvmConfig,
    pre_state: &PreState,
    block: &PreparedBlock,
    db: &Db,
    outcome: &TempoExecutionOutcome,
    failed_logs: &[Log],
) -> Vec<InvariantFailure> {
    if !*invariants::ENABLED {
        return Vec::new();
    }
    let (Ok(env), Ok(start)) = (
        evm_config.evm_env(block.recovered.header()),
        state::seed(pre_state, engine.genesis()),
    ) else {
        return Vec::new();
    };
    let (PreState::Genesis(listed) | PreState::Exact { state: listed, .. }) = pre_state;
    let logged = outcome
        .receipts
        .iter()
        .flat_map(|receipt| &receipt.logs)
        .chain(failed_logs);
    let holders: Vec<Address> = db
        .held()
        .into_iter()
        .chain(tempo_invariants::model::logged_addresses(logged))
        .collect();
    let mut failures = Vec::new();
    let mut report = Report::default();
    invariants::check(
        engine,
        &start,
        evm_config,
        &env,
        &InvariantScope::Execution,
        |address| listed.accounts.contains_key(address),
        &holders,
        None,
        &invariants::ViewCache::default(),
        &mut failures,
        &mut report,
    );
    // The chain's own checks judge the start too, over every account the pre-state lists, so a
    // failure the pre-state caused counts against it.
    let state = StepState {
        db: &start,
        evm_config,
        env: &env,
        changed: listed.accounts.keys().copied().collect(),
        start: true,
        effects: Arc::new(Effects {
            changes: Vec::new(),
            logs: Vec::new(),
            calls: None,
            ran: Ran::PreBlock,
        }),
    };
    // Checked on its own, the start carries nothing from the run's steps.
    step::check(
        engine,
        &mut E::Checks::default(),
        &state,
        &InvariantScope::Execution,
        &mut failures,
        &mut report,
    );
    failures
}

/// A block ready to execute.
pub(crate) struct PreparedBlock {
    /// The block with its header resolved, its input's txs decoded and their senders known.
    pub(crate) recovered: RecoveredBlock<Block>,
    /// Whether the harness built the header, so the chain adds its txs around the input's as
    /// its node's block builder does. A block with a given header holds the input's, as imported.
    built_header: bool,
}

/// `block` with its header resolved, its transactions decoded and their senders known. With
/// `parent`, a context header follows it: it takes the next number and links to its hash, and then
/// becomes the parent.
pub(crate) fn recover_block(
    spec: &impl TempoConsensusSpec,
    block: &TempoBlock,
    parent: Option<&mut TempoHeader>,
) -> Result<PreparedBlock, Rejection> {
    let mut header =
        chain::header(spec, &block.header).map_err(|class| Rejection::new(class, Check::Header))?;
    let txs = block
        .txs
        .iter()
        .map(|tx| decode_tx(tx))
        .collect::<Result<Vec<_>, _>>()?;
    let senders = if block.senders.is_empty() {
        txs.iter()
            .map(|tx| {
                tx.try_recover()
                    .map_err(|err| Rejection::new(ErrorClass::Rejected, err))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else if block.senders.len() == txs.len() {
        block.senders.clone()
    } else {
        return Err(Rejection::new(ErrorClass::InvalidInput, Check::SenderCount));
    };
    let built_header = matches!(block.header, BlockHeaderInput::Context(_));
    if built_header {
        header.inner.transactions_root = calculate_transaction_root(&txs);
        if let Some(parent) = parent {
            // Blocks are numbered from 1, so no input holds enough to overflow.
            header.inner.number = parent.inner.number + 1;
            header.inner.parent_hash = parent.hash_slow();
            *parent = header.clone();
        }
    }
    let body = BlockBody {
        transactions: txs,
        ommers: Vec::new(),
        // `TempoPayloadAttributes` gives every block an empty withdrawals list.
        withdrawals: Some(Default::default()),
    };
    Ok(PreparedBlock {
        recovered: RecoveredBlock::new_unhashed(Block::new(header, body), senders),
        built_header,
    })
}

/// Executes `blocks` on `db`, appending each applied block's outputs to `outcome` and setting its
/// error at the first block that fails, and calling `applied_block` with each block that applied and
/// the state after it. Returns the changes of the blocks that applied, the logs of the failed
/// block's transactions before it failed, and why it failed.
pub(crate) fn execute_blocks<E: Engine>(
    engine: &E,
    evm_config: &E::EvmConfig,
    consensus: &E::Consensus,
    db: &Db,
    blocks: &[PreparedBlock],
    outcome: &mut TempoExecutionOutcome,
    applied_block: &mut dyn FnMut(&TempoHeader, &Db),
) -> (Net, Vec<Log>, Option<Rejection>) {
    let mut applied = Net::default();
    let mut failed_logs = Vec::new();
    // What the chain's own checks carry between the run's steps, fresh for every run.
    let mut checks = E::Checks::default();
    for (index, block) in blocks.iter().enumerate() {
        let mut executed = execute_block(
            engine,
            &mut checks,
            evm_config,
            consensus,
            db,
            block,
            index as u64,
        );
        // A read the pre-state could not answer makes the result meaningless,
        // even when the error was swallowed on its way up.
        if db.pre.missed() {
            executed = Err(BlockFailure::rejected(Rejection::new(
                ErrorClass::IncompletePreState,
                Check::IncompletePreState,
            )));
        }
        match executed {
            Ok((updates, outputs)) => {
                for update in &updates {
                    applied.apply(update);
                }
                applied_block(block.recovered.header(), db);
                let (receipts, changes) = outputs.report_into(outcome);
                outcome.receipts.extend(receipts);
                outcome.state_diff.blocks.push(changes);
            }
            Err(BlockFailure { rejection, partial }) => {
                // Report what the transactions before the failing one broke.
                if let Some(partial) = partial {
                    let (receipts, _) = partial.report_into(outcome);
                    failed_logs.extend(receipts.into_iter().flat_map(|r| r.logs));
                }
                outcome.error = rejection.class();
                return (applied, failed_logs, Some(rejection));
            }
        }
    }
    (applied, failed_logs, None)
}

/// What one block produced.
#[derive(Default)]
struct BlockOutputs {
    receipts: Vec<TxReceiptOutput>,
    changes: BlockChanges,
    invariant_failures: Vec<InvariantFailure>,
    invariant_report: Report,
}

impl BlockOutputs {
    /// Adds the broken invariants and counted to `outcome`, leaving out invariants that judged
    /// nothing, such as one gated off at the block's hardfork. Returns the receipts and changes.
    fn report_into(
        self,
        outcome: &mut TempoExecutionOutcome,
    ) -> (Vec<TxReceiptOutput>, BlockChanges) {
        outcome.invariant_failures.extend(self.invariant_failures);
        for (id, counts) in self.invariant_report.counts {
            if counts.evaluated > 0 {
                outcome
                    .invariant_counts
                    .entry(id.into())
                    .or_default()
                    .add(counts);
            }
        }
        (self.receipts, self.changes)
    }
}

/// Why a block failed, and what its transactions produced before it did.
struct BlockFailure {
    rejection: Rejection,
    partial: Option<Box<BlockOutputs>>,
}

impl BlockFailure {
    /// A failure before any transaction ran.
    const fn rejected(rejection: Rejection) -> Self {
        Self {
            rejection,
            partial: None,
        }
    }
}

/// Executes `block` on `db`, returning its state updates and outputs, or why it failed.
fn execute_block<E: Engine>(
    engine: &E,
    checks: &mut E::Checks,
    evm_config: &E::EvmConfig,
    consensus: &E::Consensus,
    db: &Db,
    block: &PreparedBlock,
    block_index: u64,
) -> Result<(Vec<StateUpdate>, BlockOutputs), BlockFailure> {
    fn rejected(err: impl Debug + Display) -> BlockFailure {
        BlockFailure::rejected(Rejection::new(ErrorClass::Rejected, err))
    }
    let sealed = block.recovered.sealed_block();
    consensus
        .validate_header(sealed.sealed_header())
        .map_err(rejected)?;
    consensus
        .validate_block_pre_execution(sealed)
        .map_err(rejected)?;
    let evm = evm_config
        .evm_for_block(db.reader(), block.recovered.header())
        .map_err(rejected)?;
    let ctx = evm_config.context_for_block(sealed).map_err(rejected)?;
    let mut executor = evm_config.create_executor(evm, ctx);
    let hooked = Updates::default();
    let installed = executor.set_state_hook({
        let hooked = Arc::clone(&hooked);
        move |update| hooked.lock().expect("the hook does not panic").push(update)
    });
    assert!(installed, "Tempo's block executor takes a state hook");

    let mut run = BlockRun {
        engine,
        checks,
        evm_config,
        db,
        hooked_updates: hooked,
        block_index,
        view_cache: invariants::ViewCache::default(),
        calls: None,
        state_updates: Vec::new(),
        outputs: BlockOutputs::default(),
    };
    let failed = |run: &mut BlockRun<'_, E>, err: &BlockExecutionError| BlockFailure {
        rejection: block_rejection(err),
        partial: Some(Box::new(mem::take(&mut run.outputs))),
    };
    run.execute_txs(&mut executor, block)
        .map_err(|err| failed(&mut run, &err))?;
    let (spec, env) = env(executor.evm());
    invariants::check_block(
        &run.outputs.receipts,
        spec,
        &InvariantScope::Block { block_index },
        &mut run.outputs.invariant_failures,
        &mut run.outputs.invariant_report,
    );
    let output = executor.finish().map_err(|err| failed(&mut run, &err))?;
    let post_block = take(&run.hooked_updates);
    let net = Net::of(&post_block);
    let cache = db.cache.borrow();
    let contracts = Contracts(&[&output.state.contracts, &cache.contracts]);
    run.outputs.changes.post_block = state::changes(&net, &contracts);
    drop(cache);
    db.commit(&net, |hash| output.state.contracts.get(hash).cloned());
    let scope = InvariantScope::PostBlock { block_index };
    let effects = invariants::StepEffects::new(&net, &[], None, Ran::PostBlock, spec);
    let shared = effects.shared();
    invariants::check(
        engine,
        db,
        evm_config,
        &env,
        &scope,
        |_| true,
        &[],
        Some(effects),
        &run.view_cache,
        &mut run.outputs.invariant_failures,
        &mut run.outputs.invariant_report,
    );
    // The chain's own checks see what `finish` wrote, such as a zone stripping its overlays.
    let state = StepState {
        db,
        evm_config,
        env: &env,
        changed: net.addresses().copied().collect(),
        start: false,
        effects: shared,
    };
    step::check(
        engine,
        run.checks,
        &state,
        &scope,
        &mut run.outputs.invariant_failures,
        &mut run.outputs.invariant_report,
    );
    run.state_updates.extend(post_block);
    Ok((run.state_updates, run.outputs))
}

/// One block's execution: what its steps share, and what they produced so far.
struct BlockRun<'a, E: Engine> {
    engine: &'a E,
    /// What the chain's own checks carry between the run's steps.
    checks: &'a mut E::Checks,
    evm_config: &'a E::EvmConfig,
    db: &'a Db,
    block_index: u64,
    hooked_updates: Updates,
    state_updates: Vec<StateUpdate>,
    view_cache: invariants::ViewCache,
    /// The call frames of each transaction, recorded once invariants are checked.
    calls: Option<Calls>,
    outputs: BlockOutputs,
}

impl<E: Engine> BlockRun<'_, E> {
    /// Applies the block's pre-execution changes and its txs, checking invariants after each step.
    /// Records each receipt and the changes at each step.
    fn execute_txs<'e>(
        &mut self,
        executor: &mut impl TempoExecutor<'e>,
        block: &PreparedBlock,
    ) -> Result<(), BlockExecutionError> {
        executor.apply_pre_execution_changes()?;
        let scope = InvariantScope::Block {
            block_index: self.block_index,
        };
        self.outputs.changes.pre_block = self.step(executor, scope, Ran::PreBlock, &[], None);
        // Only invariant checks read the trace.
        self.calls = invariants::ENABLED.then(|| Calls::install(executor.evm_mut()));

        let header = block.recovered.header();
        let basefee = header.base_fee_per_gas();
        if block.built_header {
            let opening = self.engine.open_block(executor.evm_mut(), header)?;
            self.execute_synthesized(executor, opening, basefee)?;
        }
        let skips = block.built_header && self.engine.skips_invalid_txs();
        for (index, tx) in block.recovered.transactions_recovered().enumerate() {
            // The builder's pool admits no system transaction and no subblock transaction.
            if skips && (tx.is_system_tx() || tx.has_sub_block_nonce_key_prefix()) {
                self.outputs.changes.txs.push(StateChanges::default());
                continue;
            }
            let changes = match self.execute_tx(executor, tx, TxIndex::Input(index as u64), basefee)
            {
                // An invalid transaction changed nothing, so leaving it out is as if the block
                // never held it.
                Err(err) if skips && builder_skips(&err) => {
                    // Drop whatever the tracer saw of it, so the next transaction's trace starts
                    // clean.
                    if let Some(calls) = &self.calls {
                        let _ = calls.take(0, &TxOutcome::Revert);
                    }
                    StateChanges::default()
                }
                changes => changes?,
            };
            self.outputs.changes.txs.push(changes);
        }
        if block.built_header {
            let closing = self.engine.close_block(executor.evm_mut(), header)?;
            self.execute_synthesized(executor, closing, basefee)?;
        }
        Ok(())
    }

    /// Executes `txs`, which the chain added to the block, as [`Self::execute_tx`] does.
    fn execute_synthesized<'e>(
        &mut self,
        executor: &mut impl TempoExecutor<'e>,
        txs: Vec<Recovered<TempoTxEnvelope>>,
        basefee: Option<u64>,
    ) -> Result<(), BlockExecutionError> {
        for tx in txs {
            let index = TxIndex::Synthesized(self.outputs.changes.synthesized.len() as u64);
            let changes = self.execute_tx(executor, tx.as_recovered_ref(), index, basefee)?;
            self.outputs.changes.synthesized.push(changes);
        }
        Ok(())
    }

    /// Executes and commits `tx`. Records its receipt as `index` and checks invariants after it.
    fn execute_tx<'e>(
        &mut self,
        executor: &mut impl TempoExecutor<'e>,
        tx: Recovered<&TempoTxEnvelope>,
        index: TxIndex,
        basefee: Option<u64>,
    ) -> Result<StateChanges, BlockExecutionError> {
        let sender = tx.signer();
        let effective_gas_price = tx.effective_gas_price(basefee);
        let authority = invariants::authority(tx.inner(), sender);
        let result = executor.execute_transaction_without_commit(tx)?;
        let execution = &result.result().result;
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
        let receipt = executor
            .receipts()
            .last()
            .expect("committing a transaction records its receipt");
        let receipt = TxReceiptOutput {
            block_index: self.block_index,
            tx: index,
            outcome,
            gas,
            cumulative_gas_used: receipt.cumulative_gas_used,
            effective_gas_price,
            output,
            logs: receipt.logs.clone(),
        };
        let tx = Tx {
            sender,
            success: receipt.outcome == TxOutcome::Success,
            authority,
        };
        let scope = InvariantScope::Transaction {
            block_index: self.block_index,
            tx: index,
        };
        let calls = self
            .calls
            .as_ref()
            .and_then(|calls| calls.take(receipt.logs.len(), &receipt.outcome));
        let changes = self.step(executor, scope, Ran::Tx(tx), &receipt.logs, calls);
        self.outputs.receipts.push(receipt);
        Ok(changes)
    }

    /// Ends a step that ran `ran`, emitted `logs` and, when traced, made `calls`: writes its
    /// changes to the db, checks invariants at `scope`, reading again only the views that read what
    /// it changed, and returns the step's changes.
    fn step<'e>(
        &mut self,
        executor: &impl BlockExecutor<Evm = TempoEvm<'e>>,
        scope: InvariantScope,
        ran: Ran,
        logs: &[Log],
        calls: Option<Vec<Frame>>,
    ) -> StateChanges {
        let step = take(&self.hooked_updates);
        let net = Net::of(&step);
        let overlay = &executor.evm().overlay_db().cache;
        let contracts = |hash: &_| -> Option<Bytecode> { overlay.contracts.get(hash).cloned() };
        self.db.commit(&net, contracts);
        let changes = {
            let cache = self.db.cache.borrow();
            state::changes(&net, &Contracts(&[&overlay.contracts, &cache.contracts]))
        };
        let (spec, env) = env(executor.evm());
        let effects = invariants::StepEffects::new(&net, logs, calls, ran, spec);
        let shared = effects.shared();
        invariants::check(
            self.engine,
            self.db,
            self.evm_config,
            &env,
            &scope,
            |_| true,
            &[],
            Some(effects),
            &self.view_cache,
            &mut self.outputs.invariant_failures,
            &mut self.outputs.invariant_report,
        );
        let state = StepState {
            db: self.db,
            evm_config: self.evm_config,
            env: &env,
            changed: net.addresses().copied().collect(),
            start: false,
            effects: shared,
        };
        step::check(
            self.engine,
            self.checks,
            &state,
            &scope,
            &mut self.outputs.invariant_failures,
            &mut self.outputs.invariant_report,
        );
        self.state_updates.extend(step);
        changes
    }
}

/// Whether a block builder leaves out a transaction that failed with `err`: invalid at its position,
/// or needing more gas than the block has left.
const fn builder_skips(err: &BlockExecutionError) -> bool {
    matches!(
        err,
        BlockExecutionError::Validation(
            BlockValidationError::InvalidTx { .. }
                | BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas { .. }
        )
    )
}

/// The hardfork and environment `evm` executes the block in.
fn env(evm: &TempoEvm<'_>) -> (TempoHardfork, TempoEvmEnv) {
    let spec = evm.config_spec_id();
    (
        spec,
        TempoEvmEnv::new_with_version(spec, *evm.block(), *evm.version()),
    )
}

/// The updates `hooked` holds, which it then no longer does.
fn take(hooked: &Updates) -> Vec<StateUpdate> {
    mem::take(&mut *hooked.lock().expect("the hook does not panic"))
}

/// A block the node would reject is `Rejected`; anything else went wrong in the executor.
fn block_rejection(err: &BlockExecutionError) -> Rejection {
    match err {
        // A transaction's error is classed by its Tempo variant when it has one.
        BlockExecutionError::Validation(BlockValidationError::InvalidTx { error, .. }) => {
            match TempoInvalidTransaction::from_invalid_tx_error(error.as_ref()) {
                Some(tempo) => Rejection::new(ErrorClass::Rejected, tempo),
                None => Rejection::new(ErrorClass::Rejected, error),
            }
        }
        BlockExecutionError::Validation(error) => Rejection::new(ErrorClass::Rejected, error),
        BlockExecutionError::Internal(error) => Rejection::new(ErrorClass::Internal, error),
    }
}
