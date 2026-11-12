//! Zone mode: Tempo blocks, then the blocks of a zone anchored to them (TIP-1154).
//!
//! Tempo runs first, whole, keeping its state after each block. The harness then sequences the
//! zone: zone block `i` opens with the system `advanceTempo` transaction importing Tempo block
//! `i`'s header, and the zone reads Tempo state at that anchor from the kept states. User
//! transactions the zone rejects are left out, as a sequencer's block builder leaves them out.

use std::sync::{Arc, LazyLock};

use alloy_consensus::{Sealable as _, crypto::RecoveryError};
use alloy_eips::Encodable2718 as _;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, Bytes, Log, U256};
use evm2::evm::Cache;
use invariants_core::Report;
use reth_chainspec::EthChainSpec as _;
use reth_evm::{
    BlockExecutionError, BlockExecutor as _, BlockExecutorFactory as _,
    BlockTransactionResult as _, ConfigureEvm as _,
};
use reth_primitives_traits::{Recovered, SealedBlock, transaction::signed::SignedTransaction as _};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks as _},
};
use tempo_contracts::precompiles::PATH_USD_ADDRESS;
use tempo_evm::{TempoEvmConfig, TempoEvmEnv, TempoEvmError};
use tempo_fuzz_types::{
    BlockHeaderInput, ErrorClass, InvariantFailure, InvariantScope, PreState,
    TempoExecutionOutcome, TempoZoneInput,
};
use tempo_invariants::Tx;
use tempo_precompiles::storage::account_config_commitment;
use tempo_primitives::{Block, TempoHeader, TempoTxEnvelope};
use zone_chainspec::{GENESIS_TEMPLATE_JSON, ZoneChainSpec};
use zone_evm::{
    BLOCK_SIZE_SAFETY_MARGIN, BlockCandidates, Skipped, ZoneBlockExecutor, ZoneEvmConfig,
    build_advance_tempo_tx_from_parts, fill_block,
};
use zone_precompiles::{
    L1StateError, L1StorageReader,
    tempo_state::{TEMPO_BLOCK_NUMBER_SLOT, slots::TEMPO_BLOCK_HASH},
    zone_fee_manager::slots::DEFAULT_FEE_TOKEN,
};
use zone_primitives::constants::{
    MAX_RLP_BLOCK_SIZE, TEMPO_STATE_ADDRESS, ZONE_FEE_MANAGER_ADDRESS, ZONE_INBOX_ADDRESS,
    ZONE_OUTBOX_ADDRESS, zone_chain_id,
};

use crate::{
    chain,
    execute::{self, Check, Updates, class, reject, take},
    invariants::{self, ZoneMirror},
    state::{self, Db, Net},
};

/// The zone the harness runs: zone 1 of the Tempo chain.
const ZONE_ID: u32 = 1;

/// The most accounts the zone invariants watch, as each costs views at every step.
const MAX_WATCHED: usize = 32;

/// The zone dev genesis allocation, seeded once per process.
static ZONE_GENESIS: LazyLock<Cache> = LazyLock::new(|| {
    let genesis: Genesis =
        serde_json::from_str(GENESIS_TEMPLATE_JSON).expect("the zone genesis template parses");
    state::genesis(&genesis.alloc)
});

/// A Tempo block a zone can anchor to, and the state after it.
pub(crate) struct Anchor {
    header: TempoHeader,
    hash: B256,
    /// The hardfork active at the block.
    spec: TempoHardfork,
    state: Cache,
}

impl Anchor {
    /// `header`, a block of `chain`, with the state `db` holds after it.
    pub(crate) fn new(chain: &TempoChainSpec, header: &TempoHeader, db: &Db) -> Self {
        Self {
            header: header.clone(),
            hash: header.hash_slow(),
            spec: chain.tempo_hardfork_at(header.inner.timestamp),
            state: db.cache.borrow().clone(),
        }
    }

    /// The block's hash.
    pub(crate) const fn hash(&self) -> B256 {
        self.hash
    }

    /// The hardfork active at the block.
    pub(crate) const fn spec(&self) -> TempoHardfork {
        self.spec
    }

    /// The block's header.
    pub(crate) const fn header(&self) -> &TempoHeader {
        &self.header
    }

    /// The state after the block, as a database.
    pub(crate) fn db(&self) -> Db {
        state::seed(&self.state, &PreState::Genesis(Default::default()))
            .expect("an empty pre-state seeds")
    }
}

/// Tempo state at each block a zone can anchor to, by block number. A block it does not hold is
/// unavailable.
#[derive(Clone)]
pub(crate) struct AnchorReader(Arc<[Anchor]>);

impl AnchorReader {
    /// The anchor at Tempo block `number`.
    pub(crate) fn get(&self, number: u64) -> Option<&Anchor> {
        self.0
            .iter()
            .find(|anchor| anchor.header.inner.number == number)
    }
}

impl L1StorageReader for AnchorReader {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        let anchor = self
            .get(block_number)
            .ok_or_else(|| L1StateError::StorageUnavailable {
                account,
                slot,
                block_number,
                reason: "no such Tempo block".into(),
            })?;
        // A genesis pre-state reads what it does not hold as zero.
        let value = anchor
            .state
            .storage
            .get(&account)
            .and_then(|storage| storage.slots.get(&slot.into()))
            .copied()
            .unwrap_or_default();
        Ok(value.into())
    }

    fn read_l1_commitment(
        &self,
        account: Address,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        let unavailable = |reason: String| L1StateError::AccountUnavailable {
            account,
            block_number,
            reason,
        };
        let anchor = self
            .get(block_number)
            .ok_or_else(|| unavailable("no such Tempo block".into()))?;
        match anchor.state.accounts.get(&account).and_then(Option::as_ref) {
            Some(info) => account_config_commitment(info, anchor.spec)
                .map_err(|err| unavailable(err.to_string())),
            None => Ok(B256::ZERO),
        }
    }
}

/// Executes `input`: its Tempo chain, then its zone blocks on what the Tempo blocks left.
pub(crate) fn run(input: &TempoZoneInput) -> TempoExecutionOutcome {
    let failed = |error| TempoExecutionOutcome {
        error,
        ..Default::default()
    };
    let invalid = |why| failed(reject(ErrorClass::InvalidInput, Check::Zone(why)));
    let tempo = &input.tempo;
    if !matches!(tempo.pre_state, PreState::Genesis(_)) {
        return invalid("the Tempo pre-state is not a genesis pre-state");
    }
    let blocks = tempo.blocks.as_slice();
    if !blocks
        .iter()
        .all(|block| matches!(block.header, BlockHeaderInput::Context(_)))
    {
        return invalid("a Tempo header is not a context header");
    }
    if input.blocks.len() > blocks.len() {
        return invalid("more zone blocks than Tempo blocks");
    }
    let Ok(chain_id) = zone_chain_id(tempo.chain_spec.chain_id, ZONE_ID) else {
        return invalid("the Tempo chain ID has no zone chain ID");
    };
    // Zones create no contracts and reject authorization lists, so no account outside the zone
    // genesis holds code starting with 0xef: the account marker or a delegation.
    let unreachable_code = input.pre_state.accounts.iter().any(|(address, account)| {
        !ZONE_GENESIS.accounts.contains_key(address) && account.code.first() == Some(&0xef)
    });
    if unreachable_code {
        return invalid("the zone pre-state holds code a zone never stores");
    }
    let db = match state::seed(&ZONE_GENESIS, &PreState::Genesis(input.pre_state.clone())) {
        Ok(db) => db,
        Err(class) => return failed(reject(class, Check::PreState)),
    };
    let zone_blocks = match input
        .blocks
        .iter()
        .map(|block| {
            let txs = block.txs.iter().enumerate();
            txs.map(|(index, tx)| Candidate::decode(index as u64, tx))
                .collect()
        })
        .collect::<Result<Vec<Vec<_>>, _>>()
    {
        Ok(blocks) => blocks,
        Err(class) => return failed(class),
    };

    let mut anchors = Vec::new();
    let mut outcome = execute::execute(
        &tempo.chain_spec,
        &tempo.pre_state,
        blocks,
        Some(&mut anchors),
    );
    // The Tempo chain did not execute at all, or its pre-state already breaks an invariant.
    if anchors.is_empty() || outcome.error == ErrorClass::InvalidInput {
        return outcome;
    }

    let tempo_spec = chain::chain_spec(&tempo.chain_spec).expect("Tempo executed on this schedule");
    // The zone runs Tempo's hardfork schedule with its own chain ID.
    let mut spec = tempo_spec.clone();
    spec.inner.chain = chain_id.into();
    spec.inner.genesis.config.chain_id = chain_id;
    let spec = Arc::new(ZoneChainSpec {
        inner: Arc::new(spec),
    });
    let reader = AnchorReader(anchors.into());
    {
        let mut cache = db.cache.borrow_mut();
        let genesis_hash: U256 = reader.0[0].hash.into();
        cache
            .storage
            .entry(TEMPO_STATE_ADDRESS)
            .or_default()
            .slots
            .extend([
                (TEMPO_BLOCK_HASH, genesis_hash),
                (TEMPO_BLOCK_NUMBER_SLOT, U256::ZERO),
            ]);
        cache
            .storage
            .entry(ZONE_FEE_MANAGER_ADDRESS)
            .or_default()
            .slots
            .insert(DEFAULT_FEE_TOKEN, PATH_USD_ADDRESS.into_word().into());
    }
    let zone = Zone {
        config: ZoneEvmConfig::new(Arc::clone(&spec), reader.clone(), Address::ZERO),
        tempo_config: TempoEvmConfig::new(Arc::new(tempo_spec)),
        reader,
        db,
        watched: watched(input, &zone_blocks),
        chain_id,
    };
    let mut findings = Findings {
        mirror: ZoneMirror::default(),
        outcome: &mut outcome,
    };
    let mut parent_hash = spec.inner.genesis_hash();
    for (index, (txs, anchor)) in zone_blocks.into_iter().zip(&zone.reader.0[1..]).enumerate() {
        match zone.execute_block(&mut findings, index as u64, anchor, parent_hash, txs) {
            Ok(hash) => parent_hash = hash,
            Err(error) => {
                if findings.outcome.error == ErrorClass::None {
                    findings.outcome.error = error.class();
                }
                break;
            }
        }
    }
    outcome
}

/// A zone transaction of the input: decoded, with its sender if it recovers.
struct Candidate {
    /// Its index in [`tempo_fuzz_types::ZoneBlock::txs`].
    index: u64,
    tx: TempoTxEnvelope,
    sender: Result<Address, RecoveryError>,
}

impl Candidate {
    /// Decodes `bytes`, the transaction at `index`; an RLP error if they do not decode.
    fn decode(index: u64, bytes: &Bytes) -> Result<Self, ErrorClass> {
        let tx = execute::decode_tx(bytes)?;
        Ok(Self {
            index,
            sender: tx.try_recover(),
            tx,
        })
    }
}

/// Why a zone block failed.
enum ZoneBlockError {
    /// Its block environment does not resolve.
    Env(TempoEvmError),
    /// Executing it failed.
    Execution(BlockExecutionError),
}

impl ZoneBlockError {
    /// The error class, recorded as the input's rejection.
    fn class(&self) -> ErrorClass {
        match self {
            Self::Env(err) => reject(ErrorClass::Rejected, err),
            Self::Execution(err) => class(err),
        }
    }
}

/// The zone, as the harness sequences and checks it.
struct Zone {
    config: ZoneEvmConfig<AnchorReader>,
    tempo_config: TempoEvmConfig,
    reader: AnchorReader,
    db: Db,
    /// The accounts the zone invariants read at each step.
    watched: Vec<Address>,
    chain_id: u64,
}

/// What the zone invariants found so far, and the zone as they last read it.
struct Findings<'a> {
    mirror: ZoneMirror,
    /// The outcome the failures and counts are added to.
    outcome: &'a mut TempoExecutionOutcome,
}

impl Zone {
    /// Executes zone block `index` anchored to `anchor`, with `txs` after its `advanceTempo`,
    /// returning its hash.
    fn execute_block(
        &self,
        findings: &mut Findings<'_>,
        index: u64,
        anchor: &Anchor,
        parent_hash: B256,
        txs: Vec<Candidate>,
    ) -> Result<B256, ZoneBlockError> {
        let mut header = anchor.header.clone();
        header.inner.number = index + 1;
        header.inner.parent_hash = parent_hash;
        header.inner.base_fee_per_gas = Some(0);
        header.inner.extra_data = Bytes::new();
        header.general_gas_limit = 0;
        header.shared_gas_limit = 0;
        header.consensus_context = None;
        let block = SealedBlock::seal_slow(Block::new(header, Default::default()));
        let evm = self
            .config
            .evm_for_block(self.db.reader(), block.header())
            .map_err(ZoneBlockError::Env)?;
        let ctx = self
            .config
            .context_for_block(&block)
            .map_err(ZoneBlockError::Env)?;
        let mut executor = self.config.create_executor(evm, ctx);
        let hooked = Updates::default();
        let installed = executor.set_state_hook({
            let hooked = Arc::clone(&hooked);
            move |update| hooked.lock().expect("the hook does not panic").push(update)
        });
        assert!(installed, "the zone block executor takes a state hook");
        if index == 0 && *invariants::ENABLED {
            let mut report = Report::default();
            findings.mirror.start(&self.at(&executor), &mut report);
            findings.record(report, &InvariantScope::ZoneBlock { block_index: 0 });
        }

        executor
            .apply_pre_execution_changes()
            .map_err(ZoneBlockError::Execution)?;
        let advance = build_advance_tempo_tx_from_parts(
            &anchor.header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            self.chain_id,
        );
        executor
            .execute_transaction(advance.as_recovered_ref())
            .map_err(ZoneBlockError::Execution)?;
        let logs = last_logs(&executor);
        self.step(
            findings,
            &executor,
            &hooked,
            InvariantScope::ZoneBlock { block_index: index },
            None,
            &logs,
        );

        let mut candidates = Candidates {
            zone: self,
            findings,
            executor: &mut executor,
            hooked: &hooked,
            block_index: index,
            txs: txs.into_iter(),
        };
        fill_block(
            &mut candidates,
            MAX_RLP_BLOCK_SIZE - BLOCK_SIZE_SAFETY_MARGIN,
        )
        .map_err(ZoneBlockError::Execution)?;

        executor.finish().map_err(ZoneBlockError::Execution)?;
        // Zones deploy no code, so no post-block change brings any.
        self.db.commit(&Net::of(&take(&hooked)), |_| None);
        Ok(block.hash())
    }

    /// Ends a zone step: writes its changes to the zone state and checks the zone invariants at
    /// `scope`. `tx` is the step's user transaction, `logs` its logs.
    fn step(
        &self,
        findings: &mut Findings<'_>,
        executor: &ZoneBlockExecutor<'_>,
        hooked: &Updates,
        scope: InvariantScope,
        tx: Option<Tx>,
        logs: &[Log],
    ) {
        let updates = take(hooked);
        let net = Net::of(&updates);
        let overlay = &executor.evm().overlay_db().cache;
        self.db
            .commit(&net, |hash| overlay.contracts.get(hash).cloned());
        if !*invariants::ENABLED {
            return;
        }
        let mut report = Report::default();
        findings
            .mirror
            .check(&self.at(executor), &net, tx, logs, &mut report);
        findings.record(report, &scope);
    }

    /// What the zone invariants read at the executor's block.
    fn at<'b>(&'b self, executor: &ZoneBlockExecutor<'_>) -> invariants::ZoneContext<'b> {
        let evm = executor.evm();
        invariants::ZoneContext {
            db: &self.db,
            config: &self.config,
            tempo_config: &self.tempo_config,
            reader: &self.reader,
            env: TempoEvmEnv::new_with_version(evm.config_spec_id(), *evm.block(), *evm.version()),
            watched: &self.watched,
        }
    }
}

impl Findings<'_> {
    /// Adds what `report` found and counted at `scope` to the outcome.
    fn record(&mut self, mut report: Report, scope: &InvariantScope) {
        self.outcome
            .invariant_failures
            .extend(
                report
                    .violations
                    .drain(..)
                    .map(|violation| InvariantFailure {
                        id: violation.id.to_string(),
                        message: format!("{} {}", violation.subject, violation.detail),
                        scope: scope.clone(),
                    }),
            );
        for (id, counts) in report.counts {
            self.outcome
                .invariant_counts
                .entry(id.into())
                .or_default()
                .add(counts);
        }
    }
}

/// A zone block's user transactions, as a sequencer's block builder executes them.
struct Candidates<'a, 'b, 'c, I> {
    zone: &'a Zone,
    findings: &'a mut Findings<'b>,
    executor: &'a mut ZoneBlockExecutor<'c>,
    hooked: &'a Updates,
    block_index: u64,
    txs: I,
}

/// Why the sequencer leaves a transaction out before executing it: the pool admits none of these.
#[derive(Debug)]
enum Unsequenced {
    /// A system transaction, which only the sequencer itself creates.
    System,
    /// A transaction with a subblock nonce key, which zones do not support.
    Subblock,
    /// Its sender does not recover.
    Sender,
}

impl<I: Iterator<Item = Candidate>> BlockCandidates for Candidates<'_, '_, '_, I> {
    type Tx = Candidate;
    type ScreenError = Unsequenced;

    fn next(&mut self) -> Option<Candidate> {
        self.txs.next()
    }

    fn is_cancelled(&self) -> bool {
        false
    }

    fn screen(&self, tx: &Candidate) -> Result<(), Unsequenced> {
        if tx.tx.is_system_tx() {
            return Err(Unsequenced::System);
        }
        if tx.tx.has_sub_block_nonce_key_prefix() {
            return Err(Unsequenced::Subblock);
        }
        tx.sender
            .as_ref()
            .map(|_| ())
            .map_err(|_| Unsequenced::Sender)
    }

    fn encoded_length(&self, tx: &Candidate) -> usize {
        tx.tx.encode_2718_len()
    }

    fn execute(&mut self, candidate: &Candidate) -> Result<(), BlockExecutionError> {
        let sender = *candidate
            .sender
            .as_ref()
            .expect("the screen leaves out transactions whose sender does not recover");
        let spec = self.executor.evm().config_spec_id();
        let authority = invariants::authority(&candidate.tx, sender, spec.is_t14());
        let result = self
            .executor
            .execute_transaction_without_commit(Recovered::new_unchecked(&candidate.tx, sender))?;
        let success = result.result().result.status;
        self.executor.commit_transaction(result)?;
        let logs = last_logs(self.executor);
        let tx = Tx {
            sender,
            success,
            authority,
        };
        let scope = InvariantScope::ZoneTransaction {
            block_index: self.block_index,
            tx_index: candidate.index,
        };
        self.zone.step(
            self.findings,
            self.executor,
            self.hooked,
            scope,
            Some(tx),
            &logs,
        );
        Ok(())
    }

    fn skip(&mut self, _tx: &Candidate, _why: Skipped<Unsequenced>) {}
}

/// The logs of the transaction `executor` committed last.
fn last_logs(executor: &ZoneBlockExecutor<'_>) -> Vec<Log> {
    executor
        .receipts()
        .last()
        .expect("committing a transaction records its receipt")
        .logs
        .clone()
}

/// The accounts the zone invariants watch: the zone's system contracts, the zone and Tempo
/// transactions' signers and the accounts their signatures act for, and the zone pre-state's
/// accounts, the first [`MAX_WATCHED`] of them.
fn watched(input: &TempoZoneInput, zone_blocks: &[Vec<Candidate>]) -> Vec<Address> {
    let mut accounts = vec![
        TEMPO_STATE_ADDRESS,
        ZONE_INBOX_ADDRESS,
        ZONE_OUTBOX_ADDRESS,
        ZONE_FEE_MANAGER_ADDRESS,
    ];
    let mut signers = |tx: &TempoTxEnvelope, sender: Address| {
        accounts.push(sender);
        accounts.extend(invariants::authority(tx, sender, true).accounts());
    };
    for candidate in zone_blocks.iter().flatten() {
        if let Ok(sender) = candidate.sender {
            signers(&candidate.tx, sender);
        }
    }
    for block in input.tempo.blocks.as_slice() {
        for (index, bytes) in block.txs.iter().enumerate() {
            // Every Tempo transaction decoded and recovered, or no Tempo block executed.
            let Ok(tx) = execute::decode_tx(bytes) else {
                continue;
            };
            let sender = match block.senders.get(index) {
                Some(sender) => *sender,
                None => match tx.try_recover() {
                    Ok(sender) => sender,
                    Err(_) => continue,
                },
            };
            signers(&tx, sender);
        }
    }
    accounts.extend(input.pre_state.accounts.keys());
    let mut seen = std::collections::HashSet::new();
    accounts.retain(|account| seen.insert(*account));
    accounts.truncate(MAX_WATCHED);
    accounts
}
