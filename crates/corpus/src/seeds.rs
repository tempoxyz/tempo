//! Fuzz seeds from a corpus: each captured block, on the exact pre-state it read, becomes a
//! [`TempoHarnessInput::Blockchain`]. A seed is kept only if the fuzz harness reproduces what the
//! corpus recorded for the block, so a fuzzer starts from inputs known to replay history; blocks it
//! does not reproduce, and blocks that break an invariant, are written apart for triage.

use crate::{
    code,
    store::{self, Catalog, Store},
    types::{Case, Chunk},
};
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, U256};
use bincode::Options;
use crossbeam_channel::Receiver;
use parking_lot::Mutex;
use reth_chainspec::{EthChainSpec, ForkCondition};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    ops::Range,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::Arc,
};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_fuzz_types::{
    AccountInput, BlockHeaderInput, ChainSpecInput, ErrorClass, NonEmpty, PreState, StateInput,
    TempoBlock, TempoBlockchainInput, TempoExecutionOutcome, TempoHarnessInput,
    TempoHarnessOutcome, TxOutcome,
};
use tempo_primitives::Block;
use tracing::info;

/// Blocks queued between the corpus reader and the workers.
const QUEUE: usize = 256;

/// What exporting a block range produced.
#[derive(Debug, Default)]
pub struct Summary {
    /// Blocks read from the corpus.
    pub blocks: u64,
    /// Seeds written: blocks the harness reproduced without breaking an invariant.
    pub seeds: u64,
    /// Blocks the harness did not reproduce, by the first difference found.
    pub divergent: BTreeMap<&'static str, u64>,
    /// Reproduced blocks that broke an invariant, by invariant ID.
    pub invariants: BTreeMap<String, u64>,
}

/// How the harness's execution of a block differs from what the corpus recorded.
#[derive(Debug, PartialEq, Eq)]
pub enum Divergence {
    /// The harness did not execute the block.
    Error(ErrorClass),
    /// The harness panicked.
    Panic(String),
    ReceiptCount {
        expected: usize,
        actual: usize,
    },
    Status {
        index: usize,
    },
    Gas {
        index: usize,
        expected: u64,
        actual: u64,
    },
    /// Accounts the block changed historically but the harness did not, or the other way round.
    Accounts {
        missing: Vec<Address>,
        extra: Vec<Address>,
    },
    /// Storage slots the block changed historically but the harness did not, or the other way round.
    Storage {
        missing: Vec<(Address, U256)>,
        extra: Vec<(Address, U256)>,
    },
}

impl Divergence {
    /// A stable name for counting divergences of the same kind.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Error(ErrorClass::None) => "error-none",
            Self::Error(ErrorClass::InvalidInput) => "error-invalid-input",
            Self::Error(ErrorClass::RlpDecode) => "error-rlp-decode",
            Self::Error(ErrorClass::Rejected) => "error-rejected",
            Self::Error(ErrorClass::Internal) => "error-internal",
            Self::Error(ErrorClass::IncompletePreState) => "error-incomplete-pre-state",
            Self::Panic(_) => "panic",
            Self::ReceiptCount { .. } => "receipt-count",
            Self::Status { .. } => "status",
            Self::Gas { .. } => "gas",
            Self::Accounts { .. } => "accounts",
            Self::Storage { .. } => "storage",
        }
    }
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:#?}")
    }
}

/// The harness chain for `spec`: its chain ID and hardfork schedule. A hardfork `spec` never
/// activates is scheduled at `u64::MAX`, so the harness does not activate it by default.
pub fn chain_spec_input(spec: &TempoChainSpec) -> eyre::Result<ChainSpecInput> {
    let hardforks = TempoHardfork::VARIANTS
        .iter()
        .map(|&fork| match spec.tempo_fork_activation(fork) {
            ForkCondition::Timestamp(at) => Ok((fork, at)),
            ForkCondition::Never => Ok((fork, u64::MAX)),
            condition => eyre::bail!("{fork:?} activates by {condition:?}, not by timestamp"),
        })
        .collect::<eyre::Result<_>>()?;
    Ok(ChainSpecInput {
        chain_id: spec.chain_id(),
        hardforks,
    })
}

/// `chunk`'s blocks on the exact pre-state they read. Its code must be resolved
/// ([`store::resolve_code`]).
pub fn harness_input(
    chunk: &Chunk,
    chain_spec: ChainSpecInput,
) -> eyre::Result<TempoBlockchainInput> {
    let mut accounts = BTreeMap::<Address, AccountInput>::new();
    // `Chunk::validate` ensures every key's first version is the state before the chunk.
    for (address, versions) in &chunk.accounts {
        let account = match &versions[0].1 {
            Some(info) => {
                let account = info.account();
                let code = match account.bytecode_hash {
                    Some(hash) => code::code_bytes(&hash.0)
                        .ok_or_else(|| eyre::eyre!("unresolved corpus code {hash}"))?,
                    None => Bytes::new(),
                };
                AccountInput {
                    balance: account.balance,
                    nonce: account.nonce,
                    code,
                    storage: BTreeMap::new(),
                }
            }
            None => AccountInput::default(),
        };
        accounts.insert(Address::from(*address), account);
    }
    for ((address, slot), versions) in &chunk.storage {
        accounts
            .entry(Address::from(*address))
            .or_default()
            .storage
            .insert(
                U256::from_be_bytes(*slot),
                U256::from_be_bytes(versions[0].1),
            );
    }
    let blocks = chunk
        .blocks
        .iter()
        .map(|input| {
            let block: Block = alloy_rlp::decode_exact(&input.rlp)?;
            Ok(TempoBlock {
                header: BlockHeaderInput::Rlp(alloy_rlp::encode(&block.header).into()),
                txs: block
                    .body
                    .transactions
                    .iter()
                    .map(|tx| tx.encoded_2718().into())
                    .collect(),
                senders: input.senders.iter().copied().map(Address::from).collect(),
            })
        })
        .collect::<eyre::Result<Vec<_>>>()?;
    Ok(TempoBlockchainInput {
        chain_spec,
        pre_state: PreState::Exact {
            state: StateInput { accounts },
            block_hashes: chunk
                .hashes
                .iter()
                .map(|(number, hash)| (*number, B256::from(*hash)))
                .collect(),
        },
        blocks: NonEmpty::try_from(blocks).map_err(|err| eyre::eyre!(err))?,
    })
}

/// The first way `outcome` differs from what the corpus recorded for `chunk`'s single block and
/// its transactions `cases`, or `None` if it reproduces them.
pub fn divergence(
    chunk: &Chunk,
    cases: &[Case],
    outcome: &TempoExecutionOutcome,
) -> eyre::Result<Option<Divergence>> {
    if outcome.error != ErrorClass::None {
        return Ok(Some(Divergence::Error(outcome.error)));
    }
    if outcome.receipts.len() != cases.len() {
        return Ok(Some(Divergence::ReceiptCount {
            expected: cases.len(),
            actual: outcome.receipts.len(),
        }));
    }
    for (index, (case, receipt)) in cases.iter().zip(&outcome.receipts).enumerate() {
        // A stored status of 0 is success (`execute::outcome`).
        if (case.status == 0) != matches!(receipt.outcome, TxOutcome::Success) {
            return Ok(Some(Divergence::Status { index }));
        }
        let actual = receipt.gas.tx_gas_used();
        if actual != case.charged_gas {
            return Ok(Some(Divergence::Gas {
                index,
                expected: case.charged_gas,
                actual,
            }));
        }
    }
    let changeset = chunk.changeset()?;
    let diff = &outcome.state_diff.total;
    let expected: BTreeSet<_> = changeset
        .accounts
        .keys()
        .map(|a| Address::from(*a))
        .collect();
    let actual: BTreeSet<_> = diff.accounts.iter().map(|a| a.address).collect();
    if expected != actual {
        return Ok(Some(Divergence::Accounts {
            missing: expected.difference(&actual).copied().collect(),
            extra: actual.difference(&expected).copied().collect(),
        }));
    }
    let expected: BTreeSet<_> = changeset
        .storage
        .keys()
        .map(|(a, s)| (Address::from(*a), U256::from_be_bytes(*s)))
        .collect();
    let actual: BTreeSet<_> = diff.storage.iter().map(|s| (s.address, s.slot)).collect();
    if expected != actual {
        return Ok(Some(Divergence::Storage {
            missing: expected.difference(&actual).copied().collect(),
            extra: actual.difference(&expected).copied().collect(),
        }));
    }
    Ok(None)
}

/// Exports the blocks in `range` of a published corpus as harness inputs on `workers` threads: a
/// reproduced block to `<out>/<block>.bin`, one that broke an invariant to
/// `<out>/invariants/<block>.{bin,txt}` and one the harness did not reproduce to
/// `<out>/divergent/<block>.{bin,txt}`. Inputs are bincode-encoded as the harness's C ABI takes them.
pub fn export(
    store: Store,
    catalog: Catalog,
    range: Range<u64>,
    chain: &TempoChainSpec,
    out: &Path,
    workers: usize,
) -> eyre::Result<Summary> {
    eyre::ensure!(workers > 0, "workers must be positive");
    let chain_spec = chain_spec_input(chain)?;
    for dir in ["", "divergent", "invariants"] {
        fs::create_dir_all(out.join(dir))?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let reader = runtime.block_on(store.reader(&catalog))?;
    let from = runtime.block_on(store::cursor_at(&reader, &catalog.context, range.start))?;
    let to = runtime.block_on(store::cursor_at(&reader, &catalog.context, range.end))?;
    let summary = Mutex::new(Summary::default());
    let (sender, receiver) = crossbeam_channel::bounded(QUEUE);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let receiver = receiver.clone();
                let (chain_spec, summary) = (&chain_spec, &summary);
                scope.spawn(move || work(&receiver, chain_spec, out, summary))
            })
            .collect();
        drop(receiver);
        let read = runtime.block_on(store::for_each_published(
            &reader,
            from,
            &to,
            true,
            |record, block, cases| {
                let chunk = store::decode(&block, record)?;
                let cases = cases
                    .iter()
                    .zip(&record.cases)
                    .enumerate()
                    .map(|(i, (bytes, expected))| {
                        store::decode_case(bytes, expected, record.first_tx + i as u64)
                    })
                    .collect::<eyre::Result<Vec<_>>>()?;
                sender
                    .send((chunk, cases))
                    .map_err(|_| eyre::eyre!("seed workers stopped"))
            },
        ));
        drop(sender);
        let worked = handles
            .into_iter()
            .map(|handle| handle.join().expect("seed workers do not panic"))
            .collect::<eyre::Result<Vec<()>>>();
        read.and(worked.map(drop))
    })?;
    runtime.block_on(reader.close())?;
    Ok(summary.into_inner())
}

/// Converts, executes, checks and writes the blocks it receives until the channel closes.
fn work(
    receiver: &Receiver<(Arc<Chunk>, Vec<Case>)>,
    chain_spec: &ChainSpecInput,
    out: &Path,
    summary: &Mutex<Summary>,
) -> eyre::Result<()> {
    let encoding = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes();
    for (chunk, cases) in receiver {
        let number = chunk.start;
        let input = TempoHarnessInput::Blockchain(harness_input(&chunk, chain_spec.clone())?);
        let bytes = encoding.serialize(&input)?;
        // A panic is a finding: the node would crash on the same block.
        let executed =
            std::panic::catch_unwind(AssertUnwindSafe(move || tempo_fuzz_harness::run(input)));
        let found = match &executed {
            Ok(TempoHarnessOutcome::Blockchain(outcome)) => divergence(&chunk, &cases, outcome)?
                .map_or_else(|| Found::Reproduced(outcome), Found::Divergent),
            Ok(_) => eyre::bail!("a blockchain input has a blockchain outcome"),
            Err(panic) => Found::Divergent(Divergence::Panic(panic_message(panic.as_ref()))),
        };
        let mut summary = summary.lock();
        summary.blocks += 1;
        match found {
            Found::Reproduced(outcome) if outcome.invariant_failures.is_empty() => {
                fs::write(out.join(format!("{number}.bin")), &bytes)?;
                summary.seeds += 1;
            }
            Found::Reproduced(outcome) => {
                for failure in &outcome.invariant_failures {
                    *summary.invariants.entry(failure.id.clone()).or_default() += 1;
                }
                write_finding(
                    &out.join("invariants"),
                    number,
                    &bytes,
                    &format!("{:#?}", outcome.invariant_failures),
                )?;
            }
            Found::Divergent(divergence) => {
                *summary.divergent.entry(divergence.kind()).or_default() += 1;
                write_finding(
                    &out.join("divergent"),
                    number,
                    &bytes,
                    &divergence.to_string(),
                )?;
            }
        }
        if summary.blocks % 10_000 == 0 {
            info!(
                blocks = summary.blocks,
                seeds = summary.seeds,
                "Corpus seed export progress"
            );
        }
    }
    Ok(())
}

enum Found<'a> {
    Reproduced(&'a TempoExecutionOutcome),
    Divergent(Divergence),
}

fn write_finding(dir: &Path, number: u64, input: &[u8], report: &str) -> eyre::Result<()> {
    let path = |ext| -> PathBuf { dir.join(format!("{number}.{ext}")) };
    fs::write(path("bin"), input)?;
    fs::write(path("txt"), report)?;
    Ok(())
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic".to_string())
}
