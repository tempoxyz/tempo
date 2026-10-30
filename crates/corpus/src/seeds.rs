//! Fuzz seeds from a corpus: each captured block, on the exact pre-state it read, becomes a
//! [`TempoHarnessInput::Blockchain`]. A seed is kept only if the fuzz harness reproduces what the
//! corpus recorded for the block, so a fuzzer starts from inputs known to replay history; blocks it
//! does not reproduce, and blocks that break an invariant, are written apart for triage.

use crate::{
    code,
    store::{self, Catalog, Record, Store},
    types::{Case, Chunk},
};
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, U256};
use bytes::Bytes as Payload;
use parking_lot::Mutex;
use reth_chainspec::{EthChainSpec, ForkCondition};
use slatedb::DbReader;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    fs,
    ops::Range,
    panic::AssertUnwindSafe,
    path::Path,
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
use tokio::runtime::Runtime;
use tracing::info;

/// Records queued between the corpus reader and the workers.
const QUEUE: usize = 256;

/// What exporting a block range produced.
#[derive(Debug, Default)]
pub struct Summary {
    /// Blocks read from the corpus.
    pub blocks: u64,
    /// Seeds written: blocks the harness reproduced without breaking an invariant.
    pub seeds: u64,
    /// The other blocks, by `divergent/<kind>` of their first difference from history or
    /// `invariants/<id>` of each invariant they broke.
    pub findings: BTreeMap<String, u64>,
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
        let Some(info) = &versions[0].1 else {
            accounts.insert(Address::from(*address), AccountInput::default());
            continue;
        };
        let account = info.account();
        let code = match account.bytecode_hash {
            Some(hash) => code::code_bytes(&hash.0)
                .ok_or_else(|| eyre::eyre!("unresolved corpus code {hash}"))?,
            None => Bytes::new(),
        };
        accounts.insert(
            Address::from(*address),
            AccountInput {
                balance: account.balance,
                nonce: account.nonce,
                code,
                storage: BTreeMap::new(),
            },
        );
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
                .map(|(n, hash)| (*n, B256::from(*hash)))
                .collect(),
        },
        blocks: NonEmpty::try_from(blocks).map_err(|err| eyre::eyre!(err))?,
    })
}

/// The kind and a report of the first way `outcome` differs from what the corpus recorded for
/// `chunk`'s single block and its transactions `cases`, or `None` if it reproduces them: per
/// transaction status and gas, then the accounts and storage slots the block changed.
pub fn divergence(
    chunk: &Chunk,
    cases: &[Case],
    outcome: &TempoExecutionOutcome,
) -> eyre::Result<Option<(&'static str, String)>> {
    if outcome.error != ErrorClass::None {
        return Ok(Some(("error", format!("{:?}", outcome.error))));
    }
    // A stored status of 0 is success (`execute::outcome`).
    let expected = cases
        .iter()
        .map(|case| (case.status == 0, case.charged_gas));
    let actual = outcome.receipts.iter().map(|receipt| {
        (
            matches!(receipt.outcome, TxOutcome::Success),
            receipt.gas.tx_gas_used(),
        )
    });
    if !expected.clone().eq(actual.clone()) {
        let (expected, actual): (Vec<_>, Vec<_>) = (expected.collect(), actual.collect());
        return Ok(Some((
            "receipts",
            format!("(success, gas) per tx\nexpected {expected:?}\nactual   {actual:?}"),
        )));
    }
    let changeset = chunk.changeset()?;
    let diff = &outcome.state_diff.total;
    Ok(differ(
        "accounts",
        changeset.accounts.keys().map(|a| Address::from(*a)),
        diff.accounts.iter().map(|a| a.address),
    )
    .or_else(|| {
        differ(
            "storage",
            changeset
                .storage
                .keys()
                .map(|(a, s)| (Address::from(*a), U256::from_be_bytes(*s))),
            diff.storage.iter().map(|s| (s.address, s.slot)),
        )
    }))
}

/// `kind` and the keys missing from or extra in `actual`, unless it has the same as `expected`.
fn differ<T: Ord + Debug>(
    kind: &'static str,
    expected: impl Iterator<Item = T>,
    actual: impl Iterator<Item = T>,
) -> Option<(&'static str, String)> {
    let (expected, actual): (BTreeSet<_>, BTreeSet<_>) = (expected.collect(), actual.collect());
    (expected != actual).then(|| {
        let missing: Vec<_> = expected.difference(&actual).collect();
        let extra: Vec<_> = actual.difference(&expected).collect();
        (kind, format!("missing {missing:#?}\nextra {extra:#?}"))
    })
}

/// Exports the blocks in `range` of a published corpus as harness inputs on `workers` threads: a
/// reproduced block to `<out>/<block>.bin`, one that broke an invariant to
/// `<out>/invariants/<block>.{bin,txt}` and one the harness did not reproduce to
/// `<out>/divergent/<block>.{bin,txt}`. Inputs are bincode-encoded as the harness's C ABI takes them.
/// The reader only streams records; workers verify, decode and execute them.
pub fn export(
    store: Store,
    catalog: Catalog,
    range: Range<u64>,
    chain: &TempoChainSpec,
    out: &Path,
    workers: usize,
) -> eyre::Result<Summary> {
    let chain_spec = chain_spec_input(chain)?;
    for dir in ["divergent", "invariants"] {
        fs::create_dir_all(out.join(dir))?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let reader = runtime.block_on(store.reader(&catalog))?;
    let from = runtime.block_on(store::cursor_at(&reader, &catalog.context, range.start))?;
    let to = runtime.block_on(store::cursor_at(&reader, &catalog.context, range.end))?;
    let summary = Mutex::new(Summary::default());
    let (sender, receiver) = crossbeam_channel::bounded::<(Record, Payload, Vec<Payload>)>(QUEUE);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let receiver = receiver.clone();
                let (runtime, reader, chain_spec, summary) =
                    (&runtime, &reader, &chain_spec, &summary);
                scope.spawn(move || {
                    receiver.iter().try_for_each(|(record, block, cases)| {
                        let seeded =
                            seed(runtime, reader, &record, &block, &cases, chain_spec, out)?;
                        summary.lock().add(seeded);
                        Ok::<_, eyre::Report>(())
                    })
                })
            })
            .collect();
        drop(receiver);
        let read = runtime.block_on(store::for_each_published(
            &reader,
            from,
            &to,
            false,
            |record, block, cases| {
                sender
                    .send((record.clone(), block, cases))
                    .map_err(|_| eyre::eyre!("seed workers stopped"))
            },
        ));
        drop(sender);
        handles
            .into_iter()
            .try_for_each(|handle| handle.join().expect("seed workers do not panic"))
            .and(read)
    })?;
    runtime.block_on(reader.close())?;
    Ok(summary.into_inner())
}

/// A block's findings: none for a seed, or the keys it counts under in [`Summary::findings`].
type Seeded = Option<Vec<String>>;

impl Summary {
    fn add(&mut self, seeded: Seeded) {
        self.blocks += 1;
        match seeded {
            None => self.seeds += 1,
            Some(keys) => keys
                .into_iter()
                .for_each(|key| *self.findings.entry(key).or_default() += 1),
        }
        if self.blocks % 10_000 == 0 {
            info!(
                blocks = self.blocks,
                seeds = self.seeds,
                "Corpus seed export progress"
            );
        }
    }
}

/// Verifies, decodes, converts, executes, checks and writes one corpus record.
fn seed(
    runtime: &Runtime,
    reader: &DbReader,
    record: &Record,
    block: &[u8],
    cases: &[Payload],
    chain_spec: &ChainSpecInput,
    out: &Path,
) -> eyre::Result<Seeded> {
    let chunk = store::decode(block, record)?;
    runtime.block_on(store::resolve_code(reader, &chunk))?;
    let cases = record
        .cases
        .iter()
        .zip(cases)
        .zip(record.first_tx..)
        .map(|((expected, bytes), ordinal)| store::decode_case(bytes, expected, ordinal))
        .collect::<eyre::Result<Vec<_>>>()?;
    let input = TempoHarnessInput::Blockchain(harness_input(&chunk, chain_spec.clone())?);
    let bytes = bincode::serialize(&input)?;
    // A panic is a finding: the node would crash on the same block.
    let finding = match std::panic::catch_unwind(AssertUnwindSafe(|| {
        tempo_fuzz_harness::run(input)
    })) {
        Ok(TempoHarnessOutcome::Blockchain(outcome)) => match divergence(&chunk, &cases, &outcome)?
        {
            Some((kind, report)) => Some(("divergent", vec![kind.to_string()], report)),
            None if outcome.invariant_failures.is_empty() => None,
            None => Some((
                "invariants",
                outcome
                    .invariant_failures
                    .iter()
                    .map(|f| f.id.clone())
                    .collect(),
                format!("{:#?}", outcome.invariant_failures),
            )),
        },
        Ok(_) => eyre::bail!("a blockchain input has a blockchain outcome"),
        Err(panic) => Some((
            "divergent",
            vec!["panic".to_string()],
            panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_default(),
        )),
    };
    let number = chunk.start;
    let Some((dir, keys, report)) = finding else {
        fs::write(out.join(format!("{number}.bin")), &bytes)?;
        return Ok(None);
    };
    let path = |ext| out.join(dir).join(format!("{number}.{ext}"));
    fs::write(path("bin"), &bytes)?;
    fs::write(path("txt"), report)?;
    Ok(Some(
        keys.into_iter().map(|key| format!("{dir}/{key}")).collect(),
    ))
}
