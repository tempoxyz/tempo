//! Corpus blocks as fuzz harness inputs. Each block, on the exact pre-state it read, becomes a
//! [`TempoHarnessInput::Blockchain`] on the corpus's chain. A block list file names a subset of a
//! corpus, such as the blocks a minimizer kept.

use crate::{
    code,
    store::{self, Catalog, Lease, Store},
    types::Input,
};
use alloy_eips::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, U256};
use futures::{StreamExt, TryStreamExt, stream};
use reth_chainspec::{EthChainSpec, ForkCondition};
use slatedb::DbReader;
use std::{collections::BTreeMap, fs, iter, path::Path, sync::Arc};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
    spec::{MODERATO, PRESTO},
};
use tempo_fuzz_types::{
    AccountInput, BlockHeaderInput, ChainSpecInput, NonEmpty, PreState, StateInput, TempoBlock,
    TempoBlockchainInput, TempoHarnessInput,
};
use tempo_primitives::Block;
use tokio::{runtime::Runtime, sync::mpsc};
use tokio_util::task::AbortOnDropHandle;
use tracing::warn;

/// Worker threads of a corpus's runtime: they renew its lease and decode the blocks it reads ahead.
const WORKERS: usize = 4;

/// Stored block bytes [Corpus::windows] aims to read per window.
const WINDOW_BYTES: usize = 32 << 20;

/// Blocks of a window read and decoded at once.
const CONCURRENT_BLOCKS: usize = 32;

/// A window spanning at least this many corpus blocks per block it lists is read with point reads.
const SPARSE_SPAN: u64 = 4;

/// A run of neighbouring blocks shorter than this stays in a sparse window, where the window's
/// parallel point reads cover it, rather than getting a scan of its own.
const MIN_RUN: usize = 32;

/// A corpus, open at its published checkpoint. A fill extending it meanwhile does not change
/// what this reads.
pub struct Corpus {
    runtime: Runtime,
    store: Store,
    /// Keeps the snapshot readable while a fill extends the corpus; taken when dropped.
    lease: Option<Lease>,
    reader: Arc<DbReader>,
    catalog: Catalog,
    chain_spec: ChainSpecInput,
}

impl Corpus {
    /// Opens the published blocks of the corpus at `url` (`s3://bucket/prefix` or
    /// `file:///directory`), with S3 reads going to `endpoint` when given.
    pub fn open(url: &str, endpoint: Option<&str>) -> eyre::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKERS)
            .enable_all()
            .build()?;
        let (store, mut catalog) = runtime.block_on(async {
            let store = Store::open(url, endpoint).await?;
            let (catalog, _) = store
                .catalog()
                .await?
                .ok_or_else(|| eyre::eyre!("no corpus catalog at {url}"))?;
            eyre::Ok((store, catalog))
        })?;
        let lease = store.lease_published(&runtime, &mut catalog, || {})?;
        let (reader, tip) = runtime.block_on(async {
            let reader = store.reader(&catalog).await?;
            let tip = store::tip_timestamp(&reader, &catalog.cursor).await?;
            eyre::Ok((reader, tip))
        })?;
        let chain_spec = chain_spec_input(&catalog, tip)?;
        Ok(Self {
            runtime,
            store,
            lease: Some(lease),
            reader: Arc::new(reader),
            catalog,
            chain_spec,
        })
    }

    /// The catalog of the published checkpoint this reads.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Fails once the lease may expire, so reads through it must stop.
    fn ensure_leased(&self) -> eyre::Result<()> {
        eyre::ensure!(
            !self.lease.as_ref().is_some_and(Lease::expiring),
            "corpus lease expires before it can be renewed"
        );
        Ok(())
    }

    /// `block`'s harness input.
    pub fn input(&self, block: u64) -> eyre::Result<TempoHarnessInput> {
        self.ensure_leased()?;
        let stored = self
            .runtime
            .block_on(store::published(&self.reader, block))?
            .1;
        harness_input(&stored, self.chain_spec.clone())
    }

    /// Each of `blocks` with its harness input, in the order given.
    pub fn inputs(
        &self,
        blocks: impl IntoIterator<Item = u64>,
    ) -> impl Iterator<Item = eyre::Result<(u64, TempoHarnessInput)>> {
        blocks
            .into_iter()
            .map(|block| Ok((block, self.input(block)?)))
    }

    /// Each of `blocks` once, in block order, with its stored size and harness input, in windows
    /// of up to `window` blocks and about `WINDOW_BYTES` stored bytes. Each window is read ahead
    /// on the corpus's runtime while the caller works on the one before. Stops after an error.
    pub fn windows(&self, mut blocks: Vec<u64>, window: usize) -> Windows<'_> {
        blocks.sort_unstable();
        blocks.dedup();
        let (sender, receiver) = mpsc::channel(1);
        let (reader, chain_spec) = (self.reader.clone(), self.chain_spec.clone());
        let task = AbortOnDropHandle::new(self.runtime.spawn(async move {
            // Each window is sized from the stored bytes per block of the one before, starting
            // from one block, so heavy blocks come in fewer at a time.
            let (mut rest, mut target_len) = (&blocks[..], 1);
            while !rest.is_empty() {
                let (blocks, tail) = rest.split_at(window_len(rest, target_len, window as u64));
                rest = tail;
                let read = async {
                    // A dense window is scanned whole, yielding exactly `blocks` in order. A
                    // sparse one gets a point read per block in its task, which decompresses too.
                    let scanned = if dense(blocks) {
                        store::scan_blocks(&reader, blocks).await?
                    } else {
                        Vec::new()
                    };
                    let payloads = scanned
                        .into_iter()
                        .map(Some)
                        .chain(iter::repeat_with(|| None));
                    // Each block decodes in its own task, so a window decodes on every worker.
                    stream::iter(blocks.iter().copied().zip(payloads))
                        .map(|(block, payload)| {
                            let (reader, chain_spec) = (reader.clone(), chain_spec.clone());
                            // Aborted when dropped, so a dropped or failed window stops its reads.
                            AbortOnDropHandle::new(tokio::spawn(async move {
                                let (record, bytes) = match payload {
                                    Some(payload) => payload,
                                    None => store::published_payload(&reader, block).await?,
                                };
                                let stored = store::decode(&bytes, &record)?;
                                store::resolve_code(&reader, &stored).await?;
                                eyre::Ok(BlockInput {
                                    block,
                                    size: record.block_bytes,
                                    input: harness_input(&stored, chain_spec)?,
                                })
                            }))
                        })
                        .buffered(CONCURRENT_BLOCKS)
                        .map(|joined| joined.unwrap_or_else(|error| Err(error.into())))
                        .try_fold(Vec::with_capacity(blocks.len()), |mut inputs, input| {
                            inputs.push(input);
                            async { Ok(inputs) }
                        })
                        .await
                }
                .await;
                if let Ok(inputs) = &read
                    && let Some(next) = (WINDOW_BYTES * inputs.len())
                        .checked_div(inputs.iter().map(|input| input.size).sum())
                {
                    target_len = next.clamp(1, window.max(1));
                }
                let failed = read.is_err();
                if sender.send(read).await.is_err() || failed {
                    break;
                }
            }
        }));
        Windows {
            corpus: self,
            receiver: Some(receiver),
            _task: task,
        }
    }
}

impl Drop for Corpus {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take()
            && let Err(error) = lease.release(&self.runtime, &self.store)
        {
            warn!(%error, "Releasing the corpus lease failed; it expires on its own");
        }
    }
}

/// A corpus block read by [Corpus::windows].
pub struct BlockInput {
    /// The block's number.
    pub block: u64,
    /// Its stored input size in bytes.
    pub size: usize,
    /// Its harness input.
    pub input: TempoHarnessInput,
}

/// Windows of a [Corpus]'s blocks, from [Corpus::windows]. Dropping it stops the reads running.
pub struct Windows<'a> {
    corpus: &'a Corpus,
    /// `None` once an error was returned.
    receiver: Option<mpsc::Receiver<eyre::Result<Vec<BlockInput>>>>,
    _task: AbortOnDropHandle<()>,
}

impl Iterator for Windows<'_> {
    type Item = eyre::Result<Vec<BlockInput>>;

    fn next(&mut self) -> Option<Self::Item> {
        let window = self.receiver.as_mut()?.blocking_recv()?;
        // Checked after the read, so a window read while the lease was expiring is not returned.
        let window = self.corpus.ensure_leased().and(window);
        if window.is_err() {
            self.receiver = None;
        }
        Some(window)
    }
}

/// Whether `blocks`, sorted, are close enough together to scan whole rather than read one by one.
fn dense(blocks: &[u64]) -> bool {
    blocks
        .first()
        .zip(blocks.last())
        .is_none_or(|(first, last)| last - first < SPARSE_SPAN * blocks.len() as u64)
}

/// How many of sorted `blocks` the next window takes, `target_len` unless cut short. A dense run
/// of `MIN_RUN` or more ends at the first gap longer than `window`, so its scan skips the gap.
/// Blocks before such a run are read alone, so the run starts the next window.
fn window_len(blocks: &[u64], target_len: usize, window: u64) -> usize {
    let cap = target_len.min(blocks.len());
    let near = |pair: &[u64]| pair[1] - pair[0] <= window;
    let long_run = |at: usize| {
        let head = &blocks[at..blocks.len().min(at + MIN_RUN)];
        head.len() == MIN_RUN && head.windows(2).all(near) && dense(head)
    };
    // Where each run ends: the blocks after a gap longer than `window`.
    let mut gaps = (1..cap).filter(|&at| !near(&blocks[at - 1..=at]));
    if long_run(0) {
        let end = gaps.next().unwrap_or(cap);
        return if dense(&blocks[..end]) { end } else { cap };
    }
    gaps.find(|&at| long_run(at)).unwrap_or(cap)
}

/// The harness chain of `catalog`'s corpus, taken from the known chain whose forks agree with it
/// up to its `tip` timestamp ([`store::forks_agree`]). Forks that never activate get `u64::MAX`.
fn chain_spec_input(catalog: &Catalog, tip: u64) -> eyre::Result<ChainSpecInput> {
    let context = &catalog.context;
    let spec: &TempoChainSpec = [&**PRESTO, &**MODERATO]
        .into_iter()
        .find(|spec| {
            context.chain_id == spec.chain_id()
                && context.genesis == spec.genesis_hash().to_string()
                && store::forks_agree(&context.forks, &spec.display_hardforks().to_string(), tip)
        })
        .ok_or_else(|| eyre::eyre!("corpus chain {} is not a known chain", context.chain_id))?;
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

/// `stored`'s block on the exact pre-state it read. Its code must be resolved
/// ([`store::resolve_code`]).
fn harness_input(stored: &Input, chain_spec: ChainSpecInput) -> eyre::Result<TempoHarnessInput> {
    let mut accounts = stored
        .accounts
        .iter()
        .map(|(address, info)| {
            let account = match info.as_ref().map(|info| info.account()) {
                Some(account) => AccountInput {
                    balance: account.balance,
                    nonce: account.nonce,
                    code: match account.bytecode_hash {
                        Some(hash) => code::code_bytes(&hash.0)
                            .ok_or_else(|| eyre::eyre!("unresolved corpus code {hash}"))?,
                        None => Bytes::new(),
                    },
                    storage: BTreeMap::new(),
                },
                None => AccountInput::default(),
            };
            Ok((Address::from(*address), account))
        })
        .collect::<eyre::Result<BTreeMap<_, _>>>()?;
    for ((address, slot), value) in &stored.storage {
        accounts
            .entry(Address::from(*address))
            .or_default()
            .storage
            .insert(U256::from_be_bytes(*slot), U256::from_be_bytes(*value));
    }
    let block: Block = alloy_rlp::decode_exact(&stored.block.rlp)?;
    let block = TempoBlock {
        header: BlockHeaderInput::Rlp(alloy_rlp::encode(&block.header).into()),
        txs: block
            .body
            .transactions
            .iter()
            .map(|tx| tx.encoded_2718().into())
            .collect(),
        senders: stored
            .block
            .senders
            .iter()
            .copied()
            .map(Address::from)
            .collect(),
    };
    Ok(TempoHarnessInput::Blockchain(TempoBlockchainInput {
        chain_spec,
        pre_state: PreState::Exact {
            state: StateInput { accounts },
            block_hashes: stored
                .hashes
                .iter()
                .map(|(n, hash)| (*n, B256::from(*hash)))
                .collect(),
        },
        blocks: NonEmpty::try_from(vec![block]).map_err(|error| eyre::eyre!(error))?,
    }))
}

/// A block list section naming `catalog`'s corpus and `blocks` of it, one per line. A block list
/// file holds one section per corpus.
pub fn block_list<'a>(catalog: &Catalog, blocks: impl IntoIterator<Item = &'a u64>) -> String {
    let context = &catalog.context;
    let header = format!(
        "# corpus {}..{} parent {} tip {} checkpoint {}\n",
        context.start,
        catalog.cursor.next,
        context.parent,
        B256::from(catalog.cursor.parent),
        catalog.checkpoint.as_deref().unwrap_or("none")
    );
    blocks
        .into_iter()
        .fold(header, |text, block| text + &format!("{block}\n"))
}

/// The blocks a block list file lists for `catalog`'s corpus: those under its section header, and
/// any before the first header, which must be in its range. Other `#` lines are comments.
pub fn read_blocks(path: &Path, catalog: &Catalog) -> eyre::Result<Vec<u64>> {
    let context = &catalog.context;
    // A corpus grows at its tip, so a section names it by the parent of its first block, and one
    // that ends where this corpus does must also share its tip: another history can share the
    // parent. A section that shares only the parent may be a longer corpus, so its blocks past
    // this corpus's end are skipped. Sections written before that name it by the tip it had then,
    // which matches only an unextended corpus. Other `#` lines are comments.
    let end = format!("..{}", catalog.cursor.next);
    let parent = format!(" parent {} ", context.parent);
    let tip = format!(" tip {} ", B256::from(catalog.cursor.parent));
    // Whether the current section is ours, and whether it may run past this corpus's end.
    let (mut blocks, mut ours, mut longer) = (Vec::new(), true, false);
    for line in fs::read_to_string(path)?.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix("# corpus ") {
            let same_tip = header.contains(&tip);
            (ours, longer) = if header.contains(" parent ") {
                let same_end = header
                    .split_once(' ')
                    .is_some_and(|(range, _)| range.ends_with(&end));
                (
                    header.contains(&parent) && (same_tip || !same_end),
                    !same_tip,
                )
            } else {
                (same_tip, false)
            };
        } else if ours && !line.is_empty() && !line.starts_with('#') {
            let block: u64 = line.parse()?;
            if longer && block >= catalog.cursor.next {
                continue;
            }
            eyre::ensure!(
                (context.start..catalog.cursor.next).contains(&block),
                "block {block} is outside the corpus"
            );
            blocks.push(block);
        }
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::catalog;

    #[test]
    fn read_blocks_skips_comments_and_other_sections() -> eyre::Result<()> {
        let mut ours = catalog(10, 10, 0);
        ours.cursor.next = 20;
        let mut other = catalog(15, 5, 0);
        other.cursor.next = 20;
        // Same tip, another start parent.
        other.context.parent = B256::repeat_byte(1).to_string();
        // Same start parent and end, another tip.
        let mut fork = ours.clone();
        fork.cursor.parent = [1; 32];
        let list = format!(
            "{}# dex hits\n13\n{}16\n{}",
            block_list(&ours, &[12]),
            block_list(&other, &[17]),
            block_list(&fork, &[18]),
        );
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("blocks");
        fs::write(&path, list)?;
        assert_eq!(read_blocks(&path, &ours)?, [12, 13]);
        assert_eq!(read_blocks(&path, &other)?, [17, 16]);
        assert_eq!(read_blocks(&path, &fork)?, [18]);
        Ok(())
    }

    #[test]
    fn read_blocks_skips_blocks_past_a_shorter_corpus() -> eyre::Result<()> {
        let mut short = catalog(10, 10, 0);
        short.cursor.next = 20;
        // Same start, extended further.
        let mut long = short.clone();
        long.cursor.next = 30;
        long.cursor.parent = [1; 32];
        let list = format!(
            "{}{}",
            block_list(&short, &[12]),
            block_list(&long, &[14, 25])
        );
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("blocks");
        fs::write(&path, list)?;
        assert_eq!(read_blocks(&path, &short)?, [12, 14]);
        assert_eq!(read_blocks(&path, &long)?, [12, 14, 25]);
        Ok(())
    }

    #[test]
    fn window_len_cuts() {
        let runs: Vec<u64> = (0..40).chain(1_000..1_040).collect();
        let run_then_spread: Vec<u64> = (0..40).chain([1_000, 2_000]).collect();
        let spread: Vec<u64> = (0..20).map(|i| i * 1_000).collect();
        let short_runs: Vec<u64> = (0..20).flat_map(|i| [i * 1_000, i * 1_000 + 1]).collect();
        let before_run: Vec<u64> = [0, 1_000, 1_001, 2_000]
            .into_iter()
            .chain(5_000..5_040)
            .collect();
        let sparse_run: Vec<u64> = (0..40).map(|i| i * 50).chain([10_000]).collect();
        let sparse_tail: Vec<u64> = (0..32)
            .chain((1..=40).map(|i| 31 + i * 60))
            .chain([10_000])
            .collect();
        let contiguous: Vec<u64> = (0..100).collect();
        for (case, blocks, size, len) in [
            ("long run ends at gap", &runs[..], 128, 40),
            ("next long run ends at gap", &runs[40..], 128, 40),
            (
                "run ends before spread blocks",
                &run_then_spread[..],
                128,
                40,
            ),
            ("spread blocks stay together", &spread[..], 16, 16),
            ("short runs stay together", &short_runs[..], 32, 32),
            ("short runs stay together, offset", &short_runs[1..], 32, 32),
            ("blocks before long run go alone", &before_run[..], 128, 4),
            ("sparse run keeps across gap", &sparse_run[..], 128, 41),
            ("run with sparse tail keeps gap", &sparse_tail[..], 128, 73),
            ("long run respects size", &contiguous[..], 7, 7),
            ("fewer blocks than size", &contiguous[..3], 7, 3),
        ] {
            assert_eq!(window_len(blocks, size, 64), len, "{case}");
        }
    }
}
