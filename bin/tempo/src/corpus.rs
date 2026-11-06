//! `tempo corpus`: capture an archive range into an object-store corpus and replay it.

use alloy_consensus::BlockHeader as _;
use clap::{Parser, Subcommand};
use reth_chainspec::EthChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_cli_util::cancellation::CancellationToken;
use reth_ethereum::tasks::Runtime;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tempo_chainspec::{
    hardfork::TempoHardfork,
    spec::{TempoChainSpec, TempoChainSpecParser, TempoHardforks as _},
};
use tempo_corpus::{
    exec::{db::View, fill, replay, shadow::ShadowReplayer},
    fuzz, gc,
    store::{Catalog, Store},
};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_node::node::TempoNode;
use tracing::{info, warn};

/// Historical execution corpus commands.
#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    /// Capture archive blocks into `--corpus s3://bucket/prefix`, appending to an existing corpus.
    Fill(Box<FillCommand>),
    /// Replay a corpus range without opening a database.
    Replay(ReplayCommand),
    /// Delete the superseded checkpoints and unreferenced files of a complete corpus.
    Gc(GcCommand),
}

impl CorpusCommand {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        match self {
            Self::Fill(cmd) => cmd.execute(runtime).await,
            Self::Replay(cmd) => cmd.execute().await,
            Self::Gc(cmd) => cmd.execute().await,
        }
    }
}

fn components(chain: Arc<TempoChainSpec>) -> (TempoEvmConfig, TempoConsensus) {
    (
        TempoEvmConfig::new(chain.clone()),
        TempoConsensus::new(chain),
    )
}

/// `workers`, defaulting to the available parallelism; at least one.
fn workers(workers: Option<usize>) -> usize {
    workers
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .max(1)
}

/// Capture archive blocks from an archive datadir up to a pinned exclusive end, appending
/// after the blocks a corpus already published.
#[derive(Debug, Parser)]
pub struct FillCommand {
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,
    /// First block of a new corpus (genesis is context, not a captured block); an existing
    /// corpus must start here.
    #[arg(long, default_value = "1")]
    from: u64,
    /// Exclusive end, clamped to the available head; defaults to the head.
    #[arg(long)]
    to: Option<u64>,
    /// Destination s3://bucket/prefix. Existing incompatible data is rejected.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint. Credentials use the standard AWS chain.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// Re-read and fully replay published records instead of checking metadata only.
    #[arg(long)]
    verify_existing: bool,
    /// Capture worker threads; defaults to the available parallelism.
    #[arg(long)]
    workers: Option<usize>,
}

impl FillCommand {
    async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let Environment {
            provider_factory, ..
        } = self.env.init::<TempoNode>(AccessRights::RO, runtime)?;
        let (config, consensus) = components(self.env.chain.clone());
        let args = fill::FillArgs {
            from: self.from,
            to: self.to,
            verify_existing: self.verify_existing,
            workers: workers(self.workers),
        };
        let cancellation = CancellationToken::new();
        let _guard = cancellation.drop_guard();
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            fill::fill(
                provider_factory,
                store,
                &config,
                &consensus,
                args,
                &cancellation,
                handle,
            )
        })
        .await?
    }
}

/// Replay a published corpus range.
#[derive(Debug, Parser)]
pub struct ReplayCommand {
    /// The chain the corpus was captured from.
    #[arg(long, value_name = "CHAIN_OR_PATH", default_value = "mainnet", value_parser = TempoChainSpecParser::parser())]
    chain: Arc<TempoChainSpec>,
    /// Source s3://bucket/prefix.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint. Credentials use the standard AWS chain.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// First block; defaults to the corpus start.
    #[arg(long)]
    from: Option<u64>,
    /// Exclusive end; defaults to the end of the published blocks.
    #[arg(long)]
    to: Option<u64>,
    /// Replay only transactions with ordinal in [tx-from, tx-to), each independently.
    #[arg(long, requires = "tx_to")]
    tx_from: Option<u64>,
    /// Exclusive end of the standalone transaction ordinal range.
    #[arg(long, requires = "tx_from")]
    tx_to: Option<u64>,
    /// Execution worker threads; defaults to the available parallelism.
    #[arg(long)]
    workers: Option<usize>,
    /// Replay only the blocks a block list file names, such as a fuzz corpus minimizer's.
    #[arg(long, conflicts_with_all = ["from", "to", "tx_from"])]
    blocks: Option<PathBuf>,
    /// Also replay each verified block under this candidate hardfork's rules and compare it with
    /// the canonical execution.
    #[arg(long, value_name = "HARDFORK", conflicts_with = "tx_from")]
    shadow: Option<TempoHardfork>,
    /// Exit unsuccessfully on unexplained shadow findings or inconclusive comparisons.
    #[arg(long, requires = "shadow")]
    fail_on_findings: bool,
}

impl ReplayCommand {
    async fn execute(self) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let (catalog, _) = store
            .catalog()
            .await?
            .ok_or_else(|| eyre::eyre!("no corpus catalog at {}", self.corpus))?;
        let context = &catalog.context;
        eyre::ensure!(
            context.chain_id == self.chain.chain_id()
                && context.genesis == self.chain.genesis_hash().to_string(),
            "corpus chain context mismatch"
        );
        let published = &catalog.cursor;
        let from = self.from.unwrap_or(context.start);
        let end = self.to.unwrap_or(published.next).min(published.next);
        let standalone = self.tx_from.zip(self.tx_to);
        if let Some((from, to)) = standalone {
            eyre::ensure!(
                from >= context.first_tx && from < to && to <= published.tx,
                "transaction ordinal range outside the corpus"
            );
        } else {
            eyre::ensure!(
                from >= context.start && from < end,
                "corpus block range mismatch"
            );
        }
        let workers = workers(self.workers);
        let blocks = match &self.blocks {
            Some(path) => {
                let blocks = fuzz::read_blocks(path, &catalog)?;
                eyre::ensure!(
                    !blocks.is_empty(),
                    "{} lists no block of the corpus",
                    path.display()
                );
                Some(blocks)
            }
            None => None,
        };
        if let Some(hardfork) = self.shadow {
            let blocks = blocks.unwrap_or_else(|| (from..end).collect());
            let fail_on_findings = self.fail_on_findings;
            return tokio::task::spawn_blocking(move || {
                shadow_replay(
                    store,
                    catalog,
                    &blocks,
                    self.chain,
                    hardfork,
                    workers,
                    fail_on_findings,
                )
            })
            .await?;
        }
        let (config, consensus) = components(self.chain);
        if let Some(blocks) = blocks {
            return tokio::task::spawn_blocking(move || {
                replay::run_blocks(
                    store,
                    catalog,
                    &blocks,
                    config,
                    consensus,
                    workers,
                    |_, _, _| Ok(()),
                )
            })
            .await?;
        }
        let cancellation = CancellationToken::new();
        let _guard = cancellation.drop_guard();
        tokio::task::spawn_blocking(move || {
            replay::run(
                store,
                catalog,
                from..end,
                config,
                consensus,
                workers,
                standalone,
                cancellation,
            )
        })
        .await?
    }
}

/// Replays `blocks` of a corpus, then each again under `hardfork`'s rules from the pre-state it
/// recorded, and compares the two as shadow replay does. A candidate execution that reads state
/// the canonical one did not fails at that boundary, since the corpus did not capture it.
fn shadow_replay(
    store: Store,
    catalog: Catalog,
    blocks: &[u64],
    chain: Arc<TempoChainSpec>,
    hardfork: TempoHardfork,
    workers: usize,
    fail_on_findings: bool,
) -> eyre::Result<()> {
    let replayer = ShadowReplayer::new(chain.clone(), hardfork);
    // Blocks per ReplayOutcome, then blocks skipped as already canonical.
    let counts: [AtomicU64; 5] = Default::default();
    let (config, consensus) = components(chain.clone());
    replay::run_blocks(
        store,
        catalog,
        blocks,
        config,
        consensus,
        workers,
        |input, block, executed| {
            let slot = if chain.tempo_hardfork_at(block.timestamp()) >= hardfork {
                4
            } else {
                replayer
                    .replay(block, &executed.receipts()?, || {
                        Ok(View::new(input.clone()))
                    })
                    .map_err(|err| {
                        eyre::eyre!("shadow replay failed at block {}: {err}", block.number())
                    })?
                    .0 as usize
            };
            counts[slot].fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
    )?;
    let [matched, expected, inconclusive, findings, skipped] = counts.map(AtomicU64::into_inner);
    info!(
        blocks = blocks.len(),
        %hardfork,
        matched,
        expected,
        inconclusive,
        findings,
        skipped,
        "Corpus shadow replay completed"
    );
    if skipped > 0 {
        warn!(
            skipped,
            "Skipped blocks where the candidate hardfork was already canonical"
        );
    }
    if fail_on_findings && (findings > 0 || inconclusive > 0) {
        eyre::bail!(
            "corpus shadow replay needs review: {findings} blocks with unexplained differences, {inconclusive} inconclusive blocks"
        );
    }
    Ok(())
}

/// Shrink a complete corpus to its published checkpoint.
#[derive(Debug, Parser)]
pub struct GcCommand {
    /// Corpus s3://bucket/prefix or file:///directory; must be complete.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint. Credentials use the standard AWS chain.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// Take over a corpus an interrupted gc left marked as collecting. Only when no gc is
    /// still running on it.
    #[arg(long)]
    force: bool,
}

impl GcCommand {
    async fn execute(self) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        gc::gc(&store, self.force).await
    }
}
