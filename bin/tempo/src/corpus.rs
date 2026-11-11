//! `tempo corpus`: capture an archive range into an object-store corpus and replay it.

use clap::{Parser, Subcommand};
use reth_chainspec::EthChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_cli_util::cancellation::CancellationToken;
use reth_ethereum::tasks::Runtime;
use std::{path::PathBuf, sync::Arc};
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_corpus::{
    exec::{fill, replay},
    fuzz, gc,
    store::{Catalog, Store},
};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_node::node::TempoNode;

/// Historical execution corpus commands.
#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    /// Capture archive blocks into `--corpus s3://bucket/prefix`, appending to an existing corpus.
    Fill(Box<FillCommand>),
    /// Replay a corpus range without opening a database.
    Replay(ReplayCommand),
    /// Delete the superseded checkpoints and unreferenced files of a complete corpus.
    Gc(GcCommand),
    /// Index a corpus range into a Parquet file, one row per transaction.
    #[cfg(feature = "corpus-index")]
    Index(IndexCommand),
    /// Write the block list of indexed blocks whose transactions call or write a target.
    #[cfg(feature = "corpus-index")]
    Select(SelectCommand),
}

impl CorpusCommand {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        match self {
            Self::Fill(cmd) => cmd.execute(runtime).await,
            Self::Replay(cmd) => cmd.execute().await,
            Self::Gc(cmd) => cmd.execute().await,
            #[cfg(feature = "corpus-index")]
            Self::Index(cmd) => cmd.execute().await,
            #[cfg(feature = "corpus-index")]
            Self::Select(cmd) => cmd.execute(),
        }
    }
}

fn components(chain: Arc<TempoChainSpec>) -> (TempoEvmConfig, TempoConsensus) {
    (
        TempoEvmConfig::new(chain.clone()),
        TempoConsensus::new(chain),
    )
}

/// Opens the corpus at `corpus` and its published catalog.
async fn open(corpus: &str, endpoint: Option<&str>) -> eyre::Result<(Store, Catalog)> {
    let store = Store::open(corpus, endpoint).await?;
    let (catalog, _) = store
        .catalog()
        .await?
        .ok_or_else(|| eyre::eyre!("no corpus catalog at {corpus}"))?;
    Ok((store, catalog))
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
    /// Optional S3-compatible endpoint. Credentials come from AWS env vars, web identity, ECS or IMDS.
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
    /// Optional S3-compatible endpoint. Credentials come from AWS env vars, web identity, ECS or IMDS.
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
    /// Replay only the blocks a block list file names, such as `tempo corpus select` writes.
    #[arg(long, conflicts_with_all = ["from", "to", "tx_from"])]
    blocks: Option<PathBuf>,
}

impl ReplayCommand {
    async fn execute(self) -> eyre::Result<()> {
        let (store, catalog) = open(&self.corpus, self.s3_endpoint.as_deref()).await?;
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
        let mut range = from..end;
        let blocks = match &self.blocks {
            Some(path) => {
                let mut blocks = fuzz::read_blocks(path, &catalog)?;
                blocks.sort_unstable();
                blocks.dedup();
                let (Some(first), Some(last)) = (blocks.first(), blocks.last()) else {
                    eyre::bail!("{} lists no block of the corpus", path.display())
                };
                range = *first..last + 1;
                Some(blocks)
            }
            None => None,
        };
        let workers = workers(self.workers);
        let (config, consensus) = components(self.chain);
        let cancellation = CancellationToken::new();
        let _guard = cancellation.drop_guard();
        tokio::task::spawn_blocking(move || {
            replay::run(
                store,
                catalog,
                range,
                config,
                consensus,
                workers,
                standalone,
                blocks.as_deref(),
                cancellation,
            )
        })
        .await?
    }
}

/// Shrink a complete corpus to its published checkpoint.
#[derive(Debug, Parser)]
pub struct GcCommand {
    /// Corpus s3://bucket/prefix or file:///directory; must be complete.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint. Credentials come from AWS env vars, web identity, ECS or IMDS.
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

/// Index a published corpus range into a Parquet file.
#[cfg(feature = "corpus-index")]
#[derive(Debug, Parser)]
pub struct IndexCommand {
    /// Source s3://bucket/prefix or file:///directory.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint. Credentials use the standard AWS chain.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// First block; defaults to the corpus start.
    #[arg(long)]
    from: Option<u64>,
    /// Exclusive end; defaults to the corpus end.
    #[arg(long)]
    to: Option<u64>,
    /// Destination Parquet file.
    #[arg(long)]
    out: PathBuf,
    /// Parallel read tasks; defaults to the available parallelism.
    #[arg(long)]
    workers: Option<usize>,
}

#[cfg(feature = "corpus-index")]
impl IndexCommand {
    async fn execute(self) -> eyre::Result<()> {
        let (store, catalog) = open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let context = &catalog.context;
        let end = catalog.cursor.next;
        let range = self.from.unwrap_or(context.start)..self.to.unwrap_or(end);
        eyre::ensure!(
            context.start <= range.start && range.start < range.end && range.end <= end,
            "block range outside the corpus"
        );
        let started = std::time::Instant::now();
        let out = self.out.clone();
        let rows = tokio::task::spawn_blocking(move || {
            tempo_corpus::index::index(store, catalog, range, &out, workers(self.workers))
        })
        .await??;
        tracing::info!(
            rows,
            bytes = std::fs::metadata(&self.out)?.len(),
            seconds = started.elapsed().as_secs_f64(),
            "Corpus index written"
        );
        Ok(())
    }
}

/// Select the indexed blocks whose transactions call or write a target.
#[cfg(feature = "corpus-index")]
#[derive(Debug, Parser)]
pub struct SelectCommand {
    /// Index files written by `tempo corpus index`.
    #[arg(long, num_args = 1.., required = true)]
    index: Vec<PathBuf>,
    /// Target registry name, such as feeamm or dex.
    #[arg(long)]
    touches: String,
    /// Select transactions that write the target instead of ones that call it.
    #[arg(long)]
    writes: bool,
    /// First block.
    #[arg(long, default_value_t = 0)]
    from: u64,
    /// Exclusive end.
    #[arg(long, default_value_t = u64::MAX)]
    to: u64,
    /// Destination block list file.
    #[arg(long)]
    out: PathBuf,
}

#[cfg(feature = "corpus-index")]
impl SelectCommand {
    fn execute(self) -> eyre::Result<()> {
        let bit = tempo_corpus::targets::bit(&self.touches).ok_or_else(|| {
            let names: Vec<_> = tempo_corpus::targets::TARGETS
                .iter()
                .map(|(name, _)| *name)
                .collect();
            eyre::eyre!(
                "unknown target {}, expected one of {}",
                self.touches,
                names.join(", ")
            )
        })?;
        let list = tempo_corpus::index::select(&self.index, bit, self.writes, self.from..self.to)?;
        Ok(std::fs::write(&self.out, list)?)
    }
}
