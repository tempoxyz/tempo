//! `tempo corpus`: capture an archive range into an object-store corpus and replay it.

use clap::{Args, Parser, Subcommand};
use reth_chainspec::EthChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_cli_util::cancellation::CancellationToken;
use reth_ethereum::tasks::Runtime;
use std::{ops::Range, path::PathBuf, sync::Arc};
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_corpus::{
    fill, fuzz, gc, replay,
    store::{Catalog, Store},
};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_node::node::TempoNode;

/// Historical execution corpus commands.
#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    /// Capture a finite archive range into `--corpus s3://bucket/prefix`, resuming a partial fill.
    Fill(Box<FillCommand>),
    /// Replay a corpus range without opening a database.
    Replay(ReplayCommand),
    /// Rewrite a legacy corpus in the current format, without the archive DB.
    Migrate(MigrateCommand),
    /// Delete the superseded checkpoints and unreferenced files of a complete corpus.
    Gc(GcCommand),
}

impl CorpusCommand {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        match self {
            Self::Fill(cmd) => cmd.execute(runtime).await,
            Self::Replay(cmd) => cmd.execute().await,
            Self::Migrate(cmd) => cmd.execute().await,
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

/// Capture a pinned exclusive-end range from an archive datadir.
#[derive(Debug, Parser)]
pub struct FillCommand {
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,
    /// First block (genesis is context, not a captured block).
    #[arg(long, default_value = "1")]
    from: u64,
    /// Exclusive end, clamped to the available head.
    #[arg(long)]
    to: u64,
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
            workers: self.workers,
        };
        let cancellation = CancellationToken::new();
        let _guard = cancellation.drop_guard();
        let handle = tokio::runtime::Handle::current();
        let token = cancellation.clone();
        tokio::task::spawn_blocking(move || {
            fill::fill(
                provider_factory,
                store,
                &config,
                &consensus,
                args,
                &token,
                handle,
            )
        })
        .await?
    }
}

/// A block range of a published corpus and the workers to process it on.
#[derive(Debug, Args)]
struct CorpusSource {
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
    /// Exclusive end; defaults to the corpus end.
    #[arg(long)]
    to: Option<u64>,
    /// Worker threads; defaults to the available parallelism.
    #[arg(long)]
    workers: Option<usize>,
}

impl CorpusSource {
    /// Opens the complete corpus, checked against `chain`, with the selected block range (not yet
    /// checked against it) and worker count.
    async fn open(&self) -> eyre::Result<(Store, Catalog, Range<u64>, usize)> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let (catalog, _) = store
            .catalog()
            .await?
            .ok_or_else(|| eyre::eyre!("no corpus catalog at {}", self.corpus))?;
        eyre::ensure!(catalog.complete, "corpus is not complete");
        let context = &catalog.context;
        eyre::ensure!(
            context.chain_id == self.chain.chain_id()
                && context.genesis == self.chain.genesis_hash().to_string()
                && context.forks == self.chain.display_hardforks().to_string(),
            "corpus chain/fork context mismatch"
        );
        let range =
            self.from.unwrap_or(context.start)..self.to.unwrap_or(context.end).min(context.end);
        let workers = self
            .workers
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
            .max(1);
        Ok((store, catalog, range, workers))
    }
}

/// Fails unless `range` is a non-empty block range of `catalog`'s corpus.
fn ensure_blocks(catalog: &Catalog, range: &Range<u64>) -> eyre::Result<()> {
    eyre::ensure!(
        range.start >= catalog.context.start && !range.is_empty(),
        "corpus block range mismatch"
    );
    Ok(())
}

/// Replay a published corpus range.
#[derive(Debug, Parser)]
pub struct ReplayCommand {
    #[command(flatten)]
    source: CorpusSource,
    /// Replay only transactions with ordinal in [tx-from, tx-to), each independently.
    #[arg(long, requires = "tx_to")]
    tx_from: Option<u64>,
    /// Exclusive end of the standalone transaction ordinal range.
    #[arg(long, requires = "tx_from")]
    tx_to: Option<u64>,
    /// Replay only the blocks a block list file names, such as a fuzz corpus minimizer's.
    #[arg(long, conflicts_with_all = ["from", "to", "tx_from"])]
    blocks: Option<PathBuf>,
}

impl ReplayCommand {
    async fn execute(self) -> eyre::Result<()> {
        let (store, catalog, range, workers) = self.source.open().await?;
        let (config, consensus) = components(self.source.chain.clone());
        if let Some(path) = &self.blocks {
            let blocks = fuzz::read_blocks(path, &catalog)?;
            return tokio::task::spawn_blocking(move || {
                replay::run_blocks(store, catalog, &blocks, config, consensus, workers)
            })
            .await?;
        }
        let standalone = self.tx_from.zip(self.tx_to);
        if let Some((from, to)) = standalone {
            let context = &catalog.context;
            eyre::ensure!(
                from >= context.first_tx && from < to && to <= context.end_tx,
                "transaction ordinal range outside the corpus"
            );
        } else {
            ensure_blocks(&catalog, &range)?;
        }
        let cancellation = CancellationToken::new();
        let _guard = cancellation.drop_guard();
        let token = cancellation.clone();
        tokio::task::spawn_blocking(move || {
            replay::run(
                store, catalog, range, config, consensus, workers, standalone, token,
            )
        })
        .await?
    }
}

/// Migrate a complete legacy corpus to changeset bitmaps and full transaction deltas.
#[derive(Debug, Parser)]
pub struct MigrateCommand {
    /// The chain the corpus was captured from.
    #[arg(long, value_name = "CHAIN_OR_PATH", default_value = "mainnet", value_parser = TempoChainSpecParser::parser())]
    chain: Arc<TempoChainSpec>,
    /// Source s3://bucket/prefix of a legacy corpus; an unfinished one migrates up to its
    /// last published block.
    #[arg(long)]
    source: String,
    /// Destination s3://bucket/prefix; must not exist.
    #[arg(long)]
    corpus: String,
    /// Optional S3-compatible endpoint for both. Credentials use the standard AWS chain.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// First block; defaults to the source start.
    #[arg(long)]
    from: Option<u64>,
    /// Exclusive end; defaults to the source's last published block.
    #[arg(long)]
    to: Option<u64>,
}

impl MigrateCommand {
    async fn execute(self) -> eyre::Result<()> {
        let source = Store::open(&self.source, self.s3_endpoint.as_deref()).await?;
        let (catalog, _) = source
            .catalog()
            .await?
            .ok_or_else(|| eyre::eyre!("no corpus catalog at {}", self.source))?;
        let context = &catalog.context;
        let chain = self.chain.clone();
        eyre::ensure!(
            context.chain_id == chain.chain_id()
                && context.genesis == chain.genesis_hash().to_string()
                && context.forks == chain.display_hardforks().to_string(),
            "corpus chain/fork context mismatch"
        );
        // A local destination (staging on disk before an upload) takes no S3 endpoint.
        let dest_endpoint = self
            .corpus
            .starts_with("s3://")
            .then_some(self.s3_endpoint.as_deref())
            .flatten();
        let dest = Store::open(&self.corpus, dest_endpoint).await?;
        let (config, consensus) = components(chain);
        tempo_corpus::migrate::migrate(source, dest, self.from, self.to, &config, &consensus).await
    }
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
}

impl GcCommand {
    async fn execute(self) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        gc::gc(&store).await
    }
}
