//! `tempo corpus`: capture an archive range into an object-store corpus and replay it.

use clap::{Parser, Subcommand};
use reth_chainspec::EthChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::common::{AccessRights, Environment, EnvironmentArgs};
use reth_cli_util::cancellation::CancellationToken;
use reth_ethereum::tasks::Runtime;
use std::sync::Arc;
use tempo_chainspec::spec::{TempoChainSpec, TempoChainSpecParser};
use tempo_corpus::{fill, gc, migrate, replay, store::Store};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_node::node::TempoNode;

/// Historical execution corpus commands.
#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    /// Capture a finite archive range into `--corpus s3://bucket/prefix`, resuming a partial fill.
    Fill(Box<FillCommand>),
    /// Replay a corpus range without opening a database.
    Replay(ReplayCommand),
    /// Delete the superseded checkpoints and unreferenced files of a complete corpus.
    Gc(GcCommand),
    /// Rewrite a corpus of the multi-block record format into a new corpus of the current one.
    Migrate(MigrateCommand),
}

impl CorpusCommand {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        match self {
            Self::Fill(cmd) => cmd.execute(runtime).await,
            Self::Replay(cmd) => cmd.execute().await,
            Self::Gc(cmd) => cmd.execute().await,
            Self::Migrate(cmd) => cmd.execute().await,
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
    /// Exclusive end; defaults to the corpus end.
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
}

impl ReplayCommand {
    async fn execute(self) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let (catalog, _) = store
            .catalog()
            .await?
            .ok_or_else(|| eyre::eyre!("no corpus catalog at {}", self.corpus))?;
        eyre::ensure!(catalog.complete, "corpus is not complete");
        let context = &catalog.context;
        eyre::ensure!(
            context.chain_id == self.chain.chain_id()
                && context.genesis == self.chain.genesis_hash().to_string(),
            "corpus chain context mismatch"
        );
        let from = self.from.unwrap_or(context.start);
        let end = self.to.unwrap_or(context.end).min(context.end);
        let standalone = self.tx_from.zip(self.tx_to);
        if let Some((from, to)) = standalone {
            eyre::ensure!(
                from >= context.first_tx && from < to && to <= context.end_tx,
                "transaction ordinal range outside the corpus"
            );
        } else {
            eyre::ensure!(
                from >= context.start && from < end,
                "corpus block range mismatch"
            );
        }
        let workers = workers(self.workers);
        let (config, consensus) = components(self.chain);
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

/// Migrate a published legacy corpus into a new prefix, leaving the source untouched.
#[derive(Debug, Parser)]
pub struct MigrateCommand {
    /// Source s3://bucket/prefix or file:///directory of the legacy corpus.
    #[arg(long)]
    from: String,
    /// Destination s3://bucket/prefix or file:///directory; must not exist yet.
    #[arg(long)]
    to: String,
    /// Optional S3-compatible endpoint for both corpora. Credentials use the standard AWS chain.
    #[arg(long)]
    s3_endpoint: Option<String>,
    /// First block to migrate; with --end, migrates only [start, end).
    #[arg(long, requires = "end")]
    start: Option<u64>,
    /// Exclusive end of the blocks to migrate; by default every published block migrates.
    #[arg(long, requires = "start")]
    end: Option<u64>,
    /// Parallel read scans; defaults to the available parallelism.
    #[arg(long)]
    workers: Option<usize>,
}

impl MigrateCommand {
    async fn execute(self) -> eyre::Result<()> {
        let endpoint = self.s3_endpoint.as_deref();
        let source = Store::open(&self.from, endpoint).await?;
        let dest = Store::open(&self.to, endpoint).await?;
        let range = self.start.zip(self.end).map(|(start, end)| start..end);
        migrate::migrate(source, dest, range, workers(self.workers)).await
    }
}
