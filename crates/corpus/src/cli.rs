//! The `corpus` subcommands a node binary mounts: `fill`, `replay` and `gc`, generic over the chain
//! the binary runs ([`CliChain`]).

use crate::{
    exec::{
        chain::{Chain, Source},
        fill, replay, workers,
    },
    gc,
    store::Store,
};
use clap::{Args, Parser, Subcommand};
use reth_chainspec::EthereumHardforks;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::common::{AccessRights, CliNodeTypes, Environment, EnvironmentArgs};
use reth_cli_util::cancellation::CancellationToken;
use reth_consensus::FullConsensus;
use reth_tasks::Runtime;
use std::{fmt::Debug, path::PathBuf, sync::Arc};
use tempo_primitives::TempoPrimitives;

/// The chain specification [`CliChain::ChainSpecParser`] parses.
type ChainSpec<T> = <<T as CliChain>::ChainSpecParser as ChainSpecParser>::ChainSpec;

/// The chain a binary's `corpus` commands capture and replay.
pub trait CliChain: Debug + Send + Sync + 'static {
    /// Parses `--chain`. Its first supported chain is the default; with none, `--chain` is
    /// required.
    type ChainSpecParser: ChainSpecParser<ChainSpec: EthereumHardforks> + Debug;
    /// The node whose archive database `fill` opens.
    type Node: CliNodeTypes<ChainSpec = ChainSpec<Self>, Primitives = TempoPrimitives>;
    /// Executes blocks on replay.
    type Chain: Chain + 'static;
    /// Executes blocks on capture.
    type Source: Source + 'static;
    /// Validates blocks on capture and replay.
    type Consensus: FullConsensus<TempoPrimitives> + 'static;
    /// Arguments `fill` takes beyond the shared ones, such as where to read L1 state.
    type FillArgs: Args + Debug + Send;

    /// The chain to replay `spec`'s blocks with.
    fn chain(spec: Arc<ChainSpec<Self>>) -> Self::Chain;

    /// The chain to capture `spec`'s blocks with.
    fn source(spec: Arc<ChainSpec<Self>>, args: Self::FillArgs) -> Self::Source;

    /// The consensus to validate `spec`'s blocks with.
    fn consensus(spec: Arc<ChainSpec<Self>>) -> Self::Consensus;
}

/// Historical execution corpus commands.
#[derive(Debug, Subcommand)]
pub enum CorpusCommand<T: CliChain> {
    /// Capture archive blocks into `--corpus s3://bucket/prefix`, appending to an existing corpus.
    Fill(Box<FillCommand<T>>),
    /// Replay a corpus range without opening a database.
    Replay(ReplayCommand<T>),
    /// Delete the superseded checkpoints and unreferenced files of a complete corpus.
    Gc(GcCommand),
}

impl<T: CliChain> CorpusCommand<T> {
    /// Runs the command; `runtime` opens the archive a fill reads.
    pub async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        match self {
            Self::Fill(cmd) => cmd.execute(runtime).await,
            Self::Replay(cmd) => cmd.execute().await,
            Self::Gc(cmd) => cmd.execute().await,
        }
    }
}

/// Capture archive blocks from an archive datadir up to a pinned exclusive end, appending
/// after the blocks a corpus already published.
#[derive(Debug, Parser)]
pub struct FillCommand<T: CliChain> {
    #[command(flatten)]
    env: EnvironmentArgs<T::ChainSpecParser>,
    #[command(flatten)]
    chain_args: T::FillArgs,
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

impl<T: CliChain> FillCommand<T> {
    async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let Environment {
            provider_factory, ..
        } = self.env.init::<T::Node>(AccessRights::RO, runtime)?;
        let source = T::source(self.env.chain.clone(), self.chain_args);
        let consensus = T::consensus(self.env.chain.clone());
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
                &source,
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
pub struct ReplayCommand<T: CliChain> {
    /// The chain the corpus was captured from.
    #[arg(
        long,
        value_name = "CHAIN_OR_PATH",
        default_value = T::ChainSpecParser::default_value(),
        required = T::ChainSpecParser::default_value().is_none(),
        value_parser = T::ChainSpecParser::parser()
    )]
    chain: Arc<ChainSpec<T>>,
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
    /// Replay only the blocks a block list file names, such as a fuzz corpus minimizer's.
    #[arg(long, conflicts_with_all = ["from", "to", "tx_from"])]
    blocks: Option<PathBuf>,
}

impl<T: CliChain> ReplayCommand<T> {
    async fn execute(self) -> eyre::Result<()> {
        let store = Store::open(&self.corpus, self.s3_endpoint.as_deref()).await?;
        let (catalog, _) = store
            .catalog()
            .await?
            .ok_or_else(|| eyre::eyre!("no corpus catalog at {}", self.corpus))?;
        let request = replay::Request {
            from: self.from,
            to: self.to,
            transactions: self.tx_from.zip(self.tx_to),
            blocks: self.blocks,
            workers: workers(self.workers),
        };
        let consensus = T::consensus(self.chain.clone());
        let chain = T::chain(self.chain);
        let cancellation = CancellationToken::new();
        let _guard = cancellation.drop_guard();
        tokio::task::spawn_blocking(move || {
            replay::run_request(store, catalog, chain, consensus, request, cancellation)
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
