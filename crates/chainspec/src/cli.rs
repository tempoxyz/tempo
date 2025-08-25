use crate::spec::{TempoChainSpec, TempoChainSpecParser};
use clap::Parser;
use core::fmt;
use reth_cli_commands::{launcher::FnLauncher, node::NoArgs};
use reth_cli_runner::CliRunner;
use reth_ethereum::{
    chainspec::EthChainSpec,
    consensus::EthBeaconConsensus,
    evm::EthEvmConfig,
    node::{
        builder::{NodeBuilder, WithLaunchContext},
        core::args::LogArgs,
    },
    provider::db::DatabaseEnv,
};
use reth_ethereum_cli::interface::Commands;
use reth_node_metrics::recorder::install_prometheus_recorder;
use reth_tracing::FileWorkerGuard;
use std::{future::Future, sync::Arc};
use tempo_evm::evm::TempoEvmFactory;
use tracing::info;

/// The main reth_bsc cli interface.
///
/// This is the entrypoint to the executable.
#[derive(Debug, Parser)]
#[command(author, about = "Tempo node cli", long_about = None)]
pub struct Cli<Ext: clap::Args + fmt::Debug = NoArgs> {
    /// The command to run
    #[command(subcommand)]
    pub command: Commands<TempoChainSpecParser, Ext>,

    #[command(flatten)]
    logs: LogArgs,
}

impl Cli {
    /// Execute the configured cli command.
    ///
    /// This accepts a closure that is used to launch the node via the
    /// [`NodeCommand`](reth_cli_commands::node::NodeCommand).
    pub fn run<L, Fut>(self, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, TempoChainSpec>>, NoArgs) -> Fut,
        Fut: Future<Output = eyre::Result<()>>,
    {
        self.with_runner(CliRunner::try_default_runtime()?, launcher)
    }

    /// Execute the configured cli command with the provided [`CliRunner`].
    pub fn with_runner<L, Fut>(mut self, runner: CliRunner, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, TempoChainSpec>>, NoArgs) -> Fut,
        Fut: Future<Output = eyre::Result<()>>,
    {
        // Add network name if available to the logs dir
        if let Some(chain_spec) = self.command.chain_spec() {
            self.logs.log_file_directory = self
                .logs
                .log_file_directory
                .join(chain_spec.chain().to_string());
        }

        let _guard = self.init_tracing()?;
        info!(target: "reth::cli", "Initialized tracing, debug log directory: {}", self.logs.log_file_directory);

        // Install the prometheus recorder to be sure to record all metrics
        let _ = install_prometheus_recorder();

        let components = |spec: Arc<TempoChainSpec>| {
            (
                EthEvmConfig::new_with_evm_factory(spec.clone(), TempoEvmFactory::default()),
                EthBeaconConsensus::new(spec),
            )
        };

        // match self.command {
        //     Commands::Node(command) => runner.run_command_until_exit(|ctx| {
        //         command.execute(ctx, FnLauncher::new::<TempoChainSpecParser, _>(launcher))
        //     }),
        //     Commands::Init(command) => {
        //         runner.run_blocking_until_ctrl_c(command.execute::<TempoNode>())
        //     }
        //     Commands::InitState(command) => {
        //         runner.run_blocking_until_ctrl_c(command.execute::<CustomNode>())
        //     }
        //     Commands::DumpGenesis(command) => runner.run_blocking_until_ctrl_c(command.execute()),
        //     Commands::Db(command) => {
        //         runner.run_blocking_until_ctrl_c(command.execute::<TempoNo>())
        //     }
        //     Commands::Stage(command) => runner
        //         .run_command_until_exit(|ctx| command.execute::<CustomNode, _>(ctx, components)),
        //     Commands::P2P(command) => runner.run_until_ctrl_c(command.execute::<CustomNode>()),
        //     Commands::Config(command) => runner.run_until_ctrl_c(command.execute()),
        //     Commands::Recover(command) => {
        //         runner.run_command_until_exit(|ctx| command.execute::<CustomNode>(ctx))
        //     }
        //     Commands::Prune(command) => runner.run_until_ctrl_c(command.execute::<CustomNode>()),
        //     Commands::Import(command) => {
        //         runner.run_blocking_until_ctrl_c(command.execute::<CustomNode, _>(components))
        //     }
        //     Commands::Debug(_command) => todo!(),
        //     Commands::ImportEra(_command) => {
        //         todo!()
        //     }
        //     Commands::Download(_command) => {
        //         todo!()
        //     }
        // }

        todo!()
    }

    /// Initializes tracing with the configured options.
    ///
    /// If file logging is enabled, this function returns a guard that must be kept alive to ensure
    /// that all logs are flushed to disk.
    pub fn init_tracing(&self) -> eyre::Result<Option<FileWorkerGuard>> {
        let guard = self.logs.init_tracing()?;
        Ok(guard)
    }
}
