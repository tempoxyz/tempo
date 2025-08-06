//! Command-line interface for the Reth-Malachite node.
//!
//! This module provides the CLI interface for running a Reth node with Malachite consensus.
//! It includes custom chain specification parsing for Malachite chains and integrates with
//! Reth's existing CLI infrastructure while adding Malachite-specific configuration options.
//!
//! # Components
//!
//! - [`Cli`]: Main CLI structure that extends Reth's CLI with Malachite functionality
//! - [`MalachiteChainSpecParser`]: Custom chain spec parser for Malachite chains
//! - [`MalachiteArgs`]: Malachite-specific command-line arguments

mod args;

pub use args::MalachiteArgs;

use clap::Parser;
use reth_chainspec::ChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::node::NoArgs;
use reth_db::DatabaseEnv;
use reth_node_builder::{NodeBuilder, WithLaunchContext};
use std::{future::Future, sync::Arc};

/// Malachite chain spec parser
#[derive(Debug, Clone, Default)]
pub struct MalachiteChainSpecParser;

impl ChainSpecParser for MalachiteChainSpecParser {
    type ChainSpec = ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = &["malachite"];

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        match s {
            "malachite" => Ok(Arc::new(custom_malachite_chain())),
            path if std::path::Path::new(path).exists() => {
                // Try to parse as genesis file
                Self::parse_genesis_file(path)
            }
            _ => Err(eyre::eyre!("Unknown chain or file not found: {}", s)),
        }
    }
}

impl MalachiteChainSpecParser {
    /// Parse a genesis file and create a ChainSpec from it
    fn parse_genesis_file(path: &str) -> eyre::Result<Arc<ChainSpec>> {
        use alloy_genesis::Genesis;
        use reth_chainspec::ChainSpecBuilder;
        use std::fs;

        // Read and parse the genesis file
        let genesis_content = fs::read_to_string(path)?;
        let genesis: Genesis = serde_json::from_str(&genesis_content)?;

        // Extract chain ID from genesis config or use default
        let chain_id = if genesis.config.chain_id == 0 {
            2600
        } else {
            genesis.config.chain_id
        };

        // Build ChainSpec from genesis
        let chain_spec = ChainSpecBuilder::default()
            .chain(reth_chainspec::Chain::from_id(chain_id))
            .genesis(genesis)
            .paris_activated()
            .shanghai_activated()
            .cancun_activated()
            .build();

        Ok(Arc::new(chain_spec))
    }
}

/// The main Malachite CLI interface
#[derive(Debug, Parser)]
#[command(author, version, about = "Malachite Node", long_about = None)]
pub struct Cli<
    Spec: ChainSpecParser = MalachiteChainSpecParser,
    Ext: clap::Args + std::fmt::Debug = NoArgs,
> {
    /// The command to run
    #[command(subcommand)]
    pub command: reth::cli::Commands<Spec, Ext>,

    #[command(flatten)]
    logs: reth::args::LogArgs,
}

impl<C, Ext> Cli<C, Ext>
where
    C: ChainSpecParser<ChainSpec = ChainSpec>,
    Ext: clap::Args + std::fmt::Debug,
{
    /// Execute the configured CLI command
    pub fn run<L, Fut>(self, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(
                reth::builder::WithLaunchContext<
                    reth::builder::NodeBuilder<std::sync::Arc<reth_db::DatabaseEnv>, C::ChainSpec>,
                >,
                Ext,
            ) -> Fut
            + std::ops::AsyncFnOnce(
                reth_node_builder::WithLaunchContext<
                    reth_node_builder::NodeBuilder<
                        std::sync::Arc<reth_db::DatabaseEnv>,
                        reth_chainspec::ChainSpec,
                    >,
                >,
                Ext,
            ) -> eyre::Result<()>,
        Fut: std::future::Future<Output = eyre::Result<()>>,
    {
        use reth::CliRunner;
        self.with_runner(CliRunner::try_default_runtime()?, launcher)
    }

    /// Execute the configured CLI command with the provided CliRunner
    pub fn with_runner<L, Fut>(self, runner: reth::CliRunner, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(
                WithLaunchContext<NodeBuilder<std::sync::Arc<DatabaseEnv>, C::ChainSpec>>,
                Ext,
            ) -> Fut
            + std::ops::AsyncFnOnce(
                WithLaunchContext<NodeBuilder<Arc<reth_db::DatabaseEnv>, ChainSpec>>,
                Ext,
            ) -> eyre::Result<()>,
        Fut: Future<Output = eyre::Result<()>>,
    {
        let _guard = self.init_tracing()?;
        tracing::info!(target: "malachite::cli", "Initialized tracing, debug log directory: {}", self.logs.log_file_directory);

        // Install the prometheus recorder
        let _ = reth::prometheus_exporter::install_prometheus_recorder();

        match self.command {
            reth::cli::Commands::Node(command) => runner.run_command_until_exit(|ctx| {
                command.execute(
                    ctx,
                    reth_cli_commands::launcher::FnLauncher::new::<C, Ext>(launcher),
                )
            }),
            _ => todo!("Other commands not implemented yet"),
        }
    }

    /// Initializes tracing with the configured options
    pub fn init_tracing(&self) -> eyre::Result<Option<reth_tracing::FileWorkerGuard>> {
        let guard = self.logs.init_tracing()?;
        Ok(guard)
    }
}

// Temporary custom chain implementation - should be replaced with proper chain spec
fn custom_malachite_chain() -> ChainSpec {
    use alloy_genesis::{Genesis, GenesisAccount};
    use alloy_primitives::{Address, B256, Bytes, U256};
    use reth_chainspec::{Chain, ChainSpecBuilder};
    use std::collections::BTreeMap;

    // Create a basic genesis block
    let genesis = Genesis {
        config: Default::default(),
        nonce: 0x42,
        timestamp: 0x0,
        extra_data: Bytes::from_static(b"SC"),
        gas_limit: 0xa388,
        difficulty: U256::from(0x400000000_u64),
        mix_hash: B256::ZERO,
        coinbase: Address::ZERO,
        number: Some(0),
        alloc: {
            let mut alloc = BTreeMap::new();
            // Add test accounts with balance
            let test_accounts = vec![
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
                "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
            ];

            for addr in test_accounts {
                alloc.insert(
                    addr.parse().unwrap(),
                    GenesisAccount {
                        balance: U256::from_str_radix("D3C21BCECCEDA1000000", 16).unwrap(),
                        ..Default::default()
                    },
                );
            }

            // Keep original account too
            alloc.insert(
                "0x6Be02d1d3665660d22FF9624b7BE0551ee1Ac91b"
                    .parse()
                    .unwrap(),
                GenesisAccount {
                    balance: U256::from_str_radix("4a47e3c12448f4ad000000", 16).unwrap(),
                    ..Default::default()
                },
            );
            alloc
        },
        ..Default::default()
    };

    ChainSpecBuilder::default()
        .chain(Chain::from_id(2600))
        .genesis(genesis)
        .paris_activated()
        .shanghai_activated()
        .cancun_activated()
        .build()
}
