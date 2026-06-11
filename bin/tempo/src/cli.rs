//! CLI type definitions for the Tempo node.

use crate::{defaults, follow, tempo_cmd};
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_ethereum_cli::Cli;
use reth_network_peers::pk2id;
use reth_rpc_server_types::{RethRpcModule, RpcModuleSelection, RpcModuleValidator};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_faucet::args::FaucetArgs;
use tempo_node::TempoNodeArgs;

pub(crate) type TempoCli =
    Cli<TempoChainSpecParser, TempoArgs, TempoRpcModuleValidator, tempo_cmd::TempoSubcommand>;

pub(crate) const TEMPO_CUSTOM_RPC_MODULES: &[&str] = &["consensus", "operator", "tempo", "token"];

#[derive(Debug, Clone, Copy)]
pub(crate) struct TempoRpcModuleValidator;

impl RpcModuleValidator for TempoRpcModuleValidator {
    fn parse_selection(s: &str) -> Result<RpcModuleSelection, String> {
        let selection = s
            .parse::<RpcModuleSelection>()
            .map_err(|e| format!("Failed to parse RPC modules: {e}"))?;

        if let RpcModuleSelection::Selection(modules) = &selection {
            for module in modules {
                let RethRpcModule::Other(name) = module else {
                    continue;
                };

                if !TEMPO_CUSTOM_RPC_MODULES.contains(&name.as_str()) {
                    return Err(format!("Unknown RPC module: '{name}'"));
                }
            }
        }

        Ok(selection)
    }
}

// TODO: migrate this to tempo_node eventually.
#[derive(Debug, Clone, clap::Args)]
pub(crate) struct TempoArgs {
    /// Run in follow mode from an upstream node.
    /// If provided without a value, defaults to the RPC URL for the selected chain.
    #[arg(long, value_name = "WEBSOCKET_URL", default_missing_value = "auto", num_args(0..=1), env = "TEMPO_FOLLOW")]
    pub(crate) follow: Option<follow::FollowMode>,

    /// Disable consensus certification in follow mode. The follower syncs execution
    /// state from the upstream node without validating consensus state.
    /// DO NOT USE IN PRODUCTION.
    #[arg(
        long = "follow.experimental.certify",
        requires = "follow",
        default_value_t = false
    )]
    pub(crate) follow_certify: bool,

    /// HTTP endpoint that returns a JSON object mapping chain IDs to bootnode lists.
    ///
    /// The endpoint must return JSON in the format:
    /// `{ "<chain_id>": ["enode://...", ...] }`
    ///
    /// Bootnodes for the current chain are added as peer hints to the discovery service.
    ///
    /// Set to "none" to disable.
    #[arg(
        long = "tempo.bootnodes-endpoint",
        value_name = "URL",
        default_value = "https://peers.tempo.xyz",
        env = "TEMPO_BOOTNODES_ENDPOINT"
    )]
    pub(crate) bootnodes_endpoint: String,

    #[command(flatten)]
    pub(crate) telemetry: defaults::TelemetryArgs,

    #[command(flatten)]
    pub(crate) consensus: tempo_consensus::Args,

    #[command(flatten)]
    pub(crate) faucet_args: FaucetArgs,

    #[command(flatten)]
    pub(crate) node_args: TempoNodeArgs,

    #[command(flatten)]
    #[cfg(feature = "pyroscope")]
    pub(crate) pyroscope_args: PyroscopeArgs,
}

impl TempoArgs {
    pub(crate) fn is_following_uncertified(&self) -> bool {
        self.follow.is_some() && !self.follow_certify
    }

    /// Whether the consensus engine should be active.
    ///
    /// The engine runs when not in dev mode and not following uncertified.
    pub(crate) fn has_consensus_engine(&self, dev: bool) -> bool {
        !dev && !self.is_following_uncertified()
    }
}

/// Command line arguments for configuring Pyroscope continuous profiling.
#[cfg(feature = "pyroscope")]
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub(crate) struct PyroscopeArgs {
    /// Enable Pyroscope continuous profiling
    #[arg(long = "pyroscope.enabled", default_value_t = false)]
    pub(crate) pyroscope_enabled: bool,

    /// Pyroscope server URL
    #[arg(long = "pyroscope.server-url", default_value = "http://localhost:4040")]
    pub(crate) server_url: String,

    /// Application name for Pyroscope
    #[arg(long = "pyroscope.application-name", default_value = "tempo")]
    pub(crate) application_name: String,

    /// Sample rate for profiling (default: 100 Hz)
    #[arg(long = "pyroscope.sample-rate", default_value_t = 100)]
    pub(crate) sample_rate: u32,
}

pub(crate) trait NodeCommandExt {
    /// Derive the peer id from the p2p secret key without starting the network.
    fn peer_id(&self) -> reth_network_peers::PeerId;
}

impl NodeCommandExt for reth_cli_commands::node::NodeCommand<TempoChainSpecParser, TempoArgs> {
    fn peer_id(&self) -> reth_network_peers::PeerId {
        let data_dir = self.datadir.clone().resolve_datadir(self.chain.chain());
        let sk = self
            .network
            .secret_key(data_dir.p2p_secret())
            .expect("unable to derive peer id from p2p secret");

        pk2id(&sk.public_key(secp256k1::SECP256K1))
    }
}
