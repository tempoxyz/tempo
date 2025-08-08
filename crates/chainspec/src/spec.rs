use alloy_genesis::Genesis;
use reth_chainspec::{Chain, ChainHardforks, ChainSpec, EthereumHardfork};
use reth_cli::chainspec::{ChainSpecParser, parse_genesis};
use std::sync::{Arc, LazyLock};

/// Tempo chain specification parser.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TempoChainSpecParser;

/// Chains supported by Tempo. First value should be used as the default.
pub const SUPPORTED_CHAINS: &[&str] = &["presto"];

/// Clap value parser for [`ChainSpec`]s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<ChainSpec>, eyre::Error> {
    Ok(match s {
        "presto" => PRESTO.clone(),
        _ => Arc::new(parse_genesis(s)?.into()),
    })
}

impl ChainSpecParser for TempoChainSpecParser {
    type ChainSpec = ChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<ChainSpec>> {
        chain_value_parser(s)
    }
}

pub static PRESTO: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let _genesis: Genesis = serde_json::from_str(include_str!("../res/genesis/presto.json"))
        .expect("Can't deserialize Adagio genesis json");
    let _hardforks: ChainHardforks = EthereumHardfork::mainnet().into();
    let mut spec = ChainSpec {
        chain: Chain::from(1234),
        // TODO: update spec for testnet
        ..Default::default()
    };
    spec.genesis.config.dao_fork_support = true;
    spec.into()
});
