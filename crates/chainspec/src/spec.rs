use reth_chainspec::ChainSpec;
use reth_cli::chainspec::{ChainSpecParser, parse_genesis};
use std::sync::{Arc, LazyLock};

/// Tempo chain specification parser.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TempoChainSpecParser;

/// Chains supported by Tempo. First value should be used as the default.
pub const SUPPORTED_CHAINS: &[&str] = &["adagio"];

/// Clap value parser for [`ChainSpec`]s.
///
/// The value parser matches either a known chain, the path
/// to a json file, or a json formatted string in-memory. The json needs to be a Genesis struct.
pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<ChainSpec>, eyre::Error> {
    Ok(match s {
        "adagio" => ADAGIO.clone(),
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

pub static ADAGIO: LazyLock<Arc<ChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_stre!("../res/genesis/adagio.json"))
        .expect("Can't deserialize Mainnet genesis json");
    let hardforks = EthereumHardfork::mainnet().into();
    let mut spec = ChainSpec {
        chain: Chain::mainnet(),
        genesis_header: SealedHeader::new(
            make_genesis_header(&genesis, &hardforks),
            MAINNET_GENESIS_HASH,
        ),
        genesis,
        // <https://etherscan.io/block/15537394>
        paris_block_and_final_difficulty: Some((
            15537394,
            U256::from(58_750_003_716_598_352_816_469u128),
        )),
        hardforks,
        // https://etherscan.io/tx/0xe75fb554e433e03763a1560646ee22dcb74e5274b34c5ad644e7c0f619a7e1d0
        deposit_contract: Some(MAINNET_DEPOSIT_CONTRACT),
        base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
        prune_delete_limit: MAINNET_PRUNE_DELETE_LIMIT,
        blob_params: BlobScheduleBlobParams::default(),
    };
    spec.genesis.config.dao_fork_support = true;
    spec.into()
});
