use alloy::{
    network::TransactionBuilder,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    sol_types::SolValue,
};
use eyre::{WrapErr as _, eyre};
use std::path::PathBuf;
use tempo_alloy::TempoNetwork;

use crate::zone_utils::{
    L1_EXPLORER, MODERATO_ZONE_FACTORY, STABLECOIN_DEX_ADDRESS, ZoneMetadata, check,
    normalize_http_rpc, parse_private_key,
};

#[derive(Debug, clap::Parser)]
pub(crate) struct DeployRouter {
    /// Path to the zone directory containing zone.json.
    #[arg(long)]
    zone_dir: PathBuf,

    /// Tempo L1 RPC URL.
    #[arg(
        long,
        env = "L1_RPC_URL",
        default_value = "https://rpc.moderato.tempo.xyz"
    )]
    l1_rpc_url: String,

    /// Private key (hex) for signing the deployment transaction.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// ZoneFactory contract address. Falls back to `zone.json`, then the shared Moderato default.
    #[arg(long, env = "ZONE_FACTORY")]
    zone_factory: Option<Address>,

    /// StablecoinDEX address passed to the router constructor.
    #[arg(long, default_value_t = STABLECOIN_DEX_ADDRESS)]
    stablecoin_dex: Address,

    /// Path to the Foundry compiled output directory containing contract artifacts.
    #[arg(long, default_value = "crates/zones/contracts/out")]
    specs_out: PathBuf,
}

impl DeployRouter {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let mut zone_metadata = ZoneMetadata::load(&self.zone_dir)?;
        let zone_factory = self
            .zone_factory
            .or(zone_metadata.get_optional_address("zoneFactory")?)
            .unwrap_or(MODERATO_ZONE_FACTORY);

        let signer = parse_private_key(&self.private_key)?;
        let deployer = signer.address();
        let http_rpc = normalize_http_rpc(&self.l1_rpc_url);

        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(signer)
            .connect(&http_rpc)
            .await?;
        provider
            .client()
            .set_poll_interval(std::time::Duration::from_secs(1));

        let mut deploy_bytes = load_forge_bytecode(&self.specs_out, "SwapAndDepositRouter")?;
        deploy_bytes.extend_from_slice(&(self.stablecoin_dex, zone_factory).abi_encode());

        println!("Deploying SwapAndDepositRouter...");
        println!("  Deployer:       {deployer}");
        println!("  ZoneFactory:    {zone_factory}");
        println!("  StablecoinDEX:  {}", self.stablecoin_dex);

        let tx = TransactionRequest::default().with_deploy_code(deploy_bytes);
        let receipt = provider
            .send_transaction(tx.into())
            .await?
            .get_receipt()
            .await
            .wrap_err("failed to fetch router deployment receipt")?;
        check(&receipt, "deploy-router")?;

        let router = receipt
            .contract_address
            .ok_or_else(|| eyre!("router deployment receipt missing contract address"))?;

        zone_metadata.set_address("zoneFactory", zone_factory);
        zone_metadata.set_address("swapAndDepositRouter", router);
        zone_metadata.save()?;

        println!("SwapAndDepositRouter deployed successfully!");
        println!("  Address:   {router}");
        println!("  L1 tx:     {L1_EXPLORER}/{}", receipt.transaction_hash);
        println!("  Updated:   {}", self.zone_dir.join("zone.json").display());

        Ok(())
    }
}

fn load_forge_bytecode(specs_out: &std::path::Path, contract: &str) -> eyre::Result<Vec<u8>> {
    let artifact_path = specs_out.join(format!("{contract}.sol/{contract}.json"));
    let artifact = std::fs::read_to_string(&artifact_path).wrap_err_with(|| {
        format!(
            "{contract} artifact not found at {}",
            artifact_path.display()
        )
    })?;
    let artifact_json: serde_json::Value = serde_json::from_str(&artifact)
        .wrap_err_with(|| format!("failed parsing {}", artifact_path.display()))?;
    let hex_str = artifact_json["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| eyre!("missing bytecode in {}", artifact_path.display()))?;

    alloy::primitives::hex::decode(hex_str)
        .wrap_err_with(|| format!("invalid bytecode in {}", artifact_path.display()))
}
