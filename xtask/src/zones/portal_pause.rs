//! Pauses ZonePortal deposits and L1 withdrawal processing for 30 days.

use alloy::{network::ReceiptResponse as _, primitives::Address, providers::ProviderBuilder};
use eyre::{WrapErr as _, ensure};
use tempo_alloy::{TempoNetwork, provider::ext::TempoProviderExt, rpc::TempoCallBuilderExt};
use tempo_zone_contracts::ZonePortal;
use zone_sequencer::nonce_keys::ADMIN_OPS_NONCE_KEY;

use crate::zones::zone_utils::parse_private_key;

#[derive(Debug, clap::Args)]
pub(crate) struct PortalPauseArgs {
    /// Tempo L1 RPC URL.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// ZonePortal contract address on Tempo L1.
    #[arg(long, env = "L1_PORTAL_ADDRESS")]
    portal: Address,

    /// Private key authorized to send the transaction.
    #[arg(long, env = "PRIVATE_KEY", hide_env_values = true)]
    private_key: String,
}

#[derive(Debug, clap::Parser)]
pub(crate) struct PausePortal {
    #[command(flatten)]
    args: PortalPauseArgs,
}

impl PausePortal {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        pause(self.args).await
    }
}

async fn pause(args: PortalPauseArgs) -> eyre::Result<()> {
    let signer = parse_private_key(&args.private_key).wrap_err("PRIVATE_KEY is not valid")?;
    let signer_address = signer.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(signer)
        .connect(&args.l1_rpc_url)
        .await
        .wrap_err("failed connecting to Tempo L1 RPC")?;
    let portal = ZonePortal::new(args.portal, &provider);
    let nonce = provider
        .get_transaction_count_with_nonce_key(signer_address, ADMIN_OPS_NONCE_KEY)
        .await
        .wrap_err("failed reading portal pause nonce")?;

    let pending = portal
        .pause()
        .nonce_key(ADMIN_OPS_NONCE_KEY)
        .nonce(nonce)
        .send()
        .await
        .wrap_err("failed sending ZonePortal.pause")?;
    let receipt = pending
        .get_receipt()
        .await
        .wrap_err("failed waiting for portal pause transaction receipt")?;
    ensure!(receipt.status(), "portal pause transaction reverted");
    ensure!(
        portal.paused().call().await?,
        "portal pause state did not update"
    );

    println!("Portal {} paused for 30 days", args.portal);
    println!("Transaction: {}", receipt.transaction_hash());
    Ok(())
}
