//! Inspect a block's extra_data field to determine its contents.

use alloy::{
    primitives::U64,
    rpc::{client::ClientBuilder, types::Block},
};
use commonware_codec::{Read as _, ReadExt as _};
use commonware_cryptography::{
    bls12381::{dkg::SignedDealerLog, primitives::variant::MinSig},
    ed25519::PrivateKey,
};
use commonware_utils::NZU32;
use eyre::{Context as _, eyre};
use serde::Serialize;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;



#[derive(Debug, clap::Args)]
pub(crate) struct InspectBlock {
    /// RPC endpoint URL
    #[arg(long)]
    rpc_url: String,

    /// Block height to inspect
    #[arg(long)]
    height: u64,

    /// Number of players (required for parsing dealer logs)
    #[arg(long, default_value = "10")]
    num_players: u32,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ExtraDataContent {
    Empty,
    DealerLog {
        dealer: String,
    },
    DkgOutcome {
        epoch: u64,
        is_next_full_dkg: bool,
        num_dealers: usize,
        num_players: usize,
        num_next_players: usize,
    },
    Unknown {
        length: usize,
        hex_prefix: String,
    },
}

#[derive(Serialize)]
struct InspectResult {
    height: u64,
    block_hash: String,
    extra_data_length: usize,
    content: ExtraDataContent,
}

impl InspectBlock {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let client =
            ClientBuilder::default().http(self.rpc_url.parse().wrap_err("invalid RPC URL")?);

        let mut batch = client.new_batch();
        let waiter = batch
            .add_call::<_, Option<Block>>("eth_getBlockByNumber", &(U64::from(self.height), false))
            .wrap_err("failed to create request")?;

        batch.send().await.wrap_err("failed to send request")?;

        let block = waiter
            .await
            .wrap_err("failed to fetch block")?
            .ok_or_else(|| eyre!("block {} not found", self.height))?;

        let extra_data = &block.header.inner.extra_data;
        let extra_data_length = extra_data.len();

        let content = if extra_data.is_empty() {
            ExtraDataContent::Empty
        } else {
            let num_players = NZU32!(self.num_players);

            // Try parsing as SignedDealerLog first
            if let Ok(_signed_log) = SignedDealerLog::<MinSig, PrivateKey>::read_cfg(
                &mut extra_data.as_ref(),
                &num_players,
            ) {
                // We successfully parsed it as a SignedDealerLog
                // Extract dealer pubkey from the start of extra_data (32 bytes for ed25519)
                let dealer_hex = const_hex::encode_prefixed(&extra_data[..32]);

                ExtraDataContent::DealerLog {
                    dealer: dealer_hex,
                }
            } else if let Ok(outcome) = OnchainDkgOutcome::read(&mut extra_data.as_ref()) {
                ExtraDataContent::DkgOutcome {
                    epoch: outcome.epoch.get(),
                    is_next_full_dkg: outcome.is_next_full_dkg,
                    num_dealers: outcome.dealers().len(),
                    num_players: outcome.players().len(),
                    num_next_players: outcome.next_players().len(),
                }
            } else {
                // Unknown format - show hex prefix
                let hex_prefix = if extra_data.len() > 32 {
                    format!("{}...", const_hex::encode_prefixed(&extra_data[..32]))
                } else {
                    const_hex::encode_prefixed(extra_data.as_ref())
                };

                ExtraDataContent::Unknown {
                    length: extra_data_length,
                    hex_prefix,
                }
            }
        };

        let result = InspectResult {
            height: self.height,
            block_hash: format!("{:?}", block.header.hash),
            extra_data_length,
            content,
        };

        println!("{}", serde_json::to_string_pretty(&result)?);

        Ok(())
    }
}
