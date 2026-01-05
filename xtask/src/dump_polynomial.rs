//! Dump DKG outcome from a block's extra_data.

use alloy::primitives::Bytes;
use alloy::providers::{Provider, ProviderBuilder};
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::NZU64;
use eyre::{Context as _, eyre};
use serde::Serialize;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

#[derive(Debug, clap::Args)]
pub(crate) struct DumpPolynomial {
    /// RPC endpoint URL (http://, https://, ws://, or wss://)
    #[arg(long)]
    rpc_url: String,

    /// Epoch number to query
    #[arg(long)]
    epoch: u64,

    /// Epoch length (blocks per epoch)
    #[arg(long)]
    epoch_length: u64,
}

#[derive(Serialize)]
struct DkgOutcomeInfo {
    /// The epoch for which this outcome is used
    epoch: u64,
    /// Block number where this outcome was stored
    boundary_block: u64,
    /// Dealers in this DKG ceremony (ed25519 public keys)
    dealers: Vec<String>,
    /// Players in this DKG ceremony (ed25519 public keys)
    players: Vec<String>,
    /// Players for the next DKG ceremony (ed25519 public keys)
    next_players: Vec<String>,
    /// Whether the next DKG should be a full ceremony (new polynomial)
    is_next_full_dkg: bool,
    /// The shared public polynomial info
    sharing: SharingInfo,
}

#[derive(Serialize)]
struct SharingInfo {
    /// The network identity (group public key)
    network_identity: Bytes,
    /// Threshold required for signing
    threshold: u32,
    /// Total number of participants
    total_participants: u32,
}

fn pubkey_to_hex(pk: &PublicKey) -> String {
    const_hex::encode_prefixed(pk.as_ref())
}

impl DumpPolynomial {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let epoch_length = NZU64!(self.epoch_length);
        let epocher = FixedEpocher::new(epoch_length);
        let epoch = Epoch::new(self.epoch);

        let boundary_block = epocher
            .last(epoch)
            .expect("fixed epocher always returns boundary");

        let provider = ProviderBuilder::new()
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let block = provider
            .get_block_by_number(boundary_block.into())
            .await
            .wrap_err_with(|| format!("failed to fetch block number `{boundary_block}`"))?
            .ok_or_else(|| eyre!("block {boundary_block} not found"))?;

        let extra_data = &block.header.inner.extra_data;

        if extra_data.is_empty() {
            return Err(eyre!(
                "block {} has empty extra_data (not an epoch boundary?)",
                boundary_block
            ));
        }

        let outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref())
            .wrap_err("failed to parse DKG outcome from extra_data")?;

        let sharing = outcome.sharing();

        let info = DkgOutcomeInfo {
            epoch: outcome.epoch.get(),
            boundary_block,
            dealers: outcome.dealers().iter().map(pubkey_to_hex).collect(),
            players: outcome.players().iter().map(pubkey_to_hex).collect(),
            next_players: outcome.next_players().iter().map(pubkey_to_hex).collect(),
            is_next_full_dkg: outcome.is_next_full_dkg,
            sharing: SharingInfo {
                network_identity: Bytes::copy_from_slice(&sharing.public().encode()),
                threshold: sharing.required(),
                total_participants: sharing.total().get(),
            },
        };

        println!("{}", serde_json::to_string_pretty(&info)?);

        Ok(())
    }
}
