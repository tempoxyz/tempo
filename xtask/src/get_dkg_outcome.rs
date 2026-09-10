//! Dump DKG outcome from a block's extra_data.

use std::sync::Arc;

use alloy::{
    primitives::{B256, Bytes},
    providers::{Provider, ProviderBuilder},
};
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::N3f1;
use eyre::{Context as _, OptionExt as _, ensure, eyre};
use serde::Serialize;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

#[derive(Debug, clap::Args)]
pub(crate) struct GetDkgOutcome {
    /// Chain to inspect (mainnet, moderato, testnet, dev, or a genesis JSON path).
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// RPC endpoint URL override. Required when the selected chainspec does not define a default.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Epoch number to query
    #[arg(long)]
    epoch: u64,
}

#[derive(Serialize)]
struct DkgOutcomeInfo {
    /// The epoch for which this outcome is used
    epoch: u64,
    /// Block number where this outcome was stored
    block_number: u64,
    /// Block hash where this outcome was stored
    block_hash: B256,
    /// Dealers that contributed to the outcome of this DKG ceremony (ed25519 public keys)
    dealers: Vec<String>,
    /// Players that received a share from this DKG ceremony (ed25519 public keys)
    players: Vec<String>,
    /// Players for the next DKG ceremony (ed25519 public keys)
    next_players: Vec<String>,
    /// Whether the next DKG should be a full ceremony (new polynomial)
    is_next_full_dkg: bool,
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

impl GetDkgOutcome {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            chain,
            rpc_url,
            epoch,
        } = self;

        let rpc_url = rpc_url
            .or_else(|| chain.default_follow_url().map(str::to_owned))
            .ok_or_eyre(
                "selected chainspec does not define a default RPC URL; pass --rpc-url for a custom network",
            )?;

        let provider = ProviderBuilder::new()
            .connect(&rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let epoch_length = chain
            .info
            .epoch_length()
            .ok_or_eyre("epochLength not found in chainspec")?;

        let epocher = FixedEpocher::new(epoch_length);
        let block_number = epocher
            .last(Epoch::new(epoch))
            .expect("fixed epocher is valid for all epochs")
            .get();

        let block = provider
            .get_block_by_number(block_number.into())
            .await
            .wrap_err_with(|| format!("failed to fetch block number `{block_number}`"))?
            .ok_or_else(|| eyre!("block {block_number} not found"))?;

        let block_number = block.header.number;
        let block_hash = block.header.hash;
        let extra_data = &block.header.inner.extra_data;

        ensure!(
            !extra_data.is_empty(),
            "block {} has empty extra_data (not an epoch boundary?)",
            block_number
        );

        let outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref())
            .wrap_err("failed to parse DKG outcome from extra_data")?;

        let sharing = outcome.sharing();
        let info = DkgOutcomeInfo {
            epoch: outcome.epoch.get(),
            block_number,
            block_hash,
            dealers: outcome.dealers().iter().map(pubkey_to_hex).collect(),
            players: outcome.players().iter().map(pubkey_to_hex).collect(),
            next_players: outcome.next_players().iter().map(pubkey_to_hex).collect(),
            is_next_full_dkg: outcome.is_next_full_dkg,
            network_identity: Bytes::copy_from_slice(&sharing.public().encode()),
            threshold: sharing.required::<N3f1>(),
            total_participants: sharing.total().get(),
        };

        println!("{}", serde_json::to_string_pretty(&info)?);

        Ok(())
    }
}
