//! Dump polynomial commitment from a block's extra_data.

use alloy::providers::{Provider, ProviderBuilder};
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
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
struct PolynomialInfo {
    epoch: u64,
    boundary_block: u64,
    constant_term: String,
    threshold: u32,
    total_participants: u32,
}

impl DumpPolynomial {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let epoch_length = NZU64!(self.epoch_length);
        let epocher = FixedEpocher::new(epoch_length);
        let epoch = Epoch::new(self.epoch);

        let boundary_block = epocher
            .last(epoch)
            .ok_or_else(|| eyre!("invalid epoch {}", self.epoch))?;

        let provider = ProviderBuilder::new()
            .connect(&self.rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let block = provider
            .get_block_by_number(boundary_block.into())
            .await
            .wrap_err("failed to fetch block")?
            .ok_or_else(|| eyre!("block {} not found", boundary_block))?;

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
        let constant_term_bytes = sharing.public().encode();
        let constant_term = const_hex::encode_prefixed(&constant_term_bytes);

        let info = PolynomialInfo {
            epoch: self.epoch,
            boundary_block,
            constant_term,
            threshold: sharing.required(),
            total_participants: sharing.total().get(),
        };

        println!("{}", serde_json::to_string_pretty(&info)?);

        Ok(())
    }
}
