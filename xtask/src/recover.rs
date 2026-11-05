//! Generate the chainspec recovery for a chain whose epoch lost its threshold signing key.

use std::{path::PathBuf, sync::Arc};

use alloy::primitives::Bytes;
use commonware_codec::{DecodeExt as _, Encode as _, ReadExt as _};
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt, primitives::sharing::Mode},
    ed25519::PublicKey,
};
use commonware_utils::{N3f1, TryFromIterator as _, ordered};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use reth_provider::{
    BlockHashReader as _, ChainStateBlockReader as _, HeaderProvider as _,
    providers::{ProviderFactoryBuilder, ReadOnlyConfig},
};
use tempo_chainspec::{Recovery, spec::TempoChainSpec};
use tempo_consensus::recovery::build_fill_blocks;
use tempo_consensus_config::SigningShare;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::TempoEvmConfig;
use tempo_node::TempoNode;

/// Writes the chainspec `recovery` entry and the recovery member's share.
///
/// The recovery outcome hands the epoch after the halted one to a single member with a 1-of-1
/// share; that epoch's ceremony then reshares to the halted epoch's `next_players`.
#[derive(Debug, clap::Args)]
pub(crate) struct Recover {
    /// Chain to recover (mainnet, moderato, testnet, dev, or a genesis JSON path).
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// Datadir of a node of the halted chain. It is opened read-only.
    #[arg(long)]
    datadir: PathBuf,

    /// Hex-encoded ed25519 public key of the validator that runs the recovery epoch alone.
    #[arg(long)]
    member: String,

    /// Directory to write `recovery.json` and the member's `signing.share` into.
    #[arg(long)]
    output: PathBuf,
}

impl Recover {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            chain,
            datadir,
            member,
            output,
        } = self;

        let member = PublicKey::decode(commonware_codec::Copying(
            &const_hex::decode(&member).wrap_err("member is not hex")?[..],
        ))
        .wrap_err("member is not an ed25519 public key")?;

        let epocher = FixedEpocher::new(
            chain
                .info
                .epoch_length()
                .ok_or_eyre("epochLength not found in chainspec")?,
        );

        let factory = ProviderFactoryBuilder::<TempoNode>::default()
            .open_read_only(
                chain.clone(),
                ReadOnlyConfig::from_datadir(&datadir),
                reth_tasks::Runtime::test(),
            )
            .wrap_err_with(|| format!("failed opening datadir `{}`", datadir.display()))?;

        let finalized_height = Height::new(
            factory
                .provider()?
                .last_finalized_block_number()
                .wrap_err("failed reading the finalized block number")?
                .ok_or_eyre("datadir has no finalized block")?,
        );
        let finalized = factory
            .sealed_header(finalized_height.get())
            .wrap_err("failed reading the finalized header")?
            .ok_or_eyre("datadir does not have the finalized header")?;
        let epoch_info = epocher
            .containing(finalized_height)
            .expect("fixed epocher is valid for all heights");
        ensure!(
            epoch_info.last() != finalized_height,
            "the finalized block `{finalized_height}` is the boundary of epoch `{}`; the next \
            epoch can start from it without recovery",
            epoch_info.epoch(),
        );

        // The halted epoch's outcome names the players its ceremony would have dealt to.
        let halted_boundary = epoch_info.epoch().previous().map_or(0, |previous| {
            epocher
                .last(previous)
                .expect("fixed epocher is valid for all epochs")
                .get()
        });
        let halted_header = factory
            .header(
                factory
                    .block_hash(halted_boundary)?
                    .ok_or_eyre("datadir does not have the halted epoch's boundary block")?,
            )
            .wrap_err_with(|| format!("failed reading boundary block `{halted_boundary}`"))?
            .ok_or_eyre("datadir does not have the halted epoch's boundary block")?;
        let halted = OnchainDkgOutcome::read(&mut commonware_codec::Copying(
            halted_header.inner.extra_data.as_ref(),
        ))
        .wrap_err("halted epoch's boundary block has no DKG outcome")?;
        ensure!(
            halted.next_players().position(&member).is_some(),
            "member `{member}` is not among the halted epoch's next players",
        );

        let mut rng: rand::rngs::StdRng = rand::make_rng();
        let (dkg_output, shares) = feldman_desmedt::deal::<_, _, N3f1>(
            &mut rng,
            Mode::NonZeroCounter,
            ordered::Set::try_from_iter([member]).expect("a single player is unique"),
        )
        .wrap_err("failed dealing the recovery share")?;
        let (_, share) = shares
            .into_iter()
            .next()
            .expect("dealing to one player yields one share");

        let outcome = OnchainDkgOutcome {
            epoch: epoch_info.epoch().next().get(),
            output: dkg_output,
            next_players: halted.next_players,
            is_next_full_dkg: false,
        };

        let blocks = build_fill_blocks(
            factory,
            &TempoEvmConfig::new(chain.clone()),
            &chain,
            finalized.clone(),
            epoch_info.last(),
            &outcome,
        )
        .wrap_err("failed building the fill blocks")?;
        let boundary_hash = blocks
            .last()
            .expect("a recovery fills at least one block")
            .hash();

        let recovery = Recovery {
            finalized_height: finalized_height.get(),
            finalized_hash: finalized.hash(),
            boundary_hash,
            outcome: Bytes::from(outcome.encode().to_vec()),
        };

        std::fs::create_dir_all(&output)
            .wrap_err_with(|| format!("failed creating `{}`", output.display()))?;
        std::fs::write(
            output.join("recovery.json"),
            serde_json::to_string_pretty(&recovery)?,
        )
        .wrap_err("failed writing recovery.json")?;
        SigningShare::from(share)
            .write_to_file(output.join("signing.share"))
            .wrap_err("failed writing signing.share")?;

        println!(
            "wrote recovery for epoch {} (finalized height {finalized_height}, boundary {} at \
            {boundary_hash}) to `{}`",
            outcome.epoch,
            epoch_info.last(),
            output.display(),
        );
        Ok(())
    }
}
