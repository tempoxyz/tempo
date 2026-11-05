//! Generate the chainspec recovery for a chain whose epoch lost its threshold signing key.

use std::{path::PathBuf, sync::Arc};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{B256, Bytes},
    providers::{Provider, ProviderBuilder},
};
use commonware_codec::{DecodeExt as _, Encode as _, ReadExt as _};
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt, primitives::sharing::Mode},
    ed25519::PublicKey,
};
use commonware_utils::{N3f1, TryFromIterator as _, ordered};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use tempo_chainspec::{Recovery, spec::TempoChainSpec};
use tempo_consensus_config::SigningShare;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;

/// Writes the chainspec `recovery` entry and the recovery member's share.
///
/// The recovery outcome hands the epoch after the halted one to a single member with a 1-of-1
/// share; that epoch's ceremony then reshares to the halted epoch's `next_players`.
#[derive(Debug, clap::Args)]
pub(crate) struct Recover {
    /// Chain to recover (mainnet, moderato, testnet, dev, or a genesis JSON path).
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Arc<TempoChainSpec>,

    /// RPC endpoint of a node of the halted chain.
    #[arg(long)]
    rpc_url: String,

    /// Hex-encoded ed25519 public key of the validator that runs the recovery epoch alone.
    #[arg(long)]
    member: String,

    /// Pins the boundary hash the recovery member logged into the existing `recovery.json` in
    /// `--output`, without dealing again. Omit it on the first run, which deals the recovery key:
    /// the member then refuses to start and logs the boundary hash it built.
    #[arg(long)]
    boundary_hash: Option<B256>,

    /// Directory to write `recovery.json` and the member's `signing.share` into.
    #[arg(long)]
    output: PathBuf,
}

impl Recover {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            chain,
            rpc_url,
            member,
            boundary_hash,
            output,
        } = self;

        let recovery_path = output.join("recovery.json");
        if let Some(boundary_hash) = boundary_hash {
            // Dealing again would change the outcome, and with it the boundary: only pin the hash.
            let mut recovery: Recovery = serde_json::from_str(
                &std::fs::read_to_string(&recovery_path).wrap_err_with(|| {
                    format!(
                        "failed reading `{}`; run without --boundary-hash first",
                        recovery_path.display()
                    )
                })?,
            )
            .wrap_err("recovery.json is not a valid recovery")?;
            recovery.boundary_hash = boundary_hash;
            std::fs::write(&recovery_path, serde_json::to_string_pretty(&recovery)?)
                .wrap_err("failed writing recovery.json")?;
            println!(
                "pinned boundary hash {boundary_hash} in `{}`",
                recovery_path.display()
            );
            return Ok(());
        }
        ensure!(
            !recovery_path.exists(),
            "`{}` already exists; pass --boundary-hash to pin its boundary, or remove it to deal a \
            new recovery key",
            recovery_path.display(),
        );

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

        let provider = ProviderBuilder::new()
            .connect(&rpc_url)
            .await
            .wrap_err("failed to connect to RPC")?;

        let finalized = provider
            .get_block_by_number(BlockNumberOrTag::Finalized)
            .await
            .wrap_err("failed fetching the finalized block")?
            .ok_or_eyre("node has no finalized block")?;
        let finalized_height = Height::new(finalized.header.number);
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
        let halted_header = provider
            .get_block_by_number(halted_boundary.into())
            .await
            .wrap_err_with(|| format!("failed fetching boundary block `{halted_boundary}`"))?
            .ok_or_eyre("node does not have the halted epoch's boundary block")?
            .header;
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
            ordered::Set::try_from_iter([member.clone()]).expect("a single player is unique"),
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

        let recovery = Recovery {
            finalized_height: finalized_height.get(),
            finalized_hash: finalized.header.hash,
            // Unknown until the member builds the boundary from this entry.
            boundary_hash: B256::ZERO,
            outcome: Bytes::from(outcome.encode().to_vec()),
        };

        std::fs::create_dir_all(&output)
            .wrap_err_with(|| format!("failed creating `{}`", output.display()))?;
        std::fs::write(&recovery_path, serde_json::to_string_pretty(&recovery)?)
            .wrap_err("failed writing recovery.json")?;
        SigningShare::from(share)
            .write_to_file(output.join("signing.share"))
            .wrap_err("failed writing signing.share")?;

        println!(
            "wrote recovery for epoch {} (finalized height {finalized_height}, boundary {}) to `{}`",
            outcome.epoch,
            epoch_info.last(),
            output.display(),
        );
        println!(
            "boundaryHash is unset: add recovery.json under `config.recovery` in the chainspec, \
            start the member with signing.share, read the boundary hash from its `this node built \
            boundary` error, and rerun with --boundary-hash"
        );
        Ok(())
    }
}
