//! Generate the chainspec recovery for a chain whose epoch lost its threshold signing key.

use std::{path::PathBuf, sync::Arc};

use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use eyre::WrapErr as _;
use reth_provider::providers::{ProviderFactoryBuilder, ReadOnlyConfig};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_consensus_config::SigningShare;
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

        let factory = ProviderFactoryBuilder::<TempoNode>::default()
            .open_read_only(
                chain.clone(),
                ReadOnlyConfig::from_datadir(&datadir),
                reth_tasks::Runtime::test(),
            )
            .wrap_err_with(|| format!("failed opening datadir `{}`", datadir.display()))?;

        let (recovery, share) =
            tempo_consensus::recovery::prepare(factory, &chain, member, rand::rng())?;

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
            "wrote recovery (finalized height {}, boundary {}) to `{}`",
            recovery.finalized_height,
            recovery.boundary_hash,
            output.display(),
        );
        Ok(())
    }
}
