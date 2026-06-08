use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use alloy_primitives::{B256, Bytes};
use clap::{ArgMatches, FromArgMatches, Parser};
use commonware_codec::Encode as _;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::Runner as _;
use eyre::{Context as _, OptionExt};
use reth_cli_commands::download::{
    manifest::SnapshotManifest, manifest_cmd::SnapshotManifestCommand,
};
use serde::{Deserialize, Serialize};
use tempo_commonware_node::consensus::Digest;
use tempo_telemetry_util::display_duration;

pub(crate) const TEMPO_CONSENSUS_MANIFEST_KEY: &str = "consensus";

type TempoFinalization = Finalization<Scheme<PublicKey, MinSig>, Digest>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TempoConsensusManifest {
    pub(crate) height: u64,
    pub(crate) digest: B256,
    pub(crate) finalization: Bytes,
}

#[derive(Debug, Parser)]
#[command(
    name = "snapshot-manifest",
    about = "Generate snapshot archives and a manifest for the EL plus consensus floor certificate."
)]
pub(crate) struct Args {
    #[command(flatten)]
    inner: SnapshotManifestCommand,

    /// Skip encoding consensus state
    #[arg(long, default_value_t = true)]
    skip_consensus: bool,

    /// Consensus storage directory. If not set, this will be derived from --datadir.
    #[arg(long = "consensus.datadir", value_name = "PATH")]
    consensus_datadir: Option<PathBuf>,
}

pub(crate) fn run(matches: &ArgMatches) -> eyre::Result<()> {
    let args = Args::from_arg_matches(matches).wrap_err("failed to parse args")?;

    let source_datadir = matches
        .get_one::<PathBuf>("source_datadir")
        .cloned()
        .expect("--source-dir must be set");

    let output_dir = matches
        .get_one::<PathBuf>("output_dir")
        .cloned()
        .expect("--output-dir must be set");

    args.execute(&source_datadir, &output_dir)
}

impl Args {
    fn execute(self, source_datadir: &Path, output_dir: &Path) -> eyre::Result<()> {
        let Self {
            inner,
            skip_consensus,
            consensus_datadir,
        } = self;

        fs::create_dir_all(output_dir)
            .wrap_err_with(|| format!("failed to create output dir: {}", output_dir.display()))?;

        eprintln!("packaging execution layer");

        let start = Instant::now();
        inner
            .execute()
            .wrap_err("reth snapshot-manifest (EL packaging) failed")?;

        eprintln!(
            "execution layer snapshot finished in {}",
            display_duration(start.elapsed())
        );

        if skip_consensus {
            eprintln!("--skip-consensus set. skipping consensus layer");
            return Ok(());
        }

        let manifest_path = output_dir.join("manifest.json");
        let manifest = read_manifest(&manifest_path)
            .wrap_err_with(|| format!("failed reading manifest: {}", manifest_path.display()))?;

        let consensus_dir = consensus_datadir.unwrap_or_else(|| source_datadir.join("consensus"));
        eprintln!(
            "reading latest finalization. consensus dir: {}",
            consensus_dir.display()
        );

        let (height, finalization) = read_latest_finalization(&consensus_dir)
            .wrap_err("failed to read finalization state")?;

        let digest = finalization.proposal.payload;
        let consensus_manifest = TempoConsensusManifest {
            height,
            digest: digest.0,
            finalization: finalization.encode().into(),
        };

        let mut manifest_json =
            serde_json::to_value(&manifest).wrap_err("failed to serialize merged manifest")?;

        manifest_json
            .as_object_mut()
            .ok_or_eyre("serialized manifest was not a JSON object")?
            .insert(
                TEMPO_CONSENSUS_MANIFEST_KEY.to_string(),
                serde_json::to_value(consensus_manifest)
                    .wrap_err("failed to serialize Tempo consensus manifest extension")?,
            );

        let manifest_json = serde_json::to_string_pretty(&manifest_json)
            .wrap_err("failed to serialize manifest")?;
        fs::write(&manifest_path, manifest_json)
            .wrap_err_with(|| format!("failed to write {}", manifest_path.display()))?;

        eprintln!("embedded finalization for height `{height}`, digest `{digest}`");
        Ok(())
    }
}

fn read_manifest(manifest_path: &Path) -> eyre::Result<SnapshotManifest> {
    let manifest_bytes = fs::read(manifest_path).wrap_err("failed to read file")?;
    serde_json::from_slice(&manifest_bytes).wrap_err("failed to parse manifest")
}

fn read_latest_finalization(consensus_dir: &Path) -> eyre::Result<(u64, TempoFinalization)> {
    let runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir);

    let runner = commonware_runtime::tokio::Runner::new(runtime_config);
    let finalization =
        runner
            .start(|context| async move {
                tempo_commonware_node::read_latest_finalization(&context).await
            })
            .wrap_err("failed to read finalizations")?;

    finalization.ok_or_eyre("no persisted finalizations")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_manifest_serializes_binary_fields_as_hex() {
        let manifest = TempoConsensusManifest {
            height: 42,
            digest: B256::with_last_byte(0x2a),
            finalization: Bytes::from(vec![0x00, 0x01, 0x02, 0xff]),
        };

        let value = serde_json::to_value(manifest).unwrap();

        assert_eq!(value["height"], 42);
        assert_eq!(
            value["digest"],
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
        assert_eq!(value["finalization"], "0x000102ff");
    }
}
