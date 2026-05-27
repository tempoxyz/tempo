use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use alloy_primitives::hex;
use clap::{ArgMatches, FromArgMatches, Parser};
use commonware_codec::Encode as _;
use commonware_runtime::Runner as _;
use eyre::{Context as _, OptionExt, Result, ensure};
use reth_cli_commands::download::{
    manifest::SnapshotManifest, manifest_cmd::SnapshotManifestCommand,
};
use serde::{Deserialize, Serialize};

pub(crate) const TEMPO_CONSENSUS_MANIFEST_KEY: &str = "consensus";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TempoConsensusManifest {
    pub(crate) finalization: String,
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

    /// Consensus storage directory. If not set, this will be dirived from --datadir.
    #[arg(long)]
    consensus_source_dir: Option<PathBuf>,
}

pub(crate) fn run(matches: &ArgMatches) -> Result<()> {
    let args = Args::from_arg_matches(matches).map_err(|e| eyre::eyre!("{e}"))?;

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
    fn execute(self, source_datadir: &Path, output_dir: &Path) -> Result<()> {
        fs::create_dir_all(output_dir)
            .wrap_err_with(|| format!("failed to create output dir: {output_dir:?}"))?;

        eprintln!("packaging execution layer");

        let start = Instant::now();
        self.inner
            .execute()
            .wrap_err("reth snapshot-manifest (EL packaging) failed")?;

        eprintln!("execution layer snapshot finished in {:?}", start.elapsed());
        if self.skip_consensus {
            return Ok(());
        }

        let consensus_dir = self
            .consensus_source_dir
            .clone()
            .unwrap_or_else(|| source_datadir.join("consensus"));

        ensure!(
            consensus_dir.is_dir(),
            format!("consensus dir does not exist: {consensus_dir:?}")
        );

        let manifest_path = output_dir.join("manifest.json");
        let manifest_bytes = fs::read(&manifest_path)
            .wrap_err_with(|| format!("failed to read {manifest_path:?}"))?;

        let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
            .wrap_err("failed to parse manifest.json produced by reth snapshot-manifest")?;

        eprintln!("reading finalization at snapshot block {}", manifest.block);
        let finalization = read_finalization_certificate(&consensus_dir, manifest.block)?;
        let consensus_manifest = TempoConsensusManifest { finalization };

        let mut manifest_json =
            serde_json::to_value(&manifest).wrap_err("failed to serialize merged manifest")?;

        manifest_json
            .as_object_mut()
            .ok_or_eyre("serialized manifest was not a JSON object")?
            .insert(
                TEMPO_CONSENSUS_MANIFEST_KEY.to_string(),
                serde_json::to_value(&consensus_manifest)
                    .wrap_err("failed to serialize Tempo consensus manifest extension")?,
            );

        serde_json::to_string_pretty(&manifest_json)
            .wrap_err("failed to serialize manifest")
            .and_then(|json| {
                fs::write(&manifest_path, json)
                    .wrap_err_with(|| format!("failed to write {manifest_path:?}"))
            })?;

        eprintln!("finalization encoded in snapshot manifest");
        Ok(())
    }
}

fn read_finalization_certificate(consensus_dir: &Path, height: u64) -> Result<String> {
    let runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir);

    let runner = commonware_runtime::tokio::Runner::new(runtime_config);
    let finalization = runner
        .start(|context| async move {
            tempo_commonware_node::storage::read_finalization_at_height(&context, height).await
        })
        .wrap_err("failed to read finalization certificate")?;

    finalization
        .ok_or_eyre("no finalization certificate")
        .map(|f| hex::encode(f.encode().to_vec()))
}
