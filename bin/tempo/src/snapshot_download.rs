use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use alloy_primitives::hex;
use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, OptionExt, Result, bail, eyre};
use reth_cli_commands::download::{DownloadCommand, manifest::SnapshotManifest};
use reth_cli_runner::CliRunner;
use tempo_chainspec::spec::TempoChainSpecParser;

use crate::snapshot_manifest::{TEMPO_CONSENSUS_MANIFEST_KEY, TempoConsensusManifest};

const FINALIZATION_FILE: &str = "bootstrap/finalization.bin";

#[derive(Debug, Parser)]
#[command(
    name = "download",
    about = "Downloads snapshot archives produced by `tempo snapshot-manifest`."
)]
pub(crate) struct Args {
    #[command(flatten)]
    inner: DownloadCommand<TempoChainSpecParser>,

    /// Skip consensus bootstrap
    #[arg(long, default_value_t = true)]
    skip_consensus: bool,

    /// Consensus storage directory. If not set, this will be dirived from --datadir.
    #[arg(long = "consensus.datadir", value_name = "PATH")]
    consensus_datadir: Option<PathBuf>,
}

pub(crate) fn run(matches: &ArgMatches) -> Result<()> {
    let args = Args::from_arg_matches(matches).map_err(|e| eyre!("{e}"))?;

    let datadir = matches
        .get_raw("datadir")
        .and_then(|mut v| v.next())
        .map(PathBuf::from)
        .expect("--datadir must be set");

    let manifest_url = matches.get_one::<String>("manifest_url").cloned();
    let manifest_path = matches.get_one::<PathBuf>("manifest_path").cloned();

    let runner = CliRunner::try_default_runtime().wrap_err("failed to build obtain runtime")?;
    runner.block_on(async move {
        eprintln!("running execution layer download...");

        let start = Instant::now();
        args.inner
            .execute::<tempo_node::node::TempoNode>()
            .await
            .wrap_err("execution layer download failed")?;

        eprintln!("execution layer download finished in {:?}", start.elapsed());

        if args.skip_consensus {
            eprintln!("--skip-consensus set. skipping consensus layer");
            return Ok(());
        }

        let consensus_dir = args
            .consensus_datadir
            .unwrap_or_else(|| datadir.join("consensus"));

        let loaded_manifest = load_manifest(manifest_url, manifest_path).await?;

        let start = Instant::now();
        let tempo_consensus = loaded_manifest
            .tempo_consensus
            .as_ref()
            .ok_or_eyre("missing consensus in manifest")?;

        write_finalization_bootstrap(&consensus_dir, tempo_consensus)
            .wrap_err("consensus bootstrap failed")?;

        eprintln!("consensus bootstrap finished in {:?}", start.elapsed());
        Ok(())
    })
}

#[derive(Debug)]
struct LoadedManifest {
    tempo_consensus: Option<TempoConsensusManifest>,
}

async fn load_manifest(
    manifest_url: Option<String>,
    manifest_path: Option<PathBuf>,
) -> Result<LoadedManifest> {
    if let Some(path) = manifest_path {
        let bytes = fs::read(path).wrap_err("failed to read manifest file")?;
        return parse_manifest(&bytes);
    }

    if let Some(url) = manifest_url {
        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .send()
            .await
            .wrap_err("failed to fetch from manifest url")?
            .error_for_status()
            .wrap_err("invalid response from manifest url")?;
        let bytes = resp
            .bytes()
            .await
            .wrap_err("failed to parse manifest from url")?;

        return parse_manifest(&bytes);
    }

    bail!("--manifest-url or --manifest-path must be set")
}

fn parse_manifest(bytes: &[u8]) -> Result<LoadedManifest> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).wrap_err("failed to parse manifest.json")?;

    let _manifest: SnapshotManifest =
        serde_json::from_value(value.clone()).wrap_err("failed to parse manifest.json")?;

    let tempo_consensus = value
        .get(TEMPO_CONSENSUS_MANIFEST_KEY)
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .wrap_err("failed to parse Tempo consensus manifest extension")?;

    Ok(LoadedManifest { tempo_consensus })
}

fn write_finalization_bootstrap(
    consensus_dir: &Path,
    tempo_consensus: &TempoConsensusManifest,
) -> Result<()> {
    let bytes = hex::decode(&tempo_consensus.finalization)
        .wrap_err("failed to decode Tempo consensus finalization")?;
    let path = consensus_dir.join(FINALIZATION_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create finalization dir {parent:?}"))?;
    }

    fs::write(&path, bytes)
        .wrap_err_with(|| format!("failed to write finalization certificate to {path:?}"))?;

    eprintln!("wrote consensus finalization: {path:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_parses_mixed_reth_and_tempo_flags() {
        // Order interleaves tempo + reth flags to exercise both schemas in
        // the same parse pass.
        let args = Args::try_parse_from([
            "tempo",
            "--manifest-url",
            "https://snap/manifest.json",
            "--datadir",
            "/d",
            "--consensus.datadir",
            "/c",
            "--skip-consensus",
        ])
        .unwrap();

        assert!(args.skip_consensus);
        assert_eq!(args.consensus_datadir.as_deref(), Some(Path::new("/c")));
    }

    #[test]
    fn parse_manifest_reads_tempo_consensus_extension() {
        let bytes = br#"{
            "block": 42,
            "chain_id": 1,
            "storage_version": 2,
            "timestamp": 0,
            "components": {},
            "consensus": {
                "finalization": "aabbcc"
            }
        }"#;

        let loaded = parse_manifest(bytes).unwrap();
        assert_eq!(
            loaded.tempo_consensus,
            Some(TempoConsensusManifest {
                finalization: "aabbcc".to_string(),
            })
        );
    }

    #[test]
    fn write_finalization_bootstrap_decodes_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let tempo_consensus = TempoConsensusManifest {
            finalization: "000102ff".to_string(),
        };

        write_finalization_bootstrap(dir.path(), &tempo_consensus).unwrap();

        let bytes = fs::read(dir.path().join(FINALIZATION_FILE)).unwrap();
        assert_eq!(bytes, [0x00, 0x01, 0x02, 0xff]);
    }
}
