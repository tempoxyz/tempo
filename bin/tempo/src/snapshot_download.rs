use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, OptionExt, bail};
use reth_cli_commands::download::DownloadCommand;
use reth_cli_runner::CliRunner;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_telemetry_util::display_duration;
use tracing::info;

use crate::snapshot_manifest::{TEMPO_CONSENSUS_MANIFEST_KEY, TempoConsensusManifest};

const BOOTSTRAP_FINALIZATION_FILE: &str = "bootstrap/finalization.cert";

#[derive(Debug, Parser)]
#[command(
    name = "download",
    about = "Downloads snapshot archives produced by `tempo snapshot-manifest`."
)]
pub(crate) struct Args {
    #[command(flatten)]
    inner: DownloadCommand<TempoChainSpecParser>,

    /// Skip encoding consensus state. This will pass-through directly to Reth.
    #[arg(
        long,
        default_value_t = true,
        default_missing_value = "true",
        num_args = 0..=1,
        require_equals = true
    )]
    skip_consensus: bool,

    /// Consensus storage directory. If not set, this will be derived from --datadir.
    #[arg(long = "consensus.datadir", value_name = "PATH")]
    consensus_datadir: Option<PathBuf>,
}

pub(crate) fn run_with_runner(matches: &ArgMatches, runner: CliRunner) -> eyre::Result<()> {
    let args = Args::from_arg_matches(matches).wrap_err("failed to parse args")?;

    let datadir = matches
        .get_raw("datadir")
        .and_then(|mut v| v.next())
        .map(PathBuf::from)
        .expect("--datadir must be set");

    let manifest_url = matches.get_one::<String>("manifest_url").cloned();
    let manifest_path = matches.get_one::<PathBuf>("manifest_path").cloned();

    runner.block_on(async move {
        info!("running execution layer download...");

        let start = Instant::now();
        args.inner
            .execute::<tempo_node::node::TempoNode>()
            .await
            .wrap_err("execution layer download failed")?;

        info!(
            "execution layer download finished in {}",
            display_duration(start.elapsed())
        );

        if args.skip_consensus {
            info!("--skip-consensus set. skipping consensus layer");
            return Ok(());
        }

        let consensus_dir = args
            .consensus_datadir
            .unwrap_or_else(|| datadir.join("consensus"));

        let consensus_manifest = load_consensus_manifest(manifest_url, manifest_path).await?;
        write_bootstrap_finalization(&consensus_dir, &consensus_manifest)?;

        Ok(())
    })
}

async fn load_consensus_manifest(
    manifest_url: Option<String>,
    manifest_path: Option<PathBuf>,
) -> eyre::Result<TempoConsensusManifest> {
    let manifest_bytes = match (manifest_path, (manifest_url)) {
        (None, None) => bail!("--manifest-url or --manifest-path must be set"),
        (Some(path), _) => fs::read(path).wrap_err("failed to read manifest file")?,
        (_, Some(url)) => {
            let client = reqwest::Client::new();
            let resp = client
                .get(url)
                .send()
                .await
                .wrap_err("failed to fetch from manifest url")?
                .error_for_status()
                .wrap_err("invalid response from manifest url")?;

            resp.bytes()
                .await
                .wrap_err("failed to parse manifest from url")?
                .to_vec()
        }
    };

    let value: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).wrap_err("failed to parse manifest.json")?;

    let consensus_manifest = value
        .get(TEMPO_CONSENSUS_MANIFEST_KEY)
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .wrap_err("failed to parse TempoConsensusManifest extension")?
        .ok_or_eyre("missing consensus in manifest")?;

    Ok(consensus_manifest)
}

fn write_bootstrap_finalization(
    consensus_dir: &Path,
    consensus_manifest: &TempoConsensusManifest,
) -> eyre::Result<()> {
    let path = consensus_dir.join(BOOTSTRAP_FINALIZATION_FILE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create dir: {}", parent.display()))?;
    }

    fs::write(&path, consensus_manifest.finalization.as_ref())
        .wrap_err_with(|| format!("failed to write finalization to {}", path.display()))?;

    info!(path = %path.display(), "persisted bootstrap finalization");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes};

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
    fn args_accepts_explicit_skip_consensus_false() {
        let args = Args::try_parse_from([
            "tempo",
            "--manifest-url",
            "https://snap/manifest.json",
            "--datadir",
            "/d",
            "--skip-consensus=false",
        ])
        .unwrap();

        assert!(!args.skip_consensus);
    }

    #[test]
    fn load_manifest_reads_tempo_consensus_extension_from_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let bytes = br#"{
            "block": 42,
            "chain_id": 1,
            "storage_version": 2,
            "timestamp": 0,
            "components": {},
            "consensus": {
                "height": 42,
                "digest": "0x000000000000000000000000000000000000000000000000000000000000002a",
                "finalization": "0xaabbcc"
            }
        }"#;

        fs::write(&path, bytes).unwrap();

        let manifest =
            futures::executor::block_on(load_consensus_manifest(None, Some(path))).unwrap();

        assert_eq!(manifest.height, 42);
        assert_eq!(manifest.digest, B256::with_last_byte(0x2a));
        assert_eq!(manifest.finalization, Bytes::from(vec![0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn write_finalization_writes_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let tempo_consensus = TempoConsensusManifest {
            height: 42,
            digest: B256::with_last_byte(0x2a),
            finalization: Bytes::from(vec![0x00, 0x01, 0x02, 0xff]),
        };

        write_bootstrap_finalization(dir.path(), &tempo_consensus).unwrap();

        let bytes = fs::read(dir.path().join(BOOTSTRAP_FINALIZATION_FILE)).unwrap();
        assert_eq!(bytes, [0x00, 0x01, 0x02, 0xff]);
    }
}
