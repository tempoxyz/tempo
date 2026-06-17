use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
    time::Instant,
};

use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, OptionExt, bail, ensure};
use reth_cli_commands::download::DownloadCommand;
use reth_cli_runner::CliRunner;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_telemetry_util::display_duration;
use tracing::info;
use url::Url;

use crate::snapshot_manifest::{TEMPO_CONSENSUS_MANIFEST_KEY, TempoConsensusManifest};

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

        let loaded_consensus = load_consensus_manifest(manifest_url, manifest_path).await?;
        install_consensus_archive(&consensus_dir, &loaded_consensus).await?;

        Ok(())
    })
}

struct LoadedConsensusManifest {
    manifest: TempoConsensusManifest,
    archive_source: ConsensusArchiveSource,
}

enum ConsensusArchiveSource {
    Url(String),
    Path(PathBuf),
}

enum ManifestSource {
    Url(String),
    Path(PathBuf),
}

async fn load_consensus_manifest(
    manifest_url: Option<String>,
    manifest_path: Option<PathBuf>,
) -> eyre::Result<LoadedConsensusManifest> {
    let (manifest_bytes, source) = match (manifest_path, manifest_url) {
        (None, None) => bail!("--manifest-url or --manifest-path must be set"),
        (Some(path), _) => (
            fs::read(&path).wrap_err("failed to read manifest file")?,
            ManifestSource::Path(path),
        ),
        (_, Some(source)) => fetch_manifest_bytes_from_source(source).await?,
    };

    let value: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).wrap_err("failed to parse manifest.json")?;

    let consensus_manifest: TempoConsensusManifest = value
        .get(TEMPO_CONSENSUS_MANIFEST_KEY)
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .wrap_err("failed to parse TempoConsensusManifest extension")?
        .ok_or_eyre("missing consensus in manifest")?;

    let archive_source = resolve_consensus_archive_source(
        &value,
        &source,
        &consensus_manifest.consensus_archive.file,
    )?;

    Ok(LoadedConsensusManifest {
        manifest: consensus_manifest,
        archive_source,
    })
}

async fn fetch_manifest_bytes_from_source(
    source: String,
) -> eyre::Result<(Vec<u8>, ManifestSource)> {
    if let Ok(url) = Url::parse(&source) {
        return match url.scheme() {
            "http" | "https" => {
                let client = reqwest::Client::new();
                let resp = client
                    .get(source.clone())
                    .send()
                    .await
                    .wrap_err("failed to fetch from manifest url")?
                    .error_for_status()
                    .wrap_err("invalid response from manifest url")?;

                let bytes = resp
                    .bytes()
                    .await
                    .wrap_err("failed to parse manifest from url")?
                    .to_vec();
                Ok((bytes, ManifestSource::Url(source)))
            }
            "file" => {
                let path = url
                    .to_file_path()
                    .map_err(|_| eyre::eyre!("invalid file:// manifest path: {source}"))?;
                let bytes = fs::read(&path).wrap_err("failed to read manifest file")?;
                Ok((bytes, ManifestSource::Path(path)))
            }
            scheme => bail!("unsupported manifest URL scheme: {scheme}"),
        };
    }

    let path = PathBuf::from(&source);
    let bytes = fs::read(&path).wrap_err("failed to read manifest file")?;
    Ok((bytes, ManifestSource::Path(path)))
}

fn resolve_consensus_archive_source(
    manifest_json: &serde_json::Value,
    source: &ManifestSource,
    archive_file: &str,
) -> eyre::Result<ConsensusArchiveSource> {
    ensure!(!archive_file.is_empty(), "consensus archive file is empty");

    if let Ok(url) = Url::parse(archive_file) {
        return archive_source_from_url(url);
    }

    if let Some(base_url) = manifest_json
        .get("base_url")
        .and_then(serde_json::Value::as_str)
        && !base_url.is_empty()
    {
        let mut base = Url::parse(base_url).wrap_err("invalid manifest base_url")?;
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        return archive_source_from_url(base.join(archive_file)?);
    }

    match source {
        ManifestSource::Url(manifest_url) => {
            let mut base = Url::parse(manifest_url)?;
            match base.scheme() {
                "http" | "https" => {
                    {
                        let mut segments = base.path_segments_mut().map_err(|_| {
                            eyre::eyre!("manifest URL must have a hierarchical path")
                        })?;
                        segments.pop_if_empty();
                        segments.pop();
                    }
                    archive_source_from_url(base.join(archive_file)?)
                }
                "file" => {
                    let mut path = base
                        .to_file_path()
                        .map_err(|_| eyre::eyre!("invalid file:// manifest path"))?;
                    path.pop();
                    Ok(ConsensusArchiveSource::Path(path.join(archive_file)))
                }
                scheme => bail!("unsupported manifest URL scheme: {scheme}"),
            }
        }
        ManifestSource::Path(manifest_path) => {
            let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
            Ok(ConsensusArchiveSource::Path(
                manifest_dir.join(archive_file),
            ))
        }
    }
}

fn archive_source_from_url(url: Url) -> eyre::Result<ConsensusArchiveSource> {
    match url.scheme() {
        "http" | "https" => Ok(ConsensusArchiveSource::Url(url.to_string())),
        "file" => Ok(ConsensusArchiveSource::Path(
            url.to_file_path()
                .map_err(|_| eyre::eyre!("invalid file:// archive URL"))?,
        )),
        scheme => bail!("unsupported consensus archive URL scheme: {scheme}"),
    }
}

async fn install_consensus_archive(
    consensus_dir: &Path,
    loaded: &LoadedConsensusManifest,
) -> eyre::Result<()> {
    let archive_bytes = match &loaded.archive_source {
        ConsensusArchiveSource::Path(path) => fs::read(path)
            .wrap_err_with(|| format!("failed to read consensus archive {}", path.display()))?,
        ConsensusArchiveSource::Url(url) => {
            let client = reqwest::Client::new();
            client
                .get(url)
                .send()
                .await
                .wrap_err("failed to fetch consensus archive")?
                .error_for_status()
                .wrap_err("invalid response from consensus archive url")?
                .bytes()
                .await
                .wrap_err("failed reading consensus archive body")?
                .to_vec()
        }
    };

    if let Some(expected) = &loaded.manifest.consensus_archive.blake3 {
        let actual = blake3::hash(&archive_bytes).to_hex().to_string();
        ensure!(
            &actual == expected,
            "consensus archive checksum mismatch: expected {expected}, got {actual}",
        );
    }

    fs::create_dir_all(consensus_dir)
        .wrap_err_with(|| format!("failed to create {}", consensus_dir.display()))?;
    let partitions = consensus_archive_storage_partitions(&archive_bytes)?;
    clear_consensus_partitions(consensus_dir, &partitions)?;
    extract_zstd_tar_archive(&archive_bytes, consensus_dir)?;

    info!("persisted consensus archive");
    Ok(())
}

fn clear_consensus_partitions(
    consensus_dir: &Path,
    partitions: &BTreeSet<String>,
) -> eyre::Result<()> {
    for partition in partitions {
        let path = safe_output_path(consensus_dir, partition)?;
        if !path.exists() {
            continue;
        }
        let meta =
            fs::metadata(&path).wrap_err_with(|| format!("failed to stat {}", path.display()))?;
        if meta.is_dir() {
            fs::remove_dir_all(&path)
                .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
        } else {
            fs::remove_file(&path)
                .wrap_err_with(|| format!("failed to remove {}", path.display()))?;
        }
    }
    Ok(())
}

fn consensus_archive_storage_partitions(bytes: &[u8]) -> eyre::Result<BTreeSet<String>> {
    let decoder = zstd::stream::read::Decoder::new(bytes)?;
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .wrap_err("failed to read consensus archive")?;
    let mut partitions = BTreeSet::new();
    for entry in entries {
        let entry = entry.wrap_err("failed to read consensus archive entry")?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .wrap_err("failed reading consensus archive entry path")?
            .to_string_lossy()
            .to_string();
        partitions.insert(consensus_archive_partition(&entry_path, entry_type)?);
    }
    Ok(partitions)
}

fn extract_zstd_tar_archive(bytes: &[u8], target_dir: &Path) -> eyre::Result<()> {
    let decoder = zstd::stream::read::Decoder::new(bytes)?;
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .wrap_err("failed to read consensus archive")?;
    for entry in entries {
        let mut entry = entry.wrap_err("failed to read consensus archive entry")?;
        let entry_type = entry.header().entry_type();

        let entry_path = entry
            .path()
            .wrap_err("failed reading consensus archive entry path")?
            .to_string_lossy()
            .to_string();
        consensus_archive_partition(&entry_path, entry_type)?;
        if entry_type.is_dir() {
            let output_path = safe_output_path(target_dir, &entry_path)?;
            fs::create_dir_all(&output_path)
                .wrap_err_with(|| format!("failed to create {}", output_path.display()))?;
            continue;
        }

        ensure!(
            entry_type.is_file(),
            "consensus archive contains a non-file entry",
        );

        let output_path = safe_output_path(target_dir, &entry_path)?;
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
        }
        entry
            .unpack(&output_path)
            .wrap_err_with(|| format!("failed to extract {}", output_path.display()))?;
    }
    Ok(())
}

fn consensus_archive_partition(relative: &str, entry_type: tar::EntryType) -> eyre::Result<String> {
    let path = safe_relative_path(relative)?;
    let mut components = path.components();
    let Some(Component::Normal(partition)) = components.next() else {
        bail!("consensus archive entry path must not be empty");
    };
    let partition = partition.to_string_lossy().to_string();
    ensure!(
        tempo_consensus::storage::snapshot::is_snapshot_storage_partition(&partition),
        "consensus archive contains unexpected storage partition: {partition}",
    );
    if components.next().is_none() {
        ensure!(
            entry_type.is_dir(),
            "consensus archive partition entry must be a directory: {relative}",
        );
    }
    ensure!(
        entry_type.is_dir() || entry_type.is_file(),
        "consensus archive contains a non-file entry",
    );
    Ok(partition)
}

fn safe_output_path(root: &Path, relative: &str) -> eyre::Result<PathBuf> {
    Ok(root.join(safe_relative_path(relative)?))
}

fn safe_relative_path(relative: &str) -> eyre::Result<PathBuf> {
    let path = Path::new(relative);
    ensure!(
        path.is_relative(),
        "consensus archive output path must be relative: {relative}"
    );
    ensure!(
        path.components().next().is_some(),
        "consensus archive output path must not be empty"
    );
    for component in path.components() {
        ensure!(
            matches!(component, Component::Normal(_)),
            "invalid consensus archive output path: {relative}",
        );
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

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
                "execution_finalized_height": 40,
                "execution_finalized_digest": "0x0000000000000000000000000000000000000000000000000000000000000028",
                "tip_finalization_height": 42,
                "tip_finalization_digest": "0x000000000000000000000000000000000000000000000000000000000000002a",
                "anchor_finalization_height": 41,
                "anchor_finalization_digest": "0x0000000000000000000000000000000000000000000000000000000000000029",
                "consensus_archive": {
                    "file": "consensus.tar.zst",
                    "size": 0,
                    "output_files": []
                }
            }
        }"#;

        fs::write(&path, bytes).unwrap();

        let manifest =
            futures::executor::block_on(load_consensus_manifest(None, Some(path))).unwrap();

        assert_eq!(manifest.manifest.execution_finalized_height, 40);
        assert_eq!(manifest.manifest.tip_finalization_height, 42);
        assert_eq!(
            manifest.manifest.tip_finalization_digest,
            B256::with_last_byte(0x2a)
        );
        assert_eq!(manifest.manifest.anchor_finalization_height, 41);
        assert_eq!(
            manifest.manifest.anchor_finalization_digest,
            B256::with_last_byte(0x29)
        );
        match manifest.archive_source {
            ConsensusArchiveSource::Path(archive_path) => {
                assert_eq!(archive_path, dir.path().join("consensus.tar.zst"));
            }
            ConsensusArchiveSource::Url(_) => panic!("local manifest must resolve local archive"),
        }
    }

    #[test]
    fn extract_zstd_tar_archive_allows_partition_directory_entries() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let partition_name = "engine-finalized-blocks-prunable-key";
        let partition = source.path().join(partition_name).join("nested");
        fs::create_dir_all(&partition).unwrap();
        fs::write(partition.join("00"), b"abc").unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        builder
            .append_dir_all(partition_name, source.path().join(partition_name))
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();

        extract_zstd_tar_archive(&archive, target.path()).unwrap();

        assert_eq!(
            fs::read(target.path().join(partition_name).join("nested").join("00")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn extract_zstd_tar_archive_rejects_unexpected_partition() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let partition = source.path().join("unexpected-partition");
        fs::create_dir_all(&partition).unwrap();
        fs::write(partition.join("00"), b"abc").unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        builder
            .append_dir_all("unexpected-partition", &partition)
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();

        assert!(extract_zstd_tar_archive(&archive, target.path()).is_err());
    }

    #[test]
    fn safe_output_path_rejects_unsafe_paths() {
        let dir = tempfile::tempdir().unwrap();

        assert!(safe_output_path(dir.path(), "").is_err());
        assert!(safe_output_path(dir.path(), ".").is_err());
        assert!(safe_output_path(dir.path(), "../partition").is_err());
        assert!(safe_output_path(dir.path(), "/partition").is_err());
        assert!(safe_output_path(dir.path(), "partition/00").is_ok());
    }
}
