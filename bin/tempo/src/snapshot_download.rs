use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path, PathBuf},
    time::Instant,
};

use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, OptionExt, bail, ensure};
use futures::TryStreamExt;
use reth_cli_commands::download::{DownloadCommand, manifest::OutputFileChecksum};
use reth_cli_runner::CliRunner;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_telemetry_util::display_duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::io::StreamReader;
use tracing::info;
use url::Url;

use crate::snapshot_manifest::{
    CONSENSUS_ARCHIVE_ROOT, TEMPO_CONSENSUS_MANIFEST_KEY, TempoConsensusManifest,
};

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
        hide = true,
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
    let (archive_file, actual_archive_hash) =
        write_consensus_archive_to_temp(&loaded.archive_source).await?;

    if let Some(expected) = &loaded.manifest.consensus_archive.blake3 {
        let actual_archive_hash = actual_archive_hash.to_hex().to_string();
        ensure!(
            &actual_archive_hash == expected,
            "consensus archive checksum mismatch: expected {expected}, got {actual_archive_hash}",
        );
    }

    fs::create_dir_all(consensus_dir)
        .wrap_err_with(|| format!("failed to create {}", consensus_dir.display()))?;
    let partitions = consensus_archive_storage_partitions(archive_file.path())?;
    clear_consensus_partitions(consensus_dir, &partitions)?;
    extract_zstd_tar_archive(archive_file.path(), consensus_dir)?;
    verify_consensus_output_files(
        consensus_dir,
        &loaded.manifest.consensus_archive.output_files,
    )?;

    info!("persisted consensus archive");
    Ok(())
}

async fn write_consensus_archive_to_temp(
    source: &ConsensusArchiveSource,
) -> eyre::Result<(tempfile::NamedTempFile, blake3::Hash)> {
    let archive_file =
        tempfile::NamedTempFile::new().wrap_err("failed to create temporary consensus archive")?;
    let writer = archive_file
        .as_file()
        .try_clone()
        .wrap_err("failed to open temporary consensus archive")?;
    let writer = tokio::fs::File::from_std(writer);

    let hash = match source {
        ConsensusArchiveSource::Path(path) => {
            let reader = tokio::fs::File::open(path)
                .await
                .wrap_err_with(|| format!("failed to open consensus archive {}", path.display()))?;
            hash_and_write_stream(reader, writer)
                .await
                .wrap_err_with(|| format!("failed to copy consensus archive {}", path.display()))?
        }
        ConsensusArchiveSource::Url(url) => {
            let client = reqwest::Client::new();
            let resp = client
                .get(url)
                .send()
                .await
                .wrap_err("failed to fetch consensus archive")?
                .error_for_status()
                .wrap_err("invalid response from consensus archive url")?;

            let reader = StreamReader::new(resp.bytes_stream().map_err(io::Error::other));
            hash_and_write_stream(reader, writer)
                .await
                .wrap_err("failed reading consensus archive body")?
        }
    };

    Ok((archive_file, hash))
}

async fn hash_and_write_stream<R, W>(reader: R, writer: W) -> eyre::Result<blake3::Hash>
where
    R: AsyncRead,
    W: AsyncWrite,
{
    tokio::pin!(reader);
    tokio::pin!(writer);

    let mut hasher = blake3::Hasher::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = reader
            .as_mut()
            .read(&mut buf)
            .await
            .wrap_err("failed reading consensus archive")?;
        if n == 0 {
            break;
        }

        hasher.update(&buf[..n]);
        writer
            .as_mut()
            .write_all(&buf[..n])
            .await
            .wrap_err("failed writing temporary consensus archive")?;
    }

    writer
        .as_mut()
        .flush()
        .await
        .wrap_err("failed to flush temporary consensus archive")?;

    Ok(hasher.finalize())
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

fn consensus_archive_storage_partitions(archive_path: &Path) -> eyre::Result<BTreeSet<String>> {
    let file = fs::File::open(archive_path)
        .wrap_err_with(|| format!("failed to open {}", archive_path.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file)?;
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
        if let Some((partition, _)) = consensus_archive_entry(&entry_path, entry_type)? {
            partitions.insert(partition);
        }
    }
    Ok(partitions)
}

fn extract_zstd_tar_archive(archive_path: &Path, target_dir: &Path) -> eyre::Result<()> {
    let file = fs::File::open(archive_path)
        .wrap_err_with(|| format!("failed to open {}", archive_path.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file)?;
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
        let Some((_, output_relative)) = consensus_archive_entry(&entry_path, entry_type)? else {
            continue;
        };
        let output_relative = output_relative.to_string_lossy().to_string();
        if entry_type.is_dir() {
            let output_path = safe_output_path(target_dir, &output_relative)?;
            fs::create_dir_all(&output_path)
                .wrap_err_with(|| format!("failed to create {}", output_path.display()))?;
            continue;
        }

        ensure!(
            is_consensus_archive_file(entry_type),
            "consensus archive contains a non-file entry",
        );

        let output_path = safe_output_path(target_dir, &output_relative)
            .wrap_err_with(|| format!("path is not safe: {output_relative}"))?;
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

fn verify_consensus_output_files(
    consensus_dir: &Path,
    output_files: &[OutputFileChecksum],
) -> eyre::Result<()> {
    ensure!(
        !output_files.is_empty(),
        "consensus archive output metadata is empty",
    );

    for expected in output_files {
        let output_path = safe_output_path(consensus_dir, &expected.path)
            .wrap_err_with(|| format!("path is not safe: {}", expected.path))?;
        let metadata = fs::metadata(&output_path).wrap_err_with(|| {
            format!(
                "failed to stat consensus archive output {}",
                output_path.display()
            )
        })?;
        ensure!(
            metadata.is_file(),
            "consensus archive output is not a file: {}",
            expected.path,
        );
        ensure!(
            metadata.len() == expected.size,
            "consensus archive output size mismatch for {}: expected {}, got {}",
            expected.path,
            expected.size,
            metadata.len(),
        );

        let actual = hash_file_blake3(&output_path)?;
        ensure!(
            actual.eq_ignore_ascii_case(&expected.blake3),
            "consensus archive output checksum mismatch for {}: expected {}, got {}",
            expected.path,
            expected.blake3,
            actual,
        );
    }

    Ok(())
}

fn hash_file_blake3(path: &Path) -> eyre::Result<String> {
    let file =
        fs::File::open(path).wrap_err_with(|| format!("failed to open {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(file)
        .wrap_err_with(|| format!("failed reading {}", path.display()))?;
    Ok(hasher.finalize().to_hex().to_string())
}

fn consensus_archive_entry(
    relative: &str,
    entry_type: tar::EntryType,
) -> eyre::Result<Option<(String, PathBuf)>> {
    let path = safe_relative_path(relative)?;
    let mut components = path.components();
    let Some(Component::Normal(root)) = components.next() else {
        bail!("consensus archive entry path must not be empty");
    };
    ensure!(
        root == std::ffi::OsStr::new(CONSENSUS_ARCHIVE_ROOT),
        "consensus archive entry must be under `{CONSENSUS_ARCHIVE_ROOT}`: {relative}",
    );
    let Some(Component::Normal(partition)) = components.next() else {
        ensure!(
            entry_type.is_dir(),
            "consensus archive root entry must be a directory: {relative}",
        );
        return Ok(None);
    };
    let partition = partition.to_string_lossy().to_string();
    ensure!(
        tempo_consensus::storage::snapshot::is_snapshot_storage_partition(
            tempo_consensus::PARTITION_PREFIX,
            &partition,
        ),
        "consensus archive contains unexpected storage partition: {partition}",
    );
    let mut output_relative = PathBuf::from(&partition);
    let mut is_partition_root = true;
    for component in components {
        is_partition_root = false;
        let Component::Normal(component) = component else {
            bail!("invalid consensus archive entry path: {relative}");
        };
        output_relative.push(component);
    }
    if is_partition_root {
        ensure!(
            entry_type.is_dir(),
            "consensus archive partition entry must be a directory: {relative}",
        );
    }
    ensure!(
        entry_type.is_dir() || is_consensus_archive_file(entry_type),
        "consensus archive contains a non-file entry",
    );
    Ok(Some((partition, output_relative)))
}

fn is_consensus_archive_file(entry_type: tar::EntryType) -> bool {
    entry_type.is_file() || entry_type.is_contiguous() || entry_type.is_gnu_sparse()
}

fn safe_output_path(root: &Path, relative: &str) -> eyre::Result<PathBuf> {
    Ok(root.join(safe_relative_path(relative).wrap_err("path is not safe")?))
}

fn safe_relative_path(relative: &str) -> eyre::Result<PathBuf> {
    let path = Path::new(relative);
    ensure!(path.is_relative(), "path must be relative");

    let mut components = path.components().peekable();
    ensure!(components.peek().is_some(), "path must not be empty");

    ensure!(
        components.all(|comp| matches!(comp, Component::Normal(_))),
        "all path components must be normal (no root, ., .., etc)",
    );

    Ok(path.to_path_buf())
}

#[cfg(test)]
fn write_test_archive(bytes: &[u8]) -> tempfile::NamedTempFile {
    let archive_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(archive_file.path(), bytes).unwrap();
    archive_file
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::B256;
    use clap::CommandFactory;

    #[test]
    fn help_hides_skip_consensus_override() {
        let help = Args::command().render_long_help().to_string();

        assert!(!help.contains("--skip-consensus"));
    }

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
            .append_dir_all(CONSENSUS_ARCHIVE_ROOT, source.path())
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        extract_zstd_tar_archive(archive_file.path(), target.path()).unwrap();

        assert_eq!(
            fs::read(target.path().join(partition_name).join("nested").join("00")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn consensus_archive_entry_allows_sparse_file_entries() {
        let entry = consensus_archive_entry(
            "consensus/engine-finalizations-by-height-freezer-table/7461626c65",
            tar::EntryType::GNUSparse,
        )
        .unwrap();

        assert_eq!(
            entry,
            Some((
                "engine-finalizations-by-height-freezer-table".to_string(),
                PathBuf::from("engine-finalizations-by-height-freezer-table/7461626c65")
            ))
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
            .append_dir_all(CONSENSUS_ARCHIVE_ROOT, source.path())
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        assert!(extract_zstd_tar_archive(archive_file.path(), target.path()).is_err());
    }

    #[tokio::test]
    async fn write_consensus_archive_to_temp_copies_path_source_while_hashing() {
        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("consensus.tar.zst");
        fs::write(&source_path, b"archive").unwrap();

        let (archive_file, hash) =
            write_consensus_archive_to_temp(&ConsensusArchiveSource::Path(source_path))
                .await
                .unwrap();

        assert_eq!(fs::read(archive_file.path()).unwrap(), b"archive");
        assert_eq!(hash, blake3::hash(b"archive"));
    }

    #[test]
    fn verify_consensus_output_files_accepts_matching_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = "engine-finalized-blocks-prunable-key/nested/00";
        let file_path = dir.path().join(output_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, b"abc").unwrap();

        verify_consensus_output_files(
            dir.path(),
            &[OutputFileChecksum {
                path: output_path.to_string(),
                size: 3,
                blake3: blake3::hash(b"abc").to_hex().to_string(),
            }],
        )
        .unwrap();
    }

    #[test]
    fn verify_consensus_output_files_rejects_empty_metadata() {
        let dir = tempfile::tempdir().unwrap();

        assert!(verify_consensus_output_files(dir.path(), &[]).is_err());
    }

    #[test]
    fn verify_consensus_output_files_rejects_mismatched_size() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = "engine-finalized-blocks-prunable-key/00";
        let file_path = dir.path().join(output_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, b"abc").unwrap();

        assert!(
            verify_consensus_output_files(
                dir.path(),
                &[OutputFileChecksum {
                    path: output_path.to_string(),
                    size: 4,
                    blake3: blake3::hash(b"abc").to_hex().to_string(),
                }],
            )
            .is_err()
        );
    }

    #[test]
    fn verify_consensus_output_files_rejects_mismatched_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = "engine-finalized-blocks-prunable-key/00";
        let file_path = dir.path().join(output_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, b"abc").unwrap();

        assert!(
            verify_consensus_output_files(
                dir.path(),
                &[OutputFileChecksum {
                    path: output_path.to_string(),
                    size: 3,
                    blake3: blake3::hash(b"def").to_hex().to_string(),
                }],
            )
            .is_err()
        );
    }

    #[test]
    fn verify_consensus_output_files_rejects_unsafe_output_path() {
        let dir = tempfile::tempdir().unwrap();

        assert!(
            verify_consensus_output_files(
                dir.path(),
                &[OutputFileChecksum {
                    path: "../engine-finalized-blocks-prunable-key/00".to_string(),
                    size: 3,
                    blake3: blake3::hash(b"abc").to_hex().to_string(),
                }],
            )
            .is_err()
        );
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
