use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path, PathBuf},
    time::Instant,
};

use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, OptionExt, ensure};
use futures::TryStreamExt;
use reth_cli_commands::download::{
    DownloadCommand, DownloadPlanArchive,
    manifest::{OutputFileChecksum, SnapshotManifest},
};
use reth_cli_runner::CliRunner;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_telemetry_util::display_duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::io::StreamReader;
use tracing::info;
use url::Url;

use crate::snapshot_manifest::{TEMPO_CONSENSUS_MANIFEST_KEY, TempoConsensusManifest};

#[derive(Debug, Parser)]
#[command(
    name = "download",
    about = "Downloads snapshot archives produced by `tempo snapshot-manifest`.",
    mut_arg("force", |arg| arg.help(
        "Overwrite existing snapshot data by removing db, rocksdb, static_files, reth.toml, and the consensus directory."
    ))
)]
pub(crate) struct Args {
    #[command(flatten)]
    inner: DownloadCommand<TempoChainSpecParser>,

    /// Skip encoding consensus state. This will pass-through directly to Reth.
    #[arg(
        long,
        default_value_t = false,
        default_missing_value = "true",
        hide = true,
        num_args = 0..=1,
        require_equals = true
    )]
    skip_consensus: bool,

    /// Consensus storage directory. If not set, this will be derived from Reth's resolved data dir.
    #[arg(long = "consensus.datadir", value_name = "PATH")]
    consensus_datadir: Option<PathBuf>,
}

pub(crate) fn run_with_runner(matches: &ArgMatches, runner: CliRunner) -> eyre::Result<()> {
    let args = Args::from_arg_matches(matches).wrap_err("failed to parse args")?;

    let force = matches.get_one::<bool>("force").copied().unwrap_or(false);

    runner.block_on(async move {
        if args.inner.prints_plan_json() {
            let (mut plan, prepared) = args
                .inner
                .plan()
                .await
                .wrap_err("failed to plan execution layer download")?;

            if !args.skip_consensus {
                let loaded_consensus = load_consensus_manifest(&prepared.manifest)?;
                plan.push_archive(consensus_download_plan_archive(&loaded_consensus)?);
            }

            plan.write_json(io::stdout().lock())?;
            return Ok(());
        }

        info!("running execution layer download...");

        let start = Instant::now();
        let prepared = args
            .inner
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

        let prepared = prepared.ok_or_eyre(
            "consensus snapshots require a modular execution layer snapshot manifest",
        )?;
        let consensus_dir = args
            .consensus_datadir
            .unwrap_or_else(|| prepared.data_dir.join("consensus"));

        let loaded_consensus = load_consensus_manifest(&prepared.manifest)?;
        install_consensus_archive(&consensus_dir, &loaded_consensus, force).await?;

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

fn consensus_download_plan_archive(
    loaded: &LoadedConsensusManifest,
) -> eyre::Result<DownloadPlanArchive> {
    let archive = &loaded.manifest.consensus_archive;
    let url = match &loaded.archive_source {
        ConsensusArchiveSource::Url(url) => url.clone(),
        ConsensusArchiveSource::Path(path) => {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()
                    .wrap_err("failed to resolve current directory")?
                    .join(path)
            };
            Url::from_file_path(&path)
                .map_err(|_| eyre::eyre!("invalid consensus archive path: {}", path.display()))?
                .to_string()
        }
    };

    Ok(DownloadPlanArchive::new(
        TEMPO_CONSENSUS_MANIFEST_KEY,
        archive.file.clone(),
        url,
        archive.size,
        archive.output_size(),
        archive.blake3.clone(),
    ))
}

fn load_consensus_manifest(manifest: &SnapshotManifest) -> eyre::Result<LoadedConsensusManifest> {
    let consensus_manifest: TempoConsensusManifest = manifest
        .extensions
        .get(TEMPO_CONSENSUS_MANIFEST_KEY)
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .wrap_err("failed to parse TempoConsensusManifest extension")?
        .ok_or_eyre("missing consensus in manifest")?;

    let archive_source = resolve_consensus_archive_source(
        manifest
            .base_url
            .as_deref()
            .ok_or_eyre("missing resolved manifest base URL")?,
        &consensus_manifest.consensus_archive.file,
    )?;

    Ok(LoadedConsensusManifest {
        manifest: consensus_manifest,
        archive_source,
    })
}

fn resolve_consensus_archive_source(
    base_url: &str,
    archive_file: &str,
) -> eyre::Result<ConsensusArchiveSource> {
    ensure!(!archive_file.is_empty(), "consensus archive file is empty");

    if let Ok(url) = Url::parse(archive_file) {
        return archive_source_from_url(url);
    }

    let mut base = Url::parse(base_url).wrap_err("invalid manifest base_url")?;
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    archive_source_from_url(base.join(archive_file)?)
}

fn archive_source_from_url(url: Url) -> eyre::Result<ConsensusArchiveSource> {
    match url.scheme() {
        "http" | "https" => Ok(ConsensusArchiveSource::Url(url.to_string())),
        "file" => Ok(ConsensusArchiveSource::Path(
            url.to_file_path()
                .map_err(|_| eyre::eyre!("invalid file:// archive URL"))?,
        )),
        scheme => Err(eyre::eyre!(
            "unsupported consensus archive URL scheme: {scheme}"
        )),
    }
}

async fn install_consensus_archive(
    consensus_dir: &Path,
    loaded: &LoadedConsensusManifest,
    force: bool,
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

    prepare_consensus_directory(consensus_dir, force).wrap_err_with(|| {
        format!(
            "failed to prepare consensus directory at `{}`",
            consensus_dir.display()
        )
    })?;
    let extracted_files = extract_zstd_tar_archive(archive_file.path(), consensus_dir, force)?;
    verify_consensus_output_files(
        consensus_dir,
        &loaded.manifest.consensus_archive.output_files,
        &extracted_files,
    )?;

    info!("persisted consensus archive");
    Ok(())
}

#[tracing::instrument(
    parent = None,
    skip_all,
    fields(path = %consensus_dir.display())
)]
fn prepare_consensus_directory(consensus_dir: &Path, force: bool) -> eyre::Result<()> {
    if force && consensus_dir.try_exists()? {
        info!("removing existing consensus state");
        fs::remove_dir_all(consensus_dir)?;
    }

    fs::create_dir_all(consensus_dir)?;
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

/// Extracts the consensus archive into `target_dir` and returns the relative paths of the
/// regular files it wrote.
///
/// Only regular files and directories with plain relative paths are accepted: links and
/// special files are rejected so a snapshot cannot redirect consensus storage outside
/// `target_dir`.
fn extract_zstd_tar_archive(
    archive_path: &Path,
    target_dir: &Path,
    overwrite: bool,
) -> eyre::Result<BTreeSet<PathBuf>> {
    let file = fs::File::open(archive_path)
        .wrap_err_with(|| format!("failed to open {}", archive_path.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file)?;
    let mut archive = tar::Archive::new(decoder);
    archive.set_overwrite(overwrite);

    let mut files = BTreeSet::new();
    // Directories are unpacked last, deepest first, so a read-only directory mode does not
    // block writing its files (as `Archive::unpack` does).
    let mut directories = Vec::new();
    for entry in archive
        .entries()
        .wrap_err("failed to read consensus archive entries")?
    {
        let entry = entry.wrap_err("failed to read consensus archive entry")?;
        let path = entry
            .path()
            .wrap_err("invalid consensus archive entry path")?
            .into_owned();
        let entry_type = entry.header().entry_type();
        // `CurDir` components come from builders that prefix members with `./`.
        ensure!(
            path.components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
            "consensus archive entry has an unsafe path: {}",
            path.display(),
        );
        let relative: PathBuf = path
            .components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .collect();
        match entry_type {
            tar::EntryType::Directory => {
                directories.push((entry, path));
                continue;
            }
            // `tar::Builder` emits `GNUSparse` for files with holes by default.
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::GNUSparse => {
                ensure!(
                    relative.components().next().is_some(),
                    "consensus archive file entry has an empty path",
                );
                ensure!(
                    files.insert(relative.clone()),
                    "consensus archive contains duplicate entry {}",
                    relative.display(),
                );
            }
            other => eyre::bail!(
                "consensus archive entry {} has unsupported type {other:?}",
                path.display(),
            ),
        }
        unpack_entry_in(entry, &path, target_dir)?;
    }
    for (entry, path) in directories.into_iter().rev() {
        unpack_entry_in(entry, &path, target_dir)?;
    }
    Ok(files)
}

fn unpack_entry_in<R: io::Read>(
    mut entry: tar::Entry<'_, R>,
    path: &Path,
    target_dir: &Path,
) -> eyre::Result<()> {
    let unpacked = entry.unpack_in(target_dir).wrap_err_with(|| {
        format!(
            "failed to extract consensus archive entry {} into {}",
            path.display(),
            target_dir.display()
        )
    })?;
    ensure!(
        unpacked,
        "consensus archive entry {} escapes {}",
        path.display(),
        target_dir.display(),
    );
    Ok(())
}

/// Verifies that `extracted_files` are exactly the manifest's `output_files` and that each
/// one is a regular file under `consensus_dir` with the listed size and BLAKE3 hash.
fn verify_consensus_output_files(
    consensus_dir: &Path,
    output_files: &[OutputFileChecksum],
    extracted_files: &BTreeSet<PathBuf>,
) -> eyre::Result<()> {
    ensure!(
        !output_files.is_empty(),
        "consensus archive output metadata is empty",
    );

    let mut listed = BTreeSet::new();
    for expected in output_files {
        let relative = Path::new(&expected.path);
        ensure!(
            relative.components().next().is_some()
                && relative
                    .components()
                    .all(|c| matches!(c, Component::Normal(_))),
            "consensus archive output has an unsafe path: {}",
            expected.path,
        );
        ensure!(
            listed.insert(relative.to_path_buf()),
            "consensus archive output {} is listed twice",
            expected.path,
        );

        let output_path = consensus_dir.join(relative);
        let metadata = fs::symlink_metadata(&output_path).wrap_err_with(|| {
            format!(
                "failed to stat consensus archive output {}",
                output_path.display()
            )
        })?;
        ensure!(
            metadata.is_file(),
            "consensus archive output {} is not a regular file",
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

    if let Some(unlisted) = extracted_files.difference(&listed).next() {
        eyre::bail!(
            "consensus archive file {} is not listed in the manifest",
            unlisted.display()
        );
    }
    if let Some(missing) = listed.difference(extracted_files).next() {
        eyre::bail!(
            "consensus archive output {} was not extracted from the archive",
            missing.display()
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

#[cfg(test)]
fn write_test_archive(bytes: &[u8]) -> tempfile::NamedTempFile {
    let archive_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(archive_file.path(), bytes).unwrap();
    archive_file
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    use alloy_primitives::B256;
    use clap::CommandFactory;

    #[test]
    fn help_hides_skip_consensus_override() {
        let help = Args::command().render_long_help().to_string();

        assert!(!help.contains("--skip-consensus"));
    }

    #[test]
    fn args_defaults_to_include_consensus() {
        let args = Args::try_parse_from([
            "tempo",
            "--manifest-url",
            "https://snap/manifest.json",
            "--datadir",
            "/d",
        ])
        .unwrap();

        assert!(!args.skip_consensus);
    }

    #[test]
    fn help_documents_force_removing_consensus_directory() {
        let help = Args::command().render_long_help().to_string();

        assert!(help.contains(
            "Overwrite existing snapshot data by removing db, rocksdb, static_files, reth.toml, and the consensus directory."
        ));
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
    fn args_accepts_print_plan_json() {
        let args = Args::try_parse_from([
            "tempo",
            "--manifest-url",
            "https://snap/manifest.json",
            "--datadir",
            "/d",
            "--minimal",
            "--print-plan-json",
            "--skip-consensus=false",
        ])
        .unwrap();

        assert!(args.inner.prints_plan_json());
        assert!(!args.skip_consensus);
    }

    #[test]
    fn consensus_download_plan_archive_includes_resolved_metadata() {
        let loaded = LoadedConsensusManifest {
            manifest: TempoConsensusManifest {
                execution_finalized_height: 40,
                execution_finalized_digest: B256::with_last_byte(0x28),
                tip_finalization_height: 42,
                tip_finalization_digest: B256::with_last_byte(0x2a),
                anchor_finalization_height: 41,
                anchor_finalization_digest: B256::with_last_byte(0x29),
                consensus_archive: reth_cli_commands::download::manifest::SingleArchive {
                    file: "consensus.tar.zst".to_string(),
                    size: 12,
                    decompressed_size: 34,
                    blake3: Some("abc".to_string()),
                    output_files: Vec::new(),
                },
            },
            archive_source: ConsensusArchiveSource::Url(
                "https://snap/consensus.tar.zst".to_string(),
            ),
        };

        let archive = consensus_download_plan_archive(&loaded).unwrap();

        assert_eq!(archive.component, "consensus");
        assert_eq!(archive.file_name, "consensus.tar.zst");
        assert_eq!(archive.url, "https://snap/consensus.tar.zst");
        assert_eq!(archive.download_size, 12);
        assert_eq!(archive.output_size, 34);
        assert_eq!(archive.blake3.as_deref(), Some("abc"));
    }

    #[test]
    fn load_manifest_reads_tempo_consensus_extension_from_prepared_manifest() {
        let dir = tempfile::tempdir().unwrap();
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

        let mut prepared: SnapshotManifest = serde_json::from_slice(bytes).unwrap();
        prepared.base_url = Some(Url::from_directory_path(dir.path()).unwrap().to_string());
        let manifest = load_consensus_manifest(&prepared).unwrap();

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
    fn consensus_archive_url_resolves_relative_to_prepared_base_url() {
        let archive = resolve_consensus_archive_source(
            "https://snapshots.example.com/tempo-4217-42",
            "consensus.tar.zst",
        )
        .unwrap();

        match archive {
            ConsensusArchiveSource::Url(url) => assert_eq!(
                url,
                "https://snapshots.example.com/tempo-4217-42/consensus.tar.zst"
            ),
            ConsensusArchiveSource::Path(_) => panic!("remote manifest must resolve a URL"),
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
        builder.append_dir_all("", source.path()).unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        let files = extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap();

        assert_eq!(
            files,
            BTreeSet::from([PathBuf::from(partition_name).join("nested").join("00")])
        );
        assert_eq!(
            fs::read(target.path().join(partition_name).join("nested").join("00")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn prepare_consensus_directory_removes_existing_state_when_forced() {
        let parent = tempfile::tempdir().unwrap();
        let consensus_dir = parent.path().join("consensus");
        fs::create_dir_all(consensus_dir.join("nested")).unwrap();
        fs::write(consensus_dir.join("nested").join("stale"), b"stale").unwrap();

        prepare_consensus_directory(&consensus_dir, true).unwrap();

        assert!(consensus_dir.is_dir());
        assert!(fs::read_dir(&consensus_dir).unwrap().next().is_none());
    }

    #[test]
    fn prepare_consensus_directory_preserves_existing_state_without_force() {
        let parent = tempfile::tempdir().unwrap();
        let consensus_dir = parent.path().join("consensus");
        fs::create_dir_all(&consensus_dir).unwrap();
        let existing = consensus_dir.join("existing");
        fs::write(&existing, b"existing").unwrap();

        prepare_consensus_directory(&consensus_dir, false).unwrap();

        assert_eq!(fs::read(existing).unwrap(), b"existing");
    }

    #[test]
    fn extract_zstd_tar_archive_accepts_new_partition_names() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let partition_name = "new-storage-partition";
        let partition = source.path().join(partition_name);
        fs::create_dir_all(&partition).unwrap();
        fs::write(partition.join("00"), b"abc").unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all("", source.path()).unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap();

        assert_eq!(
            fs::read(target.path().join(partition_name).join("00")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn extract_zstd_tar_archive_installs_bare_archive_contents() {
        let target = tempfile::tempdir().unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);

        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_cksum();
        builder
            .append_data(&mut header, "partition/00", &mut &b"abc"[..])
            .unwrap();

        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        let files = extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap();

        assert_eq!(files, BTreeSet::from([PathBuf::from("partition/00")]));
        assert_eq!(
            fs::read(target.path().join("partition").join("00")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn extract_zstd_tar_archive_allows_existing_directories() {
        let target = tempfile::tempdir().unwrap();
        let existing = target.path().join("partition");
        fs::create_dir_all(&existing).unwrap();
        fs::write(existing.join("old"), b"old").unwrap();

        let source = tempfile::tempdir().unwrap();
        let partition = source.path().join("partition");
        fs::create_dir_all(&partition).unwrap();
        fs::write(partition.join("00"), b"new").unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all("", source.path()).unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap();
        assert_eq!(fs::read(existing.join("old")).unwrap(), b"old");
        assert_eq!(fs::read(existing.join("00")).unwrap(), b"new");
    }

    #[test]
    fn extract_zstd_tar_archive_refuses_to_overwrite_existing_file() {
        let target = tempfile::tempdir().unwrap();
        let existing = target.path().join("00");
        fs::write(&existing, b"old").unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_cksum();
        builder
            .append_data(&mut header, "00", &mut &b"new"[..])
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        assert!(extract_zstd_tar_archive(archive_file.path(), target.path(), false).is_err());
        assert_eq!(fs::read(existing).unwrap(), b"old");
    }

    #[test]
    fn extract_zstd_tar_archive_overwrites_existing_file_when_forced() {
        let target = tempfile::tempdir().unwrap();
        let existing = target.path().join("00");
        fs::write(&existing, b"old").unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_cksum();
        builder
            .append_data(&mut header, "00", &mut &b"new"[..])
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        extract_zstd_tar_archive(archive_file.path(), target.path(), true).unwrap();
        assert_eq!(fs::read(existing).unwrap(), b"new");
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
            &BTreeSet::from([PathBuf::from(output_path)]),
        )
        .unwrap();
    }

    #[test]
    fn verify_consensus_output_files_rejects_empty_metadata() {
        let dir = tempfile::tempdir().unwrap();

        assert!(verify_consensus_output_files(dir.path(), &[], &BTreeSet::new()).is_err());
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
                &BTreeSet::from([PathBuf::from(output_path)]),
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
                &BTreeSet::from([PathBuf::from(output_path)]),
            )
            .is_err()
        );
    }

    fn finish_test_archive(
        builder: tar::Builder<zstd::Encoder<'static, Vec<u8>>>,
    ) -> tempfile::NamedTempFile {
        let encoder = builder.into_inner().unwrap();
        write_test_archive(&encoder.finish().unwrap())
    }

    fn matching_output(dir: &Path, path: &str, contents: &[u8]) -> OutputFileChecksum {
        let file_path = dir.join(path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, contents).unwrap();
        OutputFileChecksum {
            path: path.to_string(),
            size: contents.len() as u64,
            blake3: blake3::hash(contents).to_hex().to_string(),
        }
    }

    #[test]
    fn extract_zstd_tar_archive_rejects_symlink_entries() {
        let target = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(zstd::Encoder::new(Vec::new(), 0).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        builder
            .append_link(&mut header, "partition", "../reth/db")
            .unwrap();
        let archive_file = finish_test_archive(builder);

        let err = extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap_err();

        assert_eq!(
            err.to_string(),
            "consensus archive entry partition has unsupported type Symlink"
        );
        assert!(fs::symlink_metadata(target.path().join("partition")).is_err());
    }

    #[test]
    fn extract_zstd_tar_archive_rejects_hard_link_entries() {
        let target = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(zstd::Encoder::new(Vec::new(), 0).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        builder.append_link(&mut header, "00", "01").unwrap();
        let archive_file = finish_test_archive(builder);

        let err = extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap_err();

        assert_eq!(
            err.to_string(),
            "consensus archive entry 00 has unsupported type Link"
        );
    }

    #[test]
    fn extract_zstd_tar_archive_rejects_parent_dir_entries() {
        let target = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(zstd::Encoder::new(Vec::new(), 0).unwrap());
        let mut header = tar::Header::new_gnu();
        // `Header::set_path` refuses `..`, so write the raw name.
        let name = b"../escape";
        header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name);
        header.set_size(3);
        header.set_cksum();
        builder.append(&header, &b"abc"[..]).unwrap();
        let archive_file = finish_test_archive(builder);

        let err = extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap_err();

        assert_eq!(
            err.to_string(),
            "consensus archive entry has an unsafe path: ../escape"
        );
    }

    #[test]
    fn verify_consensus_output_files_rejects_unsafe_paths() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["/dev/null", "../outside", "a/../b", "./a", ""] {
            let output = OutputFileChecksum {
                path: path.to_string(),
                size: 0,
                blake3: blake3::hash(b"").to_hex().to_string(),
            };

            let err =
                verify_consensus_output_files(dir.path(), &[output], &BTreeSet::new()).unwrap_err();

            assert_eq!(
                err.to_string(),
                format!("consensus archive output has an unsafe path: {path}")
            );
        }
    }

    #[test]
    fn verify_consensus_output_files_rejects_symlinked_output() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = matching_output(outside.path(), "00", b"abc");
        std::os::unix::fs::symlink(outside.path().join("00"), dir.path().join("00")).unwrap();

        let err = verify_consensus_output_files(
            dir.path(),
            &[target],
            &BTreeSet::from([PathBuf::from("00")]),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "consensus archive output 00 is not a regular file"
        );
    }

    #[test]
    fn verify_consensus_output_files_rejects_unlisted_extracted_file() {
        let dir = tempfile::tempdir().unwrap();
        let listed = matching_output(dir.path(), "partition/00", b"abc");
        matching_output(dir.path(), "partition/01", b"def");

        let err = verify_consensus_output_files(
            dir.path(),
            &[listed],
            &BTreeSet::from([PathBuf::from("partition/00"), PathBuf::from("partition/01")]),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "consensus archive file partition/01 is not listed in the manifest"
        );
    }

    #[test]
    fn verify_consensus_output_files_rejects_output_not_from_archive() {
        let dir = tempfile::tempdir().unwrap();
        let preexisting = matching_output(dir.path(), "partition/00", b"abc");

        let err = verify_consensus_output_files(dir.path(), &[preexisting], &BTreeSet::new())
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "consensus archive output partition/00 was not extracted from the archive"
        );
    }

    #[test]
    fn extract_zstd_tar_archive_strips_cur_dir_prefix() {
        let target = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(zstd::Encoder::new(Vec::new(), 0).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_cksum();
        builder
            .append_data(&mut header, "./partition/00", &mut &b"abc"[..])
            .unwrap();
        let archive_file = finish_test_archive(builder);

        let files = extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap();

        assert_eq!(files, BTreeSet::from([PathBuf::from("partition/00")]));
        verify_consensus_output_files(
            target.path(),
            &[OutputFileChecksum {
                path: "partition/00".to_string(),
                size: 3,
                blake3: blake3::hash(b"abc").to_hex().to_string(),
            }],
            &files,
        )
        .unwrap();
    }

    #[test]
    fn extract_zstd_tar_archive_accepts_sparse_files() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let partition = source.path().join("partition");
        fs::create_dir_all(&partition).unwrap();
        let file = fs::File::create(partition.join("00")).unwrap();
        file.set_len(1024 * 1024).unwrap();
        std::os::unix::fs::FileExt::write_at(&file, b"abc", 512 * 1024).unwrap();
        drop(file);
        let expected = fs::read(partition.join("00")).unwrap();

        let mut builder = tar::Builder::new(zstd::Encoder::new(Vec::new(), 0).unwrap());
        builder.append_dir_all("", source.path()).unwrap();
        let archive_file = finish_test_archive(builder);
        let decoder = zstd::Decoder::new(fs::File::open(archive_file.path()).unwrap()).unwrap();
        assert!(
            tar::Archive::new(decoder)
                .entries()
                .unwrap()
                .any(|e| e.unwrap().header().entry_type() == tar::EntryType::GNUSparse),
            "filesystem did not produce a sparse entry",
        );

        let files = extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap();

        assert_eq!(files, BTreeSet::from([PathBuf::from("partition/00")]));
        assert_eq!(
            fs::read(target.path().join("partition/00")).unwrap(),
            expected
        );
    }

    #[test]
    fn extract_zstd_tar_archive_applies_read_only_directory_mode_after_files() {
        let target = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(zstd::Encoder::new(Vec::new(), 0).unwrap());
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_mode(0o555);
        dir.set_size(0);
        builder
            .append_data(&mut dir, "partition", io::empty())
            .unwrap();
        let mut file = tar::Header::new_gnu();
        file.set_mode(0o644);
        file.set_size(3);
        builder
            .append_data(&mut file, "partition/00", &mut &b"abc"[..])
            .unwrap();
        let archive_file = finish_test_archive(builder);

        let result = extract_zstd_tar_archive(archive_file.path(), target.path(), false);
        let partition = target.path().join("partition");
        let mode = fs::metadata(&partition).map(|m| m.permissions().mode() & 0o777);
        // Let the tempdir clean up.
        fs::set_permissions(&partition, fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            result.unwrap(),
            BTreeSet::from([PathBuf::from("partition/00")])
        );
        assert_eq!(fs::read(partition.join("00")).unwrap(), b"abc");
        assert_eq!(mode.unwrap(), 0o555);
    }
}
