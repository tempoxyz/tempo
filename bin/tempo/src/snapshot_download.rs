use std::{
    collections::BTreeMap,
    fs, io,
    path::{Component, Path, PathBuf, absolute},
    time::Instant,
};

use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, OptionExt, bail, ensure};
use futures::TryStreamExt;
use reth_cli_commands::download::{
    DownloadCommand, DownloadPlanArchive,
    manifest::{OutputFileChecksum, SnapshotManifest},
};
use reth_cli_runner::CliRunner;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_consensus::storage::snapshot::is_snapshot_storage_partition;
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

    fs::create_dir_all(consensus_dir).wrap_err("failed to create consensus directory")?;

    // Keep cleanup paths consistent with tempfile's absolute staging path.
    let consensus_dir =
        absolute(consensus_dir).wrap_err("failed to resolve consensus directory")?;
    let staging = tempfile::tempdir_in(&consensus_dir)
        .wrap_err("failed to create consensus staging directory")?;

    let output_files = &loaded.manifest.consensus_archive.output_files;
    extract_zstd_tar_archive(archive_file.path(), staging.path())?;
    verify_consensus_directory(staging.path(), output_files)?;
    move_consensus_directory(staging.path(), &consensus_dir, force)?;

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

fn extract_zstd_tar_archive(archive_path: &Path, target_dir: &Path) -> eyre::Result<()> {
    let file = fs::File::open(archive_path)
        .wrap_err_with(|| format!("failed to open {}", archive_path.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file)?;
    let mut archive = tar::Archive::new(decoder);
    archive.set_overwrite(false);
    // `Archive::unpack` delegates each member to `Entry::unpack_in`, which skips
    // paths that would escape `target_dir` and validates link targets.
    archive.unpack(target_dir).wrap_err_with(|| {
        format!(
            "failed to extract consensus archive into {}",
            target_dir.display()
        )
    })
}

#[tracing::instrument(parent = None, skip_all, fields(path = %target.display(), force), err)]
fn move_consensus_directory(source: &Path, target: &Path, force: bool) -> eyre::Result<()> {
    if force && target.try_exists()? {
        info!("removing existing consensus state");
        for entry in fs::read_dir(target)? {
            let entry = entry?;
            if entry.path() == source {
                continue;
            }

            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
    }

    fs::create_dir_all(target)?;
    for partition in fs::read_dir(source)? {
        let partition = partition?;
        let destination = target.join(partition.file_name());
        match fs::create_dir(&destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => ensure!(
                fs::symlink_metadata(&destination)?.is_dir(),
                "consensus destination is not a directory: {}",
                destination.display(),
            ),
            Err(error) => return Err(error.into()),
        }
        for file in fs::read_dir(partition.path())? {
            let file = file?;
            let output_path = destination.join(file.file_name());
            tempfile::TempPath::try_from_path(file.path())?
                .persist_noclobber(&output_path)
                .map_err(|error| error.error)
                .wrap_err_with(|| format!("failed to create {}", output_path.display()))?;
        }
        fs::set_permissions(&destination, partition.metadata()?.permissions())?;
    }

    Ok(())
}

/// Verify the staged consensus archive before installing it.
///
/// Every top-level entry must be a snapshot storage partition directory holding
/// only regular files, every file must be listed in the manifest with a matching
/// size and checksum, and every listed file must be present. Structural checks
/// run before a file is hashed, and nothing here follows symlinks.
#[tracing::instrument(skip_all, fields(path = %root.display()), err)]
fn verify_consensus_directory(
    root: &Path,
    output_files: &[OutputFileChecksum],
) -> eyre::Result<()> {
    let mut expected_files = BTreeMap::new();
    for expected in output_files {
        ensure!(
            !expected.path.is_empty()
                && Path::new(&expected.path)
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "invalid consensus archive output path: {}",
            expected.path,
        );
        ensure!(
            expected_files
                .insert(PathBuf::from(&expected.path), expected)
                .is_none(),
            "duplicate consensus archive output path: {}",
            expected.path,
        );
    }

    let partitions =
        fs::read_dir(root).wrap_err_with(|| format!("failed to read {}", root.display()))?;
    for partition in partitions {
        let partition = partition?;
        let name = partition.file_name();
        let name = name.to_string_lossy();
        ensure!(
            is_snapshot_storage_partition(tempo_consensus::PARTITION_PREFIX, &name),
            "unsupported consensus snapshot partition: {name}",
        );
        ensure!(
            partition.file_type()?.is_dir(),
            "unsupported consensus snapshot file type: {name}",
        );

        let files = fs::read_dir(partition.path())
            .wrap_err_with(|| format!("failed to read consensus snapshot partition {name}"))?;
        for file in files {
            let file = file?;
            verify_consensus_output_file(root, &file, &mut expected_files).wrap_err_with(|| {
                let path = file.path();
                format!(
                    "failed to verify consensus snapshot file {}",
                    path.strip_prefix(root).unwrap_or(&path).display()
                )
            })?;
        }
    }

    if let Some(missing) = expected_files.keys().next() {
        bail!("missing consensus archive output: {}", missing.display());
    }
    ensure!(
        !output_files.is_empty(),
        "consensus archive output metadata is empty",
    );

    Ok(())
}

/// Verify one staged partition file: it must be a regular file listed in the
/// manifest with the listed size and checksum. Removes its manifest entry.
fn verify_consensus_output_file(
    root: &Path,
    file: &fs::DirEntry,
    expected_files: &mut BTreeMap<PathBuf, &OutputFileChecksum>,
) -> eyre::Result<()> {
    ensure!(file.file_type()?.is_file(), "not a regular file");
    let path = file.path();
    let expected = expected_files
        .remove(path.strip_prefix(root)?)
        .ok_or_eyre("not listed in the manifest")?;

    let size = file.metadata()?.len();
    ensure!(
        size == expected.size,
        "size mismatch: expected {}, got {size}",
        expected.size,
    );
    let actual = hash_file_blake3(&path)?;
    ensure!(
        actual.eq_ignore_ascii_case(&expected.blake3),
        "checksum mismatch: expected {}, got {actual}",
        expected.blake3,
    );
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
mod tests {
    use super::*;

    use alloy_primitives::B256;
    use clap::CommandFactory;

    fn write_test_archive(bytes: &[u8]) -> tempfile::NamedTempFile {
        let archive_file = tempfile::NamedTempFile::new().unwrap();
        fs::write(archive_file.path(), bytes).unwrap();
        archive_file
    }

    fn write_test_consensus_archive(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len().try_into().unwrap());
            builder.append_data(&mut header, path, *data).unwrap();
        }
        let archive = builder.into_inner().unwrap().finish().unwrap();
        write_test_archive(&archive)
    }

    fn loaded_test_archive(
        archive: &tempfile::NamedTempFile,
        entries: &[(&str, &[u8])],
    ) -> LoadedConsensusManifest {
        LoadedConsensusManifest {
            manifest: TempoConsensusManifest {
                execution_finalized_height: 0,
                execution_finalized_digest: B256::ZERO,
                tip_finalization_height: 0,
                tip_finalization_digest: B256::ZERO,
                anchor_finalization_height: 0,
                anchor_finalization_digest: B256::ZERO,
                consensus_archive: reth_cli_commands::download::manifest::SingleArchive {
                    file: "consensus.tar.zst".to_owned(),
                    size: archive.as_file().metadata().unwrap().len(),
                    decompressed_size: 0,
                    blake3: Some(hash_file_blake3(archive.path()).unwrap()),
                    output_files: entries
                        .iter()
                        .map(|(path, data)| OutputFileChecksum {
                            path: (*path).to_owned(),
                            size: data.len().try_into().unwrap(),
                            blake3: blake3::hash(data).to_hex().to_string(),
                        })
                        .collect(),
                },
            },
            archive_source: ConsensusArchiveSource::Path(archive.path().to_owned()),
        }
    }

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

        extract_zstd_tar_archive(archive_file.path(), target.path()).unwrap();

        assert_eq!(
            fs::read(target.path().join(partition_name).join("nested").join("00")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn move_consensus_directory_removes_existing_state_when_forced() {
        let source = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let consensus_dir = parent.path().join("consensus");
        fs::create_dir_all(consensus_dir.join("nested")).unwrap();
        fs::write(consensus_dir.join("nested").join("stale"), b"stale").unwrap();
        fs::write(consensus_dir.join("stale"), b"stale").unwrap();
        let driver = consensus_dir.join("engine_driver_states_metadata");
        fs::create_dir_all(driver.join("nested")).unwrap();
        fs::write(driver.join("nested").join("identity"), b"local identity").unwrap();

        move_consensus_directory(source.path(), &consensus_dir, true).unwrap();

        assert!(consensus_dir.is_dir());
        assert!(fs::read_dir(&consensus_dir).unwrap().next().is_none());
    }

    #[test]
    fn move_consensus_directory_preserves_existing_state_without_force() {
        let source = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let consensus_dir = parent.path().join("consensus");
        fs::create_dir_all(&consensus_dir).unwrap();
        let existing = consensus_dir.join("existing");
        fs::write(&existing, b"existing").unwrap();

        move_consensus_directory(source.path(), &consensus_dir, false).unwrap();

        assert_eq!(fs::read(existing).unwrap(), b"existing");
    }

    #[test]
    fn verify_consensus_directory_rejects_unknown_partition_names() {
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

        extract_zstd_tar_archive(archive_file.path(), target.path()).unwrap();
        let error = verify_consensus_directory(target.path(), &[]).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("unsupported consensus snapshot partition: {partition_name}")
        );
    }

    #[test]
    fn verify_consensus_directory_requires_partitions_with_only_files() {
        for nested_directory in [false, true] {
            let staging = tempfile::tempdir().unwrap();
            let partition = "engine-finalizations-by-height-metadata";
            let invalid_path = if nested_directory {
                fs::create_dir(staging.path().join(partition)).unwrap();
                let relative = format!("{partition}/nested");
                fs::create_dir(staging.path().join(&relative)).unwrap();
                relative
            } else {
                fs::write(staging.path().join(partition), b"invalid partition").unwrap();
                partition.to_owned()
            };

            let error = verify_consensus_directory(staging.path(), &[]).unwrap_err();

            let expected = if nested_directory {
                format!(
                    "failed to verify consensus snapshot file {invalid_path}: not a regular file"
                )
            } else {
                format!("unsupported consensus snapshot file type: {invalid_path}")
            };
            assert_eq!(format!("{error:#}"), expected);
        }
    }

    #[tokio::test]
    async fn install_consensus_archive_rejects_driver_storage_before_changing_destination() {
        for force in [false, true] {
            for partition in [
                "engine_driver_states_metadata",
                "ENGINE_DRIVER_states_metadata",
                "Engine_driver_states_metadata",
            ] {
                let target = tempfile::tempdir().unwrap();
                let driver = target.path().join("engine_driver_states_metadata");
                fs::create_dir_all(&driver).unwrap();
                fs::write(driver.join("identity"), b"local identity").unwrap();
                let malicious = format!("{partition}/identity");
                let entries: &[(&str, &[u8])] = &[
                    ("engine-finalizations-by-height-metadata/00", b"abc"),
                    (&malicious, b"untrusted identity"),
                ];
                let archive = write_test_consensus_archive(entries);
                let loaded = loaded_test_archive(&archive, entries);

                let error = install_consensus_archive(target.path(), &loaded, force)
                    .await
                    .unwrap_err();

                assert_eq!(
                    error.to_string(),
                    format!("unsupported consensus snapshot partition: {partition}")
                );
                assert_eq!(
                    fs::read(driver.join("identity")).unwrap(),
                    b"local identity"
                );
                assert!(
                    !target
                        .path()
                        .join("engine-finalizations-by-height-metadata")
                        .exists()
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_consensus_archive_rejects_staged_symlinks_and_redirected_driver_storage() {
        for redirect in [false, true] {
            let target = tempfile::tempdir().unwrap();
            fs::write(target.path().join("existing"), b"existing").unwrap();
            let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
            let mut builder = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder
                .append_link(
                    &mut header,
                    "engine-finalizations-by-height-metadata/alias",
                    "..",
                )
                .unwrap();
            if redirect {
                let mut header = tar::Header::new_gnu();
                header.set_size(3);
                builder
                    .append_data(
                        &mut header,
                        "engine-finalizations-by-height-metadata/alias/engine_driver_states_metadata/identity",
                        &b"bad"[..],
                    )
                    .unwrap();
            }
            let bytes = builder.into_inner().unwrap().finish().unwrap();
            let archive = write_test_archive(&bytes);
            let loaded = loaded_test_archive(&archive, &[]);

            let error = install_consensus_archive(target.path(), &loaded, true)
                .await
                .unwrap_err();

            let error = format!("{error:#}");
            let alias_error = "failed to verify consensus snapshot file engine-finalizations-by-height-metadata/alias: not a regular file";
            assert!(
                error == alias_error
                    || (redirect
                        && error
                            == "unsupported consensus snapshot partition: engine_driver_states_metadata"),
                "{error}",
            );
            assert_eq!(
                fs::read(target.path().join("existing")).unwrap(),
                b"existing"
            );
            assert!(!target.path().join("engine_driver_states_metadata").exists());
        }
    }

    #[tokio::test]
    async fn install_consensus_archive_verifies_checksums_before_clearing_destination() {
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("existing"), b"existing").unwrap();
        let output_path = "engine-finalizations-by-height-metadata/00";
        let archive = write_test_consensus_archive(&[(output_path, b"abc")]);
        let loaded = loaded_test_archive(&archive, &[(output_path, b"def")]);

        let error = install_consensus_archive(target.path(), &loaded, true)
            .await
            .unwrap_err();

        assert_eq!(
            format!("{error:#}"),
            format!(
                "failed to verify consensus snapshot file {output_path}: checksum mismatch: expected {}, got {}",
                blake3::hash(b"def").to_hex(),
                blake3::hash(b"abc").to_hex(),
            )
        );
        assert_eq!(
            fs::read(target.path().join("existing")).unwrap(),
            b"existing"
        );
        assert!(
            !target
                .path()
                .join("engine-finalizations-by-height-metadata")
                .exists()
        );
    }

    #[tokio::test]
    async fn install_consensus_archive_rejects_unlisted_files_before_clearing_destination() {
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("existing"), b"existing").unwrap();
        let declared = "engine-finalizations-by-height-metadata/00";
        let unlisted = "engine-finalizations-by-height-metadata/01";
        let archive =
            write_test_consensus_archive(&[(declared, b"abc"), (unlisted, b"unverified")]);
        let loaded = loaded_test_archive(&archive, &[(declared, b"abc")]);

        let error = install_consensus_archive(target.path(), &loaded, true)
            .await
            .unwrap_err();

        assert_eq!(
            format!("{error:#}"),
            format!(
                "failed to verify consensus snapshot file {unlisted}: not listed in the manifest"
            )
        );
        assert_eq!(
            fs::read(target.path().join("existing")).unwrap(),
            b"existing"
        );
        assert!(!target.path().join(unlisted).exists());
    }

    #[cfg(unix)]
    #[test]
    fn move_consensus_directory_preserves_blob_inode_and_allocation() {
        let target = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir_in(target.path()).unwrap();
        let output_path = "engine-finalizations-by-height-metadata/00";
        let source_path = staging.path().join(output_path);
        fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        fs::write(&source_path, b"abc").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let before = fs::metadata(&source_path).unwrap();
        fs::write(target.path().join("existing"), b"existing").unwrap();

        move_consensus_directory(staging.path(), target.path(), true).unwrap();

        let after = fs::metadata(target.path().join(output_path)).unwrap();
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&before),
            std::os::unix::fs::MetadataExt::ino(&after)
        );
        assert_eq!(
            std::os::unix::fs::MetadataExt::blocks(&before),
            std::os::unix::fs::MetadataExt::blocks(&after)
        );
        assert_eq!(before.len(), after.len());
        assert!(!source_path.exists());
        assert!(!target.path().join("existing").exists());
        assert!(staging.path().is_dir());
    }

    #[tokio::test]
    async fn install_consensus_archive_preserves_staging_for_relative_destinations() {
        let current_dir = std::env::current_dir().unwrap();
        let root = tempfile::tempdir_in(&current_dir).unwrap();
        let relative_root = root.path().strip_prefix(&current_dir).unwrap();
        let output_path = "engine-finalizations-by-height-metadata/00";
        let entries: &[(&str, &[u8])] = &[(output_path, b"abc")];
        let archive = write_test_consensus_archive(entries);
        let loaded = loaded_test_archive(&archive, entries);

        for relative in ["consensus", "./consensus", "parent/../consensus"] {
            let target = Path::new(".").join(relative_root).join(relative);
            fs::create_dir_all(&target).unwrap();
            fs::write(target.join("existing"), b"existing").unwrap();

            install_consensus_archive(&target, &loaded, true)
                .await
                .unwrap();

            assert_eq!(fs::read(target.join(output_path)).unwrap(), b"abc");
            let names: Vec<_> = fs::read_dir(&target)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(names, ["engine-finalizations-by-height-metadata"]);
        }
    }

    #[tokio::test]
    async fn install_consensus_archive_creates_destination_and_removes_staging() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("consensus");
        let output_path = "engine-finalizations-by-height-metadata/00";
        let entries: &[(&str, &[u8])] = &[(output_path, b"abc")];
        let archive = write_test_consensus_archive(entries);
        let loaded = loaded_test_archive(&archive, entries);

        install_consensus_archive(&target, &loaded, false)
            .await
            .unwrap();

        assert_eq!(fs::read(target.join(output_path)).unwrap(), b"abc");
        let names: Vec<_> = fs::read_dir(&target)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["engine-finalizations-by-height-metadata"]);
    }

    #[tokio::test]
    async fn install_consensus_archive_replaces_verified_state_when_forced() {
        let target = tempfile::tempdir().unwrap();
        let driver = target.path().join("engine_driver_states_metadata");
        fs::create_dir_all(&driver).unwrap();
        fs::write(driver.join("identity"), b"local identity").unwrap();
        let output_path = "engine-finalizations-by-height-metadata/00";
        let entries: &[(&str, &[u8])] = &[(output_path, b"abc")];
        let archive = write_test_consensus_archive(entries);
        let loaded = loaded_test_archive(&archive, entries);

        install_consensus_archive(target.path(), &loaded, true)
            .await
            .unwrap();

        assert!(!driver.exists());
        assert_eq!(fs::read(target.path().join(output_path)).unwrap(), b"abc");
    }

    #[tokio::test]
    async fn install_consensus_archive_preserves_existing_files_without_force() {
        let target = tempfile::tempdir().unwrap();
        let output_path = "engine-finalizations-by-height-metadata/00";
        let entries: &[(&str, &[u8])] = &[(output_path, b"abc")];
        let archive = write_test_consensus_archive(entries);
        let loaded = loaded_test_archive(&archive, entries);
        fs::create_dir_all(
            target
                .path()
                .join("engine-finalizations-by-height-metadata"),
        )
        .unwrap();
        fs::write(target.path().join("existing"), b"existing").unwrap();

        install_consensus_archive(target.path(), &loaded, false)
            .await
            .unwrap();
        assert_eq!(fs::read(target.path().join(output_path)).unwrap(), b"abc");
        assert_eq!(
            fs::read(target.path().join("existing")).unwrap(),
            b"existing"
        );

        let error = install_consensus_archive(target.path(), &loaded, false)
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(target.path().join(output_path)).unwrap(), b"abc");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_consensus_archive_does_not_follow_destination_symlinks() {
        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let partition = target
            .path()
            .join("engine-finalizations-by-height-metadata");
        std::os::unix::fs::symlink(outside.path(), &partition).unwrap();
        let entries: &[(&str, &[u8])] = &[("engine-finalizations-by-height-metadata/00", b"abc")];
        let archive = write_test_consensus_archive(entries);
        let loaded = loaded_test_archive(&archive, entries);

        let error = install_consensus_archive(target.path(), &loaded, false)
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "consensus destination is not a directory: {}",
                partition.display()
            )
        );
        assert!(!outside.path().join("00").exists());
    }

    #[tokio::test]
    async fn install_consensus_archive_preserves_hard_links() {
        let target = tempfile::tempdir().unwrap();
        let original = "engine-finalizations-by-height-metadata/00";
        let alias = "engine-finalizations-by-height-metadata/01";
        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        builder
            .append_data(&mut header, original, &b"abc"[..])
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        builder.append_link(&mut header, alias, original).unwrap();
        let bytes = builder.into_inner().unwrap().finish().unwrap();
        let archive = write_test_archive(&bytes);
        let loaded = loaded_test_archive(&archive, &[(original, b"abc"), (alias, b"abc")]);

        install_consensus_archive(target.path(), &loaded, false)
            .await
            .unwrap();

        assert_eq!(fs::read(target.path().join(original)).unwrap(), b"abc");
        assert_eq!(fs::read(target.path().join(alias)).unwrap(), b"abc");
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(
                &fs::metadata(target.path().join(original)).unwrap()
            ),
            std::os::unix::fs::MetadataExt::ino(&fs::metadata(target.path().join(alias)).unwrap()),
        );
    }

    #[tokio::test]
    async fn install_consensus_archive_round_trips_gnu_sparse_file() {
        const HOLE_SIZE: usize = 64 * 1024 * 1024;
        const FILE_SIZE: usize = HOLE_SIZE + 3;

        let target = tempfile::tempdir().unwrap();
        let output_path = "engine-finalizations-by-height-metadata/00";
        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_size(3);
        let gnu = header.as_gnu_mut().unwrap();
        gnu.set_real_size(FILE_SIZE.try_into().unwrap());
        gnu.sparse[0].set_offset(HOLE_SIZE.try_into().unwrap());
        gnu.sparse[0].set_length(3);
        builder
            .append_data(&mut header, output_path, &b"abc"[..])
            .unwrap();
        let archive = builder.into_inner().unwrap().finish().unwrap();
        let archive_file = write_test_archive(&archive);
        let mut contents = vec![0; FILE_SIZE];
        contents[HOLE_SIZE..].copy_from_slice(b"abc");
        let loaded = loaded_test_archive(&archive_file, &[(output_path, &contents)]);
        let reference = tempfile::tempdir().unwrap();
        extract_zstd_tar_archive(archive_file.path(), reference.path()).unwrap();

        install_consensus_archive(target.path(), &loaded, false)
            .await
            .unwrap();

        let restored = fs::read(target.path().join(output_path)).unwrap();
        assert_eq!(restored.len(), FILE_SIZE);
        assert!(restored[..HOLE_SIZE].iter().all(|&byte| byte == 0));
        assert_eq!(&restored[HOLE_SIZE..], b"abc");
        #[cfg(unix)]
        assert!(
            std::os::unix::fs::MetadataExt::blocks(
                &fs::metadata(target.path().join(output_path)).unwrap()
            ) <= std::os::unix::fs::MetadataExt::blocks(
                &fs::metadata(reference.path().join(output_path)).unwrap()
            ),
            "installation must preserve the archive's sparse allocation",
        );
    }

    #[tokio::test]
    async fn install_consensus_archive_accepts_pax_global_and_contiguous_entries() {
        let target = tempfile::tempdir().unwrap();
        let output_path = "engine-finalizations-by-height-metadata/00";
        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::XGlobalHeader);
        header.set_size(13);
        builder
            .append_data(&mut header, "pax_global_header", &b"13 comment=x\n"[..])
            .unwrap();
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Continuous);
        header.set_size(3);
        builder
            .append_data(&mut header, output_path, &b"abc"[..])
            .unwrap();
        let archive = builder.into_inner().unwrap().finish().unwrap();
        let archive_file = write_test_archive(&archive);
        let loaded = loaded_test_archive(&archive_file, &[(output_path, b"abc")]);

        install_consensus_archive(target.path(), &loaded, false)
            .await
            .unwrap();

        assert_eq!(fs::read(target.path().join(output_path)).unwrap(), b"abc");
        assert!(!target.path().join("pax_global_header").exists());
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
            .append_data(
                &mut header,
                "engine-finalizations-by-height-metadata/00",
                &mut &b"abc"[..],
            )
            .unwrap();

        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        extract_zstd_tar_archive(archive_file.path(), target.path()).unwrap();

        assert_eq!(
            fs::read(
                target
                    .path()
                    .join("engine-finalizations-by-height-metadata")
                    .join("00")
            )
            .unwrap(),
            b"abc"
        );
    }

    #[test]
    fn extract_zstd_tar_archive_allows_existing_directories() {
        let target = tempfile::tempdir().unwrap();
        let existing = target
            .path()
            .join("engine-finalizations-by-height-metadata");
        fs::create_dir_all(&existing).unwrap();
        fs::write(existing.join("old"), b"old").unwrap();

        let source = tempfile::tempdir().unwrap();
        let partition = source
            .path()
            .join("engine-finalizations-by-height-metadata");
        fs::create_dir_all(&partition).unwrap();
        fs::write(partition.join("00"), b"new").unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        builder.append_dir_all("", source.path()).unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        extract_zstd_tar_archive(archive_file.path(), target.path()).unwrap();
        assert_eq!(fs::read(existing.join("old")).unwrap(), b"old");
        assert_eq!(fs::read(existing.join("00")).unwrap(), b"new");
    }

    #[test]
    fn extract_zstd_tar_archive_refuses_to_overwrite_existing_file() {
        let target = tempfile::tempdir().unwrap();
        let partition = target
            .path()
            .join("engine-finalizations-by-height-metadata");
        fs::create_dir_all(&partition).unwrap();
        let existing = partition.join("00");
        fs::write(&existing, b"old").unwrap();

        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "engine-finalizations-by-height-metadata/00",
                &mut &b"new"[..],
            )
            .unwrap();
        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        assert!(extract_zstd_tar_archive(archive_file.path(), target.path()).is_err());
        assert_eq!(fs::read(existing).unwrap(), b"old");
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
    fn verify_consensus_directory_accepts_matching_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = "engine-finalized-blocks-prunable-key/00";
        let file_path = dir.path().join(output_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, b"abc").unwrap();

        verify_consensus_directory(
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
    fn verify_consensus_directory_rejects_paths_outside_staging() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["../outside", "/outside", "", "."] {
            let error = verify_consensus_directory(
                dir.path(),
                &[OutputFileChecksum {
                    path: path.to_owned(),
                    size: 0,
                    blake3: blake3::hash(b"").to_hex().to_string(),
                }],
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("invalid consensus archive output path: {path}")
            );
        }
    }

    #[test]
    fn verify_consensus_directory_rejects_empty_metadata() {
        let dir = tempfile::tempdir().unwrap();

        assert!(verify_consensus_directory(dir.path(), &[]).is_err());
    }

    #[test]
    fn verify_consensus_directory_rejects_missing_and_duplicate_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let present = "engine-finalized-blocks-prunable-key/00";
        let missing = "engine-finalized-blocks-prunable-key/01";
        fs::create_dir_all(dir.path().join("engine-finalized-blocks-prunable-key")).unwrap();
        fs::write(dir.path().join(present), b"abc").unwrap();
        let output = |path: &str| OutputFileChecksum {
            path: path.to_owned(),
            size: 3,
            blake3: blake3::hash(b"abc").to_hex().to_string(),
        };

        let error = verify_consensus_directory(dir.path(), &[output(present), output(missing)])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("missing consensus archive output: {missing}")
        );

        let error = verify_consensus_directory(dir.path(), &[output(present), output(present)])
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("duplicate consensus archive output path: {present}")
        );
    }

    #[test]
    fn verify_consensus_directory_rejects_mismatched_size() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = "engine-finalized-blocks-prunable-key/00";
        let file_path = dir.path().join(output_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, b"abc").unwrap();

        assert!(
            verify_consensus_directory(
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
    fn verify_consensus_directory_rejects_mismatched_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let output_path = "engine-finalized-blocks-prunable-key/00";
        let file_path = dir.path().join(output_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, b"abc").unwrap();

        assert!(
            verify_consensus_directory(
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
}
