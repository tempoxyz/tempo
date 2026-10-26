use std::{
    fs, io,
    path::{Component, Path, PathBuf},
    time::Instant,
};

use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, OptionExt, ensure};
use futures::TryStreamExt;
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::download::{
    DownloadCommand, DownloadPlanArchive,
    manifest::{OutputFileChecksum, SnapshotManifest},
};
use reth_cli_runner::CliRunner;
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_telemetry_util::display_duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::io::StreamReader;
use tracing::{error, info};
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
        let consensus_dir = args.consensus_datadir.unwrap_or_else(|| {
            let environment = args.inner.env();
            environment
                .datadir
                .clone()
                .resolve_datadir(environment.chain.chain())
                .data_dir()
                .join("consensus")
        });
        // Execution archives are unpacked at the datadir root, so they must not
        // supply local consensus metadata either.
        let mut preserved = PreservedConsensus::new(&consensus_dir)?;
        let execution_result = args.inner.execute::<tempo_node::node::TempoNode>().await;
        preserved.restore()?;
        let prepared = execution_result.wrap_err("execution layer download failed")?;

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
        let loaded_consensus = load_consensus_manifest(&prepared.manifest)?;
        install_consensus_archive(&consensus_dir, &loaded_consensus, force).await?;

        Ok(())
    })
}

/// Keeps local consensus state outside the execution archive's extraction target.
struct PreservedConsensus {
    path: PathBuf,
    backup: Option<tempfile::TempDir>,
    existed: bool,
}

impl PreservedConsensus {
    fn new(path: &Path) -> eyre::Result<Self> {
        let parent = path
            .parent()
            .ok_or_eyre("consensus directory has no parent")?;
        fs::create_dir_all(parent)?;
        let backup = tempfile::Builder::new()
            .prefix(".tempo-local-consensus-")
            .tempdir_in(parent)?;
        let existed = match path.symlink_metadata() {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "consensus directory must not be a symlink during snapshot download"
                );
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error).wrap_err("failed inspecting local consensus state"),
        };
        if existed {
            fs::rename(path, backup.path().join("consensus"))
                .wrap_err("failed preserving local consensus state")?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            backup: Some(backup),
            existed,
        })
    }

    fn restore(&mut self) -> eyre::Result<()> {
        let Some(backup) = &self.backup else {
            return Ok(());
        };
        match self.path.symlink_metadata() {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&self.path)?,
            Ok(_) => fs::remove_file(&self.path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).wrap_err("failed inspecting imported consensus state"),
        }
        if self.existed {
            fs::rename(backup.path().join("consensus"), &self.path)
                .wrap_err("failed restoring local consensus state")?;
        }
        self.backup.take();
        Ok(())
    }
}

impl Drop for PreservedConsensus {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            if let Some(backup) = self.backup.take() {
                let path = backup.keep();
                error!(%error, path = %path.display(), "failed restoring local consensus state; backup retained");
            }
        }
    }
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
    extract_zstd_tar_archive(archive_file.path(), consensus_dir, force)?;
    verify_consensus_output_files(
        consensus_dir,
        &loaded.manifest.consensus_archive.output_files,
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

fn extract_zstd_tar_archive(
    archive_path: &Path,
    target_dir: &Path,
    overwrite: bool,
) -> eyre::Result<()> {
    let file = fs::File::open(archive_path)
        .wrap_err_with(|| format!("failed to open {}", archive_path.display()))?;
    let decoder = zstd::stream::read::Decoder::new(file)?;
    let mut archive = tar::Archive::new(decoder);
    archive.set_overwrite(overwrite);
    for entry in archive
        .entries()
        .wrap_err("failed reading consensus archive entries")?
    {
        let mut entry = entry.wrap_err("failed reading consensus archive entry")?;
        let path = entry
            .path()
            .wrap_err("invalid consensus archive path")?
            .into_owned();
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "consensus snapshot links and special files are not allowed"
        );
        if kind.is_dir()
            && path
                .components()
                .all(|component| component == Component::CurDir)
        {
            continue;
        }
        validate_consensus_archive_path(&path)?;
        ensure!(
            entry
                .unpack_in(target_dir)
                .wrap_err("failed extracting consensus archive entry")?,
            "consensus archive entry escapes target directory"
        );
    }
    Ok(())
}

fn validate_consensus_archive_path(path: &Path) -> eyre::Result<()> {
    let mut components = path
        .components()
        .filter(|component| *component != Component::CurDir);
    let Some(Component::Normal(partition)) = components.next() else {
        eyre::bail!("invalid consensus snapshot path: {}", path.display());
    };
    ensure!(
        partition.to_str().is_some_and(|name| {
            tempo_consensus::storage::snapshot::is_snapshot_storage_partition(
                tempo_consensus::PARTITION_PREFIX,
                name,
            )
        }),
        "unexpected consensus snapshot partition: {}",
        partition.display()
    );
    ensure!(
        components.all(|component| matches!(component, Component::Normal(_))),
        "invalid consensus snapshot path: {}",
        path.display()
    );
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
        validate_consensus_archive_path(Path::new(&expected.path))?;
        let output_path = consensus_dir.join(&expected.path);
        let metadata = fs::metadata(&output_path).wrap_err_with(|| {
            format!(
                "failed to stat consensus archive output {}",
                output_path.display()
            )
        })?;
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

        extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap();

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
        let authentication = consensus_dir.join("engine_driver_states_metadata");
        fs::create_dir(&authentication).unwrap();
        fs::write(authentication.join("left"), b"trusted").unwrap();

        prepare_consensus_directory(&consensus_dir, true).unwrap();

        assert!(consensus_dir.is_dir());
        assert!(fs::read_dir(&consensus_dir).unwrap().next().is_none());
    }

    #[test]
    fn execution_snapshot_cannot_replace_local_consensus_state() {
        for existed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let consensus = root.path().join("consensus");
            if existed {
                fs::create_dir(&consensus).unwrap();
                fs::write(consensus.join("trusted"), b"local").unwrap();
            }
            {
                let _preserved = PreservedConsensus::new(&consensus).unwrap();
                fs::create_dir(&consensus).unwrap();
                fs::write(consensus.join("injected"), b"untrusted").unwrap();
            }
            assert!(!consensus.join("injected").exists());
            if existed {
                assert_eq!(fs::read(consensus.join("trusted")).unwrap(), b"local");
            } else {
                assert!(!consensus.exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn execution_snapshot_preservation_rejects_a_symlinked_consensus_directory() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        let consensus = root.path().join("consensus");
        std::os::unix::fs::symlink(&target, &consensus).unwrap();
        let error = PreservedConsensus::new(&consensus).err().unwrap();
        assert_eq!(
            error.to_string(),
            "consensus directory must not be a symlink during snapshot download"
        );
        assert!(
            consensus
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn snapshot_cannot_install_or_overwrite_local_authentication() {
        for force in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let name = "engine_driver_states_metadata";
            let record = root.path().join(name);
            fs::create_dir(&record).unwrap();
            fs::write(record.join("left"), b"trusted").unwrap();
            let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
            let mut builder = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(3);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("{name}/left"), &mut &b"bad"[..])
                .unwrap();
            let archive = builder.into_inner().unwrap().finish().unwrap();
            let file = write_test_archive(&archive);
            let error = extract_zstd_tar_archive(file.path(), root.path(), force).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("unexpected consensus snapshot partition: {name}")
            );
            assert_eq!(fs::read(record.join("left")).unwrap(), b"trusted");
        }
    }

    #[test]
    fn snapshot_rejects_links_into_local_authentication() {
        let root = tempfile::tempdir().unwrap();
        let encoder = zstd::Encoder::new(Vec::new(), 0).unwrap();
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header
            .set_link_name("../engine_driver_states_metadata")
            .unwrap();
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "engine-finalized-blocks-prunable-key/link",
                &mut &b""[..],
            )
            .unwrap();
        let file = write_test_archive(&builder.into_inner().unwrap().finish().unwrap());
        let error = extract_zstd_tar_archive(file.path(), root.path(), true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "consensus snapshot links and special files are not allowed"
        );
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
    fn extract_zstd_tar_archive_rejects_non_snapshot_partitions() {
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

        let error =
            extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unexpected consensus snapshot partition: new-storage-partition"
        );
        assert!(!target.path().join(partition_name).exists());
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
                "engine-finalized-blocks-prunable-key/00",
                &mut &b"abc"[..],
            )
            .unwrap();

        builder.finish().unwrap();
        let encoder = builder.into_inner().unwrap();
        let archive = encoder.finish().unwrap();
        let archive_file = write_test_archive(&archive);

        extract_zstd_tar_archive(archive_file.path(), target.path(), false).unwrap();

        assert_eq!(
            fs::read(
                target
                    .path()
                    .join("engine-finalized-blocks-prunable-key")
                    .join("00")
            )
            .unwrap(),
            b"abc"
        );
    }

    #[test]
    fn extract_zstd_tar_archive_allows_existing_directories() {
        let target = tempfile::tempdir().unwrap();
        let existing = target.path().join("engine-finalized-blocks-prunable-key");
        fs::create_dir_all(&existing).unwrap();
        fs::write(existing.join("old"), b"old").unwrap();

        let source = tempfile::tempdir().unwrap();
        let partition = source.path().join("engine-finalized-blocks-prunable-key");
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
        let partition = target.path().join("engine-finalized-blocks-prunable-key");
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
                "engine-finalized-blocks-prunable-key/00",
                &mut &b"new"[..],
            )
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
        let partition = target.path().join("engine-finalized-blocks-prunable-key");
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
                "engine-finalized-blocks-prunable-key/00",
                &mut &b"new"[..],
            )
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
}
