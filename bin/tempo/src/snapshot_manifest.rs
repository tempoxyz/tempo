use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Instant,
};

use alloy_primitives::B256;
use clap::{ArgMatches, FromArgMatches, Parser};
use commonware_runtime::Runner as _;
use eyre::{Context as _, OptionExt, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::download::{
    manifest::{OutputFileChecksum, SingleArchive, SnapshotManifest},
    manifest_cmd::SnapshotManifestCommand,
};
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_provider::providers::{BlockchainProvider, ReadOnlyConfig};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tempo_chainspec::spec::{TempoChainSpec, chain_value_parser, chainspec_from_chain_id};
use tempo_node::node::TempoNode;
use tempo_telemetry_util::display_duration;

pub(crate) const TEMPO_CONSENSUS_MANIFEST_KEY: &str = "consensus";
const CONSENSUS_ARCHIVE_FILE: &str = "consensus.tar.zst";

type TempoExecutionProvider = BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TempoConsensusManifest {
    pub(crate) execution_finalized_height: u64,
    pub(crate) execution_finalized_digest: B256,
    pub(crate) tip_finalization_height: u64,
    pub(crate) tip_finalization_digest: B256,
    pub(crate) anchor_finalization_height: u64,
    pub(crate) anchor_finalization_digest: B256,
    pub(crate) consensus_archive: SingleArchive,
}

#[derive(Debug, Parser)]
#[command(
    name = "snapshot-manifest",
    about = "Generate snapshot archives and a manifest for the EL plus consensus storage."
)]
pub(crate) struct Args {
    #[command(flatten)]
    inner: SnapshotManifestCommand,

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

    /// Chain spec override for local/unknown chains.
    #[arg(long, short, value_parser = chain_value_parser)]
    chain: Option<Arc<TempoChainSpec>>,

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
            chain,
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
            return Ok(());
        }

        let manifest_path = output_dir.join("manifest.json");
        let manifest = read_manifest(&manifest_path)
            .wrap_err_with(|| format!("failed reading manifest: {}", manifest_path.display()))?;

        let chainspec = resolve_chainspec(chain, manifest.chain_id)?;
        let consensus_dir = consensus_datadir.unwrap_or_else(|| source_datadir.join("consensus"));
        eprintln!(
            "reading snapshot consensus state. consensus dir: {}",
            consensus_dir.display(),
        );

        let prepared_consensus =
            prepare_snapshot_consensus_archive(&consensus_dir, chainspec, source_datadir)
                .wrap_err("failed to prepare consensus snapshot state")?;
        let consensus_state = &prepared_consensus.state;

        let consensus_archive =
            package_consensus_archive(output_dir, &prepared_consensus.archive_dir)
                .wrap_err("failed to package consensus storage")?;

        let consensus_manifest = TempoConsensusManifest {
            execution_finalized_height: consensus_state.execution_finalized_height,
            execution_finalized_digest: consensus_state.execution_finalized_digest.0,
            tip_finalization_height: consensus_state.tip_finalization_height,
            tip_finalization_digest: consensus_state.tip_finalization_digest.0,
            anchor_finalization_height: consensus_state.anchor_finalization_height,
            anchor_finalization_digest: consensus_state.anchor_finalization_digest.0,
            consensus_archive,
        };

        if consensus_manifest.anchor_finalization_height
            < consensus_state.execution_finalized_height
        {
            eprintln!(
                "warning: consensus anchor finalization `{}` is below execution finalized `{}`; \
                snapshot consumers may need to recover consensus state across the execution \
                finalized boundary",
                consensus_manifest.anchor_finalization_height,
                consensus_state.execution_finalized_height,
            );
        }

        let manifest_height = manifest.block;
        ensure!(
            manifest_height >= consensus_state.execution_finalized_height,
            "snapshot block `{manifest_height}` must be at or above execution finalized `{}`",
            consensus_state.execution_finalized_height,
        );

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

        let manifest_json = serde_json::to_string_pretty(&manifest_json)
            .wrap_err("failed to serialize manifest")?;
        fs::write(&manifest_path, manifest_json)
            .wrap_err_with(|| format!("failed to write {}", manifest_path.display()))?;

        eprintln!(
            "packaged consensus archive with tip finalization `{}` and anchor finalization `{}`; execution finalized=`{}`; execution snapshot=`{manifest_height}`",
            consensus_manifest.tip_finalization_height,
            consensus_manifest.anchor_finalization_height,
            consensus_state.execution_finalized_height,
        );
        Ok(())
    }
}

fn read_manifest(manifest_path: &Path) -> eyre::Result<SnapshotManifest> {
    let manifest_bytes = fs::read(manifest_path).wrap_err("failed to read file")?;
    serde_json::from_slice(&manifest_bytes).wrap_err("failed to parse manifest")
}

fn resolve_chainspec(
    chain: Option<Arc<TempoChainSpec>>,
    manifest_chain_id: u64,
) -> eyre::Result<Arc<TempoChainSpec>> {
    match chain {
        None => chainspec_from_chain_id(manifest_chain_id).ok_or_eyre(format!(
            "unknown chain id `{manifest_chain_id}`; pass --chain explicitly"
        )),
        Some(spec) => {
            let chain_id = spec.chain_id();
            ensure!(
                chain_id == manifest_chain_id,
                "mismatch in --chain id `{chain_id}` and manifest chain id `{manifest_chain_id}`",
            );
            Ok(spec)
        }
    }
}

fn prepare_snapshot_consensus_archive(
    consensus_dir: &Path,
    chainspec: Arc<TempoChainSpec>,
    source_datadir: &Path,
) -> eyre::Result<PreparedConsensusSnapshot> {
    let execution_provider = execution_provider(chainspec, source_datadir)?;
    let archive_dir = tempfile::tempdir().wrap_err("failed to create consensus snapshot dir")?;
    let archive_storage_dir = archive_dir.path().to_path_buf();
    let (archive_entries_tx, archive_entries_rx) = tokio::sync::mpsc::channel(64);

    let writer_thread = thread::spawn(move || -> eyre::Result<()> {
        let output_runtime_config = commonware_runtime::tokio::Config::default()
            .with_storage_directory(archive_storage_dir);
        let output_runner = commonware_runtime::tokio::Runner::new(output_runtime_config);
        output_runner.start(|context| async move {
            tempo_consensus::storage::snapshot::write_archive(
                &context,
                tempo_consensus::PARTITION_PREFIX,
                archive_entries_rx,
            )
            .await
        })
    });

    let source_runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir);

    let source_runner = commonware_runtime::tokio::Runner::new(source_runtime_config);
    let state = source_runner.start(|context| async move {
        tempo_consensus::storage::snapshot::prepare(
            &context,
            tempo_consensus::PARTITION_PREFIX,
            execution_provider,
            archive_entries_tx,
        )
        .await
    });

    let writer_result = writer_thread
        .join()
        .map_err(|_| eyre::eyre!("snapshot consensus archive writer panicked"))?;
    let state = state?;
    writer_result?;

    Ok(PreparedConsensusSnapshot { state, archive_dir })
}

struct PreparedConsensusSnapshot {
    state: tempo_consensus::storage::snapshot::State,
    archive_dir: TempDir,
}

fn package_consensus_archive(
    output_dir: &Path,
    archive_dir: &TempDir,
) -> eyre::Result<SingleArchive> {
    let archive_path = output_dir.join(CONSENSUS_ARCHIVE_FILE);
    let output_files = consensus_archive_output_files(archive_dir.path())?;
    let decompressed_size = output_files_size(&output_files)?;
    write_zstd_tar_archive(&archive_path, archive_dir.path())?;
    let size = fs::metadata(&archive_path)
        .wrap_err_with(|| format!("failed to stat {}", archive_path.display()))?
        .len();

    Ok(SingleArchive {
        file: CONSENSUS_ARCHIVE_FILE.to_string(),
        size,
        decompressed_size,
        blake3: Some(hash_file_blake3(&archive_path)?),
        output_files,
    })
}

fn consensus_archive_output_files(root: &Path) -> eyre::Result<Vec<OutputFileChecksum>> {
    let mut output_files = Vec::new();
    collect_consensus_archive_output_files(root, root, &mut output_files)?;
    Ok(output_files)
}

fn collect_consensus_archive_output_files(
    root: &Path,
    path: &Path,
    output_files: &mut Vec<OutputFileChecksum>,
) -> eyre::Result<()> {
    let metadata =
        fs::metadata(path).wrap_err_with(|| format!("failed to stat {}", path.display()))?;

    if metadata.is_file() {
        let relative = path.strip_prefix(root).wrap_err_with(|| {
            format!(
                "failed to derive consensus archive output path for {}",
                path.display()
            )
        })?;
        output_files.push(OutputFileChecksum {
            path: relative.to_string_lossy().to_string(),
            size: metadata.len(),
            blake3: hash_file_blake3(path)?,
        });
        return Ok(());
    }

    if !metadata.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(path)
        .wrap_err_with(|| format!("failed to read directory {}", path.display()))?
    {
        let entry = entry
            .wrap_err_with(|| format!("failed to read directory entry in {}", path.display()))?;
        collect_consensus_archive_output_files(root, &entry.path(), output_files)?;
    }
    Ok(())
}

fn output_files_size(output_files: &[OutputFileChecksum]) -> eyre::Result<u64> {
    let mut size = 0_u64;
    for output_file in output_files {
        size = size
            .checked_add(output_file.size)
            .ok_or_else(|| eyre::eyre!("consensus archive plain-output size exceeds u64::MAX"))?;
    }
    Ok(size)
}

fn write_zstd_tar_archive(path: &Path, source_dir: &Path) -> eyre::Result<()> {
    let file =
        fs::File::create(path).wrap_err_with(|| format!("failed to create {}", path.display()))?;
    let mut encoder = zstd::Encoder::new(file, 0)?;
    encoder.include_checksum(true)?;
    let mut builder = tar::Builder::new(encoder);
    builder.append_dir_all("", source_dir).wrap_err_with(|| {
        format!(
            "failed to append consensus archive from {}",
            source_dir.display()
        )
    })?;

    builder.finish()?;
    let encoder = builder.into_inner()?;
    encoder.finish()?;
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

fn execution_provider(
    chainspec: Arc<TempoChainSpec>,
    source_datadir: &Path,
) -> eyre::Result<TempoExecutionProvider> {
    let runner = CliRunner::try_default_runtime().wrap_err("failed to fetch execution runtime")?;

    let read_cfg = ReadOnlyConfig::from_datadir(source_datadir);
    let factory = TempoNode::provider_factory_builder()
        .open_read_only(chainspec, read_cfg, runner.runtime())
        .wrap_err("failed to open execution provider")?;

    BlockchainProvider::new(factory).wrap_err("failed to create execution provider")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_hides_skip_consensus_override() {
        let help = Args::command().render_long_help().to_string();

        assert!(!help.contains("--skip-consensus"));
    }

    #[test]
    fn args_defaults_to_skip_consensus() {
        let args = Args::try_parse_from([
            "tempo",
            "--source-datadir",
            "/source",
            "--output-dir",
            "/output",
        ])
        .unwrap();

        assert!(args.skip_consensus);
    }

    #[test]
    fn args_accepts_bare_skip_consensus() {
        let args = Args::try_parse_from([
            "tempo",
            "--source-datadir",
            "/source",
            "--output-dir",
            "/output",
            "--skip-consensus",
        ])
        .unwrap();

        assert!(args.skip_consensus);
    }

    #[test]
    fn args_accepts_explicit_skip_consensus_false() {
        let args = Args::try_parse_from([
            "tempo",
            "--source-datadir",
            "/source",
            "--output-dir",
            "/output",
            "--skip-consensus=false",
        ])
        .unwrap();

        assert!(!args.skip_consensus);
    }

    #[test]
    fn consensus_manifest_serializes_binary_fields_as_hex() {
        let manifest = TempoConsensusManifest {
            execution_finalized_height: 40,
            execution_finalized_digest: B256::with_last_byte(0x28),
            tip_finalization_height: 42,
            tip_finalization_digest: B256::with_last_byte(0x2a),
            anchor_finalization_height: 41,
            anchor_finalization_digest: B256::with_last_byte(0x29),
            consensus_archive: SingleArchive {
                file: "consensus.tar.zst".to_string(),
                size: 3,
                decompressed_size: 0,
                blake3: Some("abc".to_string()),
                output_files: Vec::new(),
            },
        };

        let value = serde_json::to_value(manifest).unwrap();

        assert_eq!(value["execution_finalized_height"], 40);
        assert_eq!(value["tip_finalization_height"], 42);
        assert_eq!(
            value["tip_finalization_digest"],
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
        assert_eq!(value["anchor_finalization_height"], 41);
        assert_eq!(
            value["anchor_finalization_digest"],
            "0x0000000000000000000000000000000000000000000000000000000000000029"
        );
        assert!(value.get("consensus_archive_partitions").is_none());
        assert_eq!(value["consensus_archive"]["file"], "consensus.tar.zst");
    }

    #[test]
    fn write_zstd_tar_archive_appends_partitions() {
        let dir = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let key_partition = dir.path().join("partition-key");
        let value_partition = dir.path().join("partition-value");
        fs::create_dir_all(key_partition.join("nested")).unwrap();
        fs::create_dir_all(&value_partition).unwrap();
        fs::write(key_partition.join("nested").join("00"), b"key").unwrap();
        fs::write(value_partition.join("00"), b"value").unwrap();

        let archive_path = output.path().join("consensus.tar.zst");
        write_zstd_tar_archive(&archive_path, dir.path()).unwrap();

        let file = fs::File::open(&archive_path).unwrap();
        let decoder = zstd::stream::read::Decoder::new(file).unwrap();
        let mut archive = tar::Archive::new(decoder);
        let mut paths = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        paths.sort();

        assert!(paths.contains(&"partition-key/nested/00".to_string()));
        assert!(paths.contains(&"partition-value/00".to_string()));
    }

    #[test]
    fn package_consensus_archive_sets_plain_output_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("partition").join("nested")).unwrap();
        fs::write(dir.path().join("partition").join("00"), b"abc").unwrap();
        fs::write(
            dir.path().join("partition").join("nested").join("01"),
            b"defg",
        )
        .unwrap();

        let archive = package_consensus_archive(output.path(), &dir).unwrap();

        assert_eq!(archive.decompressed_size, 7);
        assert_eq!(archive.file, "consensus.tar.zst");
        assert!(archive.size > 0);
        assert!(archive.blake3.is_some());

        let mut output_files = archive.output_files;
        output_files.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(output_files.len(), 2);
        assert_eq!(output_files[0].path, "partition/00");
        assert_eq!(output_files[0].size, 3);
        assert_eq!(
            output_files[0].blake3,
            blake3::hash(b"abc").to_hex().to_string(),
        );
        assert_eq!(output_files[1].path, "partition/nested/01");
        assert_eq!(output_files[1].size, 4);
        assert_eq!(
            output_files[1].blake3,
            blake3::hash(b"defg").to_hex().to_string(),
        );
    }
}
