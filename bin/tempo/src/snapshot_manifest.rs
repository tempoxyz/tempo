use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use alloy_primitives::B256;
use clap::{ArgMatches, FromArgMatches, Parser};
use commonware_runtime::Runner as _;
use eyre::{Context as _, OptionExt, bail, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::download::{
    manifest::{SingleArchive, SnapshotManifest},
    manifest_cmd::SnapshotManifestCommand,
};
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_provider::{
    BlockIdReader,
    providers::{BlockchainProvider, ReadOnlyConfig},
};
use serde::{Deserialize, Serialize};
use tar::HeaderMode;
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
            eprintln!("--skip-consensus set. skipping consensus layer");
            return Ok(());
        }

        let manifest_path = output_dir.join("manifest.json");
        let manifest = read_manifest(&manifest_path)
            .wrap_err_with(|| format!("failed reading manifest: {}", manifest_path.display()))?;

        let chainspec = resolve_chainspec(chain, manifest.chain_id)?;
        let execution_provider = execution_provider(chainspec, source_datadir)?;

        let consensus_dir = consensus_datadir.unwrap_or_else(|| source_datadir.join("consensus"));
        eprintln!(
            "reading snapshot consensus state. consensus dir: {}",
            consensus_dir.display(),
        );

        let execution_finalized_num_hash = execution_provider
            .finalized_block_num_hash()
            .wrap_err("failed to read finalized execution finalized block num hash")?
            .ok_or_eyre("no finalized execution state")?;

        let prepared_consensus =
            prepare_snapshot_consensus_archive(&consensus_dir, execution_finalized_num_hash.number)
                .wrap_err("failed to prepare consensus snapshot state")?;
        let consensus_state = &prepared_consensus.state;

        let consensus_archive =
            package_consensus_archive(output_dir, &prepared_consensus.archive_dir)
                .wrap_err("failed to package consensus storage")?;

        let tip_digest = consensus_state.tip_finalization.proposal.payload;
        let anchor_digest = consensus_state.anchor_finalization.proposal.payload;
        let consensus_manifest = TempoConsensusManifest {
            execution_finalized_height: execution_finalized_num_hash.number,
            execution_finalized_digest: execution_finalized_num_hash.hash,
            tip_finalization_height: consensus_state.tip_finalization_height,
            tip_finalization_digest: tip_digest.0,
            anchor_finalization_height: consensus_state.anchor_finalization_height,
            anchor_finalization_digest: anchor_digest.0,
            consensus_archive,
        };

        if consensus_manifest.anchor_finalization_height < execution_finalized_num_hash.number {
            eprintln!(
                "warning: consensus anchor finalization `{}` is below execution finalized `{}`; \
                snapshot consumers may need to recover consensus state across the execution \
                finalized boundary",
                consensus_manifest.anchor_finalization_height, execution_finalized_num_hash.number,
            );
        }

        let manifest_height = manifest.block;
        ensure!(
            manifest_height >= execution_finalized_num_hash.number,
            "snapshot block `{manifest_height}` must be at or above execution finalized `{}`",
            execution_finalized_num_hash.number,
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
            execution_finalized_num_hash.number,
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
    execution_finalized_height: u64,
) -> eyre::Result<PreparedConsensusSnapshot> {
    let source_runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir);

    let source_runner = commonware_runtime::tokio::Runner::new(source_runtime_config);
    let prepared = source_runner.start(|context| async move {
        tempo_consensus::storage::snapshot::prepare(&context, execution_finalized_height).await
    })?;

    let archive_dir = tempfile::tempdir().wrap_err("failed to create consensus snapshot dir")?;
    let finalizations_runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(archive_dir.path());
    let finalizations_runner = commonware_runtime::tokio::Runner::new(finalizations_runtime_config);
    finalizations_runner.start(|context| async move {
        tempo_consensus::storage::snapshot::write_finalizations_archive(
            &context,
            prepared.finalization_archive_entries,
        )
        .await
    })?;
    copy_prunable_partitions(consensus_dir, archive_dir.path())?;

    Ok(PreparedConsensusSnapshot {
        state: prepared.state,
        archive_dir,
    })
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
    write_zstd_tar_archive(&archive_path, archive_dir.path())?;
    let size = fs::metadata(&archive_path)
        .wrap_err_with(|| format!("failed to stat {}", archive_path.display()))?
        .len();

    Ok(SingleArchive {
        file: CONSENSUS_ARCHIVE_FILE.to_string(),
        size,
        decompressed_size: 0,
        blake3: Some(hash_file_blake3(&archive_path)?),
        output_files: Vec::new(),
    })
}

fn copy_prunable_partitions(consensus_dir: &Path, archive_dir: &Path) -> eyre::Result<()> {
    for entry in sorted_dir_entries(consensus_dir)? {
        let name = entry.file_name().to_string_lossy().to_string();
        if !tempo_consensus::storage::snapshot::is_prunable_finalized_blocks_partition(&name) {
            continue;
        }
        copy_path(&entry.path(), &archive_dir.join(&name))?;
    }
    Ok(())
}

fn copy_path(source: &Path, target: &Path) -> eyre::Result<()> {
    let metadata = fs::symlink_metadata(source)
        .wrap_err_with(|| format!("failed to stat {}", source.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "consensus partition contains symlink: {}",
        source.display(),
    );

    if metadata.is_dir() {
        fs::create_dir_all(target)
            .wrap_err_with(|| format!("failed to create {}", target.display()))?;
        for entry in sorted_dir_entries(source)? {
            copy_path(&entry.path(), &target.join(entry.file_name()))?;
        }
        return Ok(());
    }

    if metadata.is_file() {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .wrap_err_with(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(source, target).wrap_err_with(|| {
            format!(
                "failed to copy consensus partition file {} to {}",
                source.display(),
                target.display(),
            )
        })?;
        return Ok(());
    }

    bail!(
        "unsupported consensus partition entry: {}",
        source.display()
    )
}

fn sorted_dir_entries(dir: &Path) -> eyre::Result<Vec<fs::DirEntry>> {
    let mut entries = fs::read_dir(dir)
        .wrap_err_with(|| format!("failed to read directory {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .wrap_err_with(|| format!("failed to read directory entry in {}", dir.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn write_zstd_tar_archive(path: &Path, source_dir: &Path) -> eyre::Result<()> {
    let file =
        fs::File::create(path).wrap_err_with(|| format!("failed to create {}", path.display()))?;
    let mut encoder = zstd::Encoder::new(file, 0)?;
    encoder.include_checksum(true)?;
    let mut builder = tar::Builder::new(encoder);
    builder.mode(HeaderMode::Deterministic);
    builder.follow_symlinks(false);

    for entry in sorted_dir_entries(source_dir)? {
        let source_path = entry.path();
        let archive_path = PathBuf::from(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .wrap_err_with(|| format!("failed to stat {}", source_path.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "consensus archive source contains symlink: {}",
            source_path.display(),
        );

        if metadata.is_dir() {
            builder
                .append_dir_all(&archive_path, &source_path)
                .wrap_err_with(|| {
                    format!(
                        "failed to append consensus directory {} from {}",
                        archive_path.display(),
                        source_path.display(),
                    )
                })?;
        } else if metadata.is_file() {
            builder
                .append_path_with_name(&source_path, &archive_path)
                .wrap_err_with(|| {
                    format!(
                        "failed to append consensus file {} from {}",
                        archive_path.display(),
                        source_path.display(),
                    )
                })?;
        } else {
            bail!(
                "unsupported consensus archive source entry: {}",
                source_path.display(),
            );
        }
    }

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
}
