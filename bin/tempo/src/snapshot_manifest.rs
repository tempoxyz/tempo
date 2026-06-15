use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use alloy_primitives::{B256, Bytes};
use clap::{ArgMatches, FromArgMatches, Parser};
use commonware_codec::Encode as _;
use commonware_runtime::Runner as _;
use eyre::{Context as _, OptionExt, ensure};
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
use tempo_chainspec::spec::{TempoChainSpec, chain_value_parser, chainspec_from_chain_id};
use tempo_node::node::TempoNode;
use tempo_telemetry_util::display_duration;

pub(crate) const TEMPO_CONSENSUS_MANIFEST_KEY: &str = "consensus";
const CONSENSUS_PRUNABLE_ARCHIVE_FILE: &str = "consensus-prunable.tar.zst";

type TempoExecutionProvider = BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TempoConsensusManifest {
    pub(crate) execution_finalized_height: u64,
    pub(crate) execution_finalized_digest: B256,
    pub(crate) consensus_finalized_height: u64,
    pub(crate) consensus_finalized_digest: B256,
    pub(crate) finalization_certificate: Bytes,
    pub(crate) consensus_start_block_height: Option<u64>,
    pub(crate) consensus_end_block_height: Option<u64>,
    pub(crate) consensus_block_partitions: [String; 2],
    pub(crate) consensus_archive: SingleArchive,
}

#[derive(Debug, Parser)]
#[command(
    name = "snapshot-manifest",
    about = "Generate snapshot archives and a manifest for the EL plus consensus floor certificate."
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

    /// Deprecated: consensus snapshots now use the latest stored finalization certificate.
    #[arg(long = "consensus.finalization-search-depth", default_value_t = 100)]
    finalization_search_depth: u64,
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
            finalization_search_depth: _finalization_search_depth,
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

        let consensus_state =
            prepare_snapshot_consensus_archive(&consensus_dir, execution_finalized_num_hash.number)
                .wrap_err("failed to prepare consensus snapshot state")?;

        let consensus_archive = package_consensus_archive(
            &consensus_dir,
            output_dir,
            &consensus_state.consensus_blocks_partitions,
        )
        .wrap_err("failed to package consensus prunable storage")?;

        let digest = consensus_state.latest_finalization.proposal.payload;
        let consensus_manifest = TempoConsensusManifest {
            execution_finalized_height: execution_finalized_num_hash.number,
            execution_finalized_digest: execution_finalized_num_hash.hash,
            consensus_finalized_height: consensus_state.consensus_finalization_height,
            consensus_finalized_digest: digest.0,
            finalization_certificate: consensus_state.latest_finalization.encode().into(),
            consensus_start_block_height: consensus_state.consensus_start_block_height,
            consensus_end_block_height: consensus_state.consensus_end_block_height,
            consensus_block_partitions: consensus_state.consensus_blocks_partitions.clone(),
            consensus_archive,
        };

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
            "embedded finalization for height `{}`; execution finalized=`{}`; execution snapshot=`{manifest_height}`",
            consensus_manifest.consensus_finalized_height, execution_finalized_num_hash.number,
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
) -> eyre::Result<tempo_consensus::State> {
    let source_runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir);

    let source_runner = commonware_runtime::tokio::Runner::new(source_runtime_config);
    let state = source_runner.start(|context| async move {
        tempo_consensus::prepare(&context, execution_finalized_height).await
    })?;

    Ok(state)
}

#[derive(Debug)]
struct PlannedConsensusPartition {
    source_path: PathBuf,
    archive_path: PathBuf,
}

fn package_consensus_archive(
    consensus_dir: &Path,
    output_dir: &Path,
    partitions: &[String],
) -> eyre::Result<SingleArchive> {
    let partitions = consensus_prunable_partitions(consensus_dir, partitions)?;
    let archive_path = output_dir.join(CONSENSUS_PRUNABLE_ARCHIVE_FILE);
    write_zstd_tar_archive(&archive_path, &partitions)?;
    let size = fs::metadata(&archive_path)
        .wrap_err_with(|| format!("failed to stat {}", archive_path.display()))?
        .len();

    Ok(SingleArchive {
        file: CONSENSUS_PRUNABLE_ARCHIVE_FILE.to_string(),
        size,
        decompressed_size: 0,
        blake3: Some(hash_file_blake3(&archive_path)?),
        output_files: Vec::new(),
    })
}

fn consensus_prunable_partitions(
    consensus_dir: &Path,
    partitions: &[String],
) -> eyre::Result<Vec<PlannedConsensusPartition>> {
    let mut planned = Vec::new();
    for partition in partitions {
        let archive_path = PathBuf::from(partition);
        let partition_dir = consensus_dir.join(partition);
        if !partition_dir.exists() {
            continue;
        }
        ensure!(
            partition_dir.is_dir(),
            "consensus partition is not a directory: {}",
            partition_dir.display(),
        );
        planned.push(PlannedConsensusPartition {
            source_path: partition_dir,
            archive_path,
        });
    }
    planned.sort_unstable_by(|a, b| a.archive_path.cmp(&b.archive_path));
    Ok(planned)
}

fn write_zstd_tar_archive(
    path: &Path,
    partitions: &[PlannedConsensusPartition],
) -> eyre::Result<()> {
    let file =
        fs::File::create(path).wrap_err_with(|| format!("failed to create {}", path.display()))?;
    let mut encoder = zstd::Encoder::new(file, 0)?;
    encoder.include_checksum(true)?;
    let mut builder = tar::Builder::new(encoder);
    builder.mode(HeaderMode::Deterministic);
    builder.follow_symlinks(false);

    for partition in partitions {
        builder
            .append_dir_all(&partition.archive_path, &partition.source_path)
            .wrap_err_with(|| {
                format!(
                    "failed to append consensus partition {} from {}",
                    partition.archive_path.display(),
                    partition.source_path.display(),
                )
            })?;
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
            consensus_finalized_height: 42,
            consensus_finalized_digest: B256::with_last_byte(0x2a),
            finalization_certificate: Bytes::from(vec![0x00, 0x01, 0x02, 0xff]),
            consensus_start_block_height: Some(41),
            consensus_end_block_height: Some(42),
            consensus_block_partitions: [
                "engine-finalized-blocks-prunable-key".to_string(),
                "engine-finalized-blocks-prunable-value".to_string(),
            ],
            consensus_archive: SingleArchive {
                file: "consensus-prunable.tar.zst".to_string(),
                size: 3,
                decompressed_size: 0,
                blake3: Some("abc".to_string()),
                output_files: Vec::new(),
            },
        };

        let value = serde_json::to_value(manifest).unwrap();

        assert_eq!(value["execution_finalized_height"], 40);
        assert_eq!(value["consensus_finalized_height"], 42);
        assert_eq!(
            value["consensus_finalized_digest"],
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
        assert_eq!(value["finalization_certificate"], "0x000102ff");
        assert_eq!(value["consensus_start_block_height"], 41);
        assert_eq!(value["consensus_end_block_height"], 42);
        assert_eq!(
            value["consensus_block_partitions"][0],
            "engine-finalized-blocks-prunable-key"
        );
        assert_eq!(
            value["consensus_archive"]["file"],
            "consensus-prunable.tar.zst"
        );
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

        let partitions = consensus_prunable_partitions(
            dir.path(),
            &["partition-key".to_string(), "partition-value".to_string()],
        )
        .unwrap();
        let archive_path = output.path().join("consensus-prunable.tar.zst");
        write_zstd_tar_archive(&archive_path, &partitions).unwrap();

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
