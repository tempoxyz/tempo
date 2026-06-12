use std::{
    fs,
    io::Read,
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
    manifest::{OutputFileChecksum, SnapshotManifest},
    manifest_cmd::SnapshotManifestCommand,
};
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_provider::providers::{BlockchainProvider, ReadOnlyConfig};
use serde::{Deserialize, Serialize};
use tempo_chainspec::spec::{TempoChainSpec, chain_value_parser, chainspec_from_chain_id};
use tempo_consensus::{PersistedCache, collect_persisted_cache, write_persisted_cache};
use tempo_node::node::TempoNode;
use tempo_telemetry_util::display_duration;

pub(crate) const TEMPO_CONSENSUS_MANIFEST_KEY: &str = "consensus";

/// Archive file holding the minimized persisted cache, relative to the
/// manifest's base URL.
const CONSENSUS_CACHE_ARCHIVE: &str = "consensus-cache.tar.zst";

/// Scratch directory (under the output dir) the minimized persisted cache
/// is staged in before packaging. Removed after the archive is written.
const CONSENSUS_CACHE_STAGING_DIR: &str = "consensus-cache.staging";

type TempoExecutionProvider = BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TempoConsensusManifest {
    pub(crate) height: u64,
    pub(crate) digest: B256,
    pub(crate) finalization: Bytes,
    /// Minimized persisted cache: the consensus-layer finalized blocks
    /// needed to bring the execution layer up to [`Self::digest`]. Omitted
    /// when the certificate is already covered by the execution layer
    /// snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) persisted_cache: Option<PersistedCacheManifest>,
}

/// Manifest entry describing the packaged minimized persisted cache.
///
/// The archive extracts relative to the node's consensus datadir and
/// contains a prunable finalized-blocks archive holding exactly the blocks
/// `[first_block, last_block]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PersistedCacheManifest {
    /// Archive file name (relative to the manifest's base URL).
    pub(crate) file: String,
    /// First block height in the cache (execution finalized height + 1).
    pub(crate) first_block: u64,
    /// Last block height in the cache (the certificate height).
    pub(crate) last_block: u64,
    /// Compressed archive size in bytes.
    pub(crate) size: u64,
    /// Total extracted plain-output size in bytes.
    pub(crate) decompressed_size: u64,
    /// Expected extracted plain files for this archive.
    pub(crate) output_files: Vec<OutputFileChecksum>,
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

    /// Maximum blocks behind the finalized execution tip to inspect.
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
            finalization_search_depth,
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
            "extracting persisted cache. consensus dir: {}, search depth: {}",
            consensus_dir.display(),
            finalization_search_depth,
        );

        let cache = collect_cache(
            &consensus_dir,
            execution_provider,
            finalization_search_depth,
        )
        .wrap_err("failed to extract minimized persisted cache")?;

        eprintln!(
            "snapshot certificate height `{}`; execution finalized `{}`, execution tip `{}`, cached blocks `{}`",
            cache.height,
            cache.execution_height,
            manifest.block,
            cache.block_count(),
        );

        let persisted_cache = match cache.block_range() {
            Some((first_block, last_block)) => {
                let packaged = stage_and_package_cache(&cache, output_dir)
                    .wrap_err("failed to package minimized persisted cache")?;

                eprintln!(
                    "packaged minimized persisted cache: blocks [{first_block}, {last_block}], {} bytes compressed",
                    packaged.size,
                );

                Some(PersistedCacheManifest {
                    file: CONSENSUS_CACHE_ARCHIVE.to_string(),
                    first_block,
                    last_block,
                    size: packaged.size,
                    decompressed_size: packaged.decompressed_size,
                    output_files: packaged.output_files,
                })
            }
            None => {
                eprintln!(
                    "certificate is covered by the execution layer snapshot; \
                    no persisted cache to package"
                );
                None
            }
        };

        let consensus_manifest = TempoConsensusManifest {
            height: cache.height,
            digest: cache.digest().0,
            finalization: cache.finalization.encode().into(),
            persisted_cache,
        };

        let mut manifest_json =
            serde_json::to_value(&manifest).wrap_err("failed to serialize merged manifest")?;

        manifest_json
            .as_object_mut()
            .ok_or_eyre("serialized manifest was not a JSON object")?
            .insert(
                TEMPO_CONSENSUS_MANIFEST_KEY.to_string(),
                serde_json::to_value(consensus_manifest)
                    .wrap_err("failed to serialize Tempo consensus manifest extension")?,
            );

        let manifest_json = serde_json::to_string_pretty(&manifest_json)
            .wrap_err("failed to serialize manifest")?;
        fs::write(&manifest_path, manifest_json)
            .wrap_err_with(|| format!("failed to write {}", manifest_path.display()))?;

        eprintln!(
            "embedded finalization for height `{}`; execution=`{}`",
            cache.height, manifest.block,
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

/// Determines the snapshot certificate and reads the minimal persisted
/// cache out of the node's consensus storage.
fn collect_cache(
    consensus_dir: &Path,
    execution_provider: TempoExecutionProvider,
    max_depth: u64,
) -> eyre::Result<PersistedCache> {
    let runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir);

    let runner = commonware_runtime::tokio::Runner::new(runtime_config);
    runner.start(|context| async move {
        collect_persisted_cache(&context, &execution_provider, max_depth)
            .await?
            .ok_or_eyre(format!(
                "no finalization certificate matches the snapshot state \
                ({max_depth} block lookback)"
            ))
    })
}

/// Writes the minimized persisted cache into a staging directory under
/// `output_dir`, packages it as [`CONSENSUS_CACHE_ARCHIVE`], and removes
/// the staging directory.
fn stage_and_package_cache(
    cache: &PersistedCache,
    output_dir: &Path,
) -> eyre::Result<PackagedArchive> {
    let staging_dir = output_dir.join(CONSENSUS_CACHE_STAGING_DIR);
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .wrap_err_with(|| format!("failed to clear staging dir: {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .wrap_err_with(|| format!("failed to create staging dir: {}", staging_dir.display()))?;

    let runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(&staging_dir);
    let runner = commonware_runtime::tokio::Runner::new(runtime_config);
    runner.start(|context| async move { write_persisted_cache(&context, cache).await })?;

    let archive_path = output_dir.join(CONSENSUS_CACHE_ARCHIVE);
    let packaged = package_directory(&staging_dir, &archive_path)?;

    fs::remove_dir_all(&staging_dir)
        .wrap_err_with(|| format!("failed to remove staging dir: {}", staging_dir.display()))?;

    Ok(packaged)
}

#[derive(Debug)]
struct PackagedArchive {
    /// Compressed archive size in bytes.
    size: u64,
    /// Total extracted plain-output size in bytes.
    decompressed_size: u64,
    /// Expected extracted plain files.
    output_files: Vec<OutputFileChecksum>,
}

/// Packages every file under `source_dir` into a `tar.zst` archive at
/// `archive_path`, with paths stored relative to `source_dir`.
///
/// Mirrors the format of reth's EL component archives: GNU tar entries
/// (mode 0644) in standard zstd frames with checksums, plus per-file
/// BLAKE3 checksums for the modular download path.
fn package_directory(source_dir: &Path, archive_path: &Path) -> eyre::Result<PackagedArchive> {
    let mut files = Vec::new();
    collect_files_recursive(source_dir, source_dir, &mut files)?;
    files.sort_unstable_by(|a, b| a.1.cmp(&b.1));
    ensure!(
        !files.is_empty(),
        "nothing to package under {}",
        source_dir.display()
    );

    let archive = fs::File::create(archive_path)
        .wrap_err_with(|| format!("failed to create {}", archive_path.display()))?;
    let mut encoder = zstd::Encoder::new(archive, 0).wrap_err("failed to create zstd encoder")?;
    // Emit standard zstd frames with checksums for compatibility with
    // external tools such as `pzstd -d`.
    encoder
        .include_checksum(true)
        .wrap_err("failed to enable zstd checksums")?;
    let mut builder = tar::Builder::new(encoder);

    let mut output_files = Vec::with_capacity(files.len());
    for (source_path, relative_path) in &files {
        let mut header = tar::Header::new_gnu();
        header.set_size(
            fs::metadata(source_path)
                .wrap_err_with(|| format!("failed to stat {}", source_path.display()))?
                .len(),
        );
        header.set_mode(0o644);
        header.set_cksum();

        let source = fs::File::open(source_path)
            .wrap_err_with(|| format!("failed to open {}", source_path.display()))?;
        let mut reader = HashingReader::new(source);
        builder
            .append_data(&mut header, relative_path, &mut reader)
            .wrap_err_with(|| format!("failed to archive {}", source_path.display()))?;

        output_files.push(OutputFileChecksum {
            path: relative_path.to_string_lossy().to_string(),
            size: reader.bytes_read,
            blake3: reader.finalize(),
        });
    }

    builder.finish().wrap_err("failed to finish tar archive")?;
    let encoder = builder
        .into_inner()
        .wrap_err("failed to flush tar archive")?;
    encoder.finish().wrap_err("failed to finish zstd stream")?;

    let size = fs::metadata(archive_path)
        .wrap_err_with(|| format!("failed to stat {}", archive_path.display()))?
        .len();
    let decompressed_size = output_files.iter().map(|file| file.size).sum();

    Ok(PackagedArchive {
        size,
        decompressed_size,
        output_files,
    })
}

fn collect_files_recursive(
    root: &Path,
    dir: &Path,
    files: &mut Vec<(PathBuf, PathBuf)>,
) -> eyre::Result<()> {
    for entry in
        fs::read_dir(dir).wrap_err_with(|| format!("failed to read dir: {}", dir.display()))?
    {
        let entry = entry.wrap_err("failed to read dir entry")?;
        let path = entry.path();
        let file_type = entry.file_type().wrap_err("failed to read file type")?;
        if file_type.is_dir() {
            collect_files_recursive(root, &path, files)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .wrap_err("file outside packaging root")?
            .to_path_buf();
        files.push((path, relative));
    }
    Ok(())
}

struct HashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
    bytes_read: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            bytes_read: 0,
        }
    }

    fn finalize(self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.bytes_read += n as u64;
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
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
            height: 42,
            digest: B256::with_last_byte(0x2a),
            finalization: Bytes::from(vec![0x00, 0x01, 0x02, 0xff]),
            persisted_cache: None,
        };

        let value = serde_json::to_value(manifest).unwrap();

        assert_eq!(value["height"], 42);
        assert_eq!(
            value["digest"],
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
        assert_eq!(value["finalization"], "0x000102ff");
        // Absent cache must not pollute the manifest.
        assert!(value.get("persisted_cache").is_none());
    }

    #[test]
    fn consensus_manifest_round_trips_persisted_cache() {
        let manifest = TempoConsensusManifest {
            height: 42,
            digest: B256::with_last_byte(0x2a),
            finalization: Bytes::from(vec![0x00, 0x01]),
            persisted_cache: Some(PersistedCacheManifest {
                file: CONSENSUS_CACHE_ARCHIVE.to_string(),
                first_block: 33,
                last_block: 42,
                size: 100,
                decompressed_size: 400,
                output_files: vec![OutputFileChecksum {
                    path: "engine-finalized-blocks-prunable-value/0000000000000000".to_string(),
                    size: 400,
                    blake3: "abc".to_string(),
                }],
            }),
        };

        let value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(value["persisted_cache"]["file"], CONSENSUS_CACHE_ARCHIVE);
        assert_eq!(value["persisted_cache"]["first_block"], 33);
        assert_eq!(value["persisted_cache"]["last_block"], 42);

        let parsed: TempoConsensusManifest = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn old_manifests_without_persisted_cache_still_parse() {
        let parsed: TempoConsensusManifest = serde_json::from_str(
            r#"{
                "height": 42,
                "digest": "0x000000000000000000000000000000000000000000000000000000000000002a",
                "finalization": "0xaabbcc"
            }"#,
        )
        .unwrap();

        assert_eq!(parsed.height, 42);
        assert!(parsed.persisted_cache.is_none());
    }

    #[test]
    fn package_directory_archives_files_with_checksums() {
        let staging = tempfile::tempdir().unwrap();
        let nested = staging
            .path()
            .join("engine-finalized-blocks-prunable-value");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("0000000000000000"), b"value-blob").unwrap();
        let key_dir = staging.path().join("engine-finalized-blocks-prunable-key");
        fs::create_dir_all(&key_dir).unwrap();
        fs::write(key_dir.join("0000000000000000"), b"key-blob").unwrap();

        let out = tempfile::tempdir().unwrap();
        let archive_path = out.path().join(CONSENSUS_CACHE_ARCHIVE);
        let packaged = package_directory(staging.path(), &archive_path).unwrap();

        assert!(archive_path.exists());
        assert_eq!(packaged.size, fs::metadata(&archive_path).unwrap().len());
        assert_eq!(packaged.decompressed_size, 18);
        assert_eq!(packaged.output_files.len(), 2);
        // Deterministic ordering by relative path.
        assert_eq!(
            packaged.output_files[0].path,
            "engine-finalized-blocks-prunable-key/0000000000000000"
        );
        assert_eq!(
            packaged.output_files[0].blake3,
            blake3::hash(b"key-blob").to_hex().to_string()
        );

        // The archive must extract back to the original tree.
        let extracted = tempfile::tempdir().unwrap();
        let archive = fs::File::open(&archive_path).unwrap();
        let decoder = zstd::Decoder::new(archive).unwrap();
        tar::Archive::new(decoder).unpack(extracted.path()).unwrap();
        assert_eq!(
            fs::read(
                extracted
                    .path()
                    .join("engine-finalized-blocks-prunable-value/0000000000000000")
            )
            .unwrap(),
            b"value-blob"
        );
    }

    #[test]
    fn package_directory_rejects_empty_source() {
        let staging = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let err = package_directory(staging.path(), &out.path().join("x.tar.zst")).unwrap_err();
        assert!(err.to_string().contains("nothing to package"), "{err}");
    }
}
