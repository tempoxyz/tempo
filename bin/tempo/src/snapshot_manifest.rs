use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

use blake3::Hasher;
use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, Result, bail};
use reth_cli_commands::download::{
    manifest::{ComponentManifest, OutputFileChecksum, SingleArchive, SnapshotManifest},
    manifest_cmd::SnapshotManifestCommand,
};
use tar::{Builder as TarBuilder, Header};
use walkdir::WalkDir;
use zstd::Encoder as ZstdEncoder;

const DEFAULT_PARTITION_PREFIX: &str = "engine";

const FINALIZED_BLOCKS_INFIX: &str = "finalized_blocks";
const FINALIZATIONS_INFIX: &str = "finalizations-by-height";
const APPLICATION_METADATA_SUFFIX: &str = "application-metadata";

const CL_FINALIZED_BLOCKS_KEY: &str = "cl_finalized_blocks";
const CL_FINALIZATIONS_KEY: &str = "cl_finalizations";
const CL_APPLICATION_METADATA_KEY: &str = "cl_application_metadata";

const CL_FINALIZED_BLOCKS_FILE: &str = "cl_finalized_blocks.tar.zst";
const CL_FINALIZATIONS_FILE: &str = "cl_finalizations.tar.zst";
const CL_APPLICATION_METADATA_FILE: &str = "cl_application_metadata.tar.zst";

/// Component keys advertised in `manifest.components` for our CL archives.
pub(crate) const CL_COMPONENT_KEYS: &[&str] = &[
    CL_FINALIZED_BLOCKS_KEY,
    CL_FINALIZATIONS_KEY,
    CL_APPLICATION_METADATA_KEY,
];

#[derive(Debug, Parser)]
#[command(
    name = "snapshot-manifest",
    about = "Generate snapshot archives and a manifest for both the EL (via reth) and the CL."
)]
pub(crate) struct Args {
    #[command(flatten)]
    inner: SnapshotManifestCommand,

    /// Consensus storage directory. If not set, this will be dirived from --datadir.
    #[arg(long)]
    consensus_source_dir: Option<PathBuf>,
}

pub(crate) fn run(matches: &ArgMatches) -> Result<()> {
    let args = Args::from_arg_matches(matches).map_err(|e| eyre::eyre!("{e}"))?;

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
    fn execute(self, source_datadir: &Path, output_dir: &Path) -> Result<()> {
        fs::create_dir_all(output_dir)
            .wrap_err_with(|| format!("failed to create output dir: {}", output_dir.display()))?;

        let consensus_dir = self
            .consensus_source_dir
            .clone()
            .unwrap_or_else(|| source_datadir.join("consensus"));

        if !consensus_dir.is_dir() {
            bail!("consensus dir does not exist: {}", consensus_dir.display());
        }

        let groups = collect_cl_partitions(&consensus_dir)?;
        eprintln!("packaging execution layer static files");

        let start = Instant::now();
        self.inner
            .execute()
            .wrap_err("reth snapshot-manifest (EL packaging) failed")?;

        eprintln!("execution layer snapshot finished in {:?}", start.elapsed());

        // Read back manifest.json so we can amend it.
        let manifest_path = output_dir.join("manifest.json");
        let manifest_bytes = fs::read(&manifest_path)
            .wrap_err_with(|| format!("failed to read {manifest_path:?}"))?;

        let mut manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
            .wrap_err("failed to parse manifest.json produced by reth snapshot-manifest")?;

        eprintln!("packaging consensus layer archives");
        for group in &groups {
            let archive_path = output_dir.join(group.file_name);
            let start = Instant::now();
            let output_files = pack_partitions(&archive_path, &consensus_dir, &group.partitions)
                .wrap_err_with(|| format!("failed to pack {}", group.key,))?;

            let size = fs::metadata(&archive_path)
                .wrap_err("failed to reach package metadata")?
                .len();

            let decompressed_size: u64 = output_files.iter().map(|f| f.size).sum();
            eprintln!("packaged {} in {:?}", group.key, start.elapsed());

            manifest.components.insert(
                group.key.to_string(),
                ComponentManifest::Single(SingleArchive {
                    file: group.file_name.to_string(),
                    size,
                    decompressed_size,
                    blake3: None,
                    output_files,
                }),
            );
        }

        let json = serde_json::to_string_pretty(&manifest)
            .wrap_err("failed to serialize merged manifest.json")?;

        fs::write(&manifest_path, &json)
            .wrap_err_with(|| format!("failed to write {}", manifest_path.display()))?;

        eprintln!("snapshot manifest: {manifest_path:?}");

        Ok(())
    }
}

#[derive(Debug)]
struct CLGroup {
    /// Key under `manifest.components`.
    key: &'static str,
    /// Output filename, relative to `--output-dir`.
    file_name: &'static str,
    /// Absolute paths of the partition directories to include.
    partitions: Vec<PathBuf>,
}

fn collect_cl_partitions(consensus_dir: &Path) -> Result<Vec<CLGroup>> {
    let prefix = DEFAULT_PARTITION_PREFIX;

    let finalized_blocks_marker = format!("{prefix}-{FINALIZED_BLOCKS_INFIX}-");
    let finalizations_marker = format!("{prefix}-{FINALIZATIONS_INFIX}-");
    let application_metadata_dir = format!("{prefix}-{APPLICATION_METADATA_SUFFIX}");

    let mut finalized_blocks = Vec::new();
    let mut finalizations = Vec::new();
    let mut application_metadata = Vec::new();

    for entry in fs::read_dir(consensus_dir)
        .wrap_err_with(|| format!("failed to read consensus dir {consensus_dir:?}"))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name.starts_with(&finalized_blocks_marker) {
            finalized_blocks.push(path);
        } else if name.starts_with(&finalizations_marker) {
            finalizations.push(path);
        } else if name == application_metadata_dir.as_str() {
            application_metadata.push(path);
        }
    }

    if finalized_blocks.is_empty() {
        bail!("no finalized_blocks partitions found under {consensus_dir:?}");
    }

    if finalizations.is_empty() {
        bail!("no finalizations-by-height partitions found under {consensus_dir:?}");
    }

    if application_metadata.is_empty() {
        bail!("no application metadata partition found under {consensus_dir:?}");
    }

    finalized_blocks.sort();
    finalizations.sort();

    let groups = vec![
        CLGroup {
            key: CL_FINALIZED_BLOCKS_KEY,
            file_name: CL_FINALIZED_BLOCKS_FILE,
            partitions: finalized_blocks,
        },
        CLGroup {
            key: CL_FINALIZATIONS_KEY,
            file_name: CL_FINALIZATIONS_FILE,
            partitions: finalizations,
        },
        CLGroup {
            key: CL_APPLICATION_METADATA_KEY,
            file_name: CL_APPLICATION_METADATA_FILE,
            partitions: application_metadata,
        },
    ];

    Ok(groups)
}

fn pack_partitions(
    archive_path: &Path,
    base_dir: &Path,
    partitions: &[PathBuf],
) -> Result<Vec<OutputFileChecksum>> {
    let file = File::create(archive_path)
        .wrap_err_with(|| format!("failed to create archive {}", archive_path.display()))?;

    let mut encoder = ZstdEncoder::new(file, 0).wrap_err("failed to initialize zstd encoder")?;

    encoder
        .include_checksum(true)
        .wrap_err("failed to enable zstd checksums")?;

    let mut tar = TarBuilder::new(encoder);

    let mut outputs = Vec::new();
    for partition in partitions {
        let entries: Vec<PathBuf> = WalkDir::new(partition)
            .sort_by_file_name()
            .into_iter()
            .collect::<std::result::Result<Vec<_>, _>>()
            .wrap_err_with(|| format!("failed walking partition dir {}", partition.display()))?
            .into_iter()
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .collect();

        for path in entries {
            let rel = path
                .strip_prefix(base_dir)
                .wrap_err("partition path was not under consensus source dir")?
                .to_path_buf();

            let metadata = fs::metadata(&path)
                .wrap_err_with(|| format!("failed to stat {}", path.display()))?;

            let blake3 = blake3_hash(&path)?;

            let mut header = Header::new_gnu();
            header.set_size(metadata.len());
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();

            let source =
                File::open(&path).wrap_err_with(|| format!("failed to open {}", path.display()))?;
            tar.append_data(&mut header, &rel, source)
                .wrap_err_with(|| format!("failed to append {} to tar", path.display()))?;

            outputs.push(OutputFileChecksum {
                path: rel.to_string_lossy().into_owned(),
                size: metadata.len(),
                blake3,
            });
        }
    }

    let encoder = tar.into_inner().wrap_err("failed to finalize tar stream")?;
    encoder
        .finish()
        .wrap_err("failed to finalize zstd stream")?;

    Ok(outputs)
}

/// BLAKE3-hash a file's contents and return the hex digest.
pub(crate) fn blake3_hash(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).wrap_err_with(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_partitions_records_blake3_per_file() {
        let src = tempfile::tempdir().unwrap();
        let part = src.path().join("engine-finalized_blocks-ordinal");
        fs::create_dir_all(&part).unwrap();
        fs::write(part.join("0000000000000000"), b"hello").unwrap();

        let out = tempfile::tempdir().unwrap();
        let archive = out.path().join("test.tar.zst");
        let outputs = pack_partitions(&archive, src.path(), &[part]).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].size, 5);

        let expected = blake3::hash(b"hello").to_hex().to_string();
        assert_eq!(outputs[0].blake3, expected);
        assert!(archive.exists());
    }
}
