use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use clap::{ArgMatches, FromArgMatches, Parser};
use eyre::{Context as _, Result, bail, eyre};
use reth_cli_commands::download::{
    DownloadCommand,
    manifest::{ComponentManifest, OutputFileChecksum, SingleArchive, SnapshotManifest},
};
use reth_cli_runner::CliRunner;
use tar::Archive;
use tempo_chainspec::spec::TempoChainSpecParser;
use zstd::Decoder as ZstdDecoder;

use crate::snapshot_manifest::{CL_COMPONENT_KEYS, blake3_hash};

#[derive(Debug, Parser)]
#[command(
    name = "download",
    about = "Downloads snapshot archives produced by `tempo snapshot-manifest`."
)]
pub(crate) struct Args {
    #[command(flatten)]
    inner: DownloadCommand<TempoChainSpecParser>,

    /// Skip the downloading consensus archives
    #[arg(long)]
    skip_consensus: bool,

    /// Consensus storage directory. If not set, this will be dirived from --datadir.
    #[arg(long = "consensus.datadir", value_name = "PATH")]
    consensus_datadir: Option<PathBuf>,
}

pub(crate) fn run(matches: &ArgMatches) -> Result<()> {
    let args = Args::from_arg_matches(matches).map_err(|e| eyre!("{e}"))?;

    let datadir = matches
        .get_raw("datadir")
        .and_then(|mut v| v.next())
        .map(PathBuf::from)
        .expect("--datadir must be set");

    let manifest_url = matches.get_one::<String>("manifest_url").cloned();
    let manifest_path = matches.get_one::<PathBuf>("manifest_path").cloned();

    let runner = CliRunner::try_default_runtime().wrap_err("failed to build obtain runtime")?;
    runner.block_on(async move {
        eprintln!("running execution layer download...");

        let start = Instant::now();
        args.inner
            .execute::<tempo_node::node::TempoNode>()
            .await
            .wrap_err("execution layer download failed")?;

        eprintln!("execution layer download finished in {:?}", start.elapsed());

        if args.skip_consensus {
            eprintln!("--skip-consensus set. skipping consensus layer");
            return Ok(());
        }

        let consensus_dir = args
            .consensus_datadir
            .unwrap_or_else(|| datadir.join("consensus"));

        let manifest = load_manifest(manifest_url.clone(), manifest_path.clone()).await?;
        let archive_source = resolve_archive_source(manifest_url, manifest_path, &manifest)?;

        let start = Instant::now();
        download_consensus(&consensus_dir, manifest, archive_source)
            .await
            .wrap_err("consensus layer download failed")?;

        eprintln!("consensus layer download finished in {:?}", start.elapsed());
        Ok(())
    })
}

async fn download_consensus(
    consensus_dir: &Path,
    manifest: SnapshotManifest,
    archive_source: ArchiveSource,
) -> Result<()> {
    fs::create_dir_all(&consensus_dir).wrap_err("failed to create consensus dir")?;
    for &key in CL_COMPONENT_KEYS {
        let comp = manifest
            .components
            .get(key)
            .ok_or_else(|| eyre!("manifest is missing required CL component `{key}`"))?;

        let SingleArchive {
            file,
            size,
            output_files,
            ..
        } = match comp {
            ComponentManifest::Single(a) => a,
            ComponentManifest::Chunked(_) => {
                bail!("`{key}` is not a SingleArchive; manifest format mismatch")
            }
        };

        let start = Instant::now();
        if all_outputs_present(consensus_dir, output_files)? {
            eprintln!("`{key}`: already present, skipping",);
            continue;
        }

        eprintln!("`{key}`: fetching {file} ({size} bytes)...",);

        let bytes = archive_source.fetch(file).await?;
        extract_and_verify(consensus_dir, &bytes, output_files)
            .wrap_err_with(|| format!("failed extracting/verifying `{key}` archive"))?;

        eprintln!("`{key}`: extracted in {:?}", start.elapsed());
    }
    Ok(())
}

#[derive(Debug)]
enum ArchiveSource {
    Local(PathBuf),
    Remote {
        base_url: String,
        client: reqwest::Client,
    },
}

impl ArchiveSource {
    async fn fetch(&self, file_name: &str) -> Result<Vec<u8>> {
        match self {
            Self::Local(dir) => {
                let path = dir.join(file_name);
                fs::read(&path).wrap_err_with(|| format!("failed to read {}", path.display()))
            }
            Self::Remote { base_url, client } => {
                let url = if base_url.ends_with('/') {
                    format!("{base_url}{file_name}")
                } else {
                    format!("{base_url}/{file_name}")
                };
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .wrap_err_with(|| format!("failed GET {url}"))?
                    .error_for_status()
                    .wrap_err_with(|| format!("non-2xx response from {url}"))?;
                let bytes = resp
                    .bytes()
                    .await
                    .wrap_err_with(|| format!("failed reading body from {url}"))?;
                Ok(bytes.to_vec())
            }
        }
    }
}

/// Check whether every entry in `expected` already exists under `target_dir`
fn all_outputs_present(target_dir: &Path, expected: &[OutputFileChecksum]) -> Result<bool> {
    for f in expected {
        let path = target_dir.join(&f.path);
        let Ok(metadata) = fs::metadata(&path) else {
            return Ok(false);
        };

        if metadata.len() != f.size {
            return Ok(false);
        }

        if blake3_hash(&path)? != f.blake3 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Decompress + untar `archive_bytes` into `target_dir`
fn extract_and_verify(
    target_dir: &Path,
    archive_bytes: &[u8],
    expected: &[OutputFileChecksum],
) -> Result<usize> {
    let zstd = ZstdDecoder::new(archive_bytes).wrap_err("failed to init zstd decoder")?;
    Archive::new(zstd)
        .unpack(target_dir)
        .wrap_err("failed to unpack archive")?;

    for OutputFileChecksum { size, path, blake3 } in expected {
        let target = target_dir.join(path);
        let metadata = fs::metadata(&target).wrap_err("failed extracting file metadata")?;
        if metadata.len() != *size {
            bail!("size mismatch: expected {size}, got {}", metadata.len(),);
        }

        if blake3_hash(&target)? != *blake3 {
            bail!("BLAKE3 mismatch");
        }
    }
    Ok(expected.len())
}

async fn load_manifest(
    manifest_url: Option<String>,
    manifest_path: Option<PathBuf>,
) -> Result<SnapshotManifest> {
    if let Some(path) = manifest_path {
        let bytes = fs::read(path).wrap_err("failed to read manifest file")?;
        return serde_json::from_slice(&bytes).wrap_err("failed to parse manifest.json");
    }

    if let Some(url) = manifest_url {
        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .send()
            .await
            .wrap_err("failed to fetch from manifest url")?
            .error_for_status()
            .wrap_err("invalid response from manifest url")?;
        let bytes = resp
            .bytes()
            .await
            .wrap_err("failed to parse manifest from url")?;

        return serde_json::from_slice(&bytes).wrap_err("failed to parse manifest.json");
    }

    bail!("--manifest-url or --manifest-path must be set")
}

fn resolve_archive_source(
    manifest_url: Option<String>,
    manifest_path: Option<PathBuf>,
    manifest: &SnapshotManifest,
) -> Result<ArchiveSource> {
    if let Some(base) = &manifest.base_url {
        return Ok(ArchiveSource::Remote {
            base_url: base.clone(),
            client: reqwest::Client::new(),
        });
    }

    if let Some(path) = manifest_path {
        let parent = path
            .parent()
            .ok_or_else(|| eyre!("manifest path has no parent: {}", path.display()))?;

        return Ok(ArchiveSource::Local(parent.to_path_buf()));
    }

    if let Some(url) = &manifest_url {
        let last_slash = url
            .rfind('/')
            .ok_or_else(|| eyre!("manifest URL `{url}` has no `/` to derive a base from"))?;

        let base = url[..last_slash].to_string();
        return Ok(ArchiveSource::Remote {
            base_url: base,
            client: reqwest::Client::new(),
        });
    }

    bail!("--manifest-url or --manifest-path must be set");
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs::File};

    use super::*;

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
    fn resolve_archive_source_prefers_manifest_base_url() {
        let manifest = SnapshotManifest {
            block: 0,
            chain_id: 1,
            storage_version: 2,
            timestamp: 0,
            base_url: Some("https://from-manifest".into()),
            reth_version: None,
            components: BTreeMap::new(),
        };
        match resolve_archive_source(
            Some("https://other/dir/manifest.json".to_string()),
            None,
            &manifest,
        )
        .unwrap()
        {
            ArchiveSource::Remote { base_url, .. } => assert_eq!(base_url, "https://from-manifest"),
            other => panic!("expected remote, got {other:?}"),
        }
    }

    #[test]
    fn resolve_archive_source_falls_back_to_manifest_path_parent() {
        let manifest = SnapshotManifest {
            block: 0,
            chain_id: 1,
            storage_version: 2,
            timestamp: 0,
            base_url: None,
            reth_version: None,
            components: BTreeMap::new(),
        };
        match resolve_archive_source(
            None,
            Some(PathBuf::from("/snap/dir/manifest.json")),
            &manifest,
        )
        .unwrap()
        {
            ArchiveSource::Local(dir) => assert_eq!(dir, Path::new("/snap/dir")),
            other => panic!("expected local, got {other:?}"),
        }
    }

    #[test]
    fn extract_and_verify_round_trip_against_pack_partitions() {
        // Build a tiny .tar.zst with one file using the same shape as
        // snapshot_manifest::pack_partitions, then extract and verify.
        use blake3;
        use tar::{Builder as TarBuilder, Header};
        use zstd::Encoder as ZstdEncoder;

        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("test.tar.zst");
        let payload = b"hello world";
        let path_in_archive = "engine-application-metadata/6c656674";

        // Pack.
        {
            let file = File::create(&archive_path).unwrap();
            let mut enc = ZstdEncoder::new(file, 0).unwrap();
            enc.include_checksum(true).unwrap();
            let mut tar = TarBuilder::new(enc);
            let mut header = Header::new_gnu();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            tar.append_data(&mut header, path_in_archive, &payload[..])
                .unwrap();
            let enc = tar.into_inner().unwrap();
            enc.finish().unwrap();
        }

        let archive_bytes = fs::read(&archive_path).unwrap();
        let expected = vec![OutputFileChecksum {
            path: path_in_archive.into(),
            size: payload.len() as u64,
            blake3: blake3::hash(payload).to_hex().to_string(),
        }];

        let target = tempfile::tempdir().unwrap();
        let extracted = extract_and_verify(target.path(), &archive_bytes, &expected).unwrap();
        assert_eq!(extracted, 1);

        let on_disk = fs::read(target.path().join(path_in_archive)).unwrap();
        assert_eq!(on_disk, payload);
        assert!(all_outputs_present(target.path(), &expected).unwrap());
    }
}
