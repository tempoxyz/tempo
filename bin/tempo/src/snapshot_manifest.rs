use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use alloy_primitives::{B256, Bytes};
use clap::{ArgMatches, FromArgMatches, Parser};
use commonware_codec::Encode as _;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::Runner as _;
use eyre::{Context as _, OptionExt, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_commands::download::{
    manifest::SnapshotManifest, manifest_cmd::SnapshotManifestCommand,
};
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_provider::{
    BlockIdReader,
    providers::{BlockchainProvider, ReadOnlyConfig},
};
use serde::{Deserialize, Serialize};
use tempo_chainspec::spec::{TempoChainSpec, chain_value_parser, chainspec_from_chain_id};
use tempo_consensus::{consensus::Digest, find_last_finalized_marker};
use tempo_node::node::TempoNode;
use tempo_telemetry_util::display_duration;

pub(crate) const TEMPO_CONSENSUS_MANIFEST_KEY: &str = "consensus";

type TempoFinalization = Finalization<Scheme<PublicKey, MinSig>, Digest>;
type TempoExecutionProvider = BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TempoConsensusManifest {
    pub(crate) height: u64,
    pub(crate) digest: B256,
    pub(crate) finalization: Bytes,
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
            "reading snapshot finalization. consensus dir: {}, search depth: {}",
            consensus_dir.display(),
            finalization_search_depth,
        );

        let (height, finalization) = find_snapshot_finalization(
            &consensus_dir,
            execution_provider,
            finalization_search_depth,
        )
        .wrap_err("failed to read finalization state")?;

        let digest = finalization.proposal.payload;
        let consensus_manifest = TempoConsensusManifest {
            height,
            digest: digest.0,
            finalization: finalization.encode().into(),
        };

        let manifest_height = manifest.block;
        ensure!(
            manifest_height >= height,
            "finalization marker must be at or below execution"
        );

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

        eprintln!("embedded finalization for height `{height}`; execution=`{manifest_height}`",);
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

fn find_snapshot_finalization(
    consensus_dir: &Path,
    execution_provider: TempoExecutionProvider,
    max_depth: u64,
) -> eyre::Result<(u64, TempoFinalization)> {
    let runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir);

    let tip = execution_provider
        .finalized_block_number()
        .wrap_err("failed to read finalized block number")?
        .ok_or_eyre("no finalized execution state")?;

    let runner = commonware_runtime::tokio::Runner::new(runtime_config);
    runner.start(|context| async move {
        find_last_finalized_marker(&context, &execution_provider, max_depth)
            .await?
            .ok_or_eyre(format!(
                "no finalization marker found; finalized tip `{tip}` with {max_depth} block lookback"
            ))
    })
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
        };

        let value = serde_json::to_value(manifest).unwrap();

        assert_eq!(value["height"], 42);
        assert_eq!(
            value["digest"],
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
        assert_eq!(value["finalization"], "0x000102ff");
    }
}
