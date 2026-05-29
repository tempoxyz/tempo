use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use alloy_consensus::Sealable;
use alloy_primitives::hex;
use clap::{ArgMatches, FromArgMatches, Parser};
use commonware_codec::Encode as _;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::Runner as _;
use eyre::{Context as _, OptionExt, Result, bail, ensure};
use reth_chainspec::EthChainSpec;
use reth_cli_commands::download::{
    manifest::SnapshotManifest, manifest_cmd::SnapshotManifestCommand,
};
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_provider::{
    BlockReader as _,
    providers::{BlockchainProvider, ReadOnlyConfig},
};
use serde::{Deserialize, Serialize};
use tempo_chainspec::{TempoChainSpec, spec::chainspec_from_chain_id};
use tempo_commonware_node::consensus::Digest;
use tempo_node::node::TempoNode;
use tempo_telemetry_util::display_duration;

pub(crate) const TEMPO_CONSENSUS_MANIFEST_KEY: &str = "consensus";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TempoConsensusManifest {
    pub(crate) finalization: String,
}

#[derive(Debug, Parser)]
#[command(
    name = "snapshot-manifest",
    about = "Generate snapshot archives and a manifest for the EL plus consensus floor certificate."
)]
pub(crate) struct Args {
    #[command(flatten)]
    inner: SnapshotManifestCommand,

    /// Skip encoding consensus state
    #[arg(long, default_value_t = true)]
    skip_consensus: bool,

    /// Consensus storage directory. If not set, this will be dirived from --datadir.
    #[arg(long)]
    consensus_source_dir: Option<PathBuf>,

    /// Chain spec override for local/unknown chains (mainnet, testnet, moderato, or path to
    /// chainspec file). Resolved automatically from the RPC chain id when omitted.
    #[arg(long, short, value_parser = tempo_chainspec::spec::chain_value_parser)]
    chain: Option<Arc<TempoChainSpec>>,
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
        let chainspec = self.chain;

        fs::create_dir_all(output_dir)
            .wrap_err_with(|| format!("failed to create output dir: {output_dir:?}"))?;

        eprintln!("packaging execution layer");

        let start = Instant::now();
        self.inner
            .execute()
            .wrap_err("reth snapshot-manifest (EL packaging) failed")?;

        eprintln!(
            "execution layer snapshot finished in {}",
            display_duration(start.elapsed())
        );

        if self.skip_consensus {
            eprintln!("--skip-consensus set. skipping consensus layer");
            return Ok(());
        }

        let manifest_path = output_dir.join("manifest.json");
        let manifest_bytes = fs::read(&manifest_path)
            .wrap_err_with(|| format!("failed to read {manifest_path:?}"))?;
        let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
            .wrap_err("failed to parse manifest.json produced by reth snapshot-manifest")?;

        eprintln!("reading snapshot block and finalization {}", manifest.block);

        let chainspec = match chainspec {
            None => chainspec_from_chain_id(manifest.chain_id).ok_or_eyre(format!(
                "unknown chain id {}, pass --chain explicitly",
                manifest.chain_id
            ))?,
            Some(spec) if spec.chain_id() == manifest.chain_id => spec,
            Some(spec) => bail!(
                "mismatch in --chain id {} and manifest chain id {}",
                spec.chain_id(),
                manifest.chain_id
            ),
        };

        let block = execution_provider(chainspec, source_datadir)?
            .block_by_number(manifest.block)
            .wrap_err("failed to read block")?
            .ok_or_eyre("missing block")?;

        let consensus_dir = self
            .consensus_source_dir
            .unwrap_or_else(|| source_datadir.join("consensus"));

        let finalization = read_finalization_at_height(manifest.block, &consensus_dir)?;
        let block_digest = Digest(block.hash_slow());
        let finalization_digest = finalization.proposal.payload;
        ensure!(
            finalization_digest == block_digest,
            format!("digest mismatch. Finalized: {finalization_digest}, Execution: {block_digest}")
        );

        let mut manifest_json =
            serde_json::to_value(&manifest).wrap_err("failed to serialize merged manifest")?;

        manifest_json
            .as_object_mut()
            .ok_or_eyre("serialized manifest was not a JSON object")?
            .insert(
                TEMPO_CONSENSUS_MANIFEST_KEY.to_string(),
                serde_json::to_value(TempoConsensusManifest {
                    finalization: hex::encode(finalization.encode()),
                })
                .wrap_err("failed to serialize Tempo consensus manifest extension")?,
            );

        let manifest_json = serde_json::to_string_pretty(&manifest_json)
            .wrap_err("failed to serialize manifest")?;
        fs::write(&manifest_path, manifest_json)
            .wrap_err_with(|| format!("failed to write {manifest_path:?}"))?;

        eprintln!("finalization encoded in snapshot manifest");
        Ok(())
    }
}

fn read_finalization_at_height(
    height: u64,
    consensus_dir: &Path,
) -> Result<Finalization<Scheme<PublicKey, MinSig>, Digest>> {
    ensure!(
        consensus_dir.is_dir(),
        format!("consensus dir does not exist: {consensus_dir:?}")
    );

    let runtime_config =
        commonware_runtime::tokio::Config::default().with_storage_directory(consensus_dir);

    let runner = commonware_runtime::tokio::Runner::new(runtime_config);
    let finalization = runner
        .start(|context| async move {
            tempo_commonware_node::storage::read_finalization_at_height(&context, height).await
        })
        .wrap_err("failed to read finalization certificate")?;

    finalization.ok_or_eyre("no finalization certificate")
}

fn execution_provider(
    chainspec: Arc<TempoChainSpec>,
    source_datadir: &Path,
) -> eyre::Result<BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>> {
    let runner = CliRunner::try_default_runtime().wrap_err("failed to fetch execution runtime")?;

    let read_cfg = ReadOnlyConfig::from_datadir(source_datadir);
    let factory = TempoNode::provider_factory_builder()
        .open_read_only(chainspec, read_cfg, runner.runtime())
        .wrap_err("failed to open execution")?;

    let provider =
        BlockchainProvider::new(factory).wrap_err("failed to create execution provider")?;

    Ok(provider)
}
