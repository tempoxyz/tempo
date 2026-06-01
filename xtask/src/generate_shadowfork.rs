use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
};
use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::Signer as _;
use eyre::{Context as _, OptionExt as _, ensure, eyre};
use rand_08::SeedableRng as _;
use reth_network_peers::pk2id;
use secp256k1::SECP256K1;
use serde::Serialize;
use tempo_contracts::precompiles::VALIDATOR_CONFIG_V2_ADDRESS;
use tempo_precompiles::validator_config_v2::VALIDATOR_NS_ADD;
use tempo_validator_config::ValidatorConfig;

use crate::genesis_args::GenesisArgs;

const SHADOWFORK_SIGNING_KEY_SECRET: &str = "tempo-shadowfork-signing-key-secret";
const SHADOW_CHAINSPEC_FILE: &str = "shadowfork-chain.json";
const SHADOW_EPOCH: u64 = 1;

/// Generates artifacts for a private shadow fork from a live Tempo block.
///
/// The command intentionally performs only one upstream read at preparation time. The resulting
/// network is expected to run private consensus from the generated artifacts and not follow the
/// source chain after startup.
#[derive(Debug, clap::Parser)]
pub(crate) struct GenerateShadowfork {
    /// The target directory that will be populated.
    ///
    /// If this directory exists but is not empty the operation will fail unless `--force`
    /// is specified. In this case the target directory will be first cleaned.
    #[arg(long, short, value_name = "DIR")]
    output: PathBuf,

    /// Whether to overwrite `output`.
    #[arg(long)]
    force: bool,

    /// Human-readable source chain name recorded in the manifest.
    #[arg(long, default_value = "custom")]
    source_chain: String,

    /// RPC endpoint for the source chain.
    #[arg(long)]
    rpc_url: String,

    /// Source block to fork from: `latest`, a decimal block number, or a block hash.
    #[arg(long, default_value = "latest")]
    block: BlockTarget,

    /// Snapshot v2 manifest URL for the source block state.
    ///
    /// RPC can provide block metadata, but it cannot reconstruct a complete state snapshot. The
    /// generated artifacts include a prepare-state script that downloads the files referenced by
    /// this manifest into each node datadir.
    #[arg(long = "snapshot-url", alias = "snapshot-manifest-url")]
    snapshot_manifest_url: Option<String>,

    /// Keep the source chain ID in the generated genesis.
    #[arg(long, conflicts_with = "chain_id")]
    preserve_chain_id: bool,

    #[clap(flatten)]
    genesis_args: GenesisArgs,
}

impl GenerateShadowfork {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let Self {
            output,
            force,
            source_chain,
            rpc_url,
            block,
            snapshot_manifest_url,
            preserve_chain_id,
            mut genesis_args,
        } = self;

        prepare_output_dir(&output, force)?;

        let provider = ProviderBuilder::new()
            .connect(&rpc_url)
            .await
            .wrap_err("failed to connect to source RPC")?;

        let source_chain_id = provider
            .get_chain_id()
            .await
            .wrap_err("failed to fetch source chain id")?;

        if preserve_chain_id {
            genesis_args.set_chain_id(source_chain_id);
        }

        let source_block = block
            .fetch(&provider)
            .await
            .wrap_err("failed to fetch source block")?;
        if let Some(snapshot) = snapshot_manifest_url
            .as_deref()
            .and_then(parse_snapshot_manifest_url)
        {
            ensure!(
                snapshot.chain_id == source_chain_id,
                "snapshot manifest is for chain `{}`, but source RPC reported chain `{source_chain_id}`",
                snapshot.chain_id,
            );
            ensure!(
                snapshot.block_number == source_block.number,
                "snapshot manifest is for block `{}`, but --block resolved to `{}`; rerun with --block {} or use a matching snapshot",
                snapshot.block_number,
                source_block.number,
                snapshot.block_number,
            );
        }

        let seed = genesis_args.seed;
        let shadow_chain_id = genesis_args.chain_id();
        let validator_onchain_addresses = genesis_args
            .validator_onchain_addresses()
            .wrap_err("failed resolving shadow validator onchain addresses")?;
        let (genesis, consensus_config) = genesis_args
            .generate_genesis()
            .await
            .wrap_err("failed to generate shadow genesis")?;
        let consensus_config = consensus_config
            .ok_or_eyre("no consensus config generated; did you provide --validators?")?;

        let mut rng =
            rand_08::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand_08::random::<u64>));
        let mut trusted_peers = vec![];

        let mut node_outputs = vec![];
        for (idx, validator) in consensus_config.validators.iter().enumerate() {
            let (execution_p2p_signing_key, execution_p2p_identity) = {
                let (sk, pk) = SECP256K1.generate_keypair(&mut rng);
                (sk, pk2id(&pk))
            };

            let consensus_p2p_port = validator.addr.port();
            let execution_p2p_port = consensus_p2p_port + 1;
            let validator_address = validator_onchain_addresses[idx];
            let fee_recipient = validator_address;
            let validator_public_key: B256 = validator
                .public_key()
                .encode()
                .as_ref()
                .try_into()
                .expect("ed25519 public keys are 32 bytes");
            let validator_config = ValidatorConfig {
                chain_id: source_chain_id,
                validator_address,
                public_key: validator_public_key,
                ingress: validator.addr,
                egress: validator.addr.ip(),
            };
            let message = validator_config.add_validator_message_hash(fee_recipient);
            let validator_add_signature = const_hex::encode_prefixed(
                validator
                    .signing_key
                    .clone()
                    .into_inner()
                    .sign(VALIDATOR_NS_ADD, message.as_slice())
                    .encode(),
            );

            trusted_peers.push(format!(
                "enode://{execution_p2p_identity:x}@{}",
                SocketAddr::new(validator.addr.ip(), execution_p2p_port),
            ));

            node_outputs.push(NodeOutput {
                index: idx,
                validator_addr: validator.addr,
                validator_public_key,
                validator_address,
                fee_recipient,
                validator_add_signature,
                consensus_p2p_port,
                consensus_metrics_port: consensus_p2p_port + 2,
                execution_p2p_port,
                authrpc_port: execution_p2p_port + 2,
                execution_p2p_disc_key: execution_p2p_signing_key.display_secret().to_string(),
                execution_p2p_identity: format!("{execution_p2p_identity:x}"),
            });
        }
        let allow_private_ips =
            should_allow_private_ips(node_outputs.iter().map(|node| node.validator_addr.ip()));

        let genesis_dst = output.join("genesis.json");
        let genesis_ser = serde_json::to_string_pretty(&genesis)
            .wrap_err("failed serializing genesis as json")?;
        let shadow_validator_config_v2_storage = extract_validator_config_v2_storage(&genesis_ser)?;
        std::fs::write(&genesis_dst, &genesis_ser)
            .wrap_err_with(|| format!("failed writing genesis to `{}`", genesis_dst.display()))?;

        let source_execution_chain = if snapshot_manifest_url.is_some() {
            let source_execution_chain =
                source_chain_cli_arg(&source_chain, source_chain_id).ok_or_else(|| {
                    eyre!(
                        "snapshot-backed shadow forks must use a built-in source chain; \
                         expected one of mainnet, presto, moderato, testnet, or dev, got `{source_chain}`"
                    )
                })?;
            Some(source_execution_chain.to_string())
        } else {
            None
        };
        let shadow_epoch_length = source_block
            .number
            .checked_add(1)
            .ok_or_eyre("fork block number overflowed shadow epoch length")?;
        let shadow_chainspec_path = if snapshot_manifest_url.is_some() {
            Some(write_shadow_chainspec(
                &output,
                &source_chain,
                source_chain_id,
                shadow_epoch_length,
            )?)
        } else {
            None
        };
        let execution_chain = if snapshot_manifest_url.is_some() {
            format!("\"${{SCRIPT_DIR}}/{SHADOW_CHAINSPEC_FILE}\"")
        } else {
            "\"${SCRIPT_DIR}/genesis.json\"".to_string()
        };
        let mut shadow_dkg_outcome = consensus_config.to_genesis_dkg_outcome();
        shadow_dkg_outcome.epoch = Epoch::new(SHADOW_EPOCH);
        let shadow_dkg_outcome = const_hex::encode_prefixed(shadow_dkg_outcome.encode());

        let mut commands = render_script_header();
        for (validator, node) in consensus_config.validators.iter().zip(node_outputs.iter()) {
            let target_dir = node.dir(&output);
            std::fs::create_dir(&target_dir).wrap_err_with(|| {
                format!(
                    "failed creating target directory to store validator specific keys at `{}`",
                    target_dir.display()
                )
            })?;

            let signing_key_dst = target_dir.join("signing.key");
            validator
                .signing_key
                .write_to_file_encrypted(
                    &signing_key_dst,
                    tempo_commonware_node_config::SigningKeyPassphrase::from(
                        SHADOWFORK_SIGNING_KEY_SECRET,
                    ),
                )
                .wrap_err_with(|| {
                    format!(
                        "failed writing signing key to `{}`",
                        signing_key_dst.display()
                    )
                })?;

            let signing_share_dst = target_dir.join("signing.share");
            std::fs::write(&signing_share_dst, validator.signing_share.to_string()).wrap_err_with(
                || {
                    format!(
                        "failed writing signing share to `{}`",
                        signing_share_dst.display()
                    )
                },
            )?;

            let enode_key_dst = target_dir.join("enode.key");
            std::fs::write(&enode_key_dst, &node.execution_p2p_disc_key).wrap_err_with(|| {
                format!("failed writing enode key to `{}`", enode_key_dst.display())
            })?;

            let enode_identity_dst = target_dir.join("enode.identity");
            std::fs::write(&enode_identity_dst, &node.execution_p2p_identity).wrap_err_with(
                || {
                    format!(
                        "failed writing enode identity to `{}`",
                        enode_identity_dst.display()
                    )
                },
            )?;

            let script_datadir = format!("\"${{SCRIPT_DIR}}/node-{}\"", node.index);
            let script_consensus_datadir =
                format!("\"${{SCRIPT_DIR}}/node-{}/consensus\"", node.index);
            let script_signing_key = format!("\"${{SCRIPT_DIR}}/node-{}/signing.key\"", node.index);
            let script_signing_share =
                format!("\"${{SCRIPT_DIR}}/node-{}/signing.share\"", node.index);
            let script_enode_key = format!("\"${{SCRIPT_DIR}}/node-{}/enode.key\"", node.index);

            let command = render_run_command(RunCommand {
                chain: &execution_chain,
                datadir: &script_datadir,
                consensus_datadir: &script_consensus_datadir,
                trusted_peers: &trusted_peers,
                allow_private_ips,
                signing_key: &script_signing_key,
                signing_share: &script_signing_share,
                execution_p2p_secret_key: &script_enode_key,
                node,
            });
            commands.push_str(&format!("# node-{}\n{command}\n\n", node.index));
        }
        commands.push_str(&render_script_footer());

        let commands_dst = output.join("run.sh");
        std::fs::write(&commands_dst, commands)
            .wrap_err_with(|| format!("failed writing commands to `{}`", commands_dst.display()))?;
        mark_executable(&commands_dst)?;

        let prepare_state_script = if let Some(snapshot_manifest_url) = &snapshot_manifest_url {
            let script_dst = output.join("prepare-state.sh");
            let script = render_prepare_state_script(
                snapshot_manifest_url,
                source_execution_chain
                    .as_deref()
                    .expect("source execution chain must be set for snapshot-backed artifacts"),
                &node_outputs,
            );
            std::fs::write(&script_dst, script).wrap_err_with(|| {
                format!(
                    "failed writing state preparation script to `{}`",
                    script_dst.display()
                )
            })?;
            mark_executable(&script_dst)?;
            Some("prepare-state.sh".to_string())
        } else {
            None
        };

        let bootstrap_script = if snapshot_manifest_url.is_some() {
            let script_dst = output.join("bootstrap-shadowfork.sh");
            let script = render_bootstrap_script();
            std::fs::write(&script_dst, script).wrap_err_with(|| {
                format!(
                    "failed writing shadow fork bootstrap script to `{}`",
                    script_dst.display()
                )
            })?;
            mark_executable(&script_dst)?;
            Some("bootstrap-shadowfork.sh".to_string())
        } else {
            None
        };

        let manifest = ShadowForkManifest {
            source_chain,
            source_chain_id,
            shadow_chain_id,
            source_rpc_url: rpc_url,
            source_execution_chain,
            execution_chain,
            fork_block_number: source_block.number,
            fork_block_hash: source_block.hash,
            fork_parent_hash: source_block.parent_hash,
            fork_state_root: source_block.state_root,
            fork_timestamp: source_block.timestamp,
            shadow_epoch: SHADOW_EPOCH,
            shadow_epoch_length,
            shadow_dkg_outcome,
            shadow_validator_config_v2_storage,
            shadow_chainspec: shadow_chainspec_path
                .as_ref()
                .map(|_| SHADOW_CHAINSPEC_FILE.to_string()),
            snapshot_manifest_url,
            prepare_state_script,
            bootstrap_script,
            created_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .wrap_err("system clock is before UNIX epoch")?
                .as_secs(),
            validator_count: node_outputs.len(),
            validators: node_outputs,
            notes: vec![
                "This is a one-shot shadow fork preparation; generated nodes must not use --follow."
                    .to_string(),
                "Snapshot-backed runs use the source chainspec for execution because the downloaded database keeps the source genesis hash."
                    .to_string(),
                "On each node host, run prepare-state.sh for that node index, then run bootstrap-shadowfork.sh --node-index <index>; bootstrap writes a shadow chainspec whose epochLength makes the fork block the epoch-0 boundary, patches ValidatorConfigV2 in the local execution DB, and seeds private DKG state for epoch 1."
                    .to_string(),
                "Generated run commands disable public bootnode discovery with --tempo.bootnodes-endpoint none."
                    .to_string(),
            ],
        };

        let manifest_dst = output.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)
            .wrap_err("failed serializing manifest as json")?;
        std::fs::write(&manifest_dst, manifest_json).wrap_err_with(|| {
            format!(
                "failed writing shadow fork manifest to `{}`",
                manifest_dst.display()
            )
        })?;

        println!("wrote shadow genesis to `{}`", genesis_dst.display());
        if let Some(path) = &shadow_chainspec_path {
            println!("wrote shadow chainspec to `{}`", path.display());
        }
        println!("wrote shadow fork manifest to `{}`", manifest_dst.display());
        println!("wrote run commands to `{}`", commands_dst.display());
        if let Some(script) = &manifest.prepare_state_script {
            println!(
                "wrote state preparation script to `{}`",
                output.join(script).display()
            );
        }
        if let Some(script) = &manifest.bootstrap_script {
            println!(
                "wrote shadow fork bootstrap script to `{}`",
                output.join(script).display()
            );
        }
        if manifest.snapshot_manifest_url.is_none() {
            println!(
                "warning: no --snapshot-url provided; RPC metadata alone is not enough to materialize full fork state"
            );
        }

        Ok(())
    }
}

fn prepare_output_dir(output: &Path, force: bool) -> eyre::Result<()> {
    std::fs::create_dir_all(output)
        .wrap_err_with(|| format!("failed creating target directory at `{}`", output.display()))?;

    if force {
        eprintln!(
            "--force was specified: deleting all files in target directory `{}`",
            output.display()
        );
        std::fs::remove_dir_all(output)
            .and_then(|_| std::fs::create_dir(output))
            .wrap_err_with(|| {
                format!("failed clearing target directory at `{}`", output.display())
            })?;
    } else {
        let target_is_empty = std::fs::read_dir(output)
            .wrap_err_with(|| {
                format!(
                    "failed reading target directory `{}` to determine if it is empty",
                    output.display()
                )
            })?
            .next()
            .is_none();
        ensure!(
            target_is_empty,
            "target directory `{}` is not empty; delete all its contents or rerun command with --force",
            output.display(),
        );
    }

    Ok(())
}

fn write_shadow_chainspec(
    output: &Path,
    source_chain: &str,
    source_chain_id: u64,
    shadow_epoch_length: u64,
) -> eyre::Result<PathBuf> {
    let mut genesis = source_genesis_json(source_chain, source_chain_id)?;
    let config = genesis
        .get_mut("config")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_eyre("source genesis JSON does not contain an object at `config`")?;
    config.insert(
        "epochLength".to_string(),
        serde_json::Value::from(shadow_epoch_length),
    );

    let path = output.join(SHADOW_CHAINSPEC_FILE);
    let json = serde_json::to_string_pretty(&genesis)
        .wrap_err("failed serializing shadow chainspec JSON")?;
    std::fs::write(&path, json)
        .wrap_err_with(|| format!("failed writing shadow chainspec to `{}`", path.display()))?;
    Ok(path)
}

fn source_genesis_json(
    source_chain: &str,
    source_chain_id: u64,
) -> eyre::Result<serde_json::Value> {
    let genesis = match source_chain.to_ascii_lowercase().as_str() {
        "mainnet" | "presto" => include_str!("../../crates/chainspec/src/genesis/presto.json"),
        "moderato" | "testnet" => include_str!("../../crates/chainspec/src/genesis/moderato.json"),
        "dev" => include_str!("../../crates/chainspec/src/genesis/dev.json"),
        _ if source_chain_id == 4217 => {
            include_str!("../../crates/chainspec/src/genesis/presto.json")
        }
        _ if source_chain_id == 42431 => {
            include_str!("../../crates/chainspec/src/genesis/moderato.json")
        }
        _ => {
            return Err(eyre!(
                "cannot infer source chainspec for source_chain `{source_chain}` and chain id `{source_chain_id}`"
            ));
        }
    };

    serde_json::from_str(genesis).wrap_err("failed parsing bundled source genesis JSON")
}

fn extract_validator_config_v2_storage(
    genesis_json: &str,
) -> eyre::Result<BTreeMap<String, String>> {
    let genesis: serde_json::Value =
        serde_json::from_str(genesis_json).wrap_err("failed parsing generated genesis JSON")?;
    let registry_address = VALIDATOR_CONFIG_V2_ADDRESS.to_string().to_ascii_lowercase();
    let storage = genesis
        .get("alloc")
        .and_then(serde_json::Value::as_object)
        .and_then(|alloc| alloc.get(&registry_address))
        .and_then(|account| account.get("storage"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            eyre!(
                "generated genesis does not contain ValidatorConfigV2 storage at `{registry_address}`"
            )
        })?;

    storage
        .iter()
        .map(|(slot, value)| {
            Ok((
                slot.clone(),
                value
                    .as_str()
                    .ok_or_else(|| {
                        eyre!("generated ValidatorConfigV2 storage value is not a string")
                    })?
                    .to_string(),
            ))
        })
        .collect()
}

#[cfg(unix)]
fn mark_executable(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = std::fs::metadata(path)
        .wrap_err_with(|| format!("failed reading metadata for `{}`", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
        .wrap_err_with(|| format!("failed marking `{}` executable", path.display()))
}

#[cfg(not(unix))]
fn mark_executable(_path: &Path) -> eyre::Result<()> {
    Ok(())
}

#[derive(Clone, Debug)]
enum BlockTarget {
    Latest,
    Number(u64),
    Hash(B256),
}

impl FromStr for BlockTarget {
    type Err = eyre::Report;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("latest") {
            return Ok(Self::Latest);
        }

        if let Ok(number) = value.parse::<u64>() {
            return Ok(Self::Number(number));
        }

        if value.starts_with("0x") {
            return Ok(Self::Hash(value.parse().wrap_err_with(|| {
                format!("failed parsing block hash `{value}`")
            })?));
        }

        Err(eyre!(
            "invalid block target `{value}`; expected `latest`, a decimal block number, or a 0x-prefixed block hash"
        ))
    }
}

impl BlockTarget {
    async fn fetch<P>(&self, provider: &P) -> eyre::Result<SourceBlock>
    where
        P: Provider,
    {
        let block = match self {
            Self::Latest => {
                let latest = provider
                    .get_block_number()
                    .await
                    .wrap_err("failed to fetch latest block number")?;
                provider
                    .get_block_by_number(latest.into())
                    .await
                    .wrap_err_with(|| format!("failed to fetch latest block `{latest}`"))?
                    .ok_or_else(|| eyre!("latest block `{latest}` not found"))?
            }
            Self::Number(number) => provider
                .get_block_by_number((*number).into())
                .await
                .wrap_err_with(|| format!("failed to fetch block number `{number}`"))?
                .ok_or_else(|| eyre!("block number `{number}` not found"))?,
            Self::Hash(hash) => provider
                .get_block_by_hash(*hash)
                .await
                .wrap_err_with(|| format!("failed to fetch block hash `{hash}`"))?
                .ok_or_else(|| eyre!("block hash `{hash}` not found"))?,
        };

        Ok(SourceBlock {
            number: block.header.number,
            hash: block.header.hash,
            parent_hash: block.header.inner.parent_hash,
            state_root: block.header.inner.state_root,
            timestamp: block.header.inner.timestamp,
        })
    }
}

#[derive(Debug)]
struct SourceBlock {
    number: u64,
    hash: B256,
    parent_hash: B256,
    state_root: B256,
    timestamp: u64,
}

#[derive(Debug, Serialize)]
struct ShadowForkManifest {
    source_chain: String,
    source_chain_id: u64,
    shadow_chain_id: u64,
    source_rpc_url: String,
    source_execution_chain: Option<String>,
    execution_chain: String,
    fork_block_number: u64,
    fork_block_hash: B256,
    fork_parent_hash: B256,
    fork_state_root: B256,
    fork_timestamp: u64,
    shadow_epoch: u64,
    shadow_epoch_length: u64,
    shadow_dkg_outcome: String,
    shadow_validator_config_v2_storage: BTreeMap<String, String>,
    shadow_chainspec: Option<String>,
    snapshot_manifest_url: Option<String>,
    prepare_state_script: Option<String>,
    bootstrap_script: Option<String>,
    created_at_unix_secs: u64,
    validator_count: usize,
    validators: Vec<NodeOutput>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NodeOutput {
    index: usize,
    validator_addr: SocketAddr,
    validator_public_key: B256,
    validator_address: Address,
    fee_recipient: Address,
    validator_add_signature: String,
    consensus_p2p_port: u16,
    consensus_metrics_port: u16,
    execution_p2p_port: u16,
    authrpc_port: u16,
    execution_p2p_disc_key: String,
    execution_p2p_identity: String,
}

impl NodeOutput {
    fn dir(&self, output: &Path) -> PathBuf {
        output.join(format!("node-{}", self.index))
    }
}

struct RunCommand<'a> {
    chain: &'a str,
    datadir: &'a str,
    consensus_datadir: &'a str,
    trusted_peers: &'a [String],
    allow_private_ips: bool,
    signing_key: &'a str,
    signing_share: &'a str,
    execution_p2p_secret_key: &'a str,
    node: &'a NodeOutput,
}

fn render_run_command(args: RunCommand<'_>) -> String {
    let consensus_listen_addr =
        consensus_listen_addr(args.node.validator_addr, args.node.consensus_p2p_port);
    let allow_private_ips = if args.allow_private_ips {
        "\\\n--consensus.allow-private-ips "
    } else {
        ""
    };
    format!(
        "run_tempo node \
        \\\n--consensus.signing-key {signing_key} \
        \\\n--consensus.secret <(printf '%s\\n' '{signing_key_secret}') \
        \\\n--consensus.signing-share {signing_share} \
        \\\n--consensus.listen-address {consensus_listen_addr} \
        {allow_private_ips}\
        \\\n--consensus.metrics-address 127.0.0.1:{metrics_port} \
        \\\n--consensus.datadir {consensus_datadir} \
        \\\n--chain {chain} \
        \\\n--datadir {datadir} \
        \\\n--trusted-peers {trusted_peers} \
        \\\n--port {execution_p2p_port} \
        \\\n--discovery.port {execution_p2p_port} \
        \\\n--p2p-secret-key {execution_p2p_secret_key} \
        \\\n--authrpc.port {authrpc_port} \
        \\\n--tempo.bootnodes-endpoint none &\nPIDS+=(\"$!\")",
        signing_key = args.signing_key,
        signing_key_secret = SHADOWFORK_SIGNING_KEY_SECRET,
        signing_share = args.signing_share,
        consensus_listen_addr = consensus_listen_addr,
        allow_private_ips = allow_private_ips,
        metrics_port = args.node.consensus_metrics_port,
        consensus_datadir = args.consensus_datadir,
        chain = args.chain,
        datadir = args.datadir,
        trusted_peers = args.trusted_peers.join(","),
        execution_p2p_port = args.node.execution_p2p_port,
        execution_p2p_secret_key = args.execution_p2p_secret_key,
        authrpc_port = args.node.authrpc_port,
    )
}

fn consensus_listen_addr(advertised_addr: SocketAddr, listen_port: u16) -> SocketAddr {
    if advertised_addr.ip().is_loopback() {
        return SocketAddr::new(advertised_addr.ip(), listen_port);
    }

    match advertised_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listen_port),
    }
}

fn should_allow_private_ips(ips: impl IntoIterator<Item = IpAddr>) -> bool {
    ips.into_iter().any(is_private_or_loopback)
}

fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn source_chain_cli_arg(source_chain: &str, source_chain_id: u64) -> Option<&'static str> {
    match source_chain.to_ascii_lowercase().as_str() {
        "mainnet" | "presto" => Some("mainnet"),
        "moderato" | "testnet" => Some("moderato"),
        "dev" => Some("dev"),
        _ if source_chain_id == 4217 => Some("mainnet"),
        _ if source_chain_id == 42431 => Some("moderato"),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SnapshotManifestInfo {
    chain_id: u64,
    block_number: u64,
}

fn parse_snapshot_manifest_url(url: &str) -> Option<SnapshotManifestInfo> {
    let path = url.split_once('?').map_or(url, |(path, _)| path);
    for segment in path
        .split('/')
        .filter(|segment| segment.starts_with("tempo-"))
    {
        let mut parts = segment.split('-');
        if parts.next()? != "tempo" {
            continue;
        }

        let (Some(chain_id), Some(block_number)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(chain_id), Ok(block_number)) = (chain_id.parse(), block_number.parse()) else {
            continue;
        };

        return Some(SnapshotManifestInfo {
            chain_id,
            block_number,
        });
    }
    None
}

fn render_script_header() -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${TEMPO_BIN:-}" ]]; then
  TEMPO_CMD=("$TEMPO_BIN")
else
  TEMPO_CMD=(cargo run --bin tempo --)
fi

run_tempo() {
  "${TEMPO_CMD[@]}" "$@"
}

PIDS=()

shutdown_nodes() {
  local status="$1"
  trap - INT TERM
  if ((${#PIDS[@]})); then
    kill "${PIDS[@]}" 2>/dev/null || true
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
  exit "$status"
}

trap 'shutdown_nodes 130' INT
trap 'shutdown_nodes 143' TERM

"#
    .to_string()
}

fn render_script_footer() -> String {
    r#"echo "started ${#PIDS[@]} nodes; press Ctrl-C to stop"
wait "${PIDS[@]}"
"#
    .to_string()
}

fn render_prepare_state_script(
    snapshot_manifest_url: &str,
    source_execution_chain: &str,
    nodes: &[NodeOutput],
) -> String {
    let mut script = String::new();
    script.push_str("#!/usr/bin/env bash\n");
    script.push_str("set -euo pipefail\n\n");
    script.push_str(&format!(
        "SNAPSHOT_MANIFEST_URL={}\n",
        shell_single_quote(snapshot_manifest_url)
    ));
    script.push_str(&format!(
        "SOURCE_EXECUTION_CHAIN={}\n",
        shell_single_quote(source_execution_chain)
    ));
    script.push_str("SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n");
    script.push_str(
        r#"if [[ -n "${TEMPO_BIN:-}" ]]; then
  TEMPO_CMD=("$TEMPO_BIN")
else
  TEMPO_CMD=(cargo run --bin tempo --)
fi

"#,
    );
    script.push_str("NODES=(\n");
    for node in nodes {
        script.push_str(&format!(
            "  {}\n",
            shell_single_quote(&format!("node-{}", node.index))
        ));
    }
    script.push_str(")\n\n");
    script.push_str(
        r#"if (($#)); then
  NODES=()
  for node in "$@"; do
    if [[ "$node" == node-* ]]; then
      NODES+=("$node")
    else
      NODES+=("node-$node")
    fi
  done
fi

"#,
    );
    script.push_str("CHAIN_ARGS=(--chain \"$SOURCE_EXECUTION_CHAIN\")\n\n");
    script.push_str("for node in \"${NODES[@]}\"; do\n");
    script.push_str("  mkdir -p \"$SCRIPT_DIR/$node\"\n");
    script.push_str("  \"${TEMPO_CMD[@]}\" download \\\n");
    script.push_str("    --datadir \"$SCRIPT_DIR/$node\" \\\n");
    script.push_str("    \"${CHAIN_ARGS[@]}\" \\\n");
    script.push_str("    --manifest-url \"$SNAPSHOT_MANIFEST_URL\" \\\n");
    script.push_str("    --archive \\\n");
    script.push_str("    --non-interactive \\\n");
    script.push_str("    --force\n");
    script.push_str("done\n\n");
    script.push_str("echo \"snapshot v2 downloaded into ${#NODES[@]} node datadirs\"\n");
    script
}

fn render_bootstrap_script() -> String {
    r#"#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cargo run -p tempo-xtask -- bootstrap-shadowfork --manifest "$SCRIPT_DIR/manifest.json" "$@"
"#
    .to_string()
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_block_targets() {
        assert!(matches!(
            "latest".parse::<BlockTarget>().unwrap(),
            BlockTarget::Latest
        ));
        assert!(matches!(
            "42".parse::<BlockTarget>().unwrap(),
            BlockTarget::Number(42)
        ));
        assert!(
            "0x1111111111111111111111111111111111111111111111111111111111111111"
                .parse::<BlockTarget>()
                .is_ok()
        );
        assert!("finalized".parse::<BlockTarget>().is_err());
    }

    #[test]
    fn maps_source_chain_to_execution_chain() {
        assert_eq!(source_chain_cli_arg("mainnet", 0), Some("mainnet"));
        assert_eq!(source_chain_cli_arg("presto", 0), Some("mainnet"));
        assert_eq!(source_chain_cli_arg("moderato", 0), Some("moderato"));
        assert_eq!(source_chain_cli_arg("testnet", 0), Some("moderato"));
        assert_eq!(source_chain_cli_arg("dev", 0), Some("dev"));
        assert_eq!(source_chain_cli_arg("custom", 4217), Some("mainnet"));
        assert_eq!(source_chain_cli_arg("custom", 42431), Some("moderato"));
        assert_eq!(source_chain_cli_arg("custom", 1), None);
    }

    #[test]
    fn parses_snapshot_manifest_url() {
        assert_eq!(
            parse_snapshot_manifest_url(
                "https://tempo-node-snapshots.tempoxyz.dev/tempo-42431-20230873-1780289911/manifest.json"
            ),
            Some(SnapshotManifestInfo {
                chain_id: 42431,
                block_number: 20230873,
            })
        );
        assert_eq!(
            parse_snapshot_manifest_url("https://example.com/manifest.json"),
            None
        );
    }

    #[test]
    fn run_command_disables_public_bootnodes() {
        let node = NodeOutput {
            index: 0,
            validator_addr: "127.0.0.1:7000".parse().unwrap(),
            validator_public_key: B256::ZERO,
            validator_address: Address::ZERO,
            fee_recipient: Address::ZERO,
            validator_add_signature: "0x".into(),
            consensus_p2p_port: 7000,
            consensus_metrics_port: 7002,
            execution_p2p_port: 7001,
            authrpc_port: 7003,
            execution_p2p_disc_key: "abc".into(),
            execution_p2p_identity: "def".into(),
        };
        let command = render_run_command(RunCommand {
            chain: "mainnet",
            datadir: "node-0",
            consensus_datadir: "node-0/consensus",
            trusted_peers: &["enode://peer@127.0.0.1:7001".into()],
            allow_private_ips: true,
            signing_key: "node-0/signing.key",
            signing_share: "node-0/signing.share",
            execution_p2p_secret_key: "node-0/enode.key",
            node: &node,
        });

        assert!(render_script_header().contains("TEMPO_CMD=(cargo run --bin tempo --)"));
        assert!(command.starts_with("run_tempo node"));
        assert!(command.contains("--chain mainnet"));
        assert!(command.contains("--consensus.listen-address 127.0.0.1:7000"));
        assert!(command.contains("--consensus.allow-private-ips"));
        assert!(command.contains("--consensus.datadir node-0/consensus"));
        assert!(command.contains("--tempo.bootnodes-endpoint none &"));
        assert!(command.contains("PIDS+=(\"$!\")"));
        assert!(render_script_header().contains("PIDS=()"));
        assert!(render_script_header().contains("trap 'shutdown_nodes 130' INT"));
        assert!(render_script_footer().contains("wait \"${PIDS[@]}\""));
        assert!(!command.contains("$TEMPO_BIN node"));
        assert!(!command.contains("--follow"));
    }

    #[test]
    fn run_command_binds_non_loopback_validators_on_unspecified_interface() {
        let node = NodeOutput {
            index: 0,
            validator_addr: "10.0.1.10:7000".parse().unwrap(),
            validator_public_key: B256::ZERO,
            validator_address: Address::ZERO,
            fee_recipient: Address::ZERO,
            validator_add_signature: "0x".into(),
            consensus_p2p_port: 7000,
            consensus_metrics_port: 7002,
            execution_p2p_port: 7001,
            authrpc_port: 7003,
            execution_p2p_disc_key: "abc".into(),
            execution_p2p_identity: "def".into(),
        };
        let command = render_run_command(RunCommand {
            chain: "mainnet",
            datadir: "node-0",
            consensus_datadir: "node-0/consensus",
            trusted_peers: &["enode://peer@10.0.1.10:7001".into()],
            allow_private_ips: true,
            signing_key: "node-0/signing.key",
            signing_share: "node-0/signing.share",
            execution_p2p_secret_key: "node-0/enode.key",
            node: &node,
        });

        assert!(command.contains("--consensus.listen-address 0.0.0.0:7000"));
        assert!(command.contains("--consensus.allow-private-ips"));
    }

    #[test]
    fn prepare_state_script_uses_tempo_download_per_node() {
        let nodes = vec![
            NodeOutput {
                index: 0,
                validator_addr: "127.0.0.1:7000".parse().unwrap(),
                validator_public_key: B256::ZERO,
                validator_address: Address::ZERO,
                fee_recipient: Address::ZERO,
                validator_add_signature: "0x".into(),
                consensus_p2p_port: 7000,
                consensus_metrics_port: 7002,
                execution_p2p_port: 7001,
                authrpc_port: 7003,
                execution_p2p_disc_key: "abc".into(),
                execution_p2p_identity: "def".into(),
            },
            NodeOutput {
                index: 1,
                validator_addr: "127.0.0.1:7100".parse().unwrap(),
                validator_public_key: B256::ZERO,
                validator_address: Address::ZERO,
                fee_recipient: Address::ZERO,
                validator_add_signature: "0x".into(),
                consensus_p2p_port: 7100,
                consensus_metrics_port: 7102,
                execution_p2p_port: 7101,
                authrpc_port: 7103,
                execution_p2p_disc_key: "abc".into(),
                execution_p2p_identity: "def".into(),
            },
        ];
        let script = render_prepare_state_script(
            "https://example.com/a'b/manifest.json",
            "moderato",
            &nodes,
        );

        assert!(
            script.contains("SNAPSHOT_MANIFEST_URL='https://example.com/a'\"'\"'b/manifest.json'")
        );
        assert!(script.contains("'node-0'"));
        assert!(script.contains("'node-1'"));
        assert!(script.contains("SOURCE_EXECUTION_CHAIN='moderato'"));
        assert!(script.contains("CHAIN_ARGS=(--chain \"$SOURCE_EXECUTION_CHAIN\")"));
        assert!(script.contains("TEMPO_CMD=(cargo run --bin tempo --)"));
        assert!(script.contains("\"${TEMPO_CMD[@]}\" download"));
        assert!(script.contains("--manifest-url \"$SNAPSHOT_MANIFEST_URL\""));
        assert!(script.contains("--datadir \"$SCRIPT_DIR/$node\""));
        assert!(script.contains("--archive"));
    }
}
