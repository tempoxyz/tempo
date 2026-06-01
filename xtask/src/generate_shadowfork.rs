use std::{
    collections::BTreeMap,
    net::SocketAddr,
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

use crate::{
    genesis_args::GenesisArgs,
    shadowfork::{
        SHADOW_CHAINSPEC_FILE, SHADOW_EPOCH, SHADOWFORK_SIGNING_KEY_SECRET,
        parse_snapshot_manifest_url, source_chain_cli_arg,
        write_shadow_chainspec as write_shadow_chainspec_file,
    },
};

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
    /// RPC can provide block metadata, but it cannot reconstruct a complete state snapshot.
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
        let mut shadow_dkg_outcome = consensus_config.to_genesis_dkg_outcome();
        shadow_dkg_outcome.epoch = Epoch::new(SHADOW_EPOCH);
        let shadow_dkg_outcome = const_hex::encode_prefixed(shadow_dkg_outcome.encode());

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
        }

        let manifest = ShadowForkManifest {
            source_chain,
            source_chain_id,
            shadow_chain_id,
            source_rpc_url: rpc_url,
            source_execution_chain,
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
                "For snapshot-backed runs, download the snapshot into each node datadir before running bootstrap-shadowfork for that node; bootstrap writes a shadow chainspec whose epochLength makes the fork block the epoch-0 boundary, patches ValidatorConfigV2 in the local execution DB, and seeds private DKG state for epoch 1."
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
    let path = output.join(SHADOW_CHAINSPEC_FILE);
    write_shadow_chainspec_file(&path, source_chain, source_chain_id, shadow_epoch_length)?;
    Ok(path)
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
}
