//! Finalized Portal snapshots and concurrent operator-RPC cluster snapshots.

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, U64, U256},
    providers::{Provider, ProviderBuilder},
};
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag};
use eyre::{Context as _, ensure, eyre};
use futures::future::{join_all, try_join_all};
use serde::{Deserialize, Serialize};
use tempo_alloy::TempoNetwork;
use tempo_contracts::zones::{ZoneFactory, ZonePortal};
use tokio::time::timeout;
use zone_p2p::ZoneManifest;
use zone_rpc::types::{SequencerInfoResponse, ZoneInfoResponse};

use super::config::{EffectiveConfig, OperatorEndpoint, format_duration};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PortalSnapshot {
    pub finalized_block_number: u64,
    pub finalized_block_hash: B256,
    pub zone_id: u32,
    pub portal: Address,
    pub admin: Address,
    pub sequencers: Vec<Address>,
    pub threshold: u8,
    pub sequencer_set_version: u64,
    pub leader: Address,
    pub leader_epoch: u64,
    pub leader_activation_tempo_block: u64,
    pub zone_height: U256,
    pub last_synced_tempo_block: u64,
    pub block_hash: B256,
    pub zone_gas_rate: u128,
    pub paused: bool,
    pub pause_expiry: u64,
    pub pause_abdication_effective_at: u64,
    pub access_abdication_effective_at: u64,
    pub withdrawal_batch_index: u64,
    pub current_deposit_queue_hash: B256,
    pub enabled_tokens: Vec<Address>,
    pub encryption_key: Option<EncryptionKey>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EncryptionKey {
    pub x: B256,
    pub y_parity: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RpcBlock {
    pub number: U64,
    pub hash: B256,
    pub state_root: B256,
    #[serde(default, alias = "miner")]
    pub miner: Option<Address>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RpcBlockRef {
    pub number: U64,
    pub hash: B256,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NodeSnapshot {
    pub name: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<ZoneInfoResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequencer: Option<SequencerInfoResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_block: Option<RpcBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_block: Option<RpcBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ClusterView {
    pub config: EffectiveConfig,
    pub manifest: Option<ZoneManifest>,
    pub portal: PortalSnapshot,
    pub nodes: Vec<NodeSnapshot>,
}

impl ClusterView {
    pub(crate) async fn collect(
        config: EffectiveConfig,
        rpc_timeout: Duration,
        progress: impl Fn(&str),
    ) -> eyre::Result<Self> {
        if let Some(path) = config.manifest.as_ref() {
            progress(&format!("Loading expected manifest {}...", path.display()));
        } else {
            progress("No expected manifest supplied; checking live consistency only.");
        }
        let manifest = config
            .manifest
            .as_ref()
            .map(ZoneManifest::read_from_file)
            .transpose()
            .wrap_err("failed to load expected Zone manifest")?;

        progress(&format!(
            "Connecting to Tempo L1 at {}...",
            config.l1_rpc_url
        ));
        let l1 = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&config.l1_rpc_url)
            .await
            .wrap_err("failed connecting to Tempo L1 RPC")?;
        progress(&format!(
            "Reading ZoneFactory and Portal at one finalized L1 block (timeout {})...",
            format_duration(rpc_timeout)
        ));
        let portal = timeout(
            rpc_timeout,
            read_portal_snapshot(&l1, config.zone_factory, config.zone_id, config.portal),
        )
        .await
        .map_err(|_| eyre!("timed out reading finalized Portal state"))??;
        progress(&format!(
            "Finalized Portal snapshot received at L1 block {}.",
            portal.finalized_block_number
        ));

        progress(&format!(
            "Querying {} operator RPC(s) concurrently (timeout {} per endpoint)...",
            config.nodes.len(),
            format_duration(rpc_timeout)
        ));
        let mut nodes = query_nodes(&config.nodes, rpc_timeout).await;
        let responsive_nodes = nodes.iter().filter(|node| node.error.is_none()).count();
        progress(&format!(
            "Operator snapshots received from {responsive_nodes}/{} node(s).",
            nodes.len()
        ));
        let common_height = nodes
            .iter()
            .filter_map(|node| {
                node.sequencer
                    .as_ref()?
                    .local_tip
                    .as_ref()
                    .map(|tip| tip.zone_height.to::<u64>())
            })
            .min();
        if let Some(height) = common_height {
            progress(&format!(
                "Comparing block hash and state root at common Zone height {height}..."
            ));
            query_common_blocks(&mut nodes, height, rpc_timeout).await;
        } else {
            progress("No common Zone height available; canonical-state check will fail.");
        }

        Ok(Self {
            config,
            manifest,
            portal,
            nodes,
        })
    }
}

pub(crate) async fn read_portal_snapshot<P>(
    provider: &P,
    factory_address: Address,
    expected_zone_id: u32,
    expected_portal: Option<Address>,
) -> eyre::Result<PortalSnapshot>
where
    P: Provider<TempoNetwork>,
{
    let finalized: Option<RpcBlockRef> = provider
        .raw_request("eth_getBlockByNumber".into(), ("finalized", false))
        .await
        .wrap_err("failed reading finalized L1 block")?;
    let finalized = finalized.ok_or_else(|| eyre!("Tempo L1 returned no finalized block"))?;
    let block_number = finalized.number.to::<u64>();
    let block_id = BlockId::number(block_number);

    let factory = ZoneFactory::new(factory_address, provider);
    let factory_info = factory
        .zones(expected_zone_id)
        .block(block_id)
        .call()
        .await
        .wrap_err("failed resolving Zone through ZoneFactory")?;
    ensure!(
        !factory_info.portal.is_zero(),
        "ZoneFactory has no Zone {expected_zone_id} at finalized block {block_number}"
    );
    ensure!(
        factory_info.zoneId == expected_zone_id,
        "ZoneFactory returned Zone ID {}, expected {expected_zone_id}",
        factory_info.zoneId
    );
    if let Some(expected) = expected_portal {
        ensure!(
            expected == factory_info.portal,
            "supplied Portal {expected} does not match ZoneFactory Portal {}",
            factory_info.portal
        );
    }

    let portal_address = factory_info.portal;
    let portal = ZonePortal::new(portal_address, provider);
    let zone_id_call = portal.zoneId().block(block_id);
    let admin_call = portal.admin().block(block_id);
    let sequencer_count_call = portal.sequencerCount().block(block_id);
    let threshold_call = portal.sequencerThreshold().block(block_id);
    let version_call = portal.sequencerSetVersion().block(block_id);
    let leader_call = portal.leader().block(block_id);
    let leader_epoch_call = portal.leaderEpoch().block(block_id);
    let leader_activation_call = portal.leaderActivationTempoBlock().block(block_id);
    let zone_height_call = portal.zoneHeight().block(block_id);
    let last_synced_call = portal.lastSyncedTempoBlockNumber().block(block_id);
    let block_hash_call = portal.blockHash().block(block_id);
    let zone_gas_rate_call = portal.zoneGasRate().block(block_id);
    let paused_call = portal.paused().block(block_id);
    let pause_expiry_call = portal.pauseExpiry().block(block_id);
    let pause_abdication_call = portal
        .abdicationEffectiveAt(ZonePortal::Capability::PausePortal)
        .block(block_id);
    let access_abdication_call = portal
        .abdicationEffectiveAt(ZonePortal::Capability::AccessPolicy)
        .block(block_id);
    let withdrawal_batch_call = portal.withdrawalBatchIndex().block(block_id);
    let deposit_queue_call = portal.currentDepositQueueHash().block(block_id);
    let enabled_token_count_call = portal.enabledTokenCount().block(block_id);
    let encryption_key_call = async {
        let key_count = portal.encryptionKeyCount().block(block_id).call().await?;
        if key_count.is_zero() {
            Ok(None)
        } else {
            portal
                .sequencerEncryptionKey()
                .block(block_id)
                .call()
                .await
                .map(Some)
        }
    };
    let (
        zone_id,
        admin,
        sequencer_count,
        threshold,
        sequencer_set_version,
        leader,
        leader_epoch,
        leader_activation_tempo_block,
        zone_height,
        last_synced_tempo_block,
        block_hash,
        zone_gas_rate,
        paused,
        pause_expiry,
        pause_abdication_effective_at,
        access_abdication_effective_at,
        withdrawal_batch_index,
        current_deposit_queue_hash,
        enabled_token_count,
        encryption_key,
    ) = tokio::try_join!(
        zone_id_call.call(),
        admin_call.call(),
        sequencer_count_call.call(),
        threshold_call.call(),
        version_call.call(),
        leader_call.call(),
        leader_epoch_call.call(),
        leader_activation_call.call(),
        zone_height_call.call(),
        last_synced_call.call(),
        block_hash_call.call(),
        zone_gas_rate_call.call(),
        paused_call.call(),
        pause_expiry_call.call(),
        pause_abdication_call.call(),
        access_abdication_call.call(),
        withdrawal_batch_call.call(),
        deposit_queue_call.call(),
        enabled_token_count_call.call(),
        encryption_key_call,
    )
    .wrap_err("failed reading finalized ZonePortal snapshot")?;
    ensure!(
        zone_id == expected_zone_id,
        "Portal reports Zone ID {zone_id}, expected {expected_zone_id}"
    );

    let sequencers = try_join_all((0..sequencer_count.to::<usize>()).map(|index| {
        let portal = &portal;
        async move {
            portal
                .sequencerAt(U256::from(index))
                .block(block_id)
                .call()
                .await
                .wrap_err_with(|| format!("failed reading finalized sequencer index {index}"))
        }
    }))
    .await?;
    let enabled_tokens = try_join_all((0..enabled_token_count.to::<usize>()).map(|index| {
        let portal = &portal;
        async move {
            portal
                .enabledTokenAt(U256::from(index))
                .block(block_id)
                .call()
                .await
                .wrap_err_with(|| format!("failed reading finalized enabled token index {index}"))
        }
    }))
    .await?;

    let encryption_key = encryption_key
        .filter(|key| !key.x.is_zero())
        .map(|key| {
            let y_parity = key.normalized_y_parity().ok_or_else(|| {
                eyre!(
                    "Portal returned invalid encryption-key yParity {:#x}; expected 0/1 or 0x02/0x03",
                    key.yParity
                )
            })?;
            Ok::<_, eyre::Report>(EncryptionKey {
                x: key.x,
                y_parity,
            })
        })
        .transpose()?;

    Ok(PortalSnapshot {
        finalized_block_number: block_number,
        finalized_block_hash: finalized.hash,
        zone_id,
        portal: portal_address,
        admin,
        sequencers,
        threshold,
        sequencer_set_version,
        leader,
        leader_epoch,
        leader_activation_tempo_block,
        zone_height,
        last_synced_tempo_block,
        block_hash,
        zone_gas_rate,
        paused,
        pause_expiry,
        pause_abdication_effective_at,
        access_abdication_effective_at,
        withdrawal_batch_index,
        current_deposit_queue_hash,
        enabled_tokens,
        encryption_key,
    })
}

pub(crate) async fn query_nodes(
    nodes: &[OperatorEndpoint],
    rpc_timeout: Duration,
) -> Vec<NodeSnapshot> {
    join_all(nodes.iter().map(|endpoint| async move {
        let name = endpoint.display_name().to_owned();
        let url = endpoint.url.clone();
        let result = timeout(rpc_timeout, async {
            let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect(&endpoint.url)
                .await?;
            let zone: ZoneInfoResponse =
                provider.raw_request("zone_getZoneInfo".into(), ()).await?;
            let sequencer: SequencerInfoResponse = provider
                .raw_request("zone_getSequencerInfo".into(), ())
                .await?;
            let latest_block: Option<RpcBlock> = provider
                .raw_request("eth_getBlockByNumber".into(), ("latest", false))
                .await
                .ok()
                .flatten();
            Ok::<_, eyre::Report>((zone, sequencer, latest_block))
        })
        .await;
        match result {
            Ok(Ok((zone, sequencer, latest_block))) => NodeSnapshot {
                name,
                url,
                zone: Some(zone),
                sequencer: Some(sequencer),
                common_block: None,
                latest_block,
                error: None,
            },
            Ok(Err(error)) => NodeSnapshot {
                name,
                url,
                zone: None,
                sequencer: None,
                common_block: None,
                latest_block: None,
                error: Some(format!("{error:#}")),
            },
            Err(_) => NodeSnapshot {
                name,
                url,
                zone: None,
                sequencer: None,
                common_block: None,
                latest_block: None,
                error: Some(format!("timed out after {} ms", rpc_timeout.as_millis())),
            },
        }
    }))
    .await
}

pub(crate) async fn query_common_blocks(
    nodes: &mut [NodeSnapshot],
    height: u64,
    rpc_timeout: Duration,
) {
    let requests = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.error.is_none())
        .map(|(index, node)| {
            let url = node.url.clone();
            async move {
                let result = timeout(rpc_timeout, async {
                    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                        .connect(&url)
                        .await?;
                    let block: Option<RpcBlock> = provider
                        .raw_request(
                            "eth_getBlockByNumber".into(),
                            (BlockNumberOrTag::Number(height), false),
                        )
                        .await?;
                    block.ok_or_else(|| eyre!("block {height} not found"))
                })
                .await;
                (index, result)
            }
        });
    for (index, result) in join_all(requests).await {
        let node = &mut nodes[index];
        match result {
            Ok(Ok(block)) => node.common_block = Some(block),
            Ok(Err(error)) => node.error = Some(format!("common block query failed: {error:#}")),
            Err(_) => {
                node.error = Some(format!(
                    "common block query timed out after {} ms",
                    rpc_timeout.as_millis()
                ))
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn test_node_snapshot(name: &str, sequencer: SequencerInfoResponse) -> NodeSnapshot {
    NodeSnapshot {
        name: name.to_owned(),
        url: format!("http://{name}.example"),
        zone: Some(ZoneInfoResponse {
            zone_id: U64::from(1),
            is_access_enforced: false,
            is_gateway_open: false,
            zone_tokens: Vec::new(),
            sequencers: Vec::new(),
            chain_id: U64::from(1),
            tempo_block_number: U64::from(1),
        }),
        sequencer: Some(sequencer),
        common_block: None,
        latest_block: None,
        error: None,
    }
}

#[cfg(test)]
pub(crate) fn test_sequencer_info(
    rpc_only: bool,
    ready_for_promotion: bool,
) -> SequencerInfoResponse {
    SequencerInfoResponse {
        mode: "multi".to_owned(),
        portal: Address::ZERO,
        manifest_zone_id: None,
        manifest_sequencer_set_version: None,
        manifest_membership_digest: None,
        decryption_keys: None,
        local: Some(zone_rpc::types::LocalSequencerInfo {
            name: "node".to_owned(),
            sequencer_address: (!rpc_only).then_some(Address::ZERO),
            p2p_public_key: "00".to_owned(),
            role: if rpc_only {
                "follower".to_owned()
            } else {
                "leader".to_owned()
            },
        }),
        active_leader: None,
        local_tip: None,
        peers: vec![zone_rpc::types::SequencerPeerInfo {
            name: "node".to_owned(),
            sequencer_address: (!rpc_only).then_some(Address::ZERO),
            rpc_only,
            is_local: true,
            tip: None,
        }],
        progress: Some(zone_rpc::types::SequencerProgress {
            zone_height: U64::from(1),
            tempo_block_number: U64::from(1),
            latest_observed_leadership_epoch: None,
            locally_applied_leadership_epoch: None,
            pending_transitions: U64::from(0),
        }),
        readiness: Some(zone_rpc::types::SequencerReadiness {
            ready_for_promotion,
            reasons: if ready_for_promotion {
                Vec::new()
            } else {
                vec!["rpc-only nodes cannot get promoted".to_owned()]
            },
        }),
    }
}
