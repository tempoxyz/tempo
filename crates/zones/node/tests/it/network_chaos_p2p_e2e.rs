//! End-to-end coverage for P2P link failures and latency.
//!
//! Every peer-to-peer connection crosses a controllable TCP proxy. Unlike restart tests, the
//! nodes, their transaction pools, and their role generations stay alive while links fail.

use std::{collections::HashSet, time::Duration};

use alloy::{
    consensus::BlockHeader as _,
    eips::{BlockId, BlockNumberOrTag},
    primitives::{Address, B256, U256},
    providers::Provider as _,
};
use alloy_network::ReceiptResponse as _;
use tempo_zone_contracts::{TEMPO_STATE_ADDRESS, TempoState, ZONE_TOKEN_ADDRESS, ZonePortal};

use crate::utils::{
    P2pChaosNetwork, RealP2pCluster, ZoneAccount, batch_count, poll_until,
    start_real_p2p_network_chaos_cluster,
};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const L1_BLOCK_TIME: Duration = Duration::from_millis(250);
const P2P_LATENCY: Duration = Duration::from_millis(400);
const L1_LATENCY: Duration = Duration::from_millis(500);
const RECOVERY_GAP: u64 = 6;
const INITIAL_DEPOSIT: u128 = 10_000_000;
const WITHDRAWAL_AMOUNT: u128 = 250_000;

const OUTGOING_LEADER: usize = 0;
const INCOMING_LEADER: usize = 1;
const FOLLOWER: usize = 2;

#[derive(Clone, Copy, Debug)]
enum FaultTiming {
    BeforeHandoff,
    OutgoingLeaderBeforeActivation,
}

#[derive(Clone, Copy, Debug)]
enum FaultPlanes {
    L1,
    P2p,
    Both,
}

impl FaultPlanes {
    const fn disconnects_l1(self) -> bool {
        matches!(self, Self::L1 | Self::Both)
    }

    const fn disconnects_p2p(self) -> bool {
        matches!(self, Self::P2p | Self::Both)
    }
}

#[derive(Clone, Copy, Debug)]
enum ExpectedDuringFault {
    WaitForIncomingLeader,
    ContinueIfActivated,
    ContinueAndSettle,
}

#[derive(Clone, Copy, Debug)]
struct LeadershipFaultCase {
    disconnected_nodes: &'static [usize],
    planes: FaultPlanes,
    timing: FaultTiming,
    expected: ExpectedDuringFault,
}

async fn start_cluster() -> eyre::Result<(
    RealP2pCluster,
    P2pChaosNetwork,
    [crate::utils::TcpChaosProxy; 3],
)> {
    let fixture = start_real_p2p_network_chaos_cluster(4, L1_BLOCK_TIME).await?;
    let cluster = &fixture.0;
    eyre::ensure!(
        cluster.nodes.len() == 3,
        "P2P network-chaos fixture must start three nodes"
    );

    // The bootstrap leader waits for peer tip evidence before promotion. Reaching a common block
    // proves the proxy mesh carries authenticated traffic before a fault is introduced.
    cluster.nodes[0]
        .wait_for_block_number(1, NETWORK_TIMEOUT)
        .await?;
    let head = cluster.nodes[0].provider().get_block_number().await?;
    cluster.wait_all_at(head, NETWORK_TIMEOUT).await?;
    cluster.assert_same_block(head).await?;
    Ok(fixture)
}

async fn synchronized_head(cluster: &RealP2pCluster) -> eyre::Result<u64> {
    let head = cluster.nodes[0].provider().get_block_number().await?;
    cluster.wait_all_at(head, NETWORK_TIMEOUT).await?;
    cluster.assert_same_block(head).await?;
    Ok(head)
}

async fn wait_for_p2p_lag(
    cluster: &RealP2pCluster,
    leading: usize,
    lagging: usize,
) -> eyre::Result<()> {
    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "the disconnected incoming leader to fall behind",
        || async {
            let leading_height = cluster.nodes[leading].provider().get_block_number().await?;
            let lagging_height = cluster.nodes[lagging].provider().get_block_number().await?;
            Ok((leading_height >= lagging_height.saturating_add(RECOVERY_GAP)).then_some(()))
        },
    )
    .await
}

async fn rotate_leadership(cluster: &RealP2pCluster, target_index: usize) -> eyre::Result<u64> {
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    let previous_epoch = portal.leaderEpoch().call().await?;
    let target = cluster
        .attestation_signers
        .get(target_index)
        .ok_or_else(|| eyre::eyre!("leadership target node {target_index} does not exist"))?
        .address();

    // Relay through A's operator RPC so this follows the same guarded, finalized-L1 path used by
    // an operator handoff. The target's connectivity is irrelevant to submitting the rotation.
    let response: serde_json::Value = cluster.nodes[0]
        .provider()
        .raw_request("zone_setLeader".into(), [target])
        .await?;
    eyre::ensure!(
        response.get("status").and_then(serde_json::Value::as_str) == Some("submitted"),
        "leadership rotation to node {target_index} was not submitted: {response}"
    );
    Ok(previous_epoch + 1)
}

async fn submit_leadership_rotation_direct(
    cluster: &RealP2pCluster,
    target_index: usize,
) -> eyre::Result<(u64, u64)> {
    let provider = cluster.l1.admin_provider();
    let portal = ZonePortal::new(cluster.portal_address, &provider);
    let previous_epoch = portal.leaderEpoch().call().await?;
    let target = cluster
        .attestation_signers
        .get(target_index)
        .ok_or_else(|| eyre::eyre!("leadership target node {target_index} does not exist"))?
        .address();

    let receipt = portal
        .setLeader(target, previous_epoch)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "leadership rotation transaction reverted");

    let epoch = portal.leaderEpoch().call().await?;
    let activation_tempo_block = portal.leaderActivationTempoBlock().call().await?;
    eyre::ensure!(
        epoch == previous_epoch + 1,
        "leadership epoch did not advance after direct submission"
    );
    Ok((epoch, activation_tempo_block))
}

async fn wait_for_leadership_epoch(
    cluster: &RealP2pCluster,
    nodes: &[usize],
    expected_epoch: u64,
    description: &str,
) -> eyre::Result<()> {
    poll_until(NETWORK_TIMEOUT, POLL_INTERVAL, description, || async {
        Ok(nodes
            .iter()
            .all(|&index| {
                cluster.nodes[index]
                    .leadership()
                    .latest()
                    .is_some_and(|state| state.epoch() >= expected_epoch)
            })
            .then_some(()))
    })
    .await
}

async fn wait_for_producer_block(
    cluster: &RealP2pCluster,
    producer_index: usize,
    after_height: u64,
    description: &str,
) -> eyre::Result<u64> {
    let producer = cluster
        .attestation_signers
        .get(producer_index)
        .ok_or_else(|| eyre::eyre!("producer node {producer_index} does not exist"))?
        .address();
    poll_until(NETWORK_TIMEOUT, POLL_INTERVAL, description, || async {
        let height = cluster.nodes[producer_index]
            .provider()
            .get_block_number()
            .await?;
        if height <= after_height {
            return Ok(None);
        }
        let block = cluster.nodes[producer_index]
            .provider()
            .get_block_by_number(BlockNumberOrTag::Number(height))
            .await?;
        Ok(block
            .filter(|block| block.header.beneficiary() == producer)
            .map(|_| height))
    })
    .await
}

async fn wait_for_settlement_after(
    portal: &ZonePortal::ZonePortalInstance<alloy::providers::DynProvider>,
    height: u64,
) -> eyre::Result<u64> {
    let settled: U256 = poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        &format!("a batch beyond zone height {height} to settle"),
        || async {
            let settled = portal.zoneHeight().call().await?;
            Ok((settled > U256::from(height)).then_some(settled))
        },
    )
    .await?;
    settled
        .try_into()
        .map_err(|_| eyre::eyre!("settled zone height does not fit in u64"))
}

async fn assert_batch_history_is_canonical(
    cluster: &RealP2pCluster,
    portal: &ZonePortal::ZonePortalInstance<alloy::providers::DynProvider>,
) -> eyre::Result<u64> {
    let events = portal
        .BatchSubmitted_1_filter()
        .from_block(0)
        .query()
        .await?;
    eyre::ensure!(!events.is_empty(), "no batches were submitted");

    let mut indices = HashSet::with_capacity(events.len());
    let mut hashes = HashSet::with_capacity(events.len());
    for (offset, (event, _)) in events.iter().enumerate() {
        eyre::ensure!(
            indices.insert(event.withdrawalBatchIndex),
            "duplicate settlement batch index {}",
            event.withdrawalBatchIndex
        );
        eyre::ensure!(
            hashes.insert(event.nextBlockHash),
            "conflicting settlement reused zone block hash {}",
            event.nextBlockHash
        );
        if let Some((previous, _)) = offset.checked_sub(1).map(|index| &events[index]) {
            eyre::ensure!(
                event.withdrawalBatchIndex == previous.withdrawalBatchIndex + 1,
                "settlement batch indices are not contiguous: {} followed {}",
                event.withdrawalBatchIndex,
                previous.withdrawalBatchIndex
            );
        }
    }

    // Read both Portal fields at the same L1 block. A new settlement can land while the Zone
    // nodes are catching up; comparing a height captured before that settlement with the latest
    // hash afterwards would report a false fork.
    let l1_block = cluster.l1.provider().get_block_number().await?;
    let block_id = BlockId::number(l1_block);
    let settled_height: u64 = portal
        .zoneHeight()
        .block(block_id)
        .call()
        .await?
        .try_into()
        .map_err(|_| eyre::eyre!("settled zone height does not fit in u64"))?;
    let settled_hash = portal.blockHash().block(block_id).call().await?;
    cluster.wait_all_at(settled_height, NETWORK_TIMEOUT).await?;
    let canonical = cluster.assert_same_block(settled_height).await?;
    eyre::ensure!(
        settled_hash == canonical.hash,
        "Portal settled hash is not canonical at zone height {settled_height}"
    );
    Ok(settled_height)
}

async fn disconnect_leadership_case(
    network: &P2pChaosNetwork,
    l1_proxies: &[crate::utils::TcpChaosProxy; 3],
    case: LeadershipFaultCase,
) -> eyre::Result<[u64; 3]> {
    let accepted_before_outage =
        std::array::from_fn(|index| l1_proxies[index].accepted_connections());

    if case.planes.disconnects_l1() {
        for &index in case.disconnected_nodes {
            l1_proxies[index].disconnect();
        }
        for &index in case.disconnected_nodes {
            l1_proxies[index]
                .wait_for_no_connections(NETWORK_TIMEOUT)
                .await?;
        }
    }
    if case.planes.disconnects_p2p() {
        network.disconnect_nodes(case.disconnected_nodes);
        network
            .wait_for_nodes_disconnected(case.disconnected_nodes, NETWORK_TIMEOUT)
            .await?;
    }

    Ok(accepted_before_outage)
}

async fn resume_leadership_case(
    network: &P2pChaosNetwork,
    l1_proxies: &[crate::utils::TcpChaosProxy; 3],
    accepted_before_outage: [u64; 3],
    case: LeadershipFaultCase,
) -> eyre::Result<()> {
    // Restore the P2P mesh first. An outgoing leader may produce its remaining pre-activation
    // blocks as soon as L1 returns, and those live broadcasts must not be lost while peers are
    // still reconnecting.
    if case.planes.disconnects_p2p() {
        network.resume_nodes(case.disconnected_nodes);
        network
            .wait_for_nodes_connected(case.disconnected_nodes, NETWORK_TIMEOUT)
            .await?;
    }
    if case.planes.disconnects_l1() {
        for &index in case.disconnected_nodes {
            l1_proxies[index].resume();
        }
        for &index in case.disconnected_nodes {
            l1_proxies[index]
                .wait_for_connections_after(accepted_before_outage[index], 1, NETWORK_TIMEOUT)
                .await?;
        }
    }
    Ok(())
}

/// A canonical zone block together with the Tempo anchor it embeds.
///
/// Zone heights and Tempo anchors are unrelated quantities: the offset between them depends on
/// how many L1 blocks preceded the zone's genesis anchor. The anchor is therefore read from the
/// block's own post-state, never derived from its height.
#[derive(Clone, Copy, Debug)]
struct AnchoredBlock {
    height: u64,
    hash: B256,
    producer: Address,
    anchor: u64,
}

impl std::fmt::Display for AnchoredBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "zone height {} (hash {}, Tempo anchor {}, producer {})",
            self.height, self.hash, self.anchor, self.producer
        )
    }
}

/// Reads the block at `height` on one node together with the Tempo anchor it applied.
///
/// The anchor is read at the block's hash rather than its number. Two independent
/// number-addressed reads of a moving head can observe different blocks, which would attribute
/// one block's anchor to another block's hash.
async fn anchored_block(
    cluster: &RealP2pCluster,
    node_index: usize,
    height: u64,
) -> eyre::Result<AnchoredBlock> {
    let provider = cluster.nodes[node_index].provider();
    let header = provider
        .get_block_by_number(BlockNumberOrTag::Number(height))
        .await?
        .ok_or_else(|| eyre::eyre!("node {node_index} is missing zone block {height}"))?
        .header;
    let anchor = TempoState::new(TEMPO_STATE_ADDRESS, provider)
        .tempoBlockNumber()
        .block(BlockId::hash(header.hash))
        .call()
        .await?;
    Ok(AnchoredBlock {
        height,
        hash: header.hash,
        producer: header.beneficiary(),
        anchor,
    })
}

/// Reads a node's current canonical tip with the Tempo anchor it applied.
async fn anchored_tip(cluster: &RealP2pCluster, node_index: usize) -> eyre::Result<AnchoredBlock> {
    let height = cluster.nodes[node_index]
        .provider()
        .get_block_number()
        .await?;
    anchored_block(cluster, node_index, height).await
}

/// Reads the Tempo anchor at which `expected_epoch` takes effect from the Portal.
///
/// `leaderEpoch` and `leaderActivationTempoBlock` are separate slots, so both are read at one
/// pinned L1 block: a rotation landing between the two reads would otherwise pair an epoch with
/// a boundary that does not belong to it.
async fn activation_anchor_for_epoch(
    cluster: &RealP2pCluster,
    portal: &ZonePortal::ZonePortalInstance<alloy::providers::DynProvider>,
    expected_epoch: u64,
) -> eyre::Result<u64> {
    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        &format!("the Portal to expose the activation anchor of leadership epoch {expected_epoch}"),
        || async {
            let block_id = BlockId::number(cluster.l1.provider().get_block_number().await?);
            let epoch = portal.leaderEpoch().block(block_id).call().await?;
            if epoch < expected_epoch {
                return Ok(None);
            }
            eyre::ensure!(
                epoch == expected_epoch,
                "Portal leadership epoch {epoch} advanced past the expected epoch {expected_epoch}"
            );
            Ok(Some(
                portal
                    .leaderActivationTempoBlock()
                    .block(block_id)
                    .call()
                    .await?,
            ))
        },
    )
    .await
}

/// Asserts that the connected side of the cluster never crosses the handoff activation boundary
/// while the incoming leader cannot participate.
///
/// Observing the finalized epoch is not the same as having applied the outgoing leader's last
/// block: `LeadershipSchedule::latest` is status only, while production keys off the leader of
/// the locally applied anchor plus one. A connected node can therefore hold the new epoch while
/// still importing canonical blocks that the *outgoing* leader legitimately produced. Only a
/// block anchored at or after `activation_tempo_block` needs the incoming leader's authority, so
/// that boundary — not an arbitrary sampled height — is the safety property under test.
///
/// `connected_nodes` must exclude every node whose links are cut: a P2P-isolated follower cannot
/// advance at all, so including it would assert nothing about quorum acceptance.
async fn assert_handoff_stalls_without_incoming_quorum(
    cluster: &RealP2pCluster,
    portal: &ZonePortal::ZonePortalInstance<alloy::providers::DynProvider>,
    connected_nodes: &[usize],
    disconnected_nodes: &[usize],
    planes: FaultPlanes,
    expected_epoch: u64,
    activation_tempo_block: u64,
) -> eyre::Result<()> {
    eyre::ensure!(
        connected_nodes.contains(&OUTGOING_LEADER) && !connected_nodes.contains(&INCOMING_LEADER),
        "a stalled handoff requires a connected outgoing leader A and an isolated incoming \
         leader B, got connected {connected_nodes:?}"
    );
    let outgoing_producer = cluster.attestation_signers[OUTGOING_LEADER].address();
    let context = format!(
        "leadership epoch {expected_epoch} activates at Tempo anchor {activation_tempo_block}; \
         nodes {disconnected_nodes:?} disconnected on {planes:?}"
    );

    let mut fenced = Vec::with_capacity(connected_nodes.len());
    for &index in connected_nodes {
        let tip = anchored_tip(cluster, index).await?;
        eyre::ensure!(
            tip.anchor < activation_tempo_block,
            "connected node {index} had already crossed the handoff boundary at {tip} before the \
             outage window opened ({context})"
        );
        fenced.push(tip);
    }

    // Keep the observation window: it is what exercises the outage. Old-leader blocks landing
    // inside it are legitimate catch-up, so the window is measured against the activation
    // boundary instead of against an unchanged height.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Read settlement before the closing tips. Any batch observed here is then covered by the
    // pre-handoff blocks verified below, rather than by a tip that may since have advanced.
    let settled_height: u64 = portal
        .zoneHeight()
        .call()
        .await?
        .try_into()
        .map_err(|_| eyre::eyre!("settled zone height does not fit in u64"))?;

    let mut closing_tips = Vec::with_capacity(connected_nodes.len());
    for (&index, &before) in connected_nodes.iter().zip(&fenced) {
        let after = anchored_tip(cluster, index).await?;
        for height in before.height + 1..=after.height {
            let block = anchored_block(cluster, index, height).await?;
            eyre::ensure!(
                block.anchor < activation_tempo_block,
                "connected node {index} applied {block} at or beyond the handoff activation \
                 boundary while incoming leader B could not participate (node started the window \
                 at {before}, reached {after}; {context})"
            );
            eyre::ensure!(
                block.producer == outgoing_producer,
                "connected node {index} applied {block}, which outgoing leader A \
                 ({outgoing_producer}) did not produce, while incoming leader B could not \
                 participate (node started the window at {before}; {context})"
            );
        }
        closing_tips.push(after);
    }

    // Every block up to each closing tip is now a verified pre-handoff block, so an A-era batch
    // still in flight may settle. Anything beyond that bound would be isolated B's private
    // proposal reaching L1.
    let verified_pre_handoff_height = closing_tips
        .iter()
        .map(|tip| tip.height)
        .max()
        .ok_or_else(|| eyre::eyre!("no connected nodes to observe during the outage"))?;
    eyre::ensure!(
        settled_height <= verified_pre_handoff_height,
        "L1 settled zone height {settled_height} beyond the verified pre-handoff tip \
         {verified_pre_handoff_height}, so isolated B's private proposal reached L1 ({context})"
    );

    // Connected nodes must agree on every block they both hold. A shared height is the strongest
    // common point available without waiting for progress the outage may legitimately prevent.
    if connected_nodes.len() > 1 {
        let common_height = closing_tips
            .iter()
            .map(|tip| tip.height)
            .min()
            .expect("closing_tips holds one entry per connected node");
        let reference = anchored_block(cluster, connected_nodes[0], common_height).await?;
        for &index in &connected_nodes[1..] {
            let block = anchored_block(cluster, index, common_height).await?;
            eyre::ensure!(
                block.hash == reference.hash,
                "connected nodes {} and {index} diverge at shared zone height {common_height}: \
                 {reference} against {block} ({context})",
                connected_nodes[0]
            );
        }
    }
    Ok(())
}

async fn handoff_activated_during_fault(cluster: &RealP2pCluster) -> eyre::Result<bool> {
    let a_height_before_wait = cluster.nodes[OUTGOING_LEADER]
        .provider()
        .get_block_number()
        .await?;
    let b_height_before_wait = cluster.nodes[INCOMING_LEADER]
        .provider()
        .get_block_number()
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let b_height_after_wait = cluster.nodes[INCOMING_LEADER]
        .provider()
        .get_block_number()
        .await?;
    eyre::ensure!(
        cluster.nodes[OUTGOING_LEADER]
            .provider()
            .get_block_number()
            .await?
            == a_height_before_wait,
        "outgoing leader A continued producing while isolated from its quorum"
    );
    let b_producer = cluster.attestation_signers[INCOMING_LEADER].address();
    for height in b_height_before_wait + 1..=b_height_after_wait {
        let block = cluster.nodes[INCOMING_LEADER]
            .provider()
            .get_block_by_number(BlockNumberOrTag::Number(height))
            .await?
            .ok_or_else(|| eyre::eyre!("B is missing block {height} from its local chain"))?;
        if block.header.beneficiary() == b_producer {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn assert_handoff_preserves_quorum(
    cluster: &RealP2pCluster,
    portal: &ZonePortal::ZonePortalInstance<alloy::providers::DynProvider>,
    baseline: u64,
    healthy_nodes: &[usize],
    p2p_disconnected_nodes: &[usize],
) -> eyre::Result<u64> {
    eyre::ensure!(
        healthy_nodes.len() == 2 && healthy_nodes.contains(&INCOMING_LEADER),
        "continuing handoff requires B and one healthy follower"
    );
    let b_height = wait_for_producer_block(
        cluster,
        INCOMING_LEADER,
        baseline,
        "B to assume leadership with a healthy 2-of-3 quorum",
    )
    .await?;

    // Require a settlement strictly beyond the first observed B block. This rules out an
    // in-flight A-era submission and proves the remaining B-led quorum formed a new certificate.
    let settled_height = wait_for_settlement_after(portal, b_height).await?;
    for &index in healthy_nodes {
        cluster.nodes[index]
            .wait_for_block_number(settled_height, NETWORK_TIMEOUT)
            .await?;
    }
    let first_block = cluster.nodes[healthy_nodes[0]]
        .provider()
        .get_block_by_number(BlockNumberOrTag::Number(settled_height))
        .await?
        .ok_or_else(|| {
            eyre::eyre!(
                "healthy node {} is missing settled block {settled_height}",
                healthy_nodes[0]
            )
        })?;
    let second_block = cluster.nodes[healthy_nodes[1]]
        .provider()
        .get_block_by_number(BlockNumberOrTag::Number(settled_height))
        .await?
        .ok_or_else(|| {
            eyre::eyre!(
                "healthy node {} is missing settled block {settled_height}",
                healthy_nodes[1]
            )
        })?;
    eyre::ensure!(
        first_block.header.hash == second_block.header.hash,
        "healthy quorum members diverged at settled height {settled_height}"
    );
    eyre::ensure!(
        first_block.header.beneficiary() == cluster.attestation_signers[INCOMING_LEADER].address(),
        "settled block {settled_height} was not produced under leader B"
    );
    for &index in p2p_disconnected_nodes {
        eyre::ensure!(
            cluster.nodes[index].provider().get_block_number().await? < settled_height,
            "P2P-isolated node {index} reached the B-era settlement height"
        );
    }
    Ok(settled_height)
}

async fn assert_stable_b_leadership(cluster: &RealP2pCluster, baseline: u64) -> eyre::Result<u64> {
    let produced_height = wait_for_producer_block(
        cluster,
        INCOMING_LEADER,
        baseline,
        "B to recover and produce a canonical block",
    )
    .await?;
    cluster
        .wait_all_at(produced_height, NETWORK_TIMEOUT)
        .await?;
    let b_producer = cluster.attestation_signers[INCOMING_LEADER].address();
    let header = cluster.assert_same_block(produced_height).await?;
    eyre::ensure!(
        header.beneficiary() == b_producer,
        "canonical recovery block {produced_height} was not produced by B"
    );

    // One further B-produced block proves this was a stable promotion, rather than a transient
    // block observed while the cluster was still reconciling the handoff.
    let next_height = produced_height + 1;
    cluster.nodes[INCOMING_LEADER]
        .wait_for_block_number(next_height, NETWORK_TIMEOUT)
        .await?;
    cluster.wait_all_at(next_height, NETWORK_TIMEOUT).await?;
    let header = cluster.assert_same_block(next_height).await?;
    eyre::ensure!(
        header.beneficiary() == b_producer,
        "B did not retain leadership after recovery at block {next_height}"
    );
    Ok(next_height)
}

async fn run_leadership_fault_case(case: LeadershipFaultCase) -> eyre::Result<()> {
    let (cluster, network, l1_proxies) = start_cluster().await?;
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    eyre::ensure!(
        portal.sequencerThreshold().call().await? == 2,
        "test requires a 2-of-3 settlement quorum"
    );
    let baseline = synchronized_head(&cluster).await?;
    let (expected_epoch, accepted_before_outage) = match case.timing {
        FaultTiming::BeforeHandoff => {
            let accepted = disconnect_leadership_case(&network, &l1_proxies, case).await?;
            if case.planes.disconnects_p2p() && case.disconnected_nodes.contains(&INCOMING_LEADER) {
                wait_for_p2p_lag(&cluster, OUTGOING_LEADER, INCOMING_LEADER).await?;
            }
            let epoch = rotate_leadership(&cluster, INCOMING_LEADER).await?;
            (epoch, accepted)
        }
        FaultTiming::OutgoingLeaderBeforeActivation => {
            eyre::ensure!(
                case.disconnected_nodes == [OUTGOING_LEADER]
                    && matches!(case.planes, FaultPlanes::Both),
                "pre-activation outgoing-leader timing requires disconnecting A from both planes"
            );

            // Hold L1 responses to A while a direct relayer submits the transition. This makes
            // the activation block observable to B and C but impossible for A to consume before
            // its L1 and P2P links are cut.
            l1_proxies[OUTGOING_LEADER].pause_upstream_to_client(true);
            let a_tempo_block = poll_until(
                NETWORK_TIMEOUT,
                POLL_INTERVAL,
                "L1 to advance beyond A's frozen pre-activation anchor",
                || async {
                    let a_tempo_block = cluster.nodes[OUTGOING_LEADER].tempo_block_number().await?;
                    let l1_tip = cluster.l1.provider().get_block_number().await?;
                    Ok((l1_tip > a_tempo_block.saturating_add(1)).then_some(a_tempo_block))
                },
            )
            .await?;
            let (epoch, activation_tempo_block) =
                submit_leadership_rotation_direct(&cluster, INCOMING_LEADER).await?;
            let accepted = disconnect_leadership_case(&network, &l1_proxies, case).await?;
            l1_proxies[OUTGOING_LEADER].pause_upstream_to_client(false);

            let isolated_a_tempo_block =
                cluster.nodes[OUTGOING_LEADER].tempo_block_number().await?;
            eyre::ensure!(
                isolated_a_tempo_block == a_tempo_block,
                "outgoing A advanced from Tempo block {a_tempo_block} to {isolated_a_tempo_block} while L1 responses were paused"
            );
            eyre::ensure!(
                isolated_a_tempo_block.saturating_add(1) < activation_tempo_block,
                "outgoing A was not isolated before its final owned anchor: A is at Tempo block {isolated_a_tempo_block}, activation is {activation_tempo_block}"
            );
            (epoch, accepted)
        }
    };

    let healthy_nodes: Vec<_> = [OUTGOING_LEADER, INCOMING_LEADER, FOLLOWER]
        .into_iter()
        .filter(|index| !case.disconnected_nodes.contains(index))
        .collect();
    wait_for_leadership_epoch(
        &cluster,
        &healthy_nodes,
        expected_epoch,
        "healthy nodes to observe the A→B leadership transition",
    )
    .await?;

    let settled_during_outage = match case.expected {
        ExpectedDuringFault::WaitForIncomingLeader => {
            let activation_tempo_block =
                activation_anchor_for_epoch(&cluster, &portal, expected_epoch).await?;
            assert_handoff_stalls_without_incoming_quorum(
                &cluster,
                &portal,
                &healthy_nodes,
                case.disconnected_nodes,
                case.planes,
                expected_epoch,
                activation_tempo_block,
            )
            .await?;
            None
        }
        ExpectedDuringFault::ContinueIfActivated => {
            if handoff_activated_during_fault(&cluster).await? {
                Some(
                    assert_handoff_preserves_quorum(
                        &cluster,
                        &portal,
                        baseline,
                        &healthy_nodes,
                        if case.planes.disconnects_p2p() {
                            case.disconnected_nodes
                        } else {
                            &[]
                        },
                    )
                    .await?,
                )
            } else {
                None
            }
        }
        ExpectedDuringFault::ContinueAndSettle => Some(
            assert_handoff_preserves_quorum(
                &cluster,
                &portal,
                baseline,
                &healthy_nodes,
                if case.planes.disconnects_p2p() {
                    case.disconnected_nodes
                } else {
                    &[]
                },
            )
            .await?,
        ),
    };

    resume_leadership_case(&network, &l1_proxies, accepted_before_outage, case).await?;
    wait_for_leadership_epoch(
        &cluster,
        &[OUTGOING_LEADER, INCOMING_LEADER, FOLLOWER],
        expected_epoch,
        "reconnected nodes to observe the finalized leadership epoch",
    )
    .await?;

    if let Some(settled_height) = settled_during_outage {
        cluster.wait_all_at(settled_height, NETWORK_TIMEOUT).await?;
        cluster.assert_same_block(settled_height).await?;
    }
    let stable_height = assert_stable_b_leadership(&cluster, baseline).await?;
    if settled_during_outage.is_none() {
        wait_for_settlement_after(&portal, stable_height).await?;
        assert_batch_history_is_canonical(&cluster, &portal).await?;
    }
    Ok(())
}

macro_rules! leadership_fault_tests {
    ($($(#[$doc:meta])* $test_name:ident => $case:expr),+ $(,)?) => {
        $(
            $(#[$doc])*
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $test_name() -> eyre::Result<()> {
                reth_tracing::init_test_tracing();
                run_leadership_fault_case($case).await
            }
        )+
    };
}

leadership_fault_tests! {
    /// B stays connected to the quorum but cannot observe L1 when the finalized A→B transition
    /// occurs. Once its L1 link returns, it replays the missed transition and assumes leadership.
    test_incoming_leader_recovers_after_l1_disconnect => LeadershipFaultCase {
        disconnected_nodes: &[INCOMING_LEADER],
        planes: FaultPlanes::L1,
        timing: FaultTiming::BeforeHandoff,
        expected: ExpectedDuringFault::WaitForIncomingLeader,
    },
    /// B observes the finalized A→B transition on L1 while isolated from the quorum. Restoring its
    /// P2P links lets it backfill, satisfy the promotion barrier, and assume leadership.
    test_incoming_leader_recovers_after_p2p_disconnect => LeadershipFaultCase {
        disconnected_nodes: &[INCOMING_LEADER],
        planes: FaultPlanes::P2p,
        timing: FaultTiming::BeforeHandoff,
        expected: ExpectedDuringFault::WaitForIncomingLeader,
    },
    /// B is isolated from both L1 and the P2P quorum during the finalized A→B transition.
    /// Restoring both planes lets it replay L1, recover the canonical tip, and assume leadership.
    test_incoming_leader_recovers_after_l1_and_p2p_disconnect => LeadershipFaultCase {
        disconnected_nodes: &[INCOMING_LEADER],
        planes: FaultPlanes::Both,
        timing: FaultTiming::BeforeHandoff,
        expected: ExpectedDuringFault::WaitForIncomingLeader,
    },
    /// C loses both network planes while healthy A and B rotate leadership. The remaining 2-of-3
    /// quorum must hand off and settle under B before C reconnects and converges.
    test_handoff_and_settlement_continue_while_follower_is_disconnected => LeadershipFaultCase {
        disconnected_nodes: &[FOLLOWER],
        planes: FaultPlanes::Both,
        timing: FaultTiming::BeforeHandoff,
        expected: ExpectedDuringFault::ContinueAndSettle,
    },
    /// B and C lose both network planes before the handoff. A must fence at the activation
    /// boundary, then the full cluster must recover and settle under B after reconnection.
    test_handoff_waits_when_incoming_leader_and_follower_are_disconnected => LeadershipFaultCase {
        disconnected_nodes: &[INCOMING_LEADER, FOLLOWER],
        planes: FaultPlanes::Both,
        timing: FaultTiming::BeforeHandoff,
        expected: ExpectedDuringFault::WaitForIncomingLeader,
    },
    /// A loses both network planes before it can consume the handoff activation block. If B and C
    /// have already crossed the activation boundary they continue with quorum; otherwise they
    /// recover and settle under B after A reconnects.
    test_handoff_waits_when_outgoing_leader_disconnects_before_activation => LeadershipFaultCase {
        disconnected_nodes: &[OUTGOING_LEADER],
        planes: FaultPlanes::Both,
        timing: FaultTiming::OutgoingLeaderBeforeActivation,
        expected: ExpectedDuringFault::ContinueIfActivated,
    },
}

/// B is P2P-isolated during an A→B handoff and retains a withdrawal in its local pool. After
/// reconnection, B must include the withdrawal, making that block a batch boundary, and settle it
/// on the canonical chain without duplicate indices or conflicting block hashes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_handoff_recovers_across_settlement_boundary() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (cluster, network, _l1_proxies) = start_cluster().await?;
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "an initial A-era settlement",
        || {
            let portal = &portal;
            async move {
                let count = batch_count(portal).await?;
                Ok((count > 0).then_some(count))
            }
        },
    )
    .await?;
    let mut account =
        ZoneAccount::from_l1_and_zone(&cluster.l1, &cluster.nodes[1], cluster.portal_address);
    cluster
        .l1
        .fund_user(account.address(), INITIAL_DEPOSIT + 10_000_000)
        .await?;
    account
        .deposit(INITIAL_DEPOSIT, NETWORK_TIMEOUT, &cluster.nodes[1])
        .await?;
    for node in &cluster.nodes {
        node.wait_for_balance(
            ZONE_TOKEN_ADDRESS,
            account.address(),
            U256::from(INITIAL_DEPOSIT),
            NETWORK_TIMEOUT,
        )
        .await?;
    }
    account.approve_outbox(ZONE_TOKEN_ADDRESS).await?;
    let baseline = synchronized_head(&cluster).await?;

    network.disconnect_nodes(&[INCOMING_LEADER]);
    network
        .wait_for_nodes_disconnected(&[INCOMING_LEADER], NETWORK_TIMEOUT)
        .await?;
    wait_for_p2p_lag(&cluster, OUTGOING_LEADER, INCOMING_LEADER).await?;
    let expected_epoch = rotate_leadership(&cluster, INCOMING_LEADER).await?;
    wait_for_leadership_epoch(
        &cluster,
        &[0, 1, 2],
        expected_epoch,
        "all nodes to observe B's leadership at the settlement boundary",
    )
    .await?;

    // The transaction remains private to B while every P2P path involving B is down. Commonware
    // may include it in a local proposal, but that proposal must not reach A/C or settle on L1.
    // Its canonical inclusion under B after reconnection creates the boundary this test follows.
    let withdrawal_hash = account.submit_withdrawal(WITHDRAWAL_AMOUNT).await?;
    for &index in &[OUTGOING_LEADER, FOLLOWER] {
        eyre::ensure!(
            cluster.nodes[index]
                .provider()
                .get_transaction_by_hash(withdrawal_hash)
                .await?
                .is_none(),
            "node {index} received B's withdrawal while their P2P links were disconnected"
        );
    }

    let activation_tempo_block =
        activation_anchor_for_epoch(&cluster, &portal, expected_epoch).await?;
    assert_handoff_stalls_without_incoming_quorum(
        &cluster,
        &portal,
        &[OUTGOING_LEADER, FOLLOWER],
        &[INCOMING_LEADER],
        FaultPlanes::P2p,
        expected_epoch,
        activation_tempo_block,
    )
    .await?;
    eyre::ensure!(
        cluster.nodes[FOLLOWER]
            .provider()
            .get_transaction_receipt(withdrawal_hash)
            .await?
            .is_none(),
        "C observed B's withdrawal while their P2P links were disconnected"
    );

    // Reconnect B only once A has consumed every anchor it may still lead. While A can produce
    // below the activation boundary, B legitimately forwards its pooled withdrawal to A, and the
    // boundary block this test follows would be an A-era block. A keeps its quorum with C, so it
    // does reach the boundary here — unlike the cases where A itself is isolated.
    cluster.nodes[OUTGOING_LEADER]
        .wait_for_tempo_block_number(activation_tempo_block - 1, NETWORK_TIMEOUT)
        .await?;
    let batches_at_fence = batch_count(&portal).await?;

    network.resume_nodes(&[INCOMING_LEADER]);
    network
        .wait_for_nodes_connected(&[INCOMING_LEADER], NETWORK_TIMEOUT)
        .await?;
    let receipt = poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "B to include the withdrawal after assuming leadership",
        || {
            let provider = cluster.nodes[1].provider();
            async move { Ok(provider.get_transaction_receipt(withdrawal_hash).await?) }
        },
    )
    .await?;
    eyre::ensure!(receipt.status(), "B-era withdrawal reverted");
    let boundary_height = receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("B-era withdrawal receipt has no block number"))?;
    eyre::ensure!(
        boundary_height > baseline,
        "withdrawal was included before the leadership handoff"
    );
    cluster
        .wait_all_at(boundary_height, NETWORK_TIMEOUT)
        .await?;
    let boundary = cluster.assert_same_block(boundary_height).await?;
    eyre::ensure!(
        boundary.beneficiary() == cluster.attestation_signers[1].address(),
        "withdrawal boundary block {boundary_height} was not produced under leader B"
    );
    let boundary_hash = boundary.hash;

    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "B's withdrawal boundary block to settle",
        || {
            let portal = &portal;
            async move {
                let events = portal
                    .BatchSubmitted_1_filter()
                    .from_block(0)
                    .query()
                    .await?;
                Ok(events
                    .iter()
                    .any(|(event, _)| event.nextBlockHash == boundary_hash)
                    .then_some(events.len()))
            }
        },
    )
    .await?;
    eyre::ensure!(
        batch_count(&portal).await? > batches_at_fence,
        "withdrawal boundary did not create a post-handoff batch"
    );

    let settled_height = assert_batch_history_is_canonical(&cluster, &portal).await?;
    eyre::ensure!(
        settled_height >= boundary_height,
        "settlement stopped before B's withdrawal boundary: {settled_height} < {boundary_height}"
    );
    let header = cluster.assert_same_block(settled_height).await?;
    eyre::ensure!(
        header.beneficiary() == cluster.attestation_signers[1].address(),
        "post-handoff settlement at {settled_height} was not produced under leader B"
    );
    Ok(())
}

async fn assert_isolation_recovers(
    cluster: &RealP2pCluster,
    network: &P2pChaosNetwork,
    isolated: &[usize],
) -> eyre::Result<()> {
    synchronized_head(cluster).await?;
    network.disconnect_nodes(isolated);
    network
        .wait_for_nodes_disconnected(isolated, NETWORK_TIMEOUT)
        .await?;

    let outage_start = cluster.nodes[0].provider().get_block_number().await?;
    let target = outage_start + RECOVERY_GAP;
    cluster.nodes[0]
        .wait_for_block_number(target, NETWORK_TIMEOUT)
        .await?;

    // The leader produces independently of P2P. When it is isolated, both followers fall behind;
    // when the followers are isolated, those followers fall behind instead.
    let lagging: &[usize] = if isolated.contains(&0) {
        &[1, 2]
    } else {
        isolated
    };
    for index in lagging {
        eyre::ensure!(
            cluster.nodes[*index].provider().get_block_number().await? < target,
            "isolated node {index} reached block {target} without a P2P connection"
        );
    }

    network.resume_nodes(isolated);
    cluster.wait_all_at(target, NETWORK_TIMEOUT).await?;
    cluster.assert_same_block(target).await?;
    Ok(())
}

/// Disconnect every P2P path involving the leader. The leader continues producing from L1 while
/// both followers stop, then the followers backfill the missed blocks after reconnection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_followers_catch_up_after_leader_p2p_disconnect() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (cluster, network, _l1_proxies) = start_cluster().await?;
    assert_isolation_recovers(&cluster, &network, &[0]).await
}

/// Disconnect both followers from P2P while the leader continues producing, then verify both
/// followers backfill and converge on the leader's canonical chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_followers_catch_up_after_their_p2p_disconnect() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (cluster, network, _l1_proxies) = start_cluster().await?;
    assert_isolation_recovers(&cluster, &network, &[1, 2]).await
}

/// A transaction admitted to an isolated follower's pool remains pending locally. Once P2P is
/// restored, reconciliation forwards it to the leader, which includes it in a canonical block.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_follower_mempool_transaction_propagates_after_reconnect() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (cluster, network, _l1_proxies) = start_cluster().await?;
    let mut account =
        ZoneAccount::from_l1_and_zone(&cluster.l1, &cluster.nodes[1], cluster.portal_address);
    cluster
        .l1
        .fund_user(account.address(), INITIAL_DEPOSIT + 10_000_000)
        .await?;
    account
        .deposit(INITIAL_DEPOSIT, NETWORK_TIMEOUT, &cluster.nodes[1])
        .await?;
    for node in &cluster.nodes {
        node.wait_for_balance(
            ZONE_TOKEN_ADDRESS,
            account.address(),
            U256::from(INITIAL_DEPOSIT),
            NETWORK_TIMEOUT,
        )
        .await?;
    }
    account.approve_outbox(ZONE_TOKEN_ADDRESS).await?;

    let baseline = synchronized_head(&cluster).await?;
    network.disconnect_nodes(&[1]);
    network
        .wait_for_nodes_disconnected(&[1], NETWORK_TIMEOUT)
        .await?;
    cluster.nodes[0]
        .wait_for_block_number(baseline + 2, NETWORK_TIMEOUT)
        .await?;

    let transaction_hash = account.submit_withdrawal(WITHDRAWAL_AMOUNT).await?;
    eyre::ensure!(
        cluster.nodes[0]
            .provider()
            .get_transaction_by_hash(transaction_hash)
            .await?
            .is_none(),
        "leader received the follower transaction while all P2P links were disconnected"
    );

    network.resume_nodes(&[1]);
    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "reconnected follower transaction to reach the leader",
        || {
            let provider = cluster.nodes[0].provider();
            async move { Ok(provider.get_transaction_by_hash(transaction_hash).await?) }
        },
    )
    .await?;
    let receipt = poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "forwarded follower transaction to be included by the leader",
        || {
            let provider = cluster.nodes[0].provider();
            async move { Ok(provider.get_transaction_receipt(transaction_hash).await?) }
        },
    )
    .await?;
    eyre::ensure!(receipt.status(), "forwarded withdrawal reverted");
    let inclusion_block = receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("forwarded withdrawal receipt has no block number"))?;
    cluster
        .wait_all_at(inclusion_block, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(inclusion_block).await?;
    Ok(())
}

/// A follower remains able to import and validate the leader's chain while every P2P stream
/// involving that follower carries substantial latency.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_follower_keeps_up_with_high_p2p_latency() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (cluster, network, _l1_proxies) = start_cluster().await?;
    synchronized_head(&cluster).await?;
    network.set_nodes_latency(&[1], P2P_LATENCY);

    let target = cluster.nodes[0].provider().get_block_number().await? + RECOVERY_GAP;
    cluster.nodes[0]
        .wait_for_block_number(target, NETWORK_TIMEOUT)
        .await?;
    cluster.wait_all_at(target, NETWORK_TIMEOUT).await?;
    cluster.assert_same_block(target).await?;
    Ok(())
}

/// A follower does not import leader blocks while their L1 anchors are withheld. Once responses
/// resume with substantial latency, it observes the anchors and converges with the healthy nodes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_follower_keeps_up_with_high_l1_latency() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (cluster, _network, [_leader_l1, follower_l1, _other_follower_l1]) =
        start_cluster().await?;
    synchronized_head(&cluster).await?;
    let follower_anchor = cluster.nodes[1].tempo_block_number().await?;
    let highest_observed_anchor = cluster.nodes[1]
        .l1_block_tracker()
        .latest()
        .map_or(follower_anchor, |anchor| anchor.number);
    let target_anchor = highest_observed_anchor + RECOVERY_GAP;

    follower_l1.set_client_to_upstream_latency(L1_LATENCY);
    follower_l1.set_upstream_to_client_latency(L1_LATENCY);
    follower_l1.pause_upstream_to_client(true);

    cluster.nodes[0]
        .wait_for_tempo_block_number(target_anchor, NETWORK_TIMEOUT)
        .await?;
    let target_head = cluster.nodes[0].provider().get_block_number().await?;
    eyre::ensure!(
        cluster.nodes[1].tempo_block_number().await? < target_anchor,
        "follower imported anchor {target_anchor} while its L1 responses were paused"
    );
    eyre::ensure!(
        cluster.nodes[1]
            .l1_block_tracker()
            .latest()
            .is_none_or(|anchor| anchor.number < target_anchor),
        "follower observed anchor {target_anchor} while its L1 responses were paused"
    );

    follower_l1.pause_upstream_to_client(false);
    cluster.nodes[1]
        .wait_for_tempo_block_number(target_anchor, NETWORK_TIMEOUT)
        .await?;
    cluster.wait_all_at(target_head, NETWORK_TIMEOUT).await?;
    cluster.assert_same_block(target_head).await?;
    Ok(())
}
