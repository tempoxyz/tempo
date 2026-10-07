//! End-to-end tests for recovery from real TCP-level network failures.
//!
//! Unlike the restart tests, every node and background task remains alive. All nodes reach the real
//! Tempo L1 through one controlled TCP proxy, so disconnecting it closes every established RPC
//! socket and exercises the production reconnect and finalized backfill path.

use std::time::Duration;

use alloy::{primitives::U256, providers::Provider as _};
use alloy_network::ReceiptResponse as _;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::transaction::calc_gas_balance_spending;
use tempo_zone_contracts::{IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZONE_TOKEN_ADDRESS, ZonePortal};

use crate::utils::{
    RealP2pCluster, TcpChaosProxy, ZoneAccount, batch_count, poll_until,
    start_real_p2p_cluster_with_l1_proxy, start_real_p2p_cluster_with_per_node_l1_proxies,
};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);
const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const L1_BLOCK_TIME: Duration = Duration::from_millis(250);
const OUTAGE_BLOCK_GAP: u64 = 8;
const INITIAL_DEPOSIT: u128 = 10_000_000;
const OUTAGE_DEPOSIT: u128 = 1_000_000;
const OUTAGE_WITHDRAWAL: u128 = 250_000;
const ACTIVE_CONNECTION_RESET_SEED: u64 = 0x503;
const ACTIVE_CONNECTION_RESET_COUNT: u64 = 4;
const MIN_ACTIVE_CONNECTION_RESET_DELAY: Duration = Duration::from_millis(100);
const ACTIVE_CONNECTION_RESET_JITTER: Duration = Duration::from_millis(400);

// This seeded 95% schedule starts with 64 rejected attempts. That gives the short E2E outage a
// deterministic failure window while retaining probability-based behavior in the proxy itself.
const WEBSOCKET_503_SEED: u64 = 385;
const WEBSOCKET_503_PROBABILITY_PERCENT: u8 = 95;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AffectedNodes {
    Leader,
    BothFollowers,
    OneFollower,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum L1Fault {
    Disconnect,
    RandomWebSocket503,
    SilentBidirectionalStall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProgressExpectation {
    Stalls,
    Continues,
}

#[derive(Clone, Copy, Debug)]
struct L1OutageCase {
    phase: &'static str,
    affected_nodes: AffectedNodes,
    fault: L1Fault,
    production: ProgressExpectation,
    settlement: ProgressExpectation,
}

const L1_OUTAGE_CASES: &[L1OutageCase] = &[
    L1OutageCase {
        phase: "both followers disconnected",
        affected_nodes: AffectedNodes::BothFollowers,
        fault: L1Fault::Disconnect,
        production: ProgressExpectation::Continues,
        settlement: ProgressExpectation::Stalls,
    },
    L1OutageCase {
        phase: "leader disconnected",
        affected_nodes: AffectedNodes::Leader,
        fault: L1Fault::Disconnect,
        production: ProgressExpectation::Stalls,
        settlement: ProgressExpectation::Stalls,
    },
    L1OutageCase {
        phase: "one follower disconnected",
        affected_nodes: AffectedNodes::OneFollower,
        fault: L1Fault::Disconnect,
        production: ProgressExpectation::Continues,
        settlement: ProgressExpectation::Continues,
    },
    L1OutageCase {
        phase: "both followers receiving WebSocket 503s",
        affected_nodes: AffectedNodes::BothFollowers,
        fault: L1Fault::RandomWebSocket503,
        production: ProgressExpectation::Continues,
        settlement: ProgressExpectation::Stalls,
    },
    L1OutageCase {
        phase: "leader receiving WebSocket 503s",
        affected_nodes: AffectedNodes::Leader,
        fault: L1Fault::RandomWebSocket503,
        production: ProgressExpectation::Stalls,
        settlement: ProgressExpectation::Stalls,
    },
    L1OutageCase {
        phase: "one follower receiving WebSocket 503s",
        affected_nodes: AffectedNodes::OneFollower,
        fault: L1Fault::RandomWebSocket503,
        production: ProgressExpectation::Continues,
        settlement: ProgressExpectation::Continues,
    },
    L1OutageCase {
        phase: "both followers silently stalled",
        affected_nodes: AffectedNodes::BothFollowers,
        fault: L1Fault::SilentBidirectionalStall,
        production: ProgressExpectation::Continues,
        settlement: ProgressExpectation::Stalls,
    },
    L1OutageCase {
        phase: "leader silently stalled",
        affected_nodes: AffectedNodes::Leader,
        fault: L1Fault::SilentBidirectionalStall,
        production: ProgressExpectation::Stalls,
        settlement: ProgressExpectation::Stalls,
    },
    L1OutageCase {
        phase: "one follower silently stalled",
        affected_nodes: AffectedNodes::OneFollower,
        fault: L1Fault::SilentBidirectionalStall,
        production: ProgressExpectation::Continues,
        settlement: ProgressExpectation::Continues,
    },
];

struct ActiveFault {
    accepted_before: Vec<u64>,
    active_before: Vec<u64>,
}

async fn start_fault(fault: L1Fault, proxies: &[&TcpChaosProxy]) -> eyre::Result<ActiveFault> {
    let accepted_before = proxies
        .iter()
        .map(|proxy| proxy.accepted_connections())
        .collect();
    let active_before: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.active_connections())
        .collect();
    let injected_before: Vec<_> = proxies
        .iter()
        .map(|proxy| proxy.injected_websocket_503s())
        .collect();

    match fault {
        L1Fault::Disconnect => {
            for proxy in proxies {
                proxy.disconnect();
            }
        }
        L1Fault::RandomWebSocket503 => {
            for proxy in proxies {
                proxy
                    .set_websocket_503_fault(WEBSOCKET_503_SEED, WEBSOCKET_503_PROBABILITY_PERCENT);
                proxy.drop_active_connections();
            }
        }
        L1Fault::SilentBidirectionalStall => {
            for (proxy, active) in proxies.iter().zip(&active_before) {
                eyre::ensure!(
                    *active > 0,
                    "cannot silently stall proxy {} without an established connection",
                    proxy.listen_addr()
                );
                proxy.pause_client_to_upstream(true);
                proxy.pause_upstream_to_client(true);
            }
        }
    }
    if fault != L1Fault::SilentBidirectionalStall {
        for proxy in proxies {
            proxy.wait_for_no_connections(NETWORK_TIMEOUT).await?;
        }
    }
    if fault == L1Fault::RandomWebSocket503 {
        for (proxy, previous) in proxies.iter().zip(injected_before) {
            proxy
                .wait_for_injected_websocket_503s_after(previous, 1, NETWORK_TIMEOUT)
                .await?;
        }
    }
    Ok(ActiveFault {
        accepted_before,
        active_before,
    })
}

async fn clear_fault(
    fault: L1Fault,
    proxies: &[&TcpChaosProxy],
    active: ActiveFault,
) -> eyre::Result<()> {
    match fault {
        L1Fault::Disconnect | L1Fault::RandomWebSocket503 => {
            for proxy in proxies {
                match fault {
                    L1Fault::Disconnect => proxy.resume(),
                    L1Fault::RandomWebSocket503 => proxy.clear_websocket_503_fault(),
                    L1Fault::SilentBidirectionalStall => unreachable!(),
                }
            }
            for (proxy, accepted) in proxies.iter().zip(active.accepted_before) {
                proxy
                    .wait_for_connections_after(accepted, 1, NETWORK_TIMEOUT)
                    .await?;
            }
        }
        L1Fault::SilentBidirectionalStall => {
            for ((proxy, accepted_before), active_before) in proxies
                .iter()
                .zip(active.accepted_before)
                .zip(active.active_before)
            {
                eyre::ensure!(
                    proxy.accepted_connections() == accepted_before,
                    "silently stalled proxy {} accepted a replacement connection",
                    proxy.listen_addr()
                );
                eyre::ensure!(
                    proxy.active_connections() == active_before,
                    "silently stalled proxy {} did not preserve its established connections",
                    proxy.listen_addr()
                );
                proxy.pause_client_to_upstream(false);
                proxy.pause_upstream_to_client(false);
            }
        }
    }
    Ok(())
}

struct OutageAssetFlow {
    phase: &'static str,
    l2_balance_before: U256,
    l1_balance_before_withdrawal: U256,
    deposit_block: u64,
    withdrawal_hash: alloy::primitives::B256,
    withdrawal_fee: u128,
}

async fn wait_for_settled_height(
    portal: &ZonePortal::ZonePortalInstance<alloy::providers::DynProvider>,
    height: u64,
    description: &str,
) -> eyre::Result<U256> {
    poll_until(NETWORK_TIMEOUT, POLL_INTERVAL, description, || async move {
        let settled_height = portal.zoneHeight().call().await?;
        Ok((settled_height >= U256::from(height)).then_some(settled_height))
    })
    .await
}

async fn submit_outage_asset_flow(
    cluster: &RealP2pCluster,
    account: &mut ZoneAccount,
    phase: &'static str,
    outage_start: u64,
) -> eyre::Result<OutageAssetFlow> {
    let l2_balance_before = cluster.nodes[0]
        .balance_of(ZONE_TOKEN_ADDRESS, account.address())
        .await?;
    let deposit_block =
        tokio::time::timeout(SUBMISSION_TIMEOUT, account.submit_deposit(OUTAGE_DEPOSIT))
            .await
            .map_err(|_| eyre::eyre!("{phase} deposit submission timed out"))??;
    eyre::ensure!(
        deposit_block >= outage_start,
        "{phase} deposit landed before the L1 outage began"
    );

    let withdrawal_fee = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, cluster.nodes[0].provider())
        .calculateWithdrawalFee(0)
        .call()
        .await?;
    let l1_balance_before_withdrawal = cluster
        .l1
        .balance_of(PATH_USD_ADDRESS, account.address())
        .await?;
    let withdrawal_hash = tokio::time::timeout(
        SUBMISSION_TIMEOUT,
        account.submit_withdrawal(OUTAGE_WITHDRAWAL),
    )
    .await
    .map_err(|_| eyre::eyre!("{phase} withdrawal submission timed out"))??;

    Ok(OutageAssetFlow {
        phase,
        l2_balance_before,
        l1_balance_before_withdrawal,
        deposit_block,
        withdrawal_hash,
        withdrawal_fee,
    })
}

async fn assert_outage_asset_flow(
    cluster: &RealP2pCluster,
    account: &ZoneAccount,
    flow: OutageAssetFlow,
) -> eyre::Result<()> {
    let receipt = poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        &format!(
            "{} withdrawal to be included after reconnection",
            flow.phase
        ),
        || {
            let provider = cluster.nodes[0].provider();
            async move {
                Ok(provider
                    .get_transaction_receipt(flow.withdrawal_hash)
                    .await?)
            }
        },
    )
    .await?;
    eyre::ensure!(receipt.status(), "{} withdrawal reverted", flow.phase);

    cluster
        .l1
        .wait_for_withdrawal_on_l1(
            cluster.portal_address,
            account.address(),
            flow.l1_balance_before_withdrawal,
            OUTAGE_WITHDRAWAL,
            NETWORK_TIMEOUT,
        )
        .await?;
    let l1_balance_after = cluster
        .l1
        .balance_of(PATH_USD_ADDRESS, account.address())
        .await?;
    assert_eq!(
        l1_balance_after,
        flow.l1_balance_before_withdrawal + U256::from(OUTAGE_WITHDRAWAL),
        "{} produced the wrong L1 balance after withdrawal",
        flow.phase
    );

    for node in &cluster.nodes {
        node.wait_for_tempo_block_number(flow.deposit_block, NETWORK_TIMEOUT)
            .await?;
    }
    let inclusion_block = receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("{} withdrawal receipt has no block", flow.phase))?;
    cluster
        .wait_all_at(inclusion_block, NETWORK_TIMEOUT)
        .await?;

    let transaction_fee = calc_gas_balance_spending(receipt.gas_used, receipt.effective_gas_price);
    let expected_l2_balance = flow.l2_balance_before + U256::from(OUTAGE_DEPOSIT)
        - U256::from(OUTAGE_WITHDRAWAL)
        - U256::from(flow.withdrawal_fee)
        - transaction_fee;
    for (index, node) in cluster.nodes.iter().enumerate() {
        let balance = node
            .balance_of(ZONE_TOKEN_ADDRESS, account.address())
            .await?;
        assert_eq!(
            balance, expected_l2_balance,
            "{} produced the wrong L2 balance on node {index}",
            flow.phase
        );
    }
    Ok(())
}

async fn recover_both_followers(
    cluster: &RealP2pCluster,
    account: &mut ZoneAccount,
    follower_one_proxy: &TcpChaosProxy,
    follower_two_proxy: &TcpChaosProxy,
    baseline_height: u64,
    case: L1OutageCase,
) -> eyre::Result<()> {
    let affected_proxies = [follower_one_proxy, follower_two_proxy];
    let active_fault = start_fault(case.fault, &affected_proxies).await?;

    let outage_start = cluster.l1.provider().get_block_number().await?;
    let assets = submit_outage_asset_flow(cluster, account, case.phase, outage_start).await?;
    let target = (outage_start + OUTAGE_BLOCK_GAP).max(assets.deposit_block + 1);
    cluster.nodes[0]
        .wait_for_tempo_block_number(target, NETWORK_TIMEOUT)
        .await?;
    for (index, follower) in cluster.nodes[1..].iter().enumerate() {
        eyre::ensure!(
            follower.tempo_block_number().await? < target,
            "follower {} reached outage target {target} without an L1 connection",
            index + 1
        );
    }
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    let settled_during_outage = portal.zoneHeight().call().await?;
    eyre::ensure!(
        settled_during_outage < U256::from(target),
        "{} unexpectedly settled through height {target} without follower quorum",
        case.phase
    );
    clear_fault(case.fault, &affected_proxies, active_fault).await?;
    for follower in &cluster.nodes[1..] {
        follower
            .wait_for_tempo_block_number(target, NETWORK_TIMEOUT)
            .await?;
    }

    let recovered_height = cluster.nodes[0].provider().get_block_number().await?;
    eyre::ensure!(
        recovered_height > baseline_height,
        "leader did not continue producing during the follower outage"
    );
    cluster
        .wait_all_at(recovered_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(recovered_height).await?;
    wait_for_settled_height(
        &portal,
        recovered_height,
        "quorum settlement to resume after both followers catch up",
    )
    .await?;
    assert_outage_asset_flow(cluster, account, assets).await
}

async fn recover_leader(
    cluster: &RealP2pCluster,
    account: &mut ZoneAccount,
    leader_proxy: &TcpChaosProxy,
    follower_one_proxy: &TcpChaosProxy,
    follower_two_proxy: &TcpChaosProxy,
    case: L1OutageCase,
) -> eyre::Result<()> {
    let baseline_height = cluster.nodes[0].provider().get_block_number().await?;
    cluster
        .wait_all_at(baseline_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(baseline_height).await?;
    leader_proxy
        .wait_for_connections_after(0, 1, NETWORK_TIMEOUT)
        .await?;
    let affected_proxies = [leader_proxy];
    let active_fault = start_fault(case.fault, &affected_proxies).await?;

    let outage_start = cluster.l1.provider().get_block_number().await?;
    let assets = submit_outage_asset_flow(cluster, account, case.phase, outage_start).await?;
    let target = (outage_start + OUTAGE_BLOCK_GAP).max(assets.deposit_block + 1);
    for (index, follower) in cluster.nodes[1..].iter().enumerate() {
        poll_until(
            NETWORK_TIMEOUT,
            POLL_INTERVAL,
            &format!(
                "follower {} to observe L1 during the leader outage",
                index + 1
            ),
            || async {
                Ok(follower
                    .l1_block_tracker()
                    .latest()
                    .filter(|block| block.number >= target)
                    .map(|block| block.number))
            },
        )
        .await?;
    }
    eyre::ensure!(
        follower_one_proxy.active_connections() > 0 && follower_two_proxy.active_connections() > 0,
        "a follower L1 proxy lost connectivity during the leader-only outage"
    );
    for (index, node) in cluster.nodes.iter().enumerate() {
        eyre::ensure!(
            node.tempo_block_number().await? < target,
            "node {index} advanced zone state without a connected leader"
        );
    }
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    let settled_during_outage = portal.zoneHeight().call().await?;
    eyre::ensure!(
        settled_during_outage < U256::from(target),
        "{} unexpectedly settled through height {target} without leader production",
        case.phase
    );
    clear_fault(case.fault, &affected_proxies, active_fault).await?;
    for node in &cluster.nodes {
        node.wait_for_tempo_block_number(target, NETWORK_TIMEOUT)
            .await?;
    }

    let recovered_height = cluster.nodes[0].provider().get_block_number().await?;
    eyre::ensure!(
        recovered_height > baseline_height,
        "leader did not produce the anchors missed during its L1 outage"
    );
    cluster
        .wait_all_at(recovered_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(recovered_height).await?;
    wait_for_settled_height(
        &portal,
        recovered_height,
        "quorum settlement to resume after the leader catches up",
    )
    .await?;
    assert_outage_asset_flow(cluster, account, assets).await
}

async fn recover_single_follower(
    cluster: &RealP2pCluster,
    account: &mut ZoneAccount,
    leader_proxy: &TcpChaosProxy,
    follower_one_proxy: &TcpChaosProxy,
    follower_two_proxy: &TcpChaosProxy,
    case: L1OutageCase,
) -> eyre::Result<()> {
    let baseline_height = cluster.nodes[0].provider().get_block_number().await?;
    cluster
        .wait_all_at(baseline_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(baseline_height).await?;
    let affected_proxies = [follower_one_proxy];
    let active_fault = start_fault(case.fault, &affected_proxies).await?;

    let outage_start = cluster.l1.provider().get_block_number().await?;
    let assets = submit_outage_asset_flow(cluster, account, case.phase, outage_start).await?;
    let target = (outage_start + OUTAGE_BLOCK_GAP).max(assets.deposit_block + 1);
    cluster.nodes[0]
        .wait_for_tempo_block_number(target, NETWORK_TIMEOUT)
        .await?;
    cluster.nodes[2]
        .wait_for_tempo_block_number(target, NETWORK_TIMEOUT)
        .await?;
    eyre::ensure!(
        cluster.nodes[1].tempo_block_number().await? < target,
        "isolated follower reached outage target without an L1 connection"
    );
    eyre::ensure!(
        leader_proxy.active_connections() > 0 && follower_two_proxy.active_connections() > 0,
        "healthy quorum member lost L1 connectivity during the single-follower outage"
    );

    // Capture a leader-produced height after the target before checking the portal. A prior batch
    // may have already settled past the phase baseline, which would not prove 2-of-3 settlement.
    let leader_height_during_outage = cluster.nodes[0].provider().get_block_number().await?;
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    wait_for_settled_height(
        &portal,
        leader_height_during_outage,
        "2-of-3 settlement to reach the leader height during the single-follower outage",
    )
    .await?;

    clear_fault(case.fault, &affected_proxies, active_fault).await?;
    cluster.nodes[1]
        .wait_for_tempo_block_number(target, NETWORK_TIMEOUT)
        .await?;

    let recovered_height = cluster.nodes[0].provider().get_block_number().await?;
    eyre::ensure!(
        recovered_height > baseline_height,
        "healthy quorum did not advance during the single-follower outage"
    );
    cluster
        .wait_all_at(recovered_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(recovered_height).await?;
    assert_outage_asset_flow(cluster, account, assets).await
}

async fn run_l1_outage_case(
    cluster: &RealP2pCluster,
    account: &mut ZoneAccount,
    proxies: &[TcpChaosProxy; 3],
    case: L1OutageCase,
) -> eyre::Result<()> {
    let [leader_proxy, follower_one_proxy, follower_two_proxy] = proxies;
    match (case.affected_nodes, case.production, case.settlement) {
        (
            AffectedNodes::BothFollowers,
            ProgressExpectation::Continues,
            ProgressExpectation::Stalls,
        ) => {
            let baseline_height = cluster.nodes[0].provider().get_block_number().await?;
            recover_both_followers(
                cluster,
                account,
                follower_one_proxy,
                follower_two_proxy,
                baseline_height,
                case,
            )
            .await
        }
        (AffectedNodes::Leader, ProgressExpectation::Stalls, ProgressExpectation::Stalls) => {
            recover_leader(
                cluster,
                account,
                leader_proxy,
                follower_one_proxy,
                follower_two_proxy,
                case,
            )
            .await
        }
        (
            AffectedNodes::OneFollower,
            ProgressExpectation::Continues,
            ProgressExpectation::Continues,
        ) => {
            recover_single_follower(
                cluster,
                account,
                leader_proxy,
                follower_one_proxy,
                follower_two_proxy,
                case,
            )
            .await
        }
        _ => {
            eyre::bail!(
                "unsupported L1 outage matrix row {}: {:?}",
                case.phase,
                case
            );
        }
    }
}

fn active_connection_reset_delay(attempt: u64) -> Duration {
    let mut sample = ACTIVE_CONNECTION_RESET_SEED.wrapping_add(attempt);
    sample = sample.wrapping_add(0x9e37_79b9_7f4a_7c15);
    sample = (sample ^ (sample >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    sample = (sample ^ (sample >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    sample ^= sample >> 31;
    let jitter_bound = ACTIVE_CONNECTION_RESET_JITTER.as_millis() as u64;
    MIN_ACTIVE_CONNECTION_RESET_DELAY + Duration::from_millis(sample % (jitter_bound + 1))
}

async fn randomly_reset_active_connections(proxy: &TcpChaosProxy) -> eyre::Result<()> {
    for attempt in 0..ACTIVE_CONNECTION_RESET_COUNT {
        tokio::time::sleep(active_connection_reset_delay(attempt)).await;
        eyre::ensure!(
            proxy.active_connections() >= 3,
            "shared L1 proxy had fewer than three active connections before reset {attempt}"
        );
        let accepted_before_reset = proxy.accepted_connections();
        proxy.drop_active_connections();
        proxy
            .wait_for_connections_after(accepted_before_reset, 3, NETWORK_TIMEOUT)
            .await?;
    }
    Ok(())
}

/// Repeatedly reset established L1 WebSockets at seeded random times while the cluster remains in
/// normal operation. Every reset must drive fresh connections, without preventing zone progress,
/// node convergence, or quorum settlement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_three_sequencers_tolerate_random_active_l1_connection_resets() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (cluster, proxy) = start_real_p2p_cluster_with_l1_proxy(4, L1_BLOCK_TIME).await?;
    eyre::ensure!(
        cluster.nodes.len() == 3,
        "network-chaos fixture must start three nodes"
    );
    proxy
        .wait_for_connections_after(0, 3, NETWORK_TIMEOUT)
        .await?;

    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "an initial settled batch before active L1 connection resets",
        || {
            let portal = &portal;
            async move {
                let count = batch_count(portal).await?;
                Ok((count > 0).then_some(count))
            }
        },
    )
    .await?;
    let baseline_height = cluster.nodes[0].provider().get_block_number().await?;
    cluster
        .wait_all_at(baseline_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(baseline_height).await?;

    let target = baseline_height + OUTAGE_BLOCK_GAP;
    let reset_connections = randomly_reset_active_connections(&proxy);
    let maintain_progress = cluster.nodes[0].wait_for_tempo_block_number(target, NETWORK_TIMEOUT);
    tokio::try_join!(reset_connections, maintain_progress)?;
    cluster.wait_all_at(target, NETWORK_TIMEOUT).await?;

    let mut recovered_height = u64::MAX;
    for node in &cluster.nodes {
        recovered_height = recovered_height.min(node.provider().get_block_number().await?);
    }
    eyre::ensure!(
        recovered_height >= target,
        "zone did not reach target {target} during random active connection resets"
    );
    cluster
        .wait_all_at(recovered_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(recovered_height).await?;
    wait_for_settled_height(
        &portal,
        recovered_height,
        "quorum settlement after random active L1 connection resets",
    )
    .await?;

    Ok(())
}

/// All three sequencers lose their established L1 connections, remain running while L1 advances,
/// reconnect through the same endpoint, backfill the finalized gap, and converge again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_three_sequencers_reconnect_and_catch_up_after_l1_network_outage() -> eyre::Result<()>
{
    reth_tracing::init_test_tracing();

    let (cluster, proxy) = start_real_p2p_cluster_with_l1_proxy(4, L1_BLOCK_TIME).await?;
    eyre::ensure!(
        cluster.nodes.len() == 3,
        "network-chaos fixture must start three nodes"
    );

    // Establish a healthy baseline: nodes have connected through the shared proxy and all hold
    // the same leader-produced chain, and the quorum has submitted at least one batch to L1.
    proxy
        .wait_for_connections_after(0, 3, NETWORK_TIMEOUT)
        .await?;
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "an initial settled batch before the network outage",
        || {
            let portal = &portal;
            async move {
                let count = batch_count(portal).await?;
                Ok((count > 0).then_some(count))
            }
        },
    )
    .await?;
    let baseline_height = cluster.nodes[0].provider().get_block_number().await?;
    cluster
        .wait_all_at(baseline_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(baseline_height).await?;

    let accepted_before_outage = proxy.accepted_connections();
    proxy.disconnect();
    proxy.wait_for_no_connections(NETWORK_TIMEOUT).await?;
    eyre::ensure!(
        proxy.active_connections() == 0,
        "disconnect did not close every established L1 socket through {}",
        proxy.listen_addr()
    );

    // Build a gap that cannot have been prefetched before the sockets were closed.
    let outage_start = cluster.l1.provider().get_block_number().await?;
    let outage_target = outage_start + OUTAGE_BLOCK_GAP;
    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "L1 to advance while every sequencer link is disconnected",
        || {
            let provider = cluster.l1.provider();
            async move {
                let height = provider.get_block_number().await?;
                Ok((height >= outage_target).then_some(height))
            }
        },
    )
    .await?;
    for (index, node) in cluster.nodes.iter().enumerate() {
        eyre::ensure!(
            node.tempo_block_number().await? < outage_target,
            "node {index} reached outage target {outage_target} without an L1 connection"
        );
    }

    // Restoring the listeners must result in new TCP connections, not reuse of the sockets that
    // were alive before the fault. Catch-up then proves those connections carry valid RPC traffic.
    proxy.resume();
    proxy
        .wait_for_connections_after(accepted_before_outage, 3, NETWORK_TIMEOUT)
        .await?;
    for node in &cluster.nodes {
        node.wait_for_tempo_block_number(outage_target, NETWORK_TIMEOUT)
            .await?;
    }

    // Compare a fixed recovered height so continued L1 production cannot move the assertion's
    // target while nodes are being sampled.
    let mut recovered_height = u64::MAX;
    for node in &cluster.nodes {
        recovered_height = recovered_height.min(node.provider().get_block_number().await?);
    }
    eyre::ensure!(
        recovered_height > baseline_height,
        "nodes did not advance beyond their pre-outage zone height"
    );
    cluster
        .wait_all_at(recovered_height, NETWORK_TIMEOUT)
        .await?;
    cluster.assert_same_block(recovered_height).await?;

    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "batch settlement to resume after L1 reconnection",
        || {
            let portal = &portal;
            async move {
                let settled_height = portal.zoneHeight().call().await?;
                Ok((settled_height >= U256::from(recovered_height)).then_some(settled_height))
            }
        },
    )
    .await?;

    Ok(())
}

/// Exercise the asymmetric L1 fault matrix. Each restored side must backfill its missed anchors,
/// process a deposit and withdrawal submitted during the fault, and converge before the next row.
/// HTTP 503 faults happen during the WebSocket upgrade because established WebSockets do not have
/// per-request HTTP status codes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_asymmetric_l1_fault_matrix() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (cluster, [leader_proxy, follower_one_proxy, follower_two_proxy]) =
        start_real_p2p_cluster_with_per_node_l1_proxies(4, L1_BLOCK_TIME).await?;
    eyre::ensure!(
        cluster.nodes.len() == 3,
        "network-chaos fixture must start one leader and two followers"
    );
    for proxy in [&follower_one_proxy, &follower_two_proxy] {
        proxy
            .wait_for_connections_after(0, 1, NETWORK_TIMEOUT)
            .await?;
    }

    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    poll_until(
        NETWORK_TIMEOUT,
        POLL_INTERVAL,
        "an initial settled batch before disconnecting the followers",
        || {
            let portal = &portal;
            async move {
                let count = batch_count(portal).await?;
                Ok((count > 0).then_some(count))
            }
        },
    )
    .await?;

    // Seed one account before introducing faults so every outage can carry both a new L1 deposit
    // and an L2 withdrawal. Approval is also completed up front: during the leader outage the
    // withdrawal request itself may enter the pool, but no approval block can be produced.
    let mut account =
        ZoneAccount::from_l1_and_zone(&cluster.l1, &cluster.nodes[0], cluster.portal_address);
    cluster
        .l1
        .fund_user(
            account.address(),
            INITIAL_DEPOSIT + L1_OUTAGE_CASES.len() as u128 * OUTAGE_DEPOSIT + 10_000_000,
        )
        .await?;
    let initial_balance = account
        .deposit(INITIAL_DEPOSIT, NETWORK_TIMEOUT, &cluster.nodes[0])
        .await?;
    assert_eq!(initial_balance, U256::from(INITIAL_DEPOSIT));
    for node in &cluster.nodes {
        node.wait_for_balance(
            ZONE_TOKEN_ADDRESS,
            account.address(),
            initial_balance,
            NETWORK_TIMEOUT,
        )
        .await?;
    }
    account.approve_outbox(ZONE_TOKEN_ADDRESS).await?;

    let proxies = [leader_proxy, follower_one_proxy, follower_two_proxy];
    for &case in L1_OUTAGE_CASES {
        run_l1_outage_case(&cluster, &mut account, &proxies, case).await?;
    }

    Ok(())
}
