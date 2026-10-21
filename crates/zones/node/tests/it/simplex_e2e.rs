//! Simplex multi-sequencer e2e tests over synthetic L1 injection.
//!
//! Four quorum nodes run Commonware Simplex with a round-robin leader per view. Tests inject
//! finalized Tempo blocks directly into each node's deposit queue and L1 tracker, standing in for
//! each node's L1 subscriber, and observe finalized Zone blocks over RPC. No test publishes a
//! leadership transition, installs forced recovery, or restarts nodes to change who leads.

use std::{collections::BTreeSet, time::Duration};

use alloy::primitives::{U256, address};
use alloy_network::ReceiptResponse as _;
use alloy_provider::Provider as _;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::PATH_USD_ADDRESS;

use crate::utils::{
    DEFAULT_POLL, DEFAULT_TIMEOUT, L1Fixture, SimplexCluster, TIP20_TX_GAS, local_dev_zone_account,
    poll_until, start_local_simplex_cluster, start_local_simplex_cluster_with_rogue_proposer,
};

/// Ceiling for one injected anchor to finalize on every live node, including idle views that
/// time out before the anchor arrives.
const FINALIZE_TIMEOUT: Duration = Duration::from_secs(60);

/// Inject one anchor at a time and wait for it, so each anchor becomes exactly one Zone block.
async fn finalize_one_block_per_anchor(
    cluster: &mut SimplexCluster,
    blocks: u64,
) -> eyre::Result<u64> {
    let start = cluster
        .live()
        .next()
        .expect("cluster has a live node")
        .1
        .finalized_number()
        .await?;
    for height in start + 1..=start + blocks {
        cluster.inject_block(vec![]);
        cluster.wait_all_finalized(height, FINALIZE_TIMEOUT).await?;
    }
    Ok(start + blocks)
}

/// Every node finalizes the same chain while proposals rotate among the four leaders.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_finalizes_with_rotating_leaders() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;

    let tip = finalize_one_block_per_anchor(&mut cluster, 8).await?;

    let mut proposers = BTreeSet::new();
    for height in 1..=tip {
        proposers.insert(cluster.proposer_of(height).await?);
    }
    assert!(
        proposers.len() >= 3,
        "expected leadership to rotate, proposers were {proposers:?}"
    );
    Ok(())
}

/// A transaction submitted to one node reaches every future leader and is included, and an
/// injected deposit mints exactly once on every node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_includes_forwarded_transactions_and_deposits() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;

    let (wallet, sender) = local_dev_zone_account(cluster.node(3))?;
    let amount = 1_000_000_u128;
    cluster.inject_block(vec![L1Fixture::make_deposit_for_block(
        PATH_USD_ADDRESS,
        sender,
        sender,
        amount,
    )]);
    cluster.wait_all_finalized(1, FINALIZE_TIMEOUT).await?;
    for (_, node) in cluster.live() {
        node.wait_for_balance(
            PATH_USD_ADDRESS,
            sender,
            U256::from(amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
        assert_eq!(
            node.balance_of(PATH_USD_ADDRESS, sender).await?,
            U256::from(amount),
            "the deposit must mint exactly once"
        );
    }

    // Submit to node 3 only. It forwards to every quorum peer, so whichever node leads the next
    // views can include it.
    let spender = address!("0x00000000000000000000000000000000000ffff1");
    let pending = ITIP20::new(PATH_USD_ADDRESS, wallet)
        .approve(spender, U256::from(123_456_u64))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;
    let transaction_hash = *pending.tx_hash();
    for (index, node) in cluster.live() {
        let provider = node.provider();
        poll_until(
            DEFAULT_TIMEOUT,
            DEFAULT_POLL,
            &format!("forwarded transaction in node {index}'s pool"),
            || {
                let provider = &provider;
                async move { Ok(provider.get_transaction_by_hash(transaction_hash).await?) }
            },
        )
        .await?;
    }

    let receipt = tokio::time::timeout(FINALIZE_TIMEOUT, async {
        loop {
            let height = cluster.inject_block(vec![]).number;
            cluster.wait_all_finalized(height, FINALIZE_TIMEOUT).await?;
            if let Some(receipt) = cluster
                .node(0)
                .provider()
                .get_transaction_receipt(transaction_hash)
                .await?
            {
                return Ok::<_, eyre::Report>(receipt);
            }
        }
    })
    .await
    .map_err(|_| eyre::eyre!("forwarded transaction was never included"))??;
    assert!(receipt.status(), "the forwarded approval must succeed");
    let included_at = receipt
        .block_number
        .ok_or_else(|| eyre::eyre!("receipt has no block number"))?;
    cluster.assert_same_block(included_at).await?;
    // The sender paid its fee in pathUSD; every node agrees on the result.
    let balance = cluster.node(0).balance_of(PATH_USD_ADDRESS, sender).await?;
    assert!(
        balance < U256::from(amount),
        "the approval must have paid a fee"
    );
    for (_, node) in cluster.live() {
        assert_eq!(node.balance_of(PATH_USD_ADDRESS, sender).await?, balance);
    }
    Ok(())
}

/// A crashed node costs at most a few view timeouts. The survivors keep finalizing with no
/// operator action, and the crashed node never proposes again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_survives_crashed_leader() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;
    let before_crash = finalize_one_block_per_anchor(&mut cluster, 4).await?;

    cluster.crash(0);
    let started = std::time::Instant::now();
    let tip = finalize_one_block_per_anchor(&mut cluster, 8).await?;
    tracing::info!(elapsed = ?started.elapsed(), "finalized 8 blocks with one node down");

    for height in before_crash + 1..=tip {
        assert_ne!(
            cluster.proposer_of(height).await?,
            0,
            "crashed node 0 cannot have proposed block {height}"
        );
    }
    Ok(())
}

/// A node that was down while the others progressed restarts from its datadir and catches up
/// through marshal backfill, converging on the same finalized chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_restarted_node_catches_up() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;
    finalize_one_block_per_anchor(&mut cluster, 3).await?;

    cluster.crash(1);
    let tip = finalize_one_block_per_anchor(&mut cluster, 10).await?;

    cluster.restart(1, false).await?;
    cluster
        .node(1)
        .wait_for_finalized(tip, FINALIZE_TIMEOUT)
        .await?;
    for height in 1..=tip {
        cluster.assert_same_block(height).await?;
    }

    // The restarted node votes again: progress continues with all four.
    let tip = finalize_one_block_per_anchor(&mut cluster, 2).await?;
    cluster.assert_same_block(tip).await?;
    Ok(())
}

/// A node that loses its whole datadir resyncs every finalized block from its peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_node_recovers_from_disk_loss() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;
    finalize_one_block_per_anchor(&mut cluster, 3).await?;

    cluster.crash(2);
    let tip = finalize_one_block_per_anchor(&mut cluster, 6).await?;

    cluster.restart(2, true).await?;
    cluster
        .node(2)
        .wait_for_finalized(tip, FINALIZE_TIMEOUT)
        .await?;
    for height in 1..=tip {
        cluster.assert_same_block(height).await?;
    }
    Ok(())
}

/// A node that has not observed a finalized Tempo anchor abstains instead of rejecting the block.
/// The other three finalize it; once the observation arrives, the lagging node applies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_late_anchor_observation_waits_instead_of_rejecting() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;
    let before = finalize_one_block_per_anchor(&mut cluster, 2).await?;

    let anchor = cluster.inject_block_observed_by(vec![], &[0, 1, 2]);
    for index in 0..3 {
        cluster
            .node(index)
            .wait_for_finalized(before + 1, FINALIZE_TIMEOUT)
            .await?;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        cluster.node(3).finalized_number().await?,
        before,
        "node 3 must not finalize a block whose anchor it has not observed"
    );

    cluster.record_anchor(3, anchor)?;
    cluster
        .node(3)
        .wait_for_finalized(before + 1, FINALIZE_TIMEOUT)
        .await?;
    cluster.assert_same_block(before + 1).await?;

    // Node 3 votes again on later blocks.
    finalize_one_block_per_anchor(&mut cluster, 2).await?;
    Ok(())
}

/// With two of four nodes down there is no quorum: nothing finalizes and nothing is lost. When one
/// returns, the zone resumes on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_halts_without_quorum_and_resumes() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;
    let before = finalize_one_block_per_anchor(&mut cluster, 2).await?;

    cluster.crash(2);
    cluster.crash(3);
    cluster.inject_block(vec![]);
    tokio::time::sleep(Duration::from_secs(5)).await;
    for (index, node) in cluster.live() {
        assert_eq!(
            node.finalized_number().await?,
            before,
            "node {index} finalized without a quorum"
        );
    }

    cluster.restart(3, false).await?;
    cluster
        .wait_all_finalized(before + 1, FINALIZE_TIMEOUT)
        .await?;
    cluster.assert_same_block(before + 1).await?;
    Ok(())
}

/// Several anchors queued at once are imported through checkpoint-only blocks followed by one
/// full import. Deposits in the crossed anchors are owed by the full import and mint exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_checkpoint_catch_up_preserves_deposits() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;
    finalize_one_block_per_anchor(&mut cluster, 1).await?;

    let recipients = [
        address!("0x00000000000000000000000000000000000a0001"),
        address!("0x00000000000000000000000000000000000a0002"),
    ];
    let depositor = address!("0x00000000000000000000000000000000000d0001");
    let mut last_anchor = 0;
    for anchor in 0..6 {
        let deposits = match anchor {
            1 => vec![L1Fixture::make_deposit_for_block(
                PATH_USD_ADDRESS,
                depositor,
                recipients[0],
                1_000,
            )],
            3 => vec![L1Fixture::make_deposit_for_block(
                PATH_USD_ADDRESS,
                depositor,
                recipients[1],
                2_000,
            )],
            _ => Vec::new(),
        };
        last_anchor = cluster.inject_block(deposits).number;
    }

    for (_, node) in cluster.live() {
        node.wait_for_tempo_block_number(last_anchor, FINALIZE_TIMEOUT)
            .await?;
        node.wait_for_balance(
            PATH_USD_ADDRESS,
            recipients[1],
            U256::from(2_000),
            DEFAULT_TIMEOUT,
        )
        .await?;
    }
    let tip = cluster.node(0).finalized_number().await?;
    cluster.wait_all_finalized(tip, FINALIZE_TIMEOUT).await?;
    cluster.assert_same_block(tip).await?;
    assert!(
        tip < 1 + 6,
        "queued anchors should be batched through checkpoint imports, got {tip} blocks"
    );
    for (_, node) in cluster.live() {
        assert_eq!(
            node.balance_of(PATH_USD_ADDRESS, recipients[0]).await?,
            U256::from(1_000)
        );
        assert_eq!(
            node.balance_of(PATH_USD_ADDRESS, recipients[1]).await?,
            U256::from(2_000)
        );
    }
    Ok(())
}

/// Proposals that violate the beneficiary rule are rejected by every other node. The rogue
/// leader's views are nullified, none of its blocks finalize, and the zone keeps moving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_rejects_invalid_proposals() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let rogue = 1;
    let mut cluster = start_local_simplex_cluster_with_rogue_proposer(4, 64, rogue).await?;

    let tip = finalize_one_block_per_anchor(&mut cluster, 8).await?;
    let mut proposers = BTreeSet::new();
    for height in 1..=tip {
        proposers.insert(cluster.proposer_of(height).await?);
    }
    assert!(
        !proposers.contains(&rogue),
        "an invalid proposal from node {rogue} finalized"
    );
    assert!(
        proposers.len() >= 2,
        "honest leaders should still rotate, proposers were {proposers:?}"
    );
    Ok(())
}

/// Every node crashes and restarts from its own datadir. Consensus resumes from the persisted
/// vote journals and marshal archives with no recovery directive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_whole_fleet_restart_resumes() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_local_simplex_cluster(4, 64).await?;
    let before = finalize_one_block_per_anchor(&mut cluster, 3).await?;
    let mut hashes = Vec::new();
    for height in 1..=before {
        hashes.push(cluster.assert_same_block(height).await?.hash);
    }

    for index in 0..4 {
        cluster.crash(index);
    }
    for index in 0..4 {
        cluster.restart(index, false).await?;
    }

    let tip = finalize_one_block_per_anchor(&mut cluster, 3).await?;
    for (offset, hash) in hashes.into_iter().enumerate() {
        let height = offset as u64 + 1;
        assert_eq!(
            cluster.assert_same_block(height).await?.hash,
            hash,
            "restart replaced finalized block {height}"
        );
    }
    cluster.assert_same_block(tip).await?;
    Ok(())
}
