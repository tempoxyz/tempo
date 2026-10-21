//! Simplex settlement against a real Tempo L1 and ZonePortal.
//!
//! The Portal registers all four individual sequencer keys with a threshold of one. Every node
//! prepares every batch from Simplex-finalized blocks; the batch's duty owner submits it, and any
//! other node submits once the failover delay passes without the Portal advancing.

use std::{collections::BTreeSet, time::Duration};

use alloy::primitives::Address;
use alloy_network::TransactionResponse as _;
use alloy_provider::{Provider as _, ProviderBuilder};
use alloy_rpc_types_eth::BlockNumberOrTag;
use tempo_alloy::TempoNetwork;
use tempo_contracts::zones::ZonePortal;

use crate::utils::{RealSimplexCluster, poll_until, start_real_simplex_cluster};

const SETTLEMENT_TIMEOUT: Duration = Duration::from_secs(180);

/// One accepted `submitBatch`: its withdrawal batch index and the L1 account that sent it.
struct Submission {
    withdrawal_batch_index: u64,
    sender: Address,
}

async fn submissions(cluster: &RealSimplexCluster) -> eyre::Result<Vec<Submission>> {
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    // submitBatch is sent as a Tempo transaction, which the Ethereum-typed provider cannot decode.
    let l1 = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(cluster.l1.http_url().clone());
    let mut submissions = Vec::new();
    for (event, log) in portal
        .BatchSubmitted_1_filter()
        .from_block(0)
        .query()
        .await?
    {
        let hash = log
            .transaction_hash
            .ok_or_else(|| eyre::eyre!("BatchSubmitted log has no transaction hash"))?;
        let transaction = l1
            .get_transaction_by_hash(hash)
            .await?
            .ok_or_else(|| eyre::eyre!("submitBatch transaction {hash} not found"))?;
        submissions.push(Submission {
            withdrawal_batch_index: event.withdrawalBatchIndex,
            sender: transaction.from(),
        });
    }
    Ok(submissions)
}

async fn wait_for_submissions(
    cluster: &RealSimplexCluster,
    count: usize,
) -> eyre::Result<Vec<Submission>> {
    poll_until(
        SETTLEMENT_TIMEOUT,
        Duration::from_millis(500),
        &format!("{count} BatchSubmitted events"),
        || async {
            let submissions = submissions(cluster).await?;
            Ok((submissions.len() >= count).then_some(submissions))
        },
    )
    .await
}

/// Owner of `index` under the duty rotation: participants sorted by address.
fn duty_owner(cluster: &RealSimplexCluster, index: u64) -> Address {
    let mut participants: Vec<_> = cluster
        .attestation_signers
        .iter()
        .map(|signer| signer.address())
        .collect();
    participants.sort_unstable();
    participants[(index % participants.len() as u64) as usize]
}

/// Settled zone state is a block every live node finalized.
async fn assert_portal_block_finalized_everywhere(
    cluster: &RealSimplexCluster,
) -> eyre::Result<()> {
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    let settled_hash = portal.blockHash().call().await?;
    let settled_height: u64 = portal.zoneHeight().call().await?.try_into()?;
    for (index, node) in cluster.live() {
        node.wait_for_finalized(settled_height, SETTLEMENT_TIMEOUT)
            .await?;
        let block = node
            .provider()
            .get_block_by_number(BlockNumberOrTag::Number(settled_height))
            .await?
            .ok_or_else(|| eyre::eyre!("node {index} has no block {settled_height}"))?;
        eyre::ensure!(
            block.header.hash == settled_hash,
            "node {index} finalized {} at {settled_height}, the portal settled {settled_hash}",
            block.header.hash
        );
    }
    Ok(())
}

/// Each batch is settled once, by its rotating duty owner, with a one-signature certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_settles_with_rotating_duty() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let cluster = start_real_simplex_cluster(4, 4, 60_000, None).await?;
    let portal = ZonePortal::new(cluster.portal_address, cluster.l1.provider());
    assert_eq!(portal.sequencerThreshold().call().await?, 1);

    let submissions = wait_for_submissions(&cluster, 4).await?;
    let mut senders = BTreeSet::new();
    for submission in &submissions {
        assert_eq!(
            submission.sender,
            duty_owner(&cluster, submission.withdrawal_batch_index),
            "batch {} was not settled by its duty owner",
            submission.withdrawal_batch_index
        );
        senders.insert(submission.sender);
    }
    assert!(
        senders.len() >= 2,
        "settlement duty did not rotate: {senders:?}"
    );
    let indices: BTreeSet<_> = submissions
        .iter()
        .map(|submission| submission.withdrawal_batch_index)
        .collect();
    assert_eq!(
        indices.len(),
        submissions.len(),
        "a batch was settled twice"
    );
    assert_portal_block_finalized_everywhere(&cluster).await
}

/// When the owner of the next batch is down, another sequencer settles it after the failover
/// delay. No operator action is involved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_simplex_settlement_fails_over_from_crashed_owner() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_real_simplex_cluster(4, 4, 5_000, None).await?;

    let first = wait_for_submissions(&cluster, 1).await?;
    let next = first
        .iter()
        .map(|submission| submission.withdrawal_batch_index)
        .max()
        .expect("one submission")
        + 1;
    let owner = duty_owner(&cluster, next);
    let owner_node = cluster
        .attestation_signers
        .iter()
        .position(|signer| signer.address() == owner)
        .expect("owner is a cluster member");
    cluster.crash(owner_node);

    // A submission sent just before the crash may still land, so skip one batch before choosing
    // the first one the crashed owner can no longer have settled.
    let settled = submissions(&cluster)
        .await?
        .iter()
        .map(|submission| submission.withdrawal_batch_index)
        .max()
        .unwrap_or_default();
    let target = (settled + 2..)
        .find(|index| duty_owner(&cluster, *index) == owner)
        .expect("the rotation includes the owner");

    let submissions = poll_until(
        SETTLEMENT_TIMEOUT,
        Duration::from_millis(500),
        &format!("BatchSubmitted for withdrawal batch {target}"),
        || async {
            let submissions = submissions(&cluster).await?;
            Ok(submissions
                .iter()
                .any(|submission| submission.withdrawal_batch_index >= target)
                .then_some(submissions))
        },
    )
    .await?;
    let failover = submissions
        .iter()
        .find(|submission| submission.withdrawal_batch_index == target)
        .ok_or_else(|| eyre::eyre!("batch {target} was skipped"))?;
    assert_ne!(
        failover.sender, owner,
        "the crashed owner cannot have settled batch {target}"
    );
    assert_portal_block_finalized_everywhere(&cluster).await
}
