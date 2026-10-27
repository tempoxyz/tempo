//! Zone block production when the L1 RPC cannot serve the state proofs a witness needs.
//!
//! Before T15 a missing witness only forces `NoProof` settlement, so production must continue.

use std::time::Duration;

use alloy::providers::Provider as _;
use tempo_contracts::zones::ZonePortal;

use crate::utils::{
    RealP2pCluster, ZoneAccount, ZoneTestNode, poll_until, start_real_p2p_cluster_without_l1_proofs,
};

const TIMEOUT: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(200);
const DEPOSIT: u128 = 1_000_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pre_t15_zone_produces_and_settles_without_witnesses() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let cluster = start_real_p2p_cluster_without_l1_proofs(4).await?;
    let leader = &cluster.nodes[0];

    // A deposit is imported by a full block, whose witness needs L1 state proofs.
    let mut account = ZoneAccount::from_l1_and_zone(&cluster.l1, leader, cluster.portal_address);
    cluster.l1.fund_user(account.address(), DEPOSIT * 2).await?;
    account.deposit(DEPOSIT, TIMEOUT, leader).await?;

    // Followers import the leader's blocks even though they arrive without witnesses.
    let height = leader.provider().get_block_number().await?;
    cluster.wait_all_at(height, TIMEOUT).await?;
    cluster.assert_same_block(height).await?;
    // NoProof settlement can pass `height` before this check runs, and settled witnesses are
    // pruned, so look for an unwitnessed block in the leader's unsettled tail instead.
    poll_until(
        TIMEOUT,
        POLL,
        "an unsettled leader block without a witness",
        || async {
            let head = leader.provider().get_block_number().await?;
            let mut unwitnessed = Vec::new();
            for number in settled_zone_height(&cluster).await? + 1..=head {
                if !has_witness(leader, number).await? {
                    unwitnessed.push(number);
                }
            }
            // A block settled since its check may have lost its witness to pruning.
            let settled = settled_zone_height(&cluster).await?;
            Ok(unwitnessed.into_iter().find(|&number| number > settled))
        },
    )
    .await?;

    // Blocks without witnesses settle with the NoProof verifier.
    poll_until(
        TIMEOUT,
        POLL,
        "settled zone height to pass the deposit",
        || async {
            let settled = settled_zone_height(&cluster).await?;
            Ok((settled >= height).then_some(settled))
        },
    )
    .await?;
    Ok(())
}

async fn settled_zone_height(cluster: &RealP2pCluster) -> eyre::Result<u64> {
    let height = ZonePortal::new(cluster.portal_address, cluster.l1.provider())
        .zoneHeight()
        .call()
        .await?;
    Ok(u64::try_from(height)?)
}

/// Whether the node persisted a witness for its canonical block at `number`.
async fn has_witness(node: &ZoneTestNode, number: u64) -> eyre::Result<bool> {
    let block = node
        .provider()
        .get_block_by_number(number.into())
        .await?
        .ok_or_else(|| eyre::eyre!("zone block {number} not found"))?;
    Ok(node
        .proof_directory()
        .join(format!("{number}-{:x}.json", block.header.hash))
        .is_file())
}
