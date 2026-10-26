//! Exercise proof collection against a real pending engine payload and Tempo L1.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use std::{path::Path, time::Duration};
use zone_sequencer::StoredBlockProof;

use crate::utils::start_real_p2p_cluster_with_settlement_proving;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_blocks_get_durable_proofs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_real_p2p_cluster_with_settlement_proving(120, 2).await?;
    let leader = &cluster.nodes[0];
    let mut canonical = leader.subscribe_to_canonical_state();
    let mut follower_canonical = cluster.nodes[1].subscribe_to_canonical_state();
    let notification = tokio::time::timeout(Duration::from_secs(60), canonical.recv()).await??;
    let tip = notification.tip();
    let proof = wait_for_proof(&leader.proof_directory(), tip.number(), tip.hash()).await?;
    assert_eq!(proof.witness.parent_hash, tip.parent_hash());

    // Followers persist witnesses too, so a promoted node can prove its tail.
    let follower_tip = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let notification = follower_canonical.recv().await?;
            let follower_tip = notification.tip();
            if follower_tip.number() >= tip.number() {
                return Ok::<_, eyre::Report>((follower_tip.number(), follower_tip.hash()));
            }
        }
    })
    .await??;
    wait_for_proof(
        &cluster.nodes[1].proof_directory(),
        follower_tip.0,
        follower_tip.1,
    )
    .await?;

    // Turn the spool path into a regular file to force the next atomic write to fail.
    let directory = leader.proof_directory();
    let retained = directory.with_file_name("proofs-retained");
    std::fs::rename(&directory, &retained)?;
    std::fs::File::create(&directory)?;
    let _exit = tokio::time::timeout(
        Duration::from_secs(30),
        cluster.nodes[0].wait_for_node_exit(),
    )
    .await
    .expect("node must shut down after a proof-store mutation fails");
    std::fs::remove_file(&directory)?;
    std::fs::rename(&retained, &directory)?;
    Ok(())
}

/// Wait for the background collector to persist the witness of one canonical block.
async fn wait_for_proof(
    directory: &Path,
    number: u64,
    hash: B256,
) -> eyre::Result<StoredBlockProof> {
    let path = directory.join(format!("{number}-{hash:x}.json"));
    let proof: StoredBlockProof = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(bytes) = std::fs::read(&path) {
                return serde_json::from_slice(&bytes);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    assert_eq!(proof.witness.block_number, number);
    assert_eq!(proof.witness.block_hash, hash);
    Ok(proof)
}
