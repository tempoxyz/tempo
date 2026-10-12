//! Exercise proof collection against a real pending engine payload and Tempo L1.

use alloy_consensus::BlockHeader as _;
use alloy_provider::Provider as _;
use std::time::Duration;
use zone_sequencer::StoredBlockProof;

use crate::utils::start_real_p2p_cluster_with_settlement_proving;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_leader_block_has_durable_proof() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster = start_real_p2p_cluster_with_settlement_proving(120, 2).await?;
    let leader = &cluster.nodes[0];
    let mut canonical = leader.subscribe_to_canonical_state();
    let mut follower_canonical = cluster.nodes[1].subscribe_to_canonical_state();
    let notification = tokio::time::timeout(Duration::from_secs(60), canonical.recv()).await??;
    let tip = notification.tip();
    let path = leader
        .proof_directory()
        .join(format!("{}-{:x}.json", tip.number(), tip.hash()));
    let proof: StoredBlockProof = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(proof.witness.block_hash, tip.hash());
    assert_eq!(proof.witness.parent_hash, tip.parent_hash());
    assert_eq!(proof.witness.block_number, tip.number());
    assert!(leader.provider().get_block_number().await? >= proof.witness.block_number);

    // Followers must also persist before canonicalization, so a promoted node can prove its tail.
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let notification = follower_canonical.recv().await?;
            let follower_tip = notification.tip();
            let path = cluster.nodes[1].proof_directory().join(format!(
                "{}-{:x}.json",
                follower_tip.number(),
                follower_tip.hash()
            ));
            let proof: StoredBlockProof = serde_json::from_slice(&std::fs::read(path)?)?;
            assert_eq!(proof.witness.block_hash, follower_tip.hash());
            if follower_tip.number() >= tip.number() {
                return Ok::<_, eyre::Report>(());
            }
        }
    })
    .await??;

    // Turn the spool path into a regular file to force the next atomic write to fail,
    // retaining the previously collected proofs in a sibling directory.
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

    // A block already persisted when the fault was injected may still become canonical.
    // Every such notification must have a proof in the retained spool.
    while let Ok(notification) = canonical.try_recv() {
        let tip = notification.tip();
        assert!(
            retained
                .join(format!("{}-{:x}.json", tip.number(), tip.hash()))
                .is_file(),
            "proof persistence failure must not canonicalize a block without a durable proof"
        );
    }
    std::fs::remove_file(&directory)?;
    std::fs::rename(&retained, &directory)?;
    Ok(())
}
