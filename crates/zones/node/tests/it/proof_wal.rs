//! Exercise proof collection against a real pending engine payload and Tempo L1.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use alloy_provider::Provider as _;
use std::{path::Path, time::Duration};
use zone_sequencer::StoredBlockProof;

use crate::utils::start_real_p2p_cluster_with_settlement_proving;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_blocks_get_best_effort_durable_proofs() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let cluster = start_real_p2p_cluster_with_settlement_proving(120, 2).await?;
    let leader = &cluster.nodes[0];
    let mut canonical = leader.subscribe_to_canonical_state();
    let notification = tokio::time::timeout(Duration::from_secs(60), canonical.recv()).await??;
    let tip = notification.tip();

    // The leader collects witnesses in the background, after the block is canonical.
    let proof = wait_for_proof(&leader.proof_directory(), tip.number(), tip.hash()).await?;
    assert_eq!(proof.witness.parent_hash, tip.parent_hash());
    assert!(leader.provider().get_block_number().await? >= proof.witness.block_number);

    // Followers persist a broadcast witness or collect a missing one in the background, so a
    // promoted node can prove its tail.
    wait_for_proof(
        &cluster.nodes[1].proof_directory(),
        tip.number(),
        tip.hash(),
    )
    .await?;

    // Turn the spool path into a regular file so every proof write fails, retaining the
    // previously collected proofs in a sibling directory. Production must carry on.
    let directory = leader.proof_directory();
    let retained = directory.with_file_name("proofs-retained");
    std::fs::rename(&directory, &retained)?;
    std::fs::File::create(&directory)?;
    let target = tip.number() + 3;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if canonical.recv().await?.tip().number() >= target {
                return Ok::<_, eyre::Report>(());
            }
        }
    })
    .await
    .expect("leader must keep producing blocks while proof writes fail")?;
    std::fs::remove_file(&directory)?;
    std::fs::rename(&retained, &directory)?;
    Ok(())
}

/// Wait for the stored proof of block `number` with `hash` to appear in `directory`.
async fn wait_for_proof(
    directory: &Path,
    number: u64,
    hash: B256,
) -> eyre::Result<StoredBlockProof> {
    let path = directory.join(format!("{number}-{hash:x}.json"));
    tokio::time::timeout(Duration::from_secs(60), async {
        while !path.is_file() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    let proof: StoredBlockProof = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(proof.witness.block_number, number);
    assert_eq!(proof.witness.block_hash, hash);
    Ok(proof)
}
