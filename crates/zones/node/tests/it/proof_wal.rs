//! Exercise proof collection against a real Simplex quorum and Tempo L1.

use std::time::Duration;

use alloy_consensus::BlockHeader as _;
use alloy_provider::Provider as _;
use alloy_rpc_types_eth::BlockNumberOrTag;
use zone_sequencer::StoredBlockProof;

use crate::utils::{
    RealSimplexCluster, ZoneTestNode, start_real_simplex_cluster, unreachable_prover_addresses,
};

const FINALIZED_BLOCKS: u64 = 6;

/// Assert `node` holds a durable proof for every finalized block.
async fn assert_finalized_proofs(node: &ZoneTestNode, finalized: u64) -> eyre::Result<()> {
    for number in 1..=finalized {
        let block = node
            .provider()
            .get_block_by_number(BlockNumberOrTag::Number(number))
            .await?
            .ok_or_else(|| eyre::eyre!("finalized block {number} is missing"))?;
        let hash = block.header.hash;
        let path = node
            .proof_directory()
            .join(format!("{number}-{hash:x}.json"));
        let proof: StoredBlockProof = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(proof.witness.block_hash, hash);
        assert_eq!(proof.witness.parent_hash, block.header.parent_hash());
        assert_eq!(proof.witness.block_number, number);
    }
    Ok(())
}

/// Every participant persists a witness before it finalizes a block, so any node can prove any
/// batch, and a node whose proof store fails stops instead of finalizing without a proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_finalized_block_has_a_durable_proof_on_every_node() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let mut cluster: RealSimplexCluster =
        start_real_simplex_cluster(4, 120, 60_000, Some(unreachable_prover_addresses()?)).await?;
    for (_, node) in cluster.live() {
        node.wait_for_finalized(FINALIZED_BLOCKS, Duration::from_secs(60))
            .await?;
        assert_finalized_proofs(node, FINALIZED_BLOCKS).await?;
    }

    // Turn node 0's spool path into a regular file to force its next atomic write to fail.
    let directory = cluster.node(0).proof_directory();
    let retained = directory.with_file_name("proofs-retained");
    std::fs::rename(&directory, &retained)?;
    std::fs::File::create(&directory)?;
    let node = cluster.nodes[0].as_mut().expect("node 0 is running");
    let _exit = tokio::time::timeout(Duration::from_secs(30), node.wait_for_node_exit())
        .await
        .expect("node must shut down after a proof-store mutation fails");
    std::fs::remove_file(&directory)?;
    std::fs::rename(&retained, &directory)?;
    Ok(())
}
