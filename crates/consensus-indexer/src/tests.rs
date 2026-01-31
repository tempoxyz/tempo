use tempfile::NamedTempFile;
use tempo_node::rpc::consensus::{CertifiedBlock, Query};

use crate::db::ConsensusDb;

fn sample_block(height: Option<u64>, view: u64) -> CertifiedBlock {
    CertifiedBlock {
        epoch: 1,
        view,
        height,
        digest: alloy_primitives::B256::ZERO,
        certificate: "cert".to_string(),
    }
}

#[tokio::test]
async fn db_roundtrip_finalization_latest() {
    let file = NamedTempFile::new().unwrap();
    let url = format!("sqlite://{}", file.path().display());
    let db = ConsensusDb::connect(&url).await.unwrap();

    let block = sample_block(Some(5), 7);
    db.upsert_finalized_block(&block, 123).await.unwrap();

    let latest = db.get_finalization(Query::Latest).await.unwrap().unwrap();
    assert_eq!(latest, block);

    let by_height = db
        .get_finalization(Query::Height(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_height, block);
}
