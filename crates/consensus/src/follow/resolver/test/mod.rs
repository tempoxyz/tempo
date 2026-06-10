use commonware_codec::Encode as _;
use commonware_consensus::types::Height;
use futures::executor::block_on;

use super::{resolve_block, resolve_finalized};

mod utils;
use utils::{StubBlockProvider, StubUpstream, make_block, make_certified_block};

#[test]
fn resolves_blocks_from_local_execution_first() {
    block_on(async {
        let provider = StubBlockProvider::default();
        let upstream = StubUpstream::default();
        let block = make_block(3);
        provider.add_block(&block);

        let resolved = resolve_block(&provider, &upstream, block.digest()).await;

        assert_eq!(resolved, Some(block.encode()));
        assert_eq!(provider.reads(), 1);
        assert_eq!(upstream.block_reads(), 0);
    });
}

#[test]
fn falls_back_to_upstream_for_missing_blocks() {
    block_on(async {
        let provider = StubBlockProvider::default();
        let upstream = StubUpstream::default();
        let block = make_block(4);
        upstream.add_block(block.clone());

        let resolved = resolve_block(&provider, &upstream, block.digest()).await;

        assert_eq!(resolved, Some(block.encode()));
        assert_eq!(provider.reads(), 1);
        assert_eq!(upstream.block_reads(), 1);
    });
}

#[test]
fn retries_after_local_provider_errors() {
    block_on(async {
        let provider = StubBlockProvider::default();
        provider.fail_reads();
        let upstream = StubUpstream::default();
        let block = make_block(5);

        assert_eq!(
            resolve_block(&provider, &upstream, block.digest()).await,
            None
        );
        assert_eq!(upstream.block_reads(), 0);
    });
}

#[test]
fn resolves_finalizations_from_upstream() {
    block_on(async {
        let upstream = StubUpstream::default();
        let height = Height::new(6);
        let (certified, encoded) = make_certified_block(height);
        upstream.add_finalization(height, certified);

        assert_eq!(resolve_finalized(&upstream, height).await, Some(encoded));
        assert_eq!(upstream.finalization_reads(), 1);
    });
}
