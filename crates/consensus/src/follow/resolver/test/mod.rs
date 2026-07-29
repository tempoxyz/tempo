use commonware_codec::Encode as _;
use commonware_consensus::{marshal::resolver::handler, types::Height};
use futures::executor::block_on;
use std::time::{Duration, SystemTime};

use super::{MAX_RETRY_DELAY, RETRY_STATE_TTL, RetryState, resolve_block, resolve_finalized};

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

#[test]
fn malformed_finalization_is_retried() {
    block_on(async {
        let upstream = StubUpstream::default();
        let height = Height::new(6);
        let (mut certified, _) = make_certified_block(height);
        certified.certificate = "not-hex".to_string();
        upstream.add_finalization(height, certified);

        assert_eq!(resolve_finalized(&upstream, height).await, None);
        assert_eq!(upstream.finalization_reads(), 1);
    });
}

#[test]
fn retry_state_advances_resets_and_expires() {
    let now = SystemTime::UNIX_EPOCH;
    let first = handler::Key::Block(make_block(7).digest());
    let second = handler::Key::Block(make_block(8).digest());
    let mut retries = RetryState::default();

    let mut delay = retries.begin(first, now);
    assert_eq!(delay, Duration::ZERO);
    for expected in [
        Duration::from_millis(250),
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
        Duration::from_secs(8),
        Duration::from_secs(16),
        MAX_RETRY_DELAY,
        MAX_RETRY_DELAY,
    ] {
        retries.failed(first, delay, now);
        delay = retries.begin(first, now);
        assert_eq!(delay, expected);
    }

    retries.succeeded(&first);
    assert_eq!(retries.begin(first, now), Duration::ZERO);
    retries.failed(first, Duration::ZERO, now);

    let expired = now + RETRY_STATE_TTL;
    assert_eq!(retries.begin(second, expired), Duration::ZERO);
    assert!(!retries.entries.contains_key(&first));
}
