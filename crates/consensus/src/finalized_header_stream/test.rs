use alloy_primitives::B256;
use alloy_provider::{Provider, ProviderBuilder, mock::Asserter};
use alloy_rpc_types_eth::Header;
use commonware_consensus::types::Epoch;
use futures::StreamExt as _;
use rand::{SeedableRng as _, rngs::StdRng};
use tempo_alloy::{TempoNetwork, rpc::TempoHeaderResponse};
use tempo_chainspec::NetworkIdentity;

use super::{Config, Error, FinalizedHeaderStream};
use crate::{
    consensus::Block,
    follow::test_utils::{
        EPOCH_LENGTH, dkg_fixture, make_block, make_certified_block, make_child_block,
        make_finalization,
    },
};

fn mock_provider(asserter: Asserter) -> impl Provider<TempoNetwork> {
    ProviderBuilder::<_, _, TempoNetwork>::default().connect_mocked_client(asserter)
}

fn push_header(asserter: &Asserter, block: &Block) {
    asserter.push_success(&Some(TempoHeaderResponse {
        inner: Header {
            hash: block.block_hash(),
            inner: block.header().clone(),
            total_difficulty: None,
            size: None,
        },
        timestamp_millis: block.header().timestamp_millis(),
    }));
}

fn push_headers<'a>(asserter: &Asserter, blocks: impl IntoIterator<Item = &'a Block>) {
    for block in blocks {
        push_header(asserter, block);
    }
}

fn push_reverse_chunk_headers(asserter: &Asserter, blocks: &[Block], chunk_size: usize) {
    let mut to = blocks.len();
    while to > 0 {
        let from = to.saturating_sub(chunk_size);
        push_headers(asserter, &blocks[from..to]);
        to = from;
    }
}

#[tokio::test]
async fn expands_a_sparse_tip_certificate() {
    let mut rng = StdRng::seed_from_u64(1);
    let fixture = dkg_fixture(&mut rng, Epoch::zero());
    let genesis = make_block(0, Some(&fixture.outcome));
    let block_1 = make_child_block(&genesis, 1, None);
    let block_2 = make_child_block(&block_1, 2, None);

    let finalization = make_finalization(&block_2, Epoch::zero(), &fixture.schemes);
    let certified = make_certified_block(block_2.clone(), &finalization);
    let asserter = Asserter::new();
    push_header(&asserter, &genesis);
    push_header(&asserter, &genesis);
    asserter.push_success(&certified);
    push_reverse_chunk_headers(&asserter, &[block_1.clone(), block_2.clone()], 1);
    push_headers(&asserter, [&block_1, &block_2]);

    let mut config = Config::new(genesis.block_hash(), None, EPOCH_LENGTH);
    config.chunk_size = 1;
    let mut stream = FinalizedHeaderStream::init(mock_provider(asserter.clone()), config)
        .await
        .expect("stream should initialize");

    for expected in [&block_1, &block_2] {
        let actual = stream
            .next()
            .await
            .expect("stream should remain open")
            .expect("header should be authenticated");
        assert_eq!(actual.num_hash(), expected.num_hash());
    }
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn bridges_a_full_dkg_boundary() {
    let mut rng = StdRng::seed_from_u64(2);
    let current = dkg_fixture(&mut rng, Epoch::zero());
    let next = dkg_fixture(&mut rng, Epoch::new(1));
    let mut blocks = vec![make_block(0, Some(&current.outcome))];
    for height in 1..=EPOCH_LENGTH.get() {
        let outcome = (height == EPOCH_LENGTH.get() - 1).then_some(&next.outcome);
        let block = make_child_block(
            blocks.last().expect("genesis was inserted"),
            height,
            outcome,
        );
        blocks.push(block);
    }

    let boundary = &blocks[EPOCH_LENGTH.get() as usize - 1];
    let boundary_finalization = make_finalization(boundary, Epoch::zero(), &current.schemes);
    let tip = blocks.last().expect("tip was inserted");
    let tip_finalization = make_finalization(tip, Epoch::new(1), &next.schemes);
    let boundary_certified = make_certified_block(boundary.clone(), &boundary_finalization);
    let tip_certified = make_certified_block(tip.clone(), &tip_finalization);

    let asserter = Asserter::new();
    push_header(&asserter, &blocks[0]);
    push_header(&asserter, &blocks[0]);
    asserter.push_success(&tip_certified);
    asserter.push_success(&boundary_certified);
    push_reverse_chunk_headers(&asserter, &blocks[1..EPOCH_LENGTH.get() as usize], 3);
    push_headers(&asserter, &blocks[1..EPOCH_LENGTH.get() as usize]);
    asserter.push_success(&tip_certified);
    push_header(&asserter, tip);
    push_header(&asserter, tip);

    let genesis = &blocks[0];
    let mut config = Config::new(genesis.block_hash(), None, EPOCH_LENGTH);
    config.chunk_size = 3;
    let mut stream = FinalizedHeaderStream::init(mock_provider(asserter.clone()), config)
        .await
        .expect("stream should initialize");

    for expected in &blocks[1..] {
        let actual = stream
            .next()
            .await
            .expect("stream should remain open")
            .expect("header should be authenticated");
        assert_eq!(actual.num_hash(), expected.num_hash());
    }
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn uses_authoritative_identity_for_initial_backfill() {
    let mut rng = StdRng::seed_from_u64(3);
    let old = dkg_fixture(&mut rng, Epoch::zero());
    let authoritative = dkg_fixture(&mut rng, Epoch::new(1));
    let mut blocks = vec![make_block(0, Some(&old.outcome))];
    for height in 1..=EPOCH_LENGTH.get() {
        let outcome = (height == EPOCH_LENGTH.get() - 1).then_some(&authoritative.outcome);
        let block = make_child_block(
            blocks.last().expect("genesis was inserted"),
            height,
            outcome,
        );
        blocks.push(block);
    }

    let tip = blocks.last().expect("tip was inserted");
    let tip_finalization =
        make_finalization(tip, authoritative.outcome.epoch, &authoritative.schemes);
    let certified = make_certified_block(tip.clone(), &tip_finalization);
    let asserter = Asserter::new();
    push_header(&asserter, &blocks[0]);
    asserter.push_success(&certified);
    push_reverse_chunk_headers(&asserter, &blocks[1..], 4);
    push_headers(&asserter, &blocks[1..]);

    let genesis = &blocks[0];
    let network_identity = NetworkIdentity {
        from_epoch: authoritative.outcome.epoch.get(),
        identity: *authoritative.outcome.network_identity(),
    };
    let mut config = Config::new(genesis.block_hash(), Some(network_identity), EPOCH_LENGTH);
    config.chunk_size = 4;
    let mut stream = FinalizedHeaderStream::init(mock_provider(asserter.clone()), config)
        .await
        .expect("stream should initialize");

    for expected in &blocks[1..] {
        let actual = stream
            .next()
            .await
            .expect("stream should remain open")
            .expect("header should be authenticated");
        assert_eq!(actual.num_hash(), expected.num_hash());
    }
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn falls_back_to_identity_anchored_by_start() {
    let mut rng = StdRng::seed_from_u64(4);
    let old = dkg_fixture(&mut rng, Epoch::zero());
    let current = dkg_fixture(&mut rng, Epoch::new(1));
    let mut blocks = vec![make_block(0, Some(&old.outcome))];
    for height in 1..=EPOCH_LENGTH.get() {
        let outcome = (height == EPOCH_LENGTH.get() - 1).then_some(&current.outcome);
        let block = make_child_block(
            blocks.last().expect("genesis was inserted"),
            height,
            outcome,
        );
        blocks.push(block);
    }
    let tip = make_child_block(
        blocks.last().expect("start block was inserted"),
        EPOCH_LENGTH.get() + 1,
        None,
    );
    let finalization = make_finalization(&tip, Epoch::new(1), &current.schemes);
    let certified = make_certified_block(tip.clone(), &finalization);
    let start = blocks.last().expect("start block was inserted");

    let asserter = Asserter::new();
    push_header(&asserter, start);
    asserter.push_success(&certified);
    push_headers(&asserter, &blocks[EPOCH_LENGTH.get() as usize - 1..]);
    asserter.push_success(&certified);
    push_header(&asserter, &tip);
    push_header(&asserter, &tip);

    let stale_identity = NetworkIdentity {
        from_epoch: old.outcome.epoch.get(),
        identity: *old.outcome.network_identity(),
    };
    let mut stream = FinalizedHeaderStream::init(
        mock_provider(asserter.clone()),
        Config::new(start.block_hash(), Some(stale_identity), EPOCH_LENGTH),
    )
    .await
    .expect("stream should initialize");

    let actual = stream
        .next()
        .await
        .expect("stream should remain open")
        .expect("start-anchored identity should verify the tip");
    assert_eq!(actual.num_hash(), tip.num_hash());
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn applies_transition_from_start_boundary() {
    let mut rng = StdRng::seed_from_u64(5);
    let current = dkg_fixture(&mut rng, Epoch::zero());
    let next = dkg_fixture(&mut rng, Epoch::new(1));
    let start = make_block(EPOCH_LENGTH.get() - 1, Some(&next.outcome));
    let tip = make_child_block(&start, EPOCH_LENGTH.get(), None);
    let finalization = make_finalization(&tip, Epoch::new(1), &next.schemes);
    let certified = make_certified_block(tip.clone(), &finalization);

    let asserter = Asserter::new();
    push_header(&asserter, &start);
    push_header(&asserter, &start);
    asserter.push_success(&certified);
    push_header(&asserter, &tip);
    push_header(&asserter, &tip);

    let network_identity = NetworkIdentity {
        from_epoch: current.outcome.epoch.get(),
        identity: *current.outcome.network_identity(),
    };
    let mut stream = FinalizedHeaderStream::init(
        mock_provider(asserter.clone()),
        Config::new(start.block_hash(), Some(network_identity), EPOCH_LENGTH),
    )
    .await
    .expect("stream should initialize from the trusted boundary");

    let actual = stream
        .next()
        .await
        .expect("stream should remain open")
        .expect("boundary identity should verify the next epoch");
    assert_eq!(actual.num_hash(), tip.num_hash());
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn does_not_resolve_start_identity_when_caught_up() {
    let mut rng = StdRng::seed_from_u64(6);
    let fixture = dkg_fixture(&mut rng, Epoch::zero());
    let start = make_block(1, None);
    let finalization = make_finalization(&start, Epoch::zero(), &fixture.schemes);
    let certified = make_certified_block(start.clone(), &finalization);

    let asserter = Asserter::new();
    push_header(&asserter, &start);
    asserter.push_success(&certified);

    let network_identity = NetworkIdentity {
        from_epoch: fixture.outcome.epoch.get(),
        identity: *fixture.outcome.network_identity(),
    };
    FinalizedHeaderStream::init(
        mock_provider(asserter.clone()),
        Config::new(start.block_hash(), Some(network_identity), EPOCH_LENGTH),
    )
    .await
    .expect("caught-up stream should initialize without fetching start ancestry");

    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn rejects_mismatched_start_header() {
    let mut rng = StdRng::seed_from_u64(7);
    let fixture = dkg_fixture(&mut rng, Epoch::zero());
    let start = make_block(1, None);
    assert_ne!(start.block_hash(), B256::ZERO);

    let asserter = Asserter::new();
    push_header(&asserter, &start);

    let network_identity = NetworkIdentity {
        from_epoch: fixture.outcome.epoch.get(),
        identity: *fixture.outcome.network_identity(),
    };
    let error = FinalizedHeaderStream::init(
        mock_provider(asserter.clone()),
        Config::new(B256::ZERO, Some(network_identity), EPOCH_LENGTH),
    )
    .await
    .err()
    .expect("start header must match the trusted hash");

    assert!(matches!(
        error,
        Error::StartHashMismatch {
            expected: B256::ZERO,
            actual,
        } if actual == start.block_hash()
    ));
    assert!(asserter.read_q().is_empty());
}
