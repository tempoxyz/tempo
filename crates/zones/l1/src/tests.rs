use super::*;
use crate::{abi::DepositType, subscriber::L1SubscriberError};
use alloy_consensus::{Header, ReceiptWithBloom, Sealable as _, TxReceipt as _};
use alloy_primitives::{Bloom, Bytes, address};
use alloy_rpc_types_eth::{Header as RpcHeader, TransactionReceipt};
use alloy_sol_types::SolEvent;
use alloy_transport::mock::Asserter;
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use serde::Deserialize;
use std::{collections::HashSet, time::Duration};
use tempo_alloy::rpc::{TempoHeaderResponse, TempoTransactionReceipt};
use tempo_contracts::precompiles::TIP403_REGISTRY_ADDRESS;
use tempo_primitives::{TempoReceipt, TempoTxType};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositHashFixture {
    previous_hash: String,
    expected_hash: String,
    single_value_tuple_hash: String,
    deposit: DepositFixture,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositFixture {
    token: String,
    sender: String,
    amount: u128,
    tempo_refund_recipient: String,
    key_index: u64,
    encrypted: DepositPayloadFixture,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositPayloadFixture {
    ephemeral_pubkey_x: String,
    ephemeral_pubkey_y_parity: u8,
    ciphertext: String,
    nonce: String,
    tag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MalformedTempoHeadersFixture {
    trailing_bytes_after_outer_list: String,
    outer_list_length_mismatch: String,
    outer_list_long_length_leading_zero: String,
    difficulty_non_canonical_short_string: String,
    block_number_leading_zero: String,
    extra_data_long_length_below_short_threshold: String,
}

fn deposit_hash_fixture() -> DepositHashFixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/depositHashChain.json"
    )))
    .expect("deposit hash fixture JSON should decode")
}

fn malformed_tempo_headers_fixture() -> MalformedTempoHeadersFixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/malformedTempoHeaders.json"
    )))
    .expect("malformed Tempo headers fixture JSON should decode")
}

fn parse_fixture_address(value: &str) -> Address {
    value
        .parse()
        .unwrap_or_else(|err| panic!("invalid fixture address {value}: {err}"))
}

fn parse_fixture_b256(value: &str) -> B256 {
    value
        .parse()
        .unwrap_or_else(|err| panic!("invalid fixture bytes32 {value}: {err}"))
}

fn parse_fixture_hex(value: &str) -> Vec<u8> {
    const_hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .unwrap_or_else(|err| panic!("invalid fixture hex {value}: {err}"))
}

fn parse_fixture_fixed<const N: usize>(value: &str, name: &str) -> [u8; N] {
    let bytes = parse_fixture_hex(value);
    assert_eq!(bytes.len(), N, "fixture field {name} should be {N} bytes");
    let mut out = [0; N];
    out.copy_from_slice(&bytes);
    out
}

impl DepositFixture {
    fn to_l1_deposit(&self) -> Deposit {
        Deposit {
            token: parse_fixture_address(&self.token),
            sender: parse_fixture_address(&self.sender),
            amount: self.amount,
            fee: 0,
            tempo_refund_recipient: parse_fixture_address(&self.tempo_refund_recipient),
            key_index: U256::from(self.key_index),
            ephemeral_pubkey_x: parse_fixture_b256(&self.encrypted.ephemeral_pubkey_x),
            ephemeral_pubkey_y_parity: self.encrypted.ephemeral_pubkey_y_parity,
            ciphertext: parse_fixture_hex(&self.encrypted.ciphertext),
            nonce: parse_fixture_fixed(&self.encrypted.nonce, "encrypted.nonce"),
            tag: parse_fixture_fixed(&self.encrypted.tag, "encrypted.tag"),
        }
    }
}

fn make_withdrawal_bounce_back(amount: u128) -> L1Deposit {
    L1Deposit::WithdrawalBounceBack(WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(2),
        amount,
        fee: 0,
    })
}

fn set_tempo_checkpoint(provider: &MockEthProvider, checkpoint: NumHash) {
    provider.add_account(
        crate::abi::TEMPO_STATE_ADDRESS,
        ExtendedAccount::new(0, U256::ZERO).extend_storage([
            (
                crate::precompiles::tempo_state::slots::TEMPO_BLOCK_NUMBER.into(),
                U256::from(checkpoint.number),
            ),
            (
                crate::precompiles::tempo_state::slots::TEMPO_BLOCK_HASH.into(),
                checkpoint.hash.into(),
            ),
        ]),
    );
}

fn test_subscriber_with_checkpoint(checkpoint: NumHash) -> L1Subscriber<MockEthProvider> {
    let portal_address = address!("0x0000000000000000000000000000000000000ABC");
    let zone_provider = MockEthProvider::new();
    set_tempo_checkpoint(&zone_provider, checkpoint);

    L1Subscriber {
        config: L1SubscriberConfig {
            l1_rpc_url: "http://127.0.0.1:8545".to_owned(),
            portal_address,
            l1_fetch_concurrency: 1,
            retry_connection_interval: Duration::from_secs(1),
            retain_portal_evidence: false,
            deferred_work_start: None,
        },
        zone_provider,
        deposit_queue: DepositQueue::default(),
        enabled_tokens: crate::state::EnabledTokenRegistry::default(),
        l1_state_cache: crate::L1StateCache::new(),
        block_tracker: L1BlockTracker::default(),
        leadership_sink: None,
        finalized_batch_submissions: None,
        encryption_keys: None,
        subscriber_metrics: Default::default(),
    }
}

fn test_subscriber(block_number: u64) -> L1Subscriber<MockEthProvider> {
    test_subscriber_with_checkpoint(NumHash::new(block_number, B256::with_last_byte(1)))
}

#[tokio::test]
async fn l1_block_tracker_waits_for_exact_observation() {
    let tracker = L1BlockTracker::default();
    let anchor = NumHash::new(10, B256::with_last_byte(0x10));
    let waiting = tracker.clone();
    let waiter = tokio::spawn(async move { waiting.wait_for(anchor).await });

    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    tracker.record(anchor).unwrap();
    waiter.await.unwrap().unwrap();
}

#[tokio::test]
async fn l1_block_tracker_returns_receipt_authenticated_portal_events() {
    let tracker = L1BlockTracker::default();
    let anchor = NumHash::new(10, B256::with_last_byte(0x10));
    let events = L1PortalEvents::from_deposits(vec![make_withdrawal_bounce_back(100)]);
    tracker
        .record_with_portal_events(anchor, events.clone())
        .unwrap();

    let observed = tracker.wait_for_portal_events(anchor).await.unwrap();
    assert_eq!(observed.deposits.len(), 1);
    assert_eq!(
        observed.deposits[0].to_abi_queued_deposit(),
        events.deposits[0].to_abi_queued_deposit()
    );
}

#[test]
fn l1_block_tracker_retains_authenticated_portal_logs_after_consumption() {
    let tracker = L1BlockTracker::default();
    let anchor = NumHash::new(10, B256::with_last_byte(0x10));
    let parent_hash = B256::with_last_byte(0x09);
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let log = alloy_primitives::Log::new_unchecked(
        portal,
        vec![B256::with_last_byte(1)],
        Default::default(),
    );
    tracker
        .record_with_portal_evidence(
            anchor,
            parent_hash,
            0,
            L1PortalEvents::default(),
            vec![log.clone()],
        )
        .unwrap();

    let observed = tracker.authenticated_portal_logs(anchor).unwrap().unwrap();
    assert_eq!(observed.parent_hash, parent_hash);
    assert_eq!(observed.logs, vec![log.clone()]);

    tracker.prune_through(anchor.number);
    assert_eq!(tracker.observed_hash(anchor.number), None);
    assert_eq!(
        tracker
            .authenticated_portal_logs(anchor)
            .unwrap()
            .unwrap()
            .logs,
        vec![log]
    );
}

#[test]
fn observed_portal_events_require_complete_advance_tempo_inputs() {
    let events = L1PortalEvents {
        deposits: vec![
            make_withdrawal_bounce_back(100),
            make_withdrawal_bounce_back(200),
        ],
        enabled_tokens: vec![EnabledToken {
            token: address!("0x20C0000000000000000000000000000000000001"),
            name: "Alpha USD".to_owned(),
            symbol: "aUSD".to_owned(),
            currency: "USD".to_owned(),
        }],
        encryption_key_rotations: vec![],
        leader_transitions: vec![],
        portal_pause: None,
    };
    let deposits: Vec<_> = events
        .deposits
        .iter()
        .map(L1Deposit::to_abi_queued_deposit)
        .collect();
    let enabled_tokens: Vec<_> = events
        .enabled_tokens
        .iter()
        .map(EnabledToken::to_abi)
        .collect();

    // Rejection is a sequencer decision and does not change the authenticated deposit identity.
    events
        .validate_advance_tempo_inputs(&deposits, &enabled_tokens)
        .unwrap();

    let partial = events
        .validate_advance_tempo_inputs(&deposits[..1], &enabled_tokens)
        .unwrap_err();
    assert!(partial.to_string().contains("deposit count"));

    let mut fabricated = deposits.clone();
    fabricated[1].depositData = Bytes::from_static(b"fabricated");
    let fabricated = events
        .validate_advance_tempo_inputs(&fabricated, &enabled_tokens)
        .unwrap_err();
    assert!(fabricated.to_string().contains("deposit 1"));

    let missing_token = events
        .validate_advance_tempo_inputs(&deposits, &[])
        .unwrap_err();
    assert!(missing_token.to_string().contains("token enables"));
}

#[tokio::test]
async fn l1_block_tracker_rejects_conflicts_and_missing_heights() {
    let tracker = L1BlockTracker::default();
    let block_10 = NumHash::new(10, B256::with_last_byte(0x10));
    let block_11 = NumHash::new(11, B256::with_last_byte(0x11));
    tracker.record(block_10).unwrap();
    tracker.record(block_11).unwrap();
    tracker.record(block_11).unwrap();

    let conflict = NumHash::new(11, B256::with_last_byte(0xff));
    assert!(tracker.wait_for(conflict).await.is_err());
    assert!(
        tracker
            .record(NumHash::new(13, B256::with_last_byte(0x13)))
            .is_err()
    );
}

#[tokio::test]
async fn l1_block_tracker_prunes_only_consumed_observations() {
    let tracker = L1BlockTracker::default();
    for number in 10..=12 {
        tracker
            .record(NumHash::new(number, B256::with_last_byte(number as u8)))
            .unwrap();
    }

    tracker.prune_through(10);
    assert_eq!(tracker.observed_hash(10), None);
    assert_eq!(tracker.observed_hash(11), Some(B256::with_last_byte(11)));
    assert_eq!(tracker.latest().unwrap().number, 12);
    assert!(
        tracker
            .wait_for(NumHash::new(10, B256::with_last_byte(10)))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn l1_block_tracker_backpressures_at_one_hour_lookahead() {
    let tracker = L1BlockTracker::default();
    let consumed = 100;
    tracker.initialize_consumed_through(consumed);

    for number in consumed + 1..=consumed + MAX_L1_LOOKAHEAD_BLOCKS {
        tracker
            .record(NumHash::new(number, B256::with_last_byte(number as u8)))
            .unwrap();
    }

    let blocked_number = consumed + MAX_L1_LOOKAHEAD_BLOCKS + 1;
    assert!(!tracker.has_capacity_for(blocked_number));
    assert_eq!(tracker.next_observation_number(), Some(blocked_number));
    assert!(
        tracker
            .record(NumHash::new(
                blocked_number,
                B256::with_last_byte(blocked_number as u8),
            ))
            .is_err()
    );

    let waiting = tracker.clone();
    let waiter = tokio::spawn(async move { waiting.wait_for_capacity(blocked_number).await });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());

    tracker.prune_through(consumed + 1);
    waiter.await.unwrap().unwrap();
    assert!(tracker.has_capacity_for(blocked_number));
}

#[test]
fn l1_block_tracker_finalized_target_is_monotonic() {
    let tracker = L1BlockTracker::default();
    assert_eq!(tracker.finalized_target(), None);

    tracker.record_finalized_target(200);
    assert_eq!(
        tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 200,
            ready: false,
        })
    );
    tracker.mark_finalized_target_ready(200).unwrap();
    tracker.record_finalized_target(199);
    tracker.record_finalized_target(200);

    assert_eq!(
        tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 200,
            ready: true,
        })
    );

    tracker.record_finalized_target(201);
    assert_eq!(
        tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 201,
            ready: false,
        })
    );
}

#[test]
fn l1_block_tracker_rejects_first_observation_above_persisted_successor() {
    let tracker = L1BlockTracker::default();
    tracker.initialize_consumed_through(10);

    let skipped = tracker
        .record(NumHash::new(12, B256::with_last_byte(12)))
        .unwrap_err();
    assert!(
        skipped
            .to_string()
            .contains("non-contiguous first L1 observation")
    );
    assert_eq!(tracker.latest(), None);
    assert_eq!(tracker.next_observation_number(), Some(11));

    tracker
        .record(NumHash::new(11, B256::with_last_byte(11)))
        .unwrap();
    assert_eq!(tracker.latest().unwrap().number, 11);
}

#[test]
fn subscriber_applies_state_and_records_observation() {
    let subscriber = test_subscriber(9);
    let header = make_test_header(10);
    let sealed = seal(header);
    let anchor = sealed.num_hash();
    let cached_address = address!("0x0000000000000000000000000000000000000ABC");
    let cached_slot = B256::with_last_byte(1);
    let cached_value = B256::with_last_byte(2);

    {
        let mut cache = subscriber.l1_state_cache.lock();
        cache.invalidate_and_set_anchor(9, []);
        cache.set(cached_address, cached_slot, 9, cached_value);
    }
    subscriber.update_l1_state_anchor(10, &HashSet::new());
    subscriber.block_tracker.record(anchor).unwrap();

    assert_eq!(
        subscriber
            .l1_state_cache
            .lock()
            .get(cached_address, cached_slot, 10),
        Some(cached_value)
    );
    assert_eq!(
        subscriber.block_tracker.observed_hash(10),
        Some(anchor.hash)
    );
}

fn make_test_header(number: u64) -> TempoHeader {
    TempoHeader {
        inner: Header {
            number,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Create a header that chains to the given parent.
fn make_chained_header(number: u64, parent_hash: B256) -> TempoHeader {
    TempoHeader {
        inner: Header {
            number,
            parent_hash,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn seal(header: TempoHeader) -> SealedHeader<TempoHeader> {
    SealedHeader::seal_slow(header)
}

fn header_response(header: TempoHeader) -> TempoHeaderResponse {
    TempoHeaderResponse {
        inner: RpcHeader::new(header),
        timestamp_millis: 0,
    }
}

fn push_header_and_empty_receipts(asserter: &Asserter, header: TempoHeader) {
    asserter.push_success(&Some(header_response(header)));
    asserter.push_success(&Some(Vec::<TempoTransactionReceipt>::new()));
}

fn make_test_receipt(
    block_number: u64,
    block_hash: B256,
    tx_hash: B256,
    tx_index: u64,
    cumulative_gas_used: u64,
    logs_bloom: Bloom,
) -> TempoTransactionReceipt {
    TempoTransactionReceipt {
        inner: TransactionReceipt {
            inner: ReceiptWithBloom::new(
                TempoReceipt {
                    tx_type: TempoTxType::Legacy,
                    success: true,
                    cumulative_gas_used,
                    logs: vec![],
                },
                logs_bloom,
            ),
            transaction_hash: tx_hash,
            transaction_index: Some(tx_index),
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            gas_used: cumulative_gas_used,
            effective_gas_price: 0,
            blob_gas_used: None,
            blob_gas_price: None,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            contract_address: None,
        },
        fee_token: None,
        fee_payer: Address::ZERO,
    }
}

fn calculate_test_receipts_root(receipts: &[TempoTransactionReceipt]) -> B256 {
    let receipts = receipts
        .iter()
        .map(|receipt| {
            receipt
                .inner
                .inner
                .clone()
                .map_receipt(|receipt| receipt.map_logs(Into::into))
        })
        .collect::<Vec<_>>();
    alloy_consensus::proofs::calculate_receipt_root(&receipts)
}

#[test]
fn verify_receipts_accepts_matching_root_and_logs_bloom() {
    let block_number = 42;
    let header = make_test_header(block_number);
    let block_hash = header.hash_slow();
    let block = NumHash::new(block_number, block_hash);
    let receipts = vec![
        make_test_receipt(
            block_number,
            block_hash,
            B256::with_last_byte(0x01),
            0,
            21_000,
            Bloom::ZERO,
        ),
        make_test_receipt(
            block_number,
            block_hash,
            B256::with_last_byte(0x02),
            1,
            42_000,
            Bloom::ZERO,
        ),
    ];
    let receipts_root = calculate_test_receipts_root(&receipts);

    verify_receipts_against_header(block, receipts_root, Bloom::ZERO, &receipts)
        .expect("matching receipts root should validate");
}

#[test]
fn verify_receipts_rejects_receipts_root_mismatch() {
    let block_number = 42;
    let header = make_test_header(block_number);
    let block_hash = header.hash_slow();
    let block = NumHash::new(block_number, block_hash);
    let receipts = vec![make_test_receipt(
        block_number,
        block_hash,
        B256::with_last_byte(0x01),
        0,
        21_000,
        Bloom::ZERO,
    )];

    let err =
        verify_receipts_against_header(block, B256::with_last_byte(0xff), Bloom::ZERO, &receipts)
            .expect_err("mismatched receipts root should fail");

    assert!(
        err.to_string().contains("receipt root mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn verify_receipts_rejects_changed_receipt_bloom() {
    let block_number = 42;
    let header = make_test_header(block_number);
    let block_hash = header.hash_slow();
    let block = NumHash::new(block_number, block_hash);
    let receipts = vec![make_test_receipt(
        block_number,
        block_hash,
        B256::with_last_byte(0x01),
        0,
        21_000,
        Bloom::ZERO,
    )];
    let receipts_root = calculate_test_receipts_root(&receipts);
    let mut tampered_receipts = receipts;
    tampered_receipts[0].inner.inner.logs_bloom = Bloom::repeat_byte(0x01);

    let err = verify_receipts_against_header(block, receipts_root, Bloom::ZERO, &tampered_receipts)
        .expect_err("tampered receipt bloom should fail");

    assert!(
        err.to_string().contains("receipt root mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn verify_receipts_rejects_logs_bloom_mismatch() {
    let block_number = 42;
    let header = make_test_header(block_number);
    let block_hash = header.hash_slow();
    let block = NumHash::new(block_number, block_hash);
    let receipts = vec![make_test_receipt(
        block_number,
        block_hash,
        B256::with_last_byte(0x01),
        0,
        21_000,
        Bloom::repeat_byte(0x01),
    )];
    let receipts_root = calculate_test_receipts_root(&receipts);

    let err = verify_receipts_against_header(block, receipts_root, Bloom::ZERO, &receipts)
        .expect_err("mismatched header logs bloom should fail");

    assert!(
        err.to_string().contains("logs bloom mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn tempo_header_rejects_trailing_bytes_after_outer_list() {
    let fixture = malformed_tempo_headers_fixture();
    assert_tempo_header_fixture_rejected(&fixture.trailing_bytes_after_outer_list);
}

#[test]
fn tempo_header_rejects_outer_list_length_mismatch() {
    let fixture = malformed_tempo_headers_fixture();
    assert_tempo_header_fixture_rejected(&fixture.outer_list_length_mismatch);
}

#[test]
fn tempo_header_rejects_outer_list_long_length_leading_zero() {
    let fixture = malformed_tempo_headers_fixture();
    assert_tempo_header_fixture_rejected(&fixture.outer_list_long_length_leading_zero);
}

#[test]
fn tempo_header_rejects_difficulty_non_canonical_short_string() {
    let fixture = malformed_tempo_headers_fixture();
    assert_tempo_header_fixture_rejected(&fixture.difficulty_non_canonical_short_string);
}

#[test]
fn tempo_header_rejects_block_number_leading_zero() {
    let fixture = malformed_tempo_headers_fixture();
    assert_tempo_header_fixture_rejected(&fixture.block_number_leading_zero);
}

#[test]
fn tempo_header_rejects_extra_data_long_length_below_short_threshold() {
    let fixture = malformed_tempo_headers_fixture();
    assert_tempo_header_fixture_rejected(&fixture.extra_data_long_length_below_short_threshold);
}

fn assert_tempo_header_fixture_rejected(value: &str) {
    let malformed = parse_fixture_hex(value);

    assert_tempo_header_rejected(&malformed);
}

fn assert_tempo_header_rejected(input: &[u8]) {
    assert!(
        alloy_rlp::decode_exact::<TempoHeader>(input).is_err(),
        "TempoHeader should reject malformed RLP input {}",
        const_hex::encode_prefixed(input)
    );
}

#[test]
fn update_l1_state_anchor_applies_raw_mutations_before_publishing_coverage() {
    let subscriber = test_subscriber(0);
    let slot = B256::with_last_byte(1);
    let value = B256::with_last_byte(2);
    let stable_account = address!("0x0000000000000000000000000000000000000ABC");
    let stable_slot = B256::with_last_byte(3);
    let stable_value = B256::with_last_byte(4);
    subscriber
        .l1_state_cache
        .lock()
        .invalidate_and_set_anchor(9, []);
    subscriber
        .l1_state_cache
        .lock()
        .set(TIP403_REGISTRY_ADDRESS, slot, 10, value);
    subscriber
        .l1_state_cache
        .lock()
        .set(stable_account, stable_slot, 10, stable_value);

    subscriber.update_l1_state_anchor(10, &HashSet::new());
    assert_eq!(
        subscriber
            .l1_state_cache
            .lock()
            .get(TIP403_REGISTRY_ADDRESS, slot, 10),
        Some(value)
    );

    subscriber.update_l1_state_anchor(11, &HashSet::from([TIP403_REGISTRY_ADDRESS]));
    let mut cache = subscriber.l1_state_cache.lock();
    assert_eq!(
        cache.get(stable_account, stable_slot, 11),
        Some(stable_value)
    );
    assert_eq!(cache.get(TIP403_REGISTRY_ADDRESS, slot, 11), None);
}

/// Confirm the front of a shared `DepositQueue`, panicking if it fails.
fn confirm_shared(queue: &DepositQueue) -> L1BlockDeposits {
    let num_hash = queue.peek().expect("queue is empty").header.num_hash();
    queue.confirm(num_hash).expect("confirm mismatch")
}

fn deposit_hash_chain(previous_hash: B256, deposits: &[L1Deposit]) -> B256 {
    deposits.iter().fold(previous_hash, |current, deposit| {
        deposit.hash_chain(current)
    })
}

#[test]
fn test_resolve_start_block_reads_live_local_state_each_time() {
    let subscriber = test_subscriber(10);
    assert_eq!(subscriber.resolve_start_block().unwrap(), 11);
    set_tempo_checkpoint(
        &subscriber.zone_provider,
        NumHash::new(11, B256::with_last_byte(1)),
    );
    assert_eq!(subscriber.resolve_start_block().unwrap(), 12);
}

#[test]
fn test_resolve_start_block_accepts_block_zero_with_nonzero_hash() {
    let subscriber = test_subscriber(0);
    assert_eq!(subscriber.resolve_start_block().unwrap(), 1);
}

#[test]
fn test_resolve_start_block_rejects_unanchored_genesis() {
    let subscriber = test_subscriber_with_checkpoint(NumHash::default());
    assert!(
        subscriber
            .resolve_start_block()
            .unwrap_err()
            .to_string()
            .contains("zone genesis is not anchored to an L1 block")
    );
}

#[tokio::test]
async fn test_follow_finalized_uses_new_heads_to_sync_missing_finalized_range() {
    let subscriber = test_subscriber(9);
    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());

    let header_10 = make_test_header(10);
    let header_11 = make_chained_header(11, header_10.hash_slow());
    let header_12 = make_chained_header(12, header_11.hash_slow());
    let anchor_12 = seal(header_12.clone()).num_hash();

    // Initial sync through finalized block 10.
    asserter.push_success(&Some(header_response(header_10.clone())));
    push_header_and_empty_receipts(&asserter, header_10);
    asserter.push_success(&Some(header_response(make_test_header(10))));

    // One newHeads notification wakes the subscriber. The finalized tag has
    // advanced by two blocks, so both missing blocks must be ingested.
    asserter.push_success(&Some(header_response(header_12.clone())));
    push_header_and_empty_receipts(&asserter, header_11);
    push_header_and_empty_receipts(&asserter, header_12.clone());
    asserter.push_success(&Some(header_response(header_12)));

    let err = subscriber
        .follow_finalized(&l1_provider, Box::pin(futures::stream::iter([()])))
        .await
        .expect_err("finite header stream should end the subscriber");
    assert!(err.to_string().contains("head notification stream ended"));

    let blocks = subscriber.deposit_queue.drain();
    assert_eq!(
        blocks
            .iter()
            .map(|block| block.header.number())
            .collect::<Vec<_>>(),
        vec![10, 11, 12]
    );
    assert_eq!(
        subscriber.block_tracker.observed_hash(12),
        Some(anchor_12.hash),
        "a queue-backed subscriber must retain observations until its consumer prunes them"
    );
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn test_subscribe_block_headers_falls_back_to_http_block_filter() {
    let subscriber = test_subscriber(10);
    let asserter = Asserter::new();
    let l1_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_mocked_client(asserter.clone())
        .erased();

    asserter.push_success(&U256::ONE);
    asserter.push_success(&vec![B256::with_last_byte(1)]);

    let mut header_stream = subscriber
        .subscribe_block_headers(&l1_provider)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), header_stream.next())
        .await
        .expect("HTTP block filter should emit a header notification")
        .expect("HTTP block filter stream should remain open");

    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn test_sync_finalized_once_does_not_refetch_current_cursor() {
    let subscriber = test_subscriber(10);
    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());
    asserter.push_success(&Some(header_response(make_test_header(10))));
    asserter.push_success(&Some(header_response(make_test_header(10))));

    let next = subscriber
        .sync_to_finalized(&l1_provider, 11)
        .await
        .unwrap();

    assert_eq!(next, 11);
    assert_eq!(
        subscriber.block_tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 10,
            ready: true,
        })
    );
    assert!(subscriber.deposit_queue.drain().is_empty());
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn test_sync_finalized_once_extends_a_moving_finalized_target_until_stable() {
    let subscriber = test_subscriber(9);
    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());

    let header_10 = make_test_header(10);
    let header_11 = make_chained_header(11, header_10.hash_slow());
    let header_12 = make_chained_header(12, header_11.hash_slow());

    asserter.push_success(&Some(header_response(header_10.clone())));
    push_header_and_empty_receipts(&asserter, header_10);
    asserter.push_success(&Some(header_response(header_12.clone())));
    push_header_and_empty_receipts(&asserter, header_11);
    push_header_and_empty_receipts(&asserter, header_12.clone());
    asserter.push_success(&Some(header_response(header_12)));

    let next = subscriber
        .sync_to_finalized(&l1_provider, 10)
        .await
        .unwrap();

    assert_eq!(next, 13);
    assert_eq!(
        subscriber
            .deposit_queue
            .drain()
            .iter()
            .map(|block| block.header.number())
            .collect::<Vec<_>>(),
        vec![10, 11, 12]
    );
    assert_eq!(
        subscriber.block_tracker.finalized_target(),
        Some(FinalizedTarget {
            number: 12,
            ready: true,
        })
    );
    assert!(asserter.read_q().is_empty());
}

#[test]
fn test_push_log_decodes_withdrawal_bounce_back() {
    let portal_address = address!("0x0000000000000000000000000000000000000ABC");
    let fallback_nonce = 0xF1;
    let encoded_fallback_nonce = Address::with_last_byte(0xf1);
    let token = address!("0x0000000000000000000000000000000000002000");
    let event = WithdrawalBounceBack {
        newCurrentDepositQueueHash: B256::with_last_byte(0x42),
        fallbackNonce: fallback_nonce,
        token,
        amount: 123_456,
        depositNumber: 1,
    };
    let log = Log {
        inner: alloy_primitives::Log {
            address: portal_address,
            data: event.encode_log_data(),
        },
        block_hash: None,
        block_number: None,
        block_timestamp: None,
        transaction_hash: None,
        transaction_index: None,
        log_index: None,
        removed: false,
    };

    let mut events = L1PortalEvents::default();
    events
        .push_log(&log, 123)
        .expect("bounce-back should decode");

    assert_eq!(events.deposits.len(), 1, "should enqueue one deposit");
    let L1Deposit::WithdrawalBounceBack(deposit) = &events.deposits[0] else {
        panic!("bounce-back should be mapped to a withdrawal bounce-back entry");
    };
    assert_eq!(deposit.token, token);
    assert_eq!(deposit.to, encoded_fallback_nonce);
    assert_eq!(deposit.amount, event.amount);
    assert_eq!(deposit.fee, 0, "bounce-back deposits should be fee-free");
}

#[test]
fn confirmed_token_enabled_event_updates_registry() {
    let subscriber = test_subscriber(0);
    let token = address!("0x20c0000000000000000000000000000000000001");
    let events = L1PortalEvents {
        enabled_tokens: vec![EnabledToken {
            token,
            name: "Path USD".to_owned(),
            symbol: "pathUSD".to_owned(),
            currency: "USD".to_owned(),
        }],
        ..Default::default()
    };

    subscriber.apply_enabled_token_events(&events);

    assert!(subscriber.enabled_tokens.read().contains(&token));
}

#[test]
fn test_drain_returns_block_grouped_deposits() {
    let mut queue = PendingDeposits::default();

    let d1 = L1Deposit::WithdrawalBounceBack(WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(2),
        amount: 100,
        fee: 0,
    });

    let d2 = L1Deposit::WithdrawalBounceBack(WithdrawalBounceBackDeposit {
        token: address!("0x0000000000000000000000000000000000001000"),
        to: Address::with_last_byte(4),
        amount: 200,
        fee: 0,
    });

    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::from_deposits(vec![d1]));
    queue.enqueue(
        make_chained_header(11, h10_hash),
        L1PortalEvents::from_deposits(vec![d2]),
    );

    let blocks = queue.drain();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].header.number(), 10);
    assert_eq!(blocks[0].events.deposits.len(), 1);
    assert_eq!(blocks[1].header.number(), 11);
    assert_eq!(blocks[1].events.deposits.len(), 1);

    // After drain, pending is empty
    assert!(queue.drain().is_empty());
}

#[test]
fn test_deposit_hash_chain() {
    let fixture = deposit_hash_fixture();
    let encrypted = fixture.deposit.to_l1_deposit();
    let previous_hash = parse_fixture_b256(&fixture.previous_hash);

    let next_hash = deposit_hash_chain(previous_hash, &[L1Deposit::Deposit(encrypted.clone())]);

    let abi_deposit = abi::Deposit {
        token: encrypted.token,
        sender: encrypted.sender,
        amount: encrypted.amount,
        tempoRefundRecipient: encrypted.tempo_refund_recipient,
        keyIndex: encrypted.key_index,
        encrypted: abi::DepositPayload {
            ephemeralPubkeyX: encrypted.ephemeral_pubkey_x,
            ephemeralPubkeyYParity: encrypted.ephemeral_pubkey_y_parity,
            ciphertext: encrypted.ciphertext.clone().into(),
            nonce: encrypted.nonce.into(),
            tag: encrypted.tag.into(),
        },
    };
    let expected = parse_fixture_b256(&fixture.expected_hash);
    let tuple_value_hash =
        keccak256((DepositType::Deposit, abi_deposit, previous_hash).abi_encode());
    let single_value_tuple_hash = parse_fixture_b256(&fixture.single_value_tuple_hash);

    assert_eq!(
        next_hash, expected,
        "deposit hash chain must match Solidity DepositQueueLib.enqueueDeposit"
    );
    assert_eq!(
        tuple_value_hash, single_value_tuple_hash,
        "fixture should document the previous single-value tuple encoding"
    );
    assert_ne!(
        expected, tuple_value_hash,
        "single-value tuple encoding should not match Solidity abi.encode(...) for dynamic deposits"
    );
    assert_ne!(next_hash, B256::ZERO, "hash should be non-zero");
}

#[test]
fn test_withdrawal_bounce_back_and_deposit_hash_chain() {
    let token = address!("0x0000000000000000000000000000000000001000");
    let sender = address!("0x0000000000000000000000000000000000001111");
    let recipient = address!("0x000000000000000000000000000000000000A11C");

    let bounce_back = WithdrawalBounceBackDeposit {
        token,
        to: recipient,
        amount: 500_000,
        fee: 0,
    };

    let encrypted = Deposit {
        token,
        sender,
        amount: 300_000,
        fee: 0,
        tempo_refund_recipient: sender,
        key_index: U256::ONE,
        ephemeral_pubkey_x: B256::with_last_byte(0xBB),
        ephemeral_pubkey_y_parity: 0x03,
        ciphertext: vec![0x55u8; 64],
        nonce: [0x0A; 12],
        tag: [0x0B; 16],
    };

    let deposits = vec![
        L1Deposit::WithdrawalBounceBack(bounce_back.clone()),
        L1Deposit::Deposit(encrypted.clone()),
    ];

    let next_hash = deposit_hash_chain(B256::ZERO, &deposits);

    // Manually compute expected chain
    let hash_1 = keccak256(
        (
            DepositType::WithdrawalBounceBack,
            abi::WithdrawalBounceBackDeposit {
                token: bounce_back.token,
                to: bounce_back.to,
                amount: bounce_back.amount,
            },
            B256::ZERO,
        )
            .abi_encode_params(),
    );

    let hash_2 = keccak256(
        (
            DepositType::Deposit,
            abi::Deposit {
                token: encrypted.token,
                sender: encrypted.sender,
                amount: encrypted.amount,
                tempoRefundRecipient: encrypted.tempo_refund_recipient,
                keyIndex: encrypted.key_index,
                encrypted: abi::DepositPayload {
                    ephemeralPubkeyX: encrypted.ephemeral_pubkey_x,
                    ephemeralPubkeyYParity: encrypted.ephemeral_pubkey_y_parity,
                    ciphertext: encrypted.ciphertext.into(),
                    nonce: encrypted.nonce.into(),
                    tag: encrypted.tag.into(),
                },
            },
            hash_1,
        )
            .abi_encode_params(),
    );

    assert_eq!(next_hash, hash_2);
}

#[tokio::test]
async fn test_prepare_decrypted_deposit_defers_policy_to_upstream_mint() {
    use k256::{AffinePoint, ProjectivePoint, Scalar};

    let token = address!("0x0000000000000000000000000000000000001000");
    let sender = address!("0x0000000000000000000000000000000000001234");
    let recipient = address!("0x000000000000000000000000000000000000BEEF");
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let block_number = 10;

    let sequencer_key = k256::SecretKey::from_slice(&[0x11; 32]).expect("valid key");
    let seq_scalar: Scalar = *sequencer_key.to_nonzero_scalar();
    let seq_pub = AffinePoint::from(ProjectivePoint::GENERATOR * seq_scalar);
    let (seq_pub_x, seq_pub_y_parity) =
        crate::precompiles::ecies::compressed_x_and_parity(&seq_pub);
    let encrypted = crate::precompiles::ecies::encrypt_deposit(
        &seq_pub_x,
        seq_pub_y_parity,
        recipient,
        B256::ZERO,
        sender,
        portal,
        U256::ZERO,
    )
    .expect("encrypted deposit should be valid");
    let encryption_keys = EncryptionKeyRing::new([sequencer_key.clone()]);
    encryption_keys
        .apply_rotation(&EncryptionKeyRotation {
            x: seq_pub_x,
            y_parity: seq_pub_y_parity,
            pubkey: encryption_key_address(seq_pub_x, seq_pub_y_parity).unwrap(),
            key_index: U256::ZERO,
            activation_block: block_number,
        })
        .unwrap();

    let block = L1BlockDeposits {
        header: seal(make_test_header(block_number)),
        events: L1PortalEvents::from_deposits(vec![L1Deposit::Deposit(Deposit {
            token,
            sender,
            amount: 1_000_000,
            fee: 0,
            tempo_refund_recipient: sender,
            key_index: U256::ZERO,
            ephemeral_pubkey_x: encrypted.eph_pub_x,
            ephemeral_pubkey_y_parity: encrypted.eph_pub_y_parity,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            tag: encrypted.tag,
        })]),
    };

    let prepared = block
        .prepare(&encryption_keys, portal)
        .await
        .expect("decrypted deposit should prepare without an engine-side policy read");

    assert_eq!(prepared.queued_deposits.len(), 1);
    assert_eq!(
        prepared.queued_deposits[0].depositType,
        DepositType::Deposit
    );
    assert_eq!(
        prepared.decryptions.len(),
        1,
        "successfully decrypted deposits must provide on-chain decryption data"
    );
}

#[tokio::test]
async fn deposits_select_the_private_key_by_portal_index() {
    let token = address!("0x0000000000000000000000000000000000001000");
    let sender = address!("0x0000000000000000000000000000000000001234");
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let old = k256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    let current = k256::SecretKey::from_slice(&[0x22; 32]).unwrap();
    let encryption_keys = EncryptionKeyRing::new([old.clone(), current.clone()]);
    let mut deposits = Vec::new();
    let mut expected_shared_secrets = Vec::new();

    for (key_index, key, recipient) in [
        (
            U256::ZERO,
            old,
            address!("0x000000000000000000000000000000000000BEEF"),
        ),
        (
            U256::ONE,
            current,
            address!("0x000000000000000000000000000000000000CAFE"),
        ),
    ] {
        let public = key.public_key();
        let (x, y_parity) = crate::precompiles::ecies::compressed_x_and_parity(public.as_affine());
        encryption_keys
            .apply_rotation(&EncryptionKeyRotation {
                x,
                y_parity,
                pubkey: encryption_key_address(x, y_parity).unwrap(),
                key_index,
                activation_block: key_index.to::<u64>() + 10,
            })
            .unwrap();
        let encrypted = crate::precompiles::ecies::encrypt_deposit(
            &x,
            y_parity,
            recipient,
            B256::ZERO,
            sender,
            portal,
            key_index,
        )
        .unwrap();
        let decrypted = crate::precompiles::ecies::decrypt_deposit(
            &key,
            &encrypted.eph_pub_x,
            encrypted.eph_pub_y_parity,
            &encrypted.ciphertext,
            &encrypted.nonce,
            &encrypted.tag,
            portal,
            key_index,
            sender,
        )
        .unwrap();
        expected_shared_secrets.push(decrypted.proof.shared_secret);
        deposits.push(L1Deposit::Deposit(Deposit {
            token,
            sender,
            amount: 1_000_000,
            fee: 0,
            tempo_refund_recipient: sender,
            key_index,
            ephemeral_pubkey_x: encrypted.eph_pub_x,
            ephemeral_pubkey_y_parity: encrypted.eph_pub_y_parity,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            tag: encrypted.tag,
        }));
    }

    let prepared = L1BlockDeposits {
        header: seal(make_test_header(20)),
        events: L1PortalEvents::from_deposits(deposits),
    }
    .prepare(&encryption_keys, portal)
    .await
    .unwrap();

    assert_eq!(
        prepared
            .decryptions
            .iter()
            .map(|decryption| decryption.sharedSecret)
            .collect::<Vec<_>>(),
        expected_shared_secrets
    );
}

#[test]
fn finalized_queue_tracks_tip_after_consumption() {
    let queue = DepositQueue::new();
    assert!(queue.last_enqueued().is_none());

    let h100 = make_test_header(100);
    let h100_hash = h100.hash_slow();
    queue.enqueue(h100, L1PortalEvents::default());

    let h101 = make_chained_header(101, h100_hash);
    let h101_hash = h101.hash_slow();
    queue.enqueue(h101, L1PortalEvents::default());

    confirm_shared(&queue);
    confirm_shared(&queue);
    assert!(queue.peek().is_none());
    assert_eq!(
        queue.last_enqueued(),
        Some(NumHash::new(101, h101_hash)),
        "the subscriber high-water mark must survive consumption"
    );

    queue.enqueue(
        make_chained_header(102, h101_hash),
        L1PortalEvents::default(),
    );
}

#[test]
fn external_enqueue_reports_discontinuity_without_panicking() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    assert!(
        queue
            .try_enqueue_sealed(seal(h10), L1PortalEvents::default())
            .unwrap()
    );

    let err = queue
        .try_enqueue_sealed(
            seal(make_chained_header(12, h10_hash)),
            L1PortalEvents::default(),
        )
        .expect_err("external input must report a gap");
    assert!(
        err.to_string()
            .contains("non-contiguous finalized L1 block")
    );
}

#[test]
fn external_enqueue_accepts_duplicate_producers() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h11 = make_chained_header(11, h10.hash_slow());
    let h12 = make_chained_header(12, h11.hash_slow());
    let duplicate = seal(h10);
    assert!(
        queue
            .try_enqueue_sealed(duplicate.clone(), L1PortalEvents::default())
            .unwrap()
    );
    for header in [h11, h12] {
        queue
            .try_enqueue_sealed(seal(header), L1PortalEvents::default())
            .unwrap();
    }
    assert!(
        !queue
            .try_enqueue_sealed(duplicate, L1PortalEvents::default())
            .unwrap()
    );
    assert_eq!(queue.peek().unwrap().header.number(), 10);
}

#[test]
fn confirm_operational_through_is_idempotent_and_drains_stale_entries() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h11 = make_chained_header(11, h10.hash_slow());
    let h12 = make_chained_header(12, h11.hash_slow());
    let anchor = seal(h12.clone()).num_hash();
    for header in [h10, h11, h12] {
        queue
            .try_enqueue_sealed(seal(header), L1PortalEvents::default())
            .unwrap();
    }

    queue.confirm_operational_through(anchor).unwrap();
    assert!(queue.peek().is_none());
    queue.confirm_operational_through(anchor).unwrap();
}

#[test]
fn canonical_import_reconciliation_is_idempotent_across_checkpoint_and_full_blocks() {
    let queue = DepositQueue::new();
    let first = SealedHeader::seal_slow(make_test_header(1));
    let second = SealedHeader::seal_slow(make_chained_header(2, first.hash()));
    let third = SealedHeader::seal_slow(make_chained_header(3, second.hash()));
    for header in [&first, &second, &third] {
        queue
            .try_enqueue_sealed(header.clone(), L1PortalEvents::default())
            .unwrap();
    }

    queue.defer_through(second.num_hash()).unwrap();
    queue.defer_through(second.num_hash()).unwrap();
    assert_eq!(queue.peek().unwrap().header.num_hash(), third.num_hash());
    assert_eq!(queue.operational_work(third.num_hash()).unwrap().len(), 2);

    queue.confirm_operational_through(third.num_hash()).unwrap();
    queue.confirm_operational_through(third.num_hash()).unwrap();
    assert!(queue.peek().is_none());

    let fourth = SealedHeader::seal_slow(make_chained_header(4, third.hash()));
    let fifth = SealedHeader::seal_slow(make_chained_header(5, fourth.hash()));
    queue
        .try_enqueue_sealed(fourth.clone(), L1PortalEvents::default())
        .unwrap();
    queue.defer_through(fourth.num_hash()).unwrap();
    queue
        .try_enqueue_sealed(fifth, L1PortalEvents::default())
        .unwrap();

    // A late replay of block 3 must preserve block 4's newer deferred work.
    queue.confirm_operational_through(third.num_hash()).unwrap();
    let fifth = queue.peek().unwrap().header.num_hash();
    assert_eq!(queue.operational_work(fifth).unwrap().len(), 2);
}

#[test]
fn deferred_checkpoint_work_survives_until_operational_confirmation() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h11 = make_chained_header(11, h10.hash_slow());
    let h12 = make_chained_header(12, h11.hash_slow());
    for header in [h10, h11, h12] {
        queue
            .try_enqueue_sealed(seal(header), L1PortalEvents::default())
            .unwrap();
    }

    let first = queue.peek().unwrap();
    queue.defer_through(first.header.num_hash()).unwrap();
    let second = queue.peek().unwrap();
    queue.defer_through(second.header.num_hash()).unwrap();
    let current = queue.peek().unwrap();
    let work = queue.operational_work(current.header.num_hash()).unwrap();
    assert_eq!(
        work.iter()
            .map(|block| block.header.number())
            .collect::<Vec<_>>(),
        vec![11, 12]
    );

    queue
        .confirm_operational(current.header.num_hash())
        .unwrap();
    assert!(queue.peek().is_none());
}

#[test]
fn restart_can_seed_deferred_checkpoint_work() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h11 = make_chained_header(11, h10.hash_slow());
    let mut deferred = crate::queue::DeferredPortalWork::new(L1BlockDeposits {
        header: seal(h10),
        events: L1PortalEvents::default(),
    });
    deferred.push(L1BlockDeposits {
        header: seal(h11),
        events: L1PortalEvents::default(),
    });
    queue.restore_deferred(deferred).unwrap();

    let h12 = make_chained_header(12, queue.last_enqueued().unwrap().hash);
    queue
        .try_enqueue_sealed(seal(h12), L1PortalEvents::default())
        .unwrap();
    let current = queue.peek().unwrap();
    assert_eq!(
        queue
            .operational_work(current.header.num_hash())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn deferred_empty_blocks_use_constant_space() {
    let mut queue = PendingDeposits::default();
    let mut parent_hash = B256::ZERO;
    for number in 1..=10_000 {
        let header = if number == 1 {
            make_test_header(number)
        } else {
            make_chained_header(number, parent_hash)
        };
        let header = seal(header);
        let anchor = header.num_hash();
        parent_hash = anchor.hash;
        queue
            .try_enqueue(header, L1PortalEvents::default())
            .unwrap();
        queue.defer_through(anchor).unwrap();
    }

    assert_eq!(queue.deferred_event_block_len(), 0);
}

#[test]
fn confirm_operational_through_rejects_a_conflicting_anchor() {
    let queue = DepositQueue::new();
    queue
        .try_enqueue_sealed(seal(make_test_header(10)), L1PortalEvents::default())
        .unwrap();

    let err = queue
        .confirm_operational_through(NumHash::new(10, B256::repeat_byte(0xab)))
        .expect_err("a different hash at the same height must fail");
    assert!(err.to_string().contains("deposit queue holds L1 block 10"));
    assert_eq!(queue.peek().unwrap().header.number(), 10);
}

#[test]
#[should_panic(expected = "finalized L1 queue invariant violated")]
fn finalized_deposit_queue_panics_on_discontinuity() {
    let queue = DepositQueue::new();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());
    queue.enqueue(make_chained_header(12, h10_hash), L1PortalEvents::default());
}

#[test]
fn finalized_queue_accepts_only_contiguous_blocks() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();

    assert!(
        queue
            .try_enqueue(seal(h10), L1PortalEvents::default())
            .expect("first finalized block should enqueue")
    );
    assert!(
        queue
            .try_enqueue(
                seal(make_chained_header(11, h10_hash)),
                L1PortalEvents::default(),
            )
            .expect("child finalized block should enqueue")
    );
    assert_eq!(queue.pending_len(), 2);
}

#[test]
fn finalized_queue_tip_redelivery_is_idempotent() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);

    assert!(
        queue
            .try_enqueue(seal(h10.clone()), L1PortalEvents::default())
            .expect("first finalized block should enqueue")
    );
    assert!(
        !queue
            .try_enqueue(seal(h10), L1PortalEvents::default())
            .expect("exact tip redelivery should be accepted")
    );
    assert_eq!(queue.pending_len(), 1);
}

#[test]
fn finalized_queue_rejects_gap_without_mutation() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());

    let err = queue
        .try_enqueue(
            seal(make_chained_header(12, h10_hash)),
            L1PortalEvents::default(),
        )
        .expect_err("a finalized height gap must be fatal");

    assert!(
        err.to_string()
            .contains("non-contiguous finalized L1 block")
    );
    assert_eq!(queue.pending_len(), 1);
    assert_eq!(queue.last_enqueued(), Some(NumHash::new(10, h10_hash)));
}

#[test]
fn finalized_queue_rejects_parent_mismatch_without_mutation() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());

    let err = queue
        .try_enqueue(
            seal(make_chained_header(11, B256::with_last_byte(0xff))),
            L1PortalEvents::default(),
        )
        .expect_err("a finalized parent mismatch must be fatal");

    assert!(err.to_string().contains("finalized L1 parent mismatch"));
    assert_eq!(queue.pending_len(), 1);
    assert_eq!(queue.last_enqueued(), Some(NumHash::new(10, h10_hash)));
}

#[test]
fn finalized_queue_rejects_conflicting_tip_without_mutation() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());

    let mut conflicting = make_test_header(10);
    conflicting.inner.gas_limit += 1;
    let err = queue
        .try_enqueue(seal(conflicting), L1PortalEvents::default())
        .expect_err("a conflicting finalized tip must be fatal");

    assert!(err.to_string().contains("conflicting finalized L1 block"));
    assert_eq!(queue.pending_len(), 1);
    assert_eq!(queue.last_enqueued(), Some(NumHash::new(10, h10_hash)));
}

#[test]
fn finalized_queue_rejects_stale_blocks() {
    let mut queue = PendingDeposits::default();
    queue.enqueue(make_test_header(10), L1PortalEvents::default());

    let err = queue
        .try_enqueue(seal(make_test_header(9)), L1PortalEvents::default())
        .expect_err("an out-of-order finalized block must be fatal");

    assert!(err.to_string().contains("out-of-order finalized L1 block"));
    assert_eq!(queue.pending_len(), 1);
}

#[test]
fn finalized_queue_rejects_confirmation_mismatch_without_mutation() {
    let mut queue = PendingDeposits::default();
    let h10 = make_test_header(10);
    let h10_hash = h10.hash_slow();
    queue.enqueue(h10, L1PortalEvents::default());

    let err = queue
        .confirm(NumHash::new(10, B256::with_last_byte(0xff)))
        .expect_err("confirming a different block must fail");

    assert!(
        err.to_string()
            .contains("finalized L1 queue confirmation mismatch")
    );
    assert_eq!(queue.pending_len(), 1);
    assert_eq!(
        queue
            .peek()
            .expect("front should remain queued")
            .header
            .hash(),
        h10_hash
    );
}

fn leader_updated_log(
    portal: Address,
    previous: Address,
    new_leader: Address,
    epoch: u64,
    activation: u64,
) -> Log {
    let event = crate::abi::ZonePortal::LeaderUpdated {
        previousLeader: previous,
        newLeader: new_leader,
        epoch,
        activationTempoBlock: activation,
    };
    Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: event.encode_log_data(),
        },
        ..Default::default()
    }
}

fn encryption_key_updated_log(
    portal: Address,
    x: B256,
    y_parity: u8,
    pubkey: Address,
    key_index: U256,
    activation_block: u64,
) -> Log {
    let event = crate::abi::ZonePortal::SequencerEncryptionKeyUpdated {
        x,
        yParity: y_parity,
        pubkey,
        keyIndex: key_index,
        activationBlock: activation_block,
    };
    Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: event.encode_log_data(),
        },
        ..Default::default()
    }
}

#[test]
fn encryption_key_event_binds_private_key_to_portal_index() {
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let private_key = k256::SecretKey::from_slice(&[0x42; 32]).unwrap();
    let public_key = private_key.public_key();
    let (x, y_parity) = crate::precompiles::ecies::compressed_x_and_parity(public_key.as_affine());
    let pubkey = encryption_key_address(x, y_parity).unwrap();
    let key_index = U256::from(7);
    let mut events = L1PortalEvents::default();

    events
        .push_log(
            &encryption_key_updated_log(portal, x, y_parity, pubkey, key_index, 77),
            77,
        )
        .unwrap();

    assert_eq!(
        events.encryption_key_rotations,
        vec![EncryptionKeyRotation {
            x,
            y_parity,
            pubkey,
            key_index,
            activation_block: 77,
        }]
    );

    let ring = EncryptionKeyRing::new([private_key.clone()]);
    ring.apply_rotation(&events.encryption_key_rotations[0])
        .unwrap();
    assert_eq!(
        ring.key(key_index).unwrap().to_bytes(),
        private_key.to_bytes()
    );
}

#[test]
fn decodes_leader_updated_into_portal_events() {
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let previous = address!("0x0000000000000000000000000000000000001111");
    let new_leader = address!("0x0000000000000000000000000000000000002222");

    let mut events = L1PortalEvents::default();
    events
        .push_log(&leader_updated_log(portal, previous, new_leader, 4, 77), 77)
        .unwrap();

    assert_eq!(
        events.leader_transitions,
        vec![LeaderTransition {
            previous_leader: previous,
            new_leader,
            epoch: 4,
            activation_tempo_block: 77,
        }]
    );
    let transition = events.final_leader_transition().unwrap().unwrap();
    assert_eq!(transition.new_leader, new_leader);
    assert_eq!(transition.epoch, 4);
}

#[test]
fn rejects_multiple_leader_transitions_in_one_block() {
    let portal = address!("0x0000000000000000000000000000000000000ABC");
    let a = address!("0x0000000000000000000000000000000000001111");
    let b = address!("0x0000000000000000000000000000000000002222");
    let c = address!("0x0000000000000000000000000000000000003333");

    let mut events = L1PortalEvents::default();
    events
        .push_log(&leader_updated_log(portal, a, b, 4, 77), 77)
        .unwrap();
    events
        .push_log(&leader_updated_log(portal, b, c, 5, 77), 77)
        .unwrap();

    let err = events.final_leader_transition().unwrap_err();
    assert!(err.to_string().contains("at most one"));
}

fn make_receipt_with_logs(
    block_number: u64,
    block_hash: B256,
    logs: Vec<Log>,
) -> TempoTransactionReceipt {
    TempoTransactionReceipt {
        inner: TransactionReceipt {
            inner: TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 21_000,
                logs,
            }
            .into_with_bloom(),
            transaction_hash: B256::with_last_byte(0xaa),
            transaction_index: Some(0),
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            gas_used: 21_000,
            effective_gas_price: 0,
            blob_gas_used: None,
            blob_gas_price: None,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            contract_address: None,
        },
        fee_token: None,
        fee_payer: Address::ZERO,
    }
}

fn corrupt_recognized_portal_log(portal: Address) -> Log {
    Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: alloy_primitives::LogData::new_unchecked(
                vec![crate::abi::ZonePortal::LeaderUpdated::SIGNATURE_HASH],
                Bytes::from_static(b"garbage"),
            ),
        },
        ..Default::default()
    }
}

#[test]
fn extracts_finalized_batch_submission_for_observer() {
    let mut subscriber = test_subscriber(9);
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    subscriber.finalized_batch_submissions = Some(sender);
    let portal = subscriber.config.portal_address;
    let event = crate::abi::LegacyBatchSubmitted {
        withdrawalBatchIndex: 7,
        withdrawalQueueIndex: U256::from(3),
        nextProcessedDepositQueueHash: B256::repeat_byte(0x11),
        nextBlockHash: B256::repeat_byte(0x22),
        withdrawalQueueHash: B256::repeat_byte(0x33),
        lastProcessedDepositNumber: 9,
    };
    let log = Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: event.encode_log_data(),
        },
        log_index: Some(4),
        ..Default::default()
    };
    let receipt = make_receipt_with_logs(10, B256::with_last_byte(0x10), vec![log]);

    let block = NumHash::new(10, B256::with_last_byte(0x10));
    let (_, _, _, submissions) = subscriber.extract_events(block, &[receipt]).unwrap();

    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].block, block);
    assert_eq!(submissions[0].transaction_index, 0);
    assert_eq!(submissions[0].log_index, 0);
    assert_eq!(submissions[0].event.nextBlockHash, B256::repeat_byte(0x22));
}

#[test]
fn extracts_t13_finalized_batch_submission_for_observer() {
    let mut subscriber = test_subscriber(9);
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    subscriber.finalized_batch_submissions = Some(sender);
    let portal = subscriber.config.portal_address;
    let event = crate::abi::BatchSubmitted {
        withdrawalBatchIndex: 7,
        withdrawalQueueIndex: U256::from(3),
        nextProcessedDepositQueueHash: B256::repeat_byte(0x11),
        nextBlockHash: B256::repeat_byte(0x22),
        withdrawalQueueHash: B256::repeat_byte(0x33),
        lastProcessedDepositNumber: 9,
        lastProcessedEnabledTokenCount: 4,
    };
    let log = Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: event.encode_log_data(),
        },
        log_index: Some(4),
        ..Default::default()
    };
    let receipt = make_receipt_with_logs(10, B256::with_last_byte(0x10), vec![log]);

    let block = NumHash::new(10, B256::with_last_byte(0x10));
    let (_, _, _, submissions) = subscriber.extract_events(block, &[receipt]).unwrap();

    assert_eq!(submissions.len(), 1);
    assert!(!submissions[0].is_legacy);
    assert_eq!(submissions[0].event.lastProcessedEnabledTokenCount, 4);
    assert_eq!(submissions[0].block, block);
    assert_eq!(submissions[0].transaction_index, 0);
    assert_eq!(submissions[0].log_index, 0);
    assert_eq!(submissions[0].event.nextBlockHash, B256::repeat_byte(0x22));
}

#[test]
fn finalized_batch_observer_ignores_rpc_log_metadata() {
    let mut subscriber = test_subscriber(9);
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    subscriber.finalized_batch_submissions = Some(sender);
    let portal = subscriber.config.portal_address;
    let malformed = Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: alloy_primitives::LogData::new_unchecked(
                vec![crate::abi::LegacyBatchSubmitted::SIGNATURE_HASH],
                Bytes::from_static(b"garbage"),
            ),
        },
        log_index: Some(4),
        ..Default::default()
    };
    let missing_index = Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: crate::abi::LegacyBatchSubmitted {
                withdrawalBatchIndex: 7,
                withdrawalQueueIndex: U256::from(3),
                nextProcessedDepositQueueHash: B256::repeat_byte(0x11),
                nextBlockHash: B256::repeat_byte(0x22),
                withdrawalQueueHash: B256::repeat_byte(0x33),
                lastProcessedDepositNumber: 9,
            }
            .encode_log_data(),
        },
        log_index: None,
        ..Default::default()
    };
    let receipt = make_receipt_with_logs(
        10,
        B256::with_last_byte(0x10),
        vec![malformed, missing_index],
    );

    let block = NumHash::new(10, B256::with_last_byte(0x10));
    let (_, _, _, submissions) = subscriber.extract_events(block, &[receipt]).unwrap();

    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].block, block);
    assert_eq!(submissions[0].transaction_index, 0);
    assert_eq!(submissions[0].log_index, 1);
}

#[test]
fn extract_events_fails_closed_on_corrupt_recognized_portal_log() {
    let mut subscriber = test_subscriber(9);
    subscriber.config.retain_portal_evidence = true;
    let portal = subscriber.config.portal_address;

    // A recognized topic0 with garbage payload must reject the whole block, never be skipped.
    let corrupt = corrupt_recognized_portal_log(portal);
    let receipt = make_receipt_with_logs(10, B256::with_last_byte(0x10), vec![corrupt]);

    let block = NumHash::new(10, B256::with_last_byte(0x10));
    let err = subscriber.extract_events(block, &[receipt]).unwrap_err();
    assert!(
        err.to_string()
            .contains("failed to decode a portal event in L1 block 10")
    );

    // Unknown signatures are still skipped: a pre-upgrade contract event cannot reject the block.
    let unknown = Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: alloy_primitives::LogData::new_unchecked(
                vec![B256::with_last_byte(0x77)],
                Bytes::from_static(b"whatever"),
            ),
        },
        ..Default::default()
    };
    let receipt = make_receipt_with_logs(10, B256::with_last_byte(0x10), vec![unknown]);
    let (events, _, portal_logs, _) = subscriber.extract_events(block, &[receipt]).unwrap();
    assert!(events.deposits.is_empty());
    assert!(events.leader_transitions.is_empty());
    assert_eq!(portal_logs.unwrap().len(), 1);
}

#[test]
fn pause_events_invalidate_cached_portal_storage() {
    let subscriber = test_subscriber(9);
    let portal = subscriber.config.portal_address;
    let account = address!("0x0000000000000000000000000000000000000123");
    let pause_slot = B256::with_last_byte(25);
    {
        let mut cache = subscriber.l1_state_cache.lock();
        cache.set(portal, pause_slot, 0, B256::with_last_byte(0x42));
    }
    let logs = vec![
        Log {
            inner: alloy_primitives::Log {
                address: portal,
                data: crate::abi::ZonePortal::PortalPaused { account }.encode_log_data(),
            },
            ..Default::default()
        },
        Log {
            inner: alloy_primitives::Log {
                address: portal,
                data: crate::abi::ZonePortal::AbdicationScheduled {
                    capability: crate::abi::ZonePortal::Capability::PausePortal,
                    effectiveAt: 0,
                }
                .encode_log_data(),
            },
            ..Default::default()
        },
    ];
    let receipt = make_receipt_with_logs(1, B256::with_last_byte(0x10), logs);

    let block = NumHash::new(1, B256::with_last_byte(0x10));
    let (events, invalidated, _, _) = subscriber.extract_events(block, &[receipt]).unwrap();
    assert_eq!(events.portal_pause, Some(true));
    assert!(invalidated.contains(&portal));
    subscriber.update_l1_state_anchor(1, &invalidated);
    assert_eq!(
        subscriber.l1_state_cache.lock().get(portal, pause_slot, 1),
        None
    );
}

#[tokio::test]
async fn sync_classifies_corrupt_recognized_portal_log_as_fatal() {
    let subscriber = test_subscriber(9);
    let portal = subscriber.config.portal_address;
    let queue = subscriber.deposit_queue.clone();

    let receipt =
        make_receipt_with_logs(10, B256::ZERO, vec![corrupt_recognized_portal_log(portal)]);
    let mut header_10 = make_test_header(10);
    header_10.inner.receipts_root = calculate_test_receipts_root(std::slice::from_ref(&receipt));
    header_10.inner.logs_bloom = *receipt.inner.inner.bloom_ref();

    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());
    asserter.push_success(&Some(header_response(header_10.clone())));
    asserter.push_success(&Some(header_response(header_10)));
    asserter.push_success(&Some(vec![receipt]));

    let err = subscriber
        .sync_to_finalized(&l1_provider, 10)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        L1SubscriberError::Fatal {
            block_number: 10,
            stage: "portal event decoding",
            ..
        }
    ));
    assert_eq!(queue.last_enqueued(), None);
    assert_eq!(subscriber.block_tracker.latest(), None);
}

#[tokio::test]
async fn sync_fails_fatally_when_finalized_batch_observer_is_closed() {
    let mut subscriber = test_subscriber(9);
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    drop(receiver);
    subscriber.finalized_batch_submissions = Some(sender);
    let portal = subscriber.config.portal_address;
    let event = crate::abi::LegacyBatchSubmitted {
        withdrawalBatchIndex: 7,
        withdrawalQueueIndex: U256::from(3),
        nextProcessedDepositQueueHash: B256::repeat_byte(0x11),
        nextBlockHash: B256::repeat_byte(0x22),
        withdrawalQueueHash: B256::repeat_byte(0x33),
        lastProcessedDepositNumber: 9,
    };
    let log = Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: event.encode_log_data(),
        },
        ..Default::default()
    };
    let receipt = make_receipt_with_logs(10, B256::ZERO, vec![log]);
    let mut header_10 = make_test_header(10);
    header_10.inner.receipts_root = calculate_test_receipts_root(std::slice::from_ref(&receipt));
    header_10.inner.logs_bloom = *receipt.inner.inner.bloom_ref();

    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());
    asserter.push_success(&Some(header_response(header_10.clone())));
    asserter.push_success(&Some(header_response(header_10)));
    asserter.push_success(&Some(vec![receipt]));

    let err = subscriber
        .sync_to_finalized(&l1_provider, 10)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        L1SubscriberError::Fatal {
            block_number: 10,
            stage: "finalized batch observer delivery",
            ..
        }
    ));
}

#[test]
fn ordinary_subscriber_errors_remain_retryable() {
    let error = L1SubscriberError::Other(eyre::eyre!("transient L1 RPC failure"));
    assert!(error.should_retry());
}

#[derive(Debug)]
struct RecordingLeadershipSink {
    queue: DepositQueue,
    seen: parking_lot::Mutex<Vec<(LeaderTransition, Option<NumHash>)>>,
    fail: bool,
}

impl LeadershipSink for RecordingLeadershipSink {
    fn apply_leader_transition(&self, transition: &LeaderTransition) -> eyre::Result<()> {
        if self.fail {
            eyre::bail!("injected leadership sink failure");
        }
        self.seen
            .lock()
            .push((transition.clone(), self.queue.last_enqueued()));
        Ok(())
    }
}

#[tokio::test]
async fn sync_applies_leadership_transition_before_enqueueing_the_activation_block() {
    let mut subscriber = test_subscriber(9);
    let portal = subscriber.config.portal_address;
    let queue = subscriber.deposit_queue.clone();
    let sink = Arc::new(RecordingLeadershipSink {
        queue: queue.clone(),
        seen: parking_lot::Mutex::new(Vec::new()),
        fail: false,
    });
    subscriber.leadership_sink = Some(sink.clone());

    let new_leader = address!("0x0000000000000000000000000000000000002222");
    let log = leader_updated_log(portal, Address::ZERO, new_leader, 2, 10);
    let mut header_10 = make_test_header(10);
    let receipt = make_receipt_with_logs(10, B256::ZERO, vec![log]);
    header_10.inner.receipts_root = calculate_test_receipts_root(std::slice::from_ref(&receipt));
    header_10.inner.logs_bloom = *receipt.inner.inner.bloom_ref();

    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());
    asserter.push_success(&Some(header_response(header_10.clone())));
    asserter.push_success(&Some(header_response(header_10.clone())));
    asserter.push_success(&Some(vec![receipt]));
    asserter.push_success(&Some(header_response(header_10)));

    assert_eq!(
        subscriber
            .sync_to_finalized(&l1_provider, 10)
            .await
            .unwrap(),
        11
    );

    let seen = sink.seen.lock();
    assert_eq!(seen.len(), 1);
    let (transition, queue_tip_at_apply) = &seen[0];
    assert_eq!(transition.new_leader, new_leader);
    assert_eq!(transition.epoch, 2);
    assert_eq!(transition.activation_tempo_block, 10);
    assert_eq!(
        *queue_tip_at_apply, None,
        "the transition must be applied before the activation block is enqueued"
    );
    assert_eq!(queue.last_enqueued().unwrap().number, 10);
}

#[tokio::test]
async fn sync_fails_fatally_when_the_leadership_sink_rejects_the_transition() {
    let mut subscriber = test_subscriber(9);
    let portal = subscriber.config.portal_address;
    let queue = subscriber.deposit_queue.clone();
    subscriber.leadership_sink = Some(Arc::new(RecordingLeadershipSink {
        queue: queue.clone(),
        seen: parking_lot::Mutex::new(Vec::new()),
        fail: true,
    }));

    let new_leader = address!("0x0000000000000000000000000000000000002222");
    let log = leader_updated_log(portal, Address::ZERO, new_leader, 2, 10);
    let mut header_10 = make_test_header(10);
    let receipt = make_receipt_with_logs(10, B256::ZERO, vec![log]);
    header_10.inner.receipts_root = calculate_test_receipts_root(std::slice::from_ref(&receipt));
    header_10.inner.logs_bloom = *receipt.inner.inner.bloom_ref();

    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());
    asserter.push_success(&Some(header_response(header_10.clone())));
    asserter.push_success(&Some(header_response(header_10.clone())));
    asserter.push_success(&Some(vec![receipt]));

    let err = subscriber
        .sync_to_finalized(&l1_provider, 10)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        L1SubscriberError::Fatal {
            block_number: 10,
            stage: "leadership transition application",
            ..
        }
    ));

    // Nothing was enqueued and no observation advanced: the block was not half-applied.
    assert_eq!(queue.last_enqueued(), None);
    assert_eq!(subscriber.block_tracker.latest(), None);
}

#[test]
fn portal_pause_events_record_the_final_state_in_log_order() {
    let subscriber = test_subscriber(9);
    let portal = subscriber.config.portal_address;
    let account = address!("0x0000000000000000000000000000000000000123");
    let log = |data| Log {
        inner: alloy_primitives::Log {
            address: portal,
            data,
        },
        ..Default::default()
    };
    let block = NumHash::new(10, B256::with_last_byte(0x10));

    let receipt = make_receipt_with_logs(10, block.hash, vec![]);
    let (events, _, _, _) = subscriber.extract_events(block, &[receipt]).unwrap();
    assert_eq!(events.portal_pause, None);

    let receipt = make_receipt_with_logs(
        10,
        block.hash,
        vec![
            log(crate::abi::ZonePortal::PortalPaused { account }.encode_log_data()),
            log(crate::abi::ZonePortal::PortalResumed { account }.encode_log_data()),
        ],
    );
    let (events, _, _, _) = subscriber.extract_events(block, &[receipt]).unwrap();
    assert_eq!(events.portal_pause, Some(false));

    // The pause is applied during ingestion and must not be carried into operational work.
    let mut operational = L1PortalEvents::default();
    operational.extend_operational(events);
    assert_eq!(operational.portal_pause, None);
}

#[test]
fn l1_block_tracker_applies_only_newer_portal_pause_observations() {
    let tracker = L1BlockTracker::default();
    let block = |number: u64| NumHash::new(number, B256::with_last_byte(number as u8));
    assert!(!tracker.portal_paused());
    assert_eq!(tracker.portal_pause_block(), None);

    assert!(tracker.observe_portal_pause(block(11), true).unwrap());
    assert!(tracker.portal_paused());
    assert_eq!(tracker.portal_pause_block(), Some(block(11)));

    // Replayed older events cannot regress the finalized state.
    assert!(!tracker.observe_portal_pause(block(10), false).unwrap());
    assert!(tracker.portal_paused());
    // A repeated observation is idempotent and reports no change.
    assert!(!tracker.observe_portal_pause(block(11), true).unwrap());
    assert!(!tracker.observe_portal_pause(block(12), true).unwrap());
    assert_eq!(tracker.portal_pause_block(), Some(block(12)));

    assert!(tracker.observe_portal_pause(block(13), false).unwrap());
    assert!(!tracker.portal_paused());
}

#[test]
fn l1_block_tracker_rejects_conflicting_portal_pause_observations() {
    let tracker = L1BlockTracker::default();
    let block = NumHash::new(11, B256::repeat_byte(1));
    tracker.observe_portal_pause(block, true).unwrap();

    assert!(tracker.observe_portal_pause(block, false).is_err());
    assert!(
        tracker
            .observe_portal_pause(NumHash::new(11, B256::repeat_byte(2)), true)
            .is_err()
    );
    assert!(tracker.portal_paused());
    assert_eq!(tracker.portal_pause_block(), Some(block));
}

#[tokio::test]
async fn sync_applies_portal_pause_before_enqueueing_the_pause_block() {
    let subscriber = test_subscriber(9);
    let portal = subscriber.config.portal_address;
    let tracker = subscriber.block_tracker.clone();
    let queue = subscriber.deposit_queue.clone();
    let log = Log {
        inner: alloy_primitives::Log {
            address: portal,
            data: crate::abi::ZonePortal::PortalPaused {
                account: Address::repeat_byte(1),
            }
            .encode_log_data(),
        },
        ..Default::default()
    };
    let mut header_10 = make_test_header(10);
    let receipt = make_receipt_with_logs(10, B256::ZERO, vec![log]);
    header_10.inner.receipts_root = calculate_test_receipts_root(std::slice::from_ref(&receipt));
    header_10.inner.logs_bloom = *receipt.inner.inner.bloom_ref();
    let anchor = seal(header_10.clone()).num_hash();

    let asserter = Asserter::new();
    let l1_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());
    asserter.push_success(&Some(header_response(header_10.clone())));
    asserter.push_success(&Some(header_response(header_10.clone())));
    asserter.push_success(&Some(vec![receipt]));
    asserter.push_success(&Some(header_response(header_10)));

    assert_eq!(
        subscriber
            .sync_to_finalized(&l1_provider, 10)
            .await
            .unwrap(),
        11
    );
    assert!(tracker.portal_paused());
    assert_eq!(tracker.portal_pause_block(), Some(anchor));
    assert_eq!(queue.last_enqueued(), Some(anchor));
}

#[tokio::test]
async fn paused_subscriber_wedges_at_lookahead_then_resumes_contiguously() {
    let checkpoint = seal(make_test_header(0)).num_hash();
    let subscriber = test_subscriber_with_checkpoint(checkpoint);
    let tracker = subscriber.block_tracker.clone();
    let queue = subscriber.deposit_queue.clone();
    tracker.observe_portal_pause(checkpoint, true).unwrap();
    assert_eq!(subscriber.next_block_to_sync().unwrap(), 1);

    let tip = MAX_L1_LOOKAHEAD_BLOCKS + 1;
    let mut parent = checkpoint.hash;
    let mut headers = Vec::new();
    for number in 1..=tip {
        let header = make_chained_header(number, parent);
        parent = header.hash_slow();
        headers.push(header);
    }
    let asserter = Asserter::new();
    asserter.push_success(&Some(header_response(headers.last().unwrap().clone())));
    for header in &headers[..headers.len() - 1] {
        push_header_and_empty_receipts(&asserter, header.clone());
    }
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter.clone());

    let sync = subscriber.sync_to_finalized(&provider, 1);
    tokio::pin!(sync);
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut sync => panic!("ingestion must wedge at the lookahead bound: {result:?}"),
            () = async {
                while tracker.latest().is_none_or(|latest| latest.number < tip - 1) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            } => {}
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut sync)
            .await
            .is_err(),
        "ingestion must wedge at the lookahead bound while nothing is consumed"
    );
    assert!(tracker.portal_paused());
    assert_eq!(tracker.latest().map(|block| block.number), Some(tip - 1));
    assert_eq!(
        queue.last_enqueued().map(|block| block.number),
        Some(tip - 1)
    );
    assert!(!tracker.has_capacity_for(tip));
    assert!(
        asserter.read_q().is_empty(),
        "the block beyond the lookahead must not be fetched while wedged"
    );

    // The poller observes resume (or expiry) independently of ingestion, the engine consumes the
    // first queued anchor, and pruning releases exactly one block of capacity.
    tracker
        .observe_portal_pause(NumHash::new(tip, parent), false)
        .unwrap();
    let first = queue.peek().unwrap().header.num_hash();
    queue.confirm(first).unwrap();
    tracker.prune_through(first.number);
    push_header_and_empty_receipts(&asserter, headers.last().unwrap().clone());
    // The unchanged finalized target lets the sync return.
    asserter.push_success(&Some(header_response(headers.last().unwrap().clone())));

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), &mut sync)
            .await
            .unwrap()
            .unwrap(),
        tip + 1
    );
    assert!(!tracker.portal_paused());
    assert_eq!(tracker.latest(), Some(NumHash::new(tip, parent)));
    assert_eq!(queue.last_enqueued(), Some(NumHash::new(tip, parent)));
    assert!(asserter.read_q().is_empty());
}
