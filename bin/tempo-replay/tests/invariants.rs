mod common;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{B256, Sealable, Signature, U256};
use common::*;
use std::{collections::BTreeMap, time::Duration};
use tempo_primitives::TempoTxEnvelope;
use tempo_replay::{
    config::Config,
    engine::{Budget, Outcome, classify, retry_delay},
    journal::Journal,
    model::*,
    rpc::RpcError,
    timing::Pacer,
    verify::route,
};

#[test]
fn signed_envelope_families_roundtrip_and_share_protocol_lane() {
    let d = tempfile::tempdir().unwrap();
    let c = config(d.path());
    c.validate().unwrap();
    let mut txs = vec![
        legacy(0, 1),
        aa(1, U256::ZERO, None, 1),
        aa(0, U256::from(2), None, 1),
        aa(0, U256::MAX, Some(100000), 1),
    ];
    let t = TxEip2930 {
        chain_id: 4217,
        ..Default::default()
    };
    let sig = sign(t.signature_hash(), 1);
    txs.push(TempoTxEnvelope::Eip2930(t.into_signed(sig)));
    let t = TxEip1559 {
        chain_id: 4217,
        ..Default::default()
    };
    let sig = sign(t.signature_hash(), 1);
    txs.push(TempoTxEnvelope::Eip1559(t.into_signed(sig)));
    let auth = alloy_eips::eip7702::Authorization {
        chain_id: U256::from(4217),
        address: alloy_primitives::Address::repeat_byte(4),
        nonce: 9,
    };
    let signature = sign(auth.signature_hash(), 2);
    let t = TxEip7702 {
        chain_id: 4217,
        authorization_list: vec![auth.into_signed(signature)],
        ..Default::default()
    };
    let sig = sign(t.signature_hash(), 1);
    txs.push(TempoTxEnvelope::Eip7702(t.into_signed(sig)));
    for tx in &txs {
        let raw = tx.encoded_2718();
        let decoded = TempoTxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        assert_eq!(decoded.encoded_2718(), raw);
        let v = serde_json::to_value(tx).unwrap();
        let again: TempoTxEnvelope = serde_json::from_value(v).unwrap();
        assert_eq!(again.encoded_2718(), raw);
        Tx::from_envelope(tx, 4217).unwrap();
    }
    assert_eq!(
        Tx::from_envelope(&txs[0], 4217).unwrap().lane(),
        Tx::from_envelope(&txs[1], 4217).unwrap().lane()
    );
    assert!(Tx::from_envelope(&txs[3], 4217).unwrap().lane().is_none());
    assert!(Tx::from_envelope(&txs[0], 42431).is_err());
    assert!(TempoTxEnvelope::decode_2718(&mut [0x77, 0xc0].as_slice()).is_err());
}
#[test]
fn system_hash_occurrences_and_root_validation() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let mut j = Journal::open(&c, Some(1)).unwrap();
    let t = TxLegacy {
        chain_id: Some(4217),
        ..Default::default()
    };
    let tx = TempoTxEnvelope::Legacy(t.into_signed(Signature::new(U256::ZERO, U256::ZERO, false)));
    let b1 = block(1, B256::ZERO, 1000, vec![tx.clone()], false);
    let b2 = block(2, b1.header.hash_slow(), 1100, vec![tx], false);
    let c1 = captured(&b1);
    let c2 = captured(&b2);
    assert_eq!(c1.transactions[0].class, Class::System);
    j.stage(&c1).unwrap();
    j.stage(&c2).unwrap();
    j.publish(&c2.point, 1).unwrap();
    assert_eq!(
        j.inspect(&c1.transactions[0].hash.to_string())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(j.state.counts.system_occurrences, 2);
    let mut invalid = b1;
    invalid.header.inner.transactions_root = B256::ZERO;
    assert!(CapturedBlock::from_certified(certified(&invalid), 4217).is_err());
}
#[test]
fn journal_attempt_intent_survives_reopen_and_observers_do_not_own_writer_lock() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let b = captured(&block(1, B256::ZERO, 1000, vec![legacy(0, 1)], false));
    let mut j = Journal::open(&c, Some(1)).unwrap();
    j.stage(&b).unwrap();
    j.publish(&b.point, 1).unwrap();
    j.bind(0, "binding").unwrap();
    let mut o = j.occurrences(1).unwrap().remove(0);
    o.attempts = 1;
    o.first_attempt_ms = Some(now_ms());
    o.last_attempt_ms = o.first_attempt_ms;
    o.transition(State::Attempting, "before-write crash");
    j.update(&o).unwrap();
    j.refresh_cursors().unwrap();
    assert!(Journal::open(&c, None).is_err());
    {
        let reader = Journal::read(dir.path()).unwrap();
        assert_eq!(reader.state.counts.attempts, 1);
    }
    assert_eq!(j.state.cursors.dispatch_accounted_through, Some(1));
    assert_eq!(j.state.cursors.accounted_through, Some(0));
    drop(j);
    let j = Journal::open(&c, None).unwrap();
    assert_eq!(j.occurrences(1).unwrap()[0].state, State::Attempting);
    assert_eq!(j.state.counts.reserved_count, 1);
}
#[tokio::test(start_paused = true)]
async fn anchored_pacing_preserves_slip_and_never_dumps_overdue_blocks() {
    let d = tempfile::tempdir().unwrap();
    let c = config(d.path());
    let mut p = Pacer::new(&c.timing, Phase::CatchUp, 1, 1000, "test");
    assert!(
        p.release_at(1000).unwrap() > tokio::time::Instant::now(),
        "old source timestamps start at a new catch-up anchor"
    );
    tokio::time::advance(Duration::from_secs(10)).await;
    let slip = p.released(1000, &c.timing).unwrap();
    assert!(slip >= 9990);
    let next = p.release_at(1400).unwrap();
    assert_eq!(
        next.duration_since(tokio::time::Instant::now()),
        Duration::from_millis(100)
    );
    tokio::time::advance(Duration::from_millis(100)).await;
    let next_slip = p.released(1400, &c.timing).unwrap();
    assert!(
        next_slip >= slip,
        "rate limiting must not reset ideal schedule slip"
    );
    assert!(p.release_at(1399).is_err());
    let live = Pacer::new(&c.timing, Phase::Live, 1, now_ms(), "test");
    assert_eq!(
        live.due(live.segment.source_ms + 250).unwrap() - live.due(live.segment.source_ms).unwrap(),
        Duration::from_millis(250)
    );
}
#[test]
fn configuration_rejects_unknown_policy_and_unsafe_bounds() {
    let mut c: Config = toml::from_str(include_str!("../tempo-replay.example.toml")).unwrap();
    c.validate().unwrap();
    c.timing.live_speed = 2.;
    assert!(c.validate().is_err());
    c.timing.live_speed = 1.;
    c.limits.pool_budget_fraction = 1.;
    assert!(c.validate().is_err());
    c.limits.pool_budget_fraction = 0.8;
    c.source.rpc_http = "http://localhost".into();
    assert!(c.validate().is_err());
    let bad = include_str!("../tempo-replay.example.toml")
        .replace("schema_version = 2", "schema_version = 2\nunknown = true");
    assert!(toml::from_str::<Config>(&bad).is_err());
}
#[test]
fn submission_errors_are_not_false_success_or_permanent_capacity_gaps() {
    let error = |message: &str| RpcError {
        code: -32000,
        message: message.into(),
        retry_ms: None,
        ambiguous: false,
    };
    assert_eq!(classify(&error("already known")), Outcome::Accepted);
    assert_eq!(
        classify(&error("SpammerExceededCapacity")),
        Outcome::Capacity
    );
    assert_eq!(
        classify(&error("Access key expired: expiry 5 <= min allowed 6")),
        Outcome::Expired
    );
    assert_eq!(classify(&error("nonce too low")), Outcome::NonceLow);
    assert_eq!(classify(&error("invalid signature")), Outcome::Incident);
    assert_eq!(
        classify(&error("brand new node failure")),
        Outcome::Incident
    );
    assert!(retry_delay(1, B256::ZERO, Some(5000)) >= 5000);
}
#[test]
fn reserved_subblock_prefix_and_expiry_second_boundary() {
    let key = U256::from_be_bytes::<32>({
        let mut k = [0; 32];
        k[0] = 0x5b;
        k
    });
    assert_eq!(
        Tx::from_envelope(&aa(0, key, None, 1), 4217).unwrap().class,
        Class::Subblock
    );
    let t = Tx::from_envelope(&aa(0, U256::MAX, Some(104), 1), 4217).unwrap();
    assert!(!t.expired_at(100));
    assert!(t.expired_at(101));
}
#[tokio::test]
async fn network_budget_deduplicates_retries_and_counts_across_lanes() {
    let mock = Mock::start(vec![block(0, B256::ZERO, 0, vec![], true)], true).await;
    let mut q = qualified(&mock);
    q.sender_budget = 1;
    let b = captured(&block(
        1,
        B256::ZERO,
        1000,
        vec![legacy(0, 1), aa(0, U256::from(5), None, 1), legacy(0, 2)],
        false,
    ));
    let mut first = Occurrence::new(&b, 0);
    first.state = State::Unknown;
    let mut active = BTreeMap::new();
    active.insert(first.key(), first.clone());
    let budget = Budget::from_active(&active, &q);
    assert!(budget.can_reserve(&first, &q));
    assert!(!budget.can_reserve(&Occurrence::new(&b, 1), &q));
    assert!(budget.can_reserve(&Occurrence::new(&b, 2), &q));
    assert_eq!(route(first.tx.sender, &q.targets, &[true]), Some(0));
    assert_eq!(route(first.tx.sender, &q.targets, &[false]), None);
    mock.close().await;
}

#[test]
fn disk_low_watermark_fails_before_capture_and_examples_parse() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    c.journal.min_free_bytes = u64::MAX;
    assert!(Journal::open(&c, Some(1)).is_err());
    let capture: Config = toml::from_str(include_str!("../examples/capture.toml")).unwrap();
    capture.validate().unwrap();
    assert!(capture.replay().is_err());
    serde_json::from_str::<tempo_replay::config::Deployment>(include_str!(
        "../examples/shadow-deployment.json"
    ))
    .unwrap();
}
