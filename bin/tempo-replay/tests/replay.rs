mod common;
use alloy_primitives::{B256, Sealable, U256};
use common::*;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tempo_replay::{
    capture::capture_once,
    engine::replay,
    journal::{Journal, lock},
    model::*,
    profile::profile,
};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn capture_fallback_replay_lost_response_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    let ts = now_ms() - 2000;
    let genesis = block(0, B256::ZERO, ts, vec![], false);
    let target_genesis = block(0, B256::ZERO, ts, vec![], true);
    let b1 = block(
        1,
        genesis.header.hash_slow(),
        ts + 100,
        vec![legacy(0, 1), aa(0, U256::from(42), None, 2)],
        false,
    );
    let b2 = block(
        2,
        b1.header.hash_slow(),
        ts + 200,
        vec![legacy(1, 1)],
        false,
    );
    let source = Mock::start(vec![genesis.clone(), b1, b2], false).await;
    source.state.lock().unwrap().missing_certificates.insert(1);
    let target = Mock::start(vec![target_genesis.clone()], true).await;
    attach_shadow(&mut c, &genesis, &target_genesis);
    let j = Arc::new(Mutex::new(Journal::open(&c, Some(1)).unwrap()));
    let stop = CancellationToken::new();
    assert_eq!(
        capture_once(&c, &source.rpc(1000), &j, None, Some(2), &stop)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        lock(&j).unwrap().block(1).unwrap().unwrap().provenance,
        "anchored_execution_range"
    );
    let first = lock(&j).unwrap().occurrences(1).unwrap()[0].clone();
    target
        .state
        .lock()
        .unwrap()
        .lose_response
        .insert(first.tx.hash);
    tokio::time::timeout(
        Duration::from_secs(5),
        replay(
            c.clone(),
            qualified(&target),
            source.rpc(1000),
            j.clone(),
            Some(2),
            false,
            stop.clone(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let state = lock(&j).unwrap().state.clone();
    assert_eq!(state.counts.offered, 3);
    assert_eq!(state.counts.finalized, 3);
    assert_eq!(state.counts.gaps, 0);
    assert_eq!(state.cursors.included_through, Some(2));
    assert_eq!(
        state.counts.attempts, 3,
        "lost response must reconcile without another submission"
    );
    assert_eq!(target.state.lock().unwrap().sent.len(), 3);
    let p = profile(&lock(&j).unwrap(), None, None).unwrap();
    assert_eq!(p.users, 3);
    assert_eq!(p.nonzero_nonce_keys, 1);
    lock(&j).unwrap().flush().unwrap();
    drop(j);
    let j = Arc::new(Mutex::new(Journal::open(&c, None).unwrap()));
    tokio::time::timeout(
        Duration::from_secs(5),
        replay(
            c,
            qualified(&target),
            source.rpc(1000),
            j.clone(),
            Some(2),
            false,
            stop,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        target.state.lock().unwrap().sent.len(),
        3,
        "restart must not resend finalized hashes"
    );
    source.close().await;
    target.close().await;
}
#[tokio::test]
async fn expiry_gap_blocks_successor_but_other_sender_continues() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    let ts = now_ms() - 10000;
    let g = block(0, B256::ZERO, ts, vec![], false);
    let sg = block(0, B256::ZERO, ts, vec![], true);
    let bad = aa(0, U256::from(7), Some(ts / 1000 + 1), 1);
    let b1 = block(1, g.header.hash_slow(), ts + 100, vec![bad.clone()], false);
    let b2 = block(
        2,
        b1.header.hash_slow(),
        ts + 200,
        vec![aa(1, U256::from(7), None, 1), legacy(0, 2)],
        false,
    );
    let source = Mock::start(vec![g.clone(), b1, b2], false).await;
    let target = Mock::start(vec![sg.clone()], true).await;
    target.state.lock().unwrap().reject.insert(
        Tx::from_envelope(&bad, 4217).unwrap().hash,
        "transaction expired".into(),
    );
    attach_shadow(&mut c, &g, &sg);
    let j = Arc::new(Mutex::new(Journal::open(&c, Some(1)).unwrap()));
    let stop = CancellationToken::new();
    capture_once(&c, &source.rpc(1000), &j, None, Some(2), &stop)
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        replay(
            c,
            qualified(&target),
            source.rpc(1000),
            j.clone(),
            Some(2),
            false,
            stop,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let s = lock(&j).unwrap().state.clone();
    assert_eq!(s.counts.user_occurrences, 3);
    assert_eq!(s.counts.offered, 2);
    assert_eq!(s.counts.finalized, 1);
    assert_eq!(s.counts.gaps, 2);
    assert_eq!(s.cursors.included_through, Some(0));
    assert_eq!(s.cursors.accounted_through, Some(2));
    assert_eq!(target.state.lock().unwrap().sent.len(), 2);
    source.close().await;
    target.close().await;
}
#[tokio::test]
async fn corrupt_fallback_never_advances_canonical_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let g = block(0, B256::ZERO, 1000, vec![], false);
    let b1 = block(1, g.header.hash_slow(), 1100, vec![legacy(0, 1)], false);
    let b2 = block(2, b1.header.hash_slow(), 1200, vec![], false);
    let source = Mock::start(vec![g, b1, b2], false).await;
    {
        let mut s = source.state.lock().unwrap();
        s.missing_certificates.insert(1);
        s.corrupt_height = Some(1);
    }
    let j = Arc::new(Mutex::new(Journal::open(&c, Some(1)).unwrap()));
    assert!(
        capture_once(
            &c,
            &source.rpc(1000),
            &j,
            None,
            None,
            &CancellationToken::new()
        )
        .await
        .is_err()
    );
    assert!(lock(&j).unwrap().state.cursors.captured_through.is_none());
    source.close().await;
}

#[tokio::test]
async fn durable_attempt_before_write_is_reconciled_and_resent_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    let ts = now_ms() - 1000;
    let g = block(0, B256::ZERO, ts, vec![], false);
    let sg = block(0, B256::ZERO, ts, vec![], true);
    let b = block(1, g.header.hash_slow(), ts + 100, vec![legacy(0, 1)], false);
    let source = Mock::start(vec![g.clone(), b], false).await;
    let target = Mock::start(vec![sg.clone()], true).await;
    attach_shadow(&mut c, &g, &sg);
    let j = Arc::new(Mutex::new(Journal::open(&c, Some(1)).unwrap()));
    let stop = CancellationToken::new();
    capture_once(&c, &source.rpc(1000), &j, None, Some(1), &stop)
        .await
        .unwrap();
    {
        let mut db = lock(&j).unwrap();
        db.bind(0, "test-binding").unwrap();
        let mut o = db.occurrences(1).unwrap().remove(0);
        o.attempts = 1;
        o.first_attempt_ms = Some(now_ms());
        o.last_attempt_ms = o.first_attempt_ms;
        o.endpoint = Some("shadow-a".into());
        o.transition(State::Attempting, "crash before socket write");
        db.update(&o).unwrap();
        db.state.last_release_height = Some(1);
        db.save_state().unwrap();
    }
    drop(j);
    let j = Arc::new(Mutex::new(Journal::open(&c, None).unwrap()));
    tokio::time::timeout(
        Duration::from_secs(5),
        replay(
            c,
            qualified(&target),
            source.rpc(1000),
            j.clone(),
            Some(1),
            false,
            stop,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let o = lock(&j).unwrap().occurrences(1).unwrap().remove(0);
    assert_eq!(o.state, State::Finalized);
    assert_eq!(o.ambiguous_resends, 1);
    assert_eq!(target.state.lock().unwrap().sent.len(), 1);
    source.close().await;
    target.close().await;
}
#[tokio::test]
async fn target_finality_conflict_stops_before_sending() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    let ts = now_ms() - 1000;
    let g = block(0, B256::ZERO, ts, vec![], false);
    let sg = block(0, B256::ZERO, ts, vec![], true);
    let b = block(1, g.header.hash_slow(), ts + 100, vec![legacy(0, 1)], false);
    let source = Mock::start(vec![g.clone(), b], false).await;
    let bad = block(1, B256::repeat_byte(99), ts + 200, vec![], true);
    let target = Mock::start(vec![sg.clone(), bad], true).await;
    attach_shadow(&mut c, &g, &sg);
    let j = Arc::new(Mutex::new(Journal::open(&c, Some(1)).unwrap()));
    let stop = CancellationToken::new();
    capture_once(&c, &source.rpc(1000), &j, None, Some(1), &stop)
        .await
        .unwrap();
    assert!(
        replay(
            c,
            qualified(&target),
            source.rpc(1000),
            j.clone(),
            Some(1),
            false,
            stop
        )
        .await
        .is_err()
    );
    assert!(target.state.lock().unwrap().sent.is_empty());
    assert!(lock(&j).unwrap().state.incident.is_some());
    source.close().await;
    target.close().await;
}

#[tokio::test]
async fn bounded_capture_uses_later_finality_anchor_when_end_certificate_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(dir.path());
    let g = block(0, B256::ZERO, 1000, vec![], false);
    let b1 = block(1, g.header.hash_slow(), 1100, vec![legacy(0, 1)], false);
    let b2 = block(2, b1.header.hash_slow(), 1200, vec![legacy(1, 1)], false);
    let source = Mock::start(vec![g, b1, b2], false).await;
    source.state.lock().unwrap().missing_certificates.insert(1);
    let j = Arc::new(Mutex::new(Journal::open(&c, Some(1)).unwrap()));
    capture_once(
        &c,
        &source.rpc(1000),
        &j,
        None,
        Some(1),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        lock(&j)
            .unwrap()
            .state
            .cursors
            .captured_through
            .as_ref()
            .unwrap()
            .height,
        1
    );
    assert_eq!(lock(&j).unwrap().state.counts.user_occurrences, 1);
    capture_once(
        &c,
        &source.rpc(1000),
        &j,
        None,
        Some(2),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(lock(&j).unwrap().state.counts.user_occurrences, 2);
    source.close().await;
}
#[tokio::test]
async fn capacity_rejection_is_deferred_then_retried_without_a_gap() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    let ts = now_ms() - 1000;
    let g = block(0, B256::ZERO, ts, vec![], false);
    let sg = block(0, B256::ZERO, ts, vec![], true);
    let tx = legacy(0, 1);
    let hash = Tx::from_envelope(&tx, 4217).unwrap().hash;
    let b = block(1, g.header.hash_slow(), ts + 100, vec![tx], false);
    let source = Mock::start(vec![g.clone(), b], false).await;
    let target = Mock::start(vec![sg.clone()], true).await;
    attach_shadow(&mut c, &g, &sg);
    let j = Arc::new(Mutex::new(Journal::open(&c, Some(1)).unwrap()));
    let stop = CancellationToken::new();
    target
        .state
        .lock()
        .unwrap()
        .reject
        .insert(hash, "SpammerExceededCapacity".into());
    capture_once(&c, &source.rpc(1000), &j, None, Some(1), &stop)
        .await
        .unwrap();
    let task = tokio::spawn(replay(
        c,
        qualified(&target),
        source.rpc(1000),
        j.clone(),
        Some(1),
        false,
        stop.clone(),
    ));
    wait_for_state(&j, State::Deferred).await;
    target.state.lock().unwrap().reject.clear();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let s = lock(&j).unwrap().state.clone();
    assert_eq!(s.counts.gaps, 0);
    assert_eq!(s.counts.finalized, 1);
    assert!(s.counts.attempts >= 2);
    source.close().await;
    target.close().await;
}
#[tokio::test]
async fn cancellation_drains_writes_and_retains_unfinalized_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(dir.path());
    let ts = now_ms() - 1000;
    let g = block(0, B256::ZERO, ts, vec![], false);
    let sg = block(0, B256::ZERO, ts, vec![], true);
    let b = block(1, g.header.hash_slow(), ts + 100, vec![legacy(0, 1)], false);
    let source = Mock::start(vec![g.clone(), b], false).await;
    let target = Mock::start(vec![sg.clone()], true).await;
    target.state.lock().unwrap().auto_mine = false;
    attach_shadow(&mut c, &g, &sg);
    let j = Arc::new(Mutex::new(Journal::open(&c, Some(1)).unwrap()));
    let stop = CancellationToken::new();
    capture_once(&c, &source.rpc(1000), &j, None, Some(1), &stop)
        .await
        .unwrap();
    let task = tokio::spawn(replay(
        c,
        qualified(&target),
        source.rpc(1000),
        j.clone(),
        None,
        false,
        stop.clone(),
    ));
    wait_for_state(&j, State::Accepted).await;
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(target.state.lock().unwrap().sent.len(), 1);
    let o = lock(&j).unwrap().occurrences(1).unwrap().remove(0);
    assert_eq!(o.state, State::Accepted);
    assert_eq!(lock(&j).unwrap().state.counts.reserved_count, 1);
    source.close().await;
    target.close().await;
}

async fn wait_for_state(j: &tempo_replay::journal::SharedJournal, state: State) {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if lock(j)
                .unwrap()
                .occurrences(1)
                .unwrap()
                .iter()
                .any(|o| o.state == state)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected journal transition did not occur");
}
