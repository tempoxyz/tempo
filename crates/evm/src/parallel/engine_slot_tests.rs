//! Forced interleavings for the Engine completed-result ring and its byte budget.

use super::{
    tests::{candidate, counts, diagnostic_session, env, hash, tx},
    *,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Barrier, mpsc},
    thread,
};

const DEADLINE: Duration = Duration::from_secs(5);

fn wait_for_cursor(session: &EnginePrewarmingSession, expected: usize) -> bool {
    let deadline = Instant::now() + DEADLINE;
    while session.next.load(Ordering::Acquire) < expected {
        if Instant::now() >= deadline {
            return false;
        }
        thread::yield_now();
    }
    true
}

/// Call only after all publishers, consumers and provisional reservations finish.
fn assert_conserved(session: &EnginePrewarmingSession) -> (usize, usize) {
    let mut entries = 0;
    let mut bytes = 0;
    for slot in session.retained.slots.iter() {
        let guard = slot.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = guard.as_ref() {
            entries += 1;
            bytes += entry.bytes;
        }
    }
    assert!(entries <= session.window.transactions());
    assert!(bytes <= MAX_ESTIMATED_BYTES);
    assert_eq!(
        session.retained.estimated_bytes.load(Ordering::Acquire),
        bytes
    );
    if let Some(diagnostics) = &session.diagnostics {
        let snapshot = diagnostics.snapshot();
        let published = snapshot.0[CaptureEvent::Published as usize];
        let rejected: u64 = COUNTER_NAMES
            .iter()
            .zip(snapshot.0.iter())
            .filter(|(name, _)| name.starts_with("publish_") && **name != "publish_attempts")
            .map(|(_, value)| *value)
            .sum();
        assert_eq!(
            snapshot.0[CaptureEvent::PublishAttempts as usize],
            published + rejected
        );
        assert_eq!(
            published,
            snapshot.0[CaptureEvent::TakeFound as usize]
                + snapshot.0[CaptureEvent::Evicted as usize]
                + entries as u64
        );
    }
    (entries, bytes)
}

#[test]
fn held_slot_does_not_block_publication_to_another_slot() {
    let session = diagnostic_session(2);
    let blocked = candidate(0);
    let independent = candidate(1);
    let guard = session.retained.slot(0).lock().unwrap();
    let worker_session = Arc::clone(&session);
    let (done, completion) = mpsc::channel();
    let worker = thread::spawn(move || {
        let rejected = !worker_session.publish(blocked);
        let published = worker_session.publish(independent);
        done.send((rejected, published)).unwrap();
    });
    let outcome = completion.recv_timeout(DEADLINE);
    drop(guard);
    worker.join().unwrap();
    assert_eq!(outcome.unwrap(), (true, true));
    assert_eq!(counts(&session)(CaptureEvent::PublishContended), 1);
    assert_eq!(assert_conserved(&session).0, 1);
    assert!(session.take(&tx(1)).is_some());
    assert_eq!(assert_conserved(&session), (0, 0));
}

#[test]
fn occupied_wrap_slot_preserves_the_result_of_a_waiting_take() {
    let session = diagnostic_session(257);
    let window = session.window.transactions();
    assert!(session.publish(candidate(0)));
    let gate = session.retained.drained.lock().unwrap();
    let consumer_session = Arc::clone(&session);
    let consumer = thread::spawn(move || consumer_session.take(&tx(0)));
    let advanced = wait_for_cursor(&session, 1);
    let worker_session = Arc::clone(&session);
    let completed = candidate(window);
    let (done, completion) = mpsc::channel();
    let worker = thread::spawn(move || {
        done.send(worker_session.publish(completed)).unwrap();
    });
    let publication = completion.recv_timeout(DEADLINE);
    drop(gate);
    let taken = consumer.join().unwrap();
    worker.join().unwrap();
    assert!(advanced);
    assert!(!publication.unwrap());
    assert_eq!(taken.unwrap().tx.execution_context, tx(0).execution_context);
    assert_eq!(counts(&session)(CaptureEvent::PublishSlotOccupied), 1);
    assert_eq!(assert_conserved(&session), (0, 0));
    assert!(session.publish(candidate(window)));
    assert!(session.take(&tx(window)).is_some());
    assert_eq!(assert_conserved(&session), (0, 0));
}

#[test]
fn wrapped_future_generation_survives_an_older_drain() {
    let session = diagnostic_session(257);
    let window = session.window.transactions();
    let gate = session.retained.drained.lock().unwrap();
    let consumer_session = Arc::clone(&session);
    let consumer = thread::spawn(move || consumer_session.take(&tx(0)));
    let advanced = wait_for_cursor(&session, 1);
    let worker_session = Arc::clone(&session);
    let completed = candidate(window);
    let (done, completion) = mpsc::channel();
    let worker = thread::spawn(move || {
        done.send(worker_session.publish(completed)).unwrap();
    });
    let publication = completion.recv_timeout(DEADLINE);
    drop(gate);
    let taken = consumer.join().unwrap();
    worker.join().unwrap();
    assert!(advanced);
    assert!(publication.unwrap());
    assert!(taken.is_none());
    assert_eq!(
        session
            .retained
            .slot(window)
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .index,
        window
    );
    assert_eq!(assert_conserved(&session).0, 1);
    assert!(session.take(&tx(window)).is_some());
    assert_eq!(assert_conserved(&session), (0, 0));
}

#[test]
fn a_worker_finishing_after_a_canonical_miss_cannot_repopulate_the_slot() {
    let session = diagnostic_session(1);
    let completed = candidate(0);
    let worker_session = Arc::clone(&session);
    let (release, released) = mpsc::channel();
    let worker = thread::spawn(move || {
        released.recv_timeout(DEADLINE).unwrap();
        worker_session.publish(completed)
    });
    assert!(session.take(&tx(0)).is_none());
    release.send(()).unwrap();
    assert!(!worker.join().unwrap());
    assert_eq!(counts(&session)(CaptureEvent::PublishStaleBefore), 1);
    assert!(session.take(&tx(0)).is_none());
    assert_eq!(session.next.load(Ordering::Acquire), 1);
    assert_eq!(assert_conserved(&session), (0, 0));
}

#[test]
fn later_consumer_wins_without_resurrecting_an_earlier_or_duplicate_take() {
    for later_index in [0, 1] {
        let session = diagnostic_session(2);
        assert!(session.publish(candidate(0)));
        assert!(session.publish(candidate(1)));
        let earlier_session = Arc::clone(&session);
        let (advanced, advancement) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let earlier = thread::spawn(move || {
            earlier_session.capture_event(CaptureEvent::Takes);
            let previous = earlier_session.next.fetch_max(1, Ordering::AcqRel);
            advanced.send(previous).unwrap();
            released.recv_timeout(DEADLINE).unwrap();
            earlier_session.take_after_advance(0, previous, false).0
        });
        assert_eq!(advancement.recv_timeout(DEADLINE).unwrap(), 0);
        let later = session.take(&tx(later_index));
        release.send(()).unwrap();
        assert!(earlier.join().unwrap().is_none());
        assert_eq!(later.is_some(), later_index == 1);
        assert_eq!(session.next.load(Ordering::Acquire), later_index + 1);
        assert_eq!(*session.retained.drained.lock().unwrap(), later_index + 1);
        if later_index == 0 {
            assert!(session.take(&tx(1)).is_some());
        }
        assert_eq!(assert_conserved(&session), (0, 0));
    }
}

#[test]
fn concurrent_budget_reservations_are_bounded_and_refund_on_rollback() {
    let retained = Arc::new(Retained::new(4));
    let start = Arc::new(Barrier::new(5));
    let (reserved, reservations) = mpsc::channel();
    let mut releases = Vec::new();
    let mut workers = Vec::new();
    for _ in 0..4 {
        let retained = Arc::clone(&retained);
        let start = Arc::clone(&start);
        let reserved = reserved.clone();
        let (release, released) = mpsc::channel();
        releases.push(release);
        workers.push(thread::spawn(move || {
            start.wait();
            let reservation = retained.reserve(MAX_ESTIMATED_BYTES / 4);
            reserved.send(reservation.is_ok()).unwrap();
            released.recv_timeout(DEADLINE).unwrap();
            drop(reservation);
        }));
    }
    drop(reserved);
    start.wait();
    let outcomes: Vec<_> = (0..4)
        .map(|_| reservations.recv_timeout(DEADLINE))
        .collect();
    let full = retained.estimated_bytes.load(Ordering::Acquire);
    let rejected_extra = retained.reserve(1).is_err();
    let rejected_overflow = retained.reserve(usize::MAX).is_err();
    for release in releases {
        let _ = release.send(());
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(outcomes.into_iter().all(|outcome| outcome == Ok(true)));
    assert_eq!(full, MAX_ESTIMATED_BYTES);
    assert!(rejected_extra);
    assert!(rejected_overflow);
    assert_eq!(retained.estimated_bytes.load(Ordering::Acquire), 0);
    let reservation = retained.reserve(MAX_ESTIMATED_BYTES).ok().unwrap();
    assert_eq!(
        retained.estimated_bytes.load(Ordering::Acquire),
        MAX_ESTIMATED_BYTES
    );
    drop(reservation);
    assert_eq!(retained.estimated_bytes.load(Ordering::Acquire), 0);
}

#[test]
fn an_unwinding_provisional_reservation_refunds_its_charge() {
    let retained = Retained::new(2);
    let unwind = catch_unwind(AssertUnwindSafe(|| {
        let _reservation = retained.reserve(MAX_ESTIMATED_BYTES).ok().unwrap();
        panic!("unwind after reservation, before entry installation");
    }));
    assert!(unwind.is_err());
    assert_eq!(retained.estimated_bytes.load(Ordering::Acquire), 0);
    assert!(retained.reserve(MAX_ESTIMATED_BYTES).is_ok());
    assert_eq!(retained.estimated_bytes.load(Ordering::Acquire), 0);
}

#[test]
fn poison_after_detaching_an_entry_refunds_only_the_detached_charge() {
    let session = diagnostic_session(3);
    assert!(session.publish(candidate(0)));
    assert!(session.publish(candidate(1)));
    let retained_bytes = session
        .retained
        .slot(1)
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .bytes;
    let unwind = catch_unwind(AssertUnwindSafe(|| {
        let _slot = session.retained.slot(1).lock().unwrap();
        panic!("poison a later slot before canonical draining");
    }));
    assert!(unwind.is_err());
    // Raw mutex poisoning is discovered only when the drain reaches slot one.
    assert!(!session.retained.poisoned.load(Ordering::Acquire));
    assert!(session.take(&tx(1)).is_none());
    assert!(session.retained.slot(0).lock().unwrap().is_none());
    assert!(session.retained.poisoned.load(Ordering::Acquire));
    assert_eq!(assert_conserved(&session), (1, retained_bytes));
    assert!(!session.publish(candidate(2)));
    assert!(session.take(&tx(2)).is_none());
    assert_eq!(assert_conserved(&session), (1, retained_bytes));
}

#[test]
fn a_worker_finishing_after_session_replacement_keeps_its_old_ring() {
    let cache = EnginePrewarmingCache::default();
    let old = cache.begin(env(), [hash(0)]).unwrap();
    let worker_session = Arc::clone(&old);
    let completed = candidate(0);
    let (release, released) = mpsc::channel();
    let worker = thread::spawn(move || {
        released.recv_timeout(DEADLINE).unwrap();
        worker_session.publish(completed)
    });
    let new = cache.begin(env(), [hash(0)]).unwrap();
    release.send(()).unwrap();
    assert!(worker.join().unwrap());
    assert!(new.take(&tx(0)).is_none());
    assert_eq!(assert_conserved(&new), (0, 0));
    assert_eq!(assert_conserved(&old).0, 1);
    assert!(old.take(&tx(0)).is_some());
    assert_eq!(assert_conserved(&old), (0, 0));
    assert!(Arc::ptr_eq(&cache.session(&env()).unwrap(), &new));
}

#[test]
fn prepared_publication_rechecks_the_cursor_after_canonical_progress() {
    let session = diagnostic_session(1);
    let mut completed = candidate(0);
    assert!(session.can_capture(&completed.tx));
    let bytes = completed.estimated_retained_bytes().unwrap();
    let completed = Box::new(completed);
    session.capture_event(CaptureEvent::PublishAttempts);
    let worker_session = Arc::clone(&session);
    let (release, released) = mpsc::channel();
    let worker = thread::spawn(move || {
        released.recv_timeout(DEADLINE).unwrap();
        worker_session.publish_prepared(0, completed, bytes)
    });
    assert!(session.take(&tx(0)).is_none());
    release.send(()).unwrap();
    assert!(!worker.join().unwrap());
    assert_eq!(counts(&session)(CaptureEvent::PublishStaleBefore), 0);
    assert_eq!(counts(&session)(CaptureEvent::PublishStaleAfter), 1);
    assert_eq!(assert_conserved(&session), (0, 0));
}

#[test]
fn concurrent_workers_for_one_index_publish_exactly_one_candidate() {
    let session = diagnostic_session(1);
    let start = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let mut completed = candidate(0);
        let bytes = completed.estimated_retained_bytes().unwrap();
        let worker_session = Arc::clone(&session);
        let start = Arc::clone(&start);
        workers.push(thread::spawn(move || {
            start.wait();
            (worker_session.publish(completed), bytes)
        }));
    }
    start.wait();
    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let published: Vec<_> = outcomes
        .iter()
        .filter(|(published, _)| *published)
        .collect();
    assert_eq!(published.len(), 1);
    assert_eq!(assert_conserved(&session), (1, published[0].1));
    let count = counts(&session);
    assert_eq!(count(CaptureEvent::Published), 1);
    assert_eq!(
        count(CaptureEvent::PublishContended) + count(CaptureEvent::PublishDuplicate),
        1
    );
    assert!(session.take(&tx(0)).is_some());
    assert!(session.take(&tx(0)).is_none());
    assert_eq!(assert_conserved(&session), (0, 0));
}

#[test]
fn a_large_canonical_jump_retires_every_old_slot_once() {
    let window = EngineCaptureWindow::Transactions128.transactions();
    let session = diagnostic_session(3 * window + 1);
    for index in 0..window {
        assert!(session.publish(candidate(index)));
    }
    assert_eq!(assert_conserved(&session).0, window);
    let jump = 2 * window + 3;
    assert!(session.take(&tx(jump)).is_none());
    assert_eq!(*session.retained.drained.lock().unwrap(), jump + 1);
    assert_eq!(counts(&session)(CaptureEvent::Evicted), window as u64);
    assert_eq!(assert_conserved(&session), (0, 0));
    assert!(session.publish(candidate(jump + 1)));
    assert!(session.take(&tx(jump + 1)).is_some());
    assert_eq!(assert_conserved(&session), (0, 0));
}

#[test]
fn a_system_take_evicts_its_candidate_without_reuse() {
    let session = diagnostic_session(2);
    assert!(session.publish(candidate(0)));
    assert!(session.publish(candidate(1)));
    let mut system = tx(0);
    system.is_system_tx = true;
    assert!(session.take(&system).is_none());
    assert!(!session.retained.contains(0));
    assert!(session.retained.contains(1));
    assert_eq!(counts(&session)(CaptureEvent::TakeFound), 0);
    assert_eq!(counts(&session)(CaptureEvent::Evicted), 1);
    assert_eq!(assert_conserved(&session).0, 1);
    assert!(session.take(&tx(1)).is_some());
    assert_eq!(assert_conserved(&session), (0, 0));
}
