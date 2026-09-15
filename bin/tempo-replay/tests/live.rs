mod common;

use alloy_primitives::{B256, Sealable};
use common::*;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tempo_replay::{
    capture::capture_loop,
    config::Config,
    engine::replay,
    journal::{Journal, SharedJournal, lock},
    model::{Phase, now_ms},
};
use tokio::{task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

fn start(
    c: &Config,
    source: &Mock,
    shadow: &Mock,
    journal: &SharedJournal,
    stop: &CancellationToken,
) -> JoinSet<anyhow::Result<()>> {
    let mut tasks = JoinSet::new();
    tasks.spawn(capture_loop(
        c.clone(),
        source.rpc(1000),
        journal.clone(),
        None,
        stop.clone(),
    ));
    tasks.spawn(replay(
        c.clone(),
        qualified(shadow),
        source.rpc(1000),
        journal.clone(),
        None,
        false,
        stop.clone(),
    ));
    tasks
}
async fn included(journal: &SharedJournal, height: u64) {
    timeout(Duration::from_secs(8), async {
        loop {
            let s = lock(journal).unwrap().state.clone();
            assert!(
                s.incident.is_none(),
                "unexpected incident: {:?}",
                s.incident
            );
            if s.cursors.included_through == Some(height) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("mirror did not follow newly finalized traffic");
}
async fn shutdown(tasks: &mut JoinSet<anyhow::Result<()>>, stop: &CancellationToken) {
    stop.cancel();
    timeout(Duration::from_secs(3), async {
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
    })
    .await
    .expect("mirror tasks did not stop");
}

#[tokio::test]
async fn catches_up_follows_new_blocks_and_resumes_the_same_start_height() {
    let directory = tempfile::tempdir().unwrap();
    let mut c = config(directory.path());
    c.timing.target_lag_ms = 1000;
    let old = now_ms() - 30000;
    let g = block(100, B256::ZERO, old, vec![], false);
    let sg = block(100, B256::ZERO, old, vec![], true);
    let b1 = block(
        101,
        g.header.hash_slow(),
        old + 100,
        vec![legacy(0, 1)],
        false,
    );
    let b2 = block(
        102,
        b1.header.hash_slow(),
        old + 200,
        vec![legacy(1, 1)],
        false,
    );
    let source = Mock::start(vec![g.clone(), b1, b2.clone()], false).await;
    let shadow = Mock::start(vec![sg.clone()], true).await;
    attach_shadow(&mut c, &g, &sg);
    // No websocket feed is served here: polling must continue to discover new finality.
    c.source.consensus_ws = source.url.replacen("http://", "ws://", 1);
    let journal = Arc::new(Mutex::new(
        Journal::open_replay(&c, Some(101), None).unwrap(),
    ));
    let stop = CancellationToken::new();
    let mut tasks = start(&c, &source, &shadow, &journal, &stop);
    included(&journal, 102).await;
    assert_eq!(lock(&journal).unwrap().state.phase, Phase::CatchUp);
    assert_eq!(
        tasks.len(),
        2,
        "reaching the startup tip must not end either task"
    );

    // These blocks did not exist when the process started. Preserve the empty block too.
    let b3 = block(103, b2.header.hash_slow(), now_ms(), vec![], false);
    let b4 = block(
        104,
        b3.header.hash_slow(),
        b3.header.timestamp_millis() + 100,
        vec![legacy(2, 1)],
        false,
    );
    {
        let mut state = source.state.lock().unwrap();
        state.blocks.insert(103, b3);
        state.blocks.insert(104, b4.clone());
    }
    included(&journal, 104).await;
    assert_eq!(lock(&journal).unwrap().state.phase, Phase::Live);
    assert_eq!(shadow.state.lock().unwrap().sent.len(), 3);
    shutdown(&mut tasks, &stop).await;
    drop(journal);

    // A block arrives during downtime. Repeating --from-block is an assertion, not a reset.
    let b5 = block(
        105,
        b4.header.hash_slow(),
        now_ms().max(b4.header.timestamp_millis() + 100),
        vec![legacy(3, 1)],
        false,
    );
    source.state.lock().unwrap().blocks.insert(105, b5);
    let journal = Arc::new(Mutex::new(
        Journal::open_replay(&c, Some(101), None).unwrap(),
    ));
    let stop = CancellationToken::new();
    let mut tasks = start(&c, &source, &shadow, &journal, &stop);
    included(&journal, 105).await;
    assert_eq!(
        shadow.state.lock().unwrap().sent.len(),
        4,
        "only new traffic should be sent after restart"
    );
    assert_eq!(lock(&journal).unwrap().state.counts.finalized, 4);
    shutdown(&mut tasks, &stop).await;
    source.close().await;
    shadow.close().await;
}

#[tokio::test]
async fn can_start_at_the_tip_before_the_first_mirrored_block_exists() {
    let directory = tempfile::tempdir().unwrap();
    let mut c = config(directory.path());
    c.timing.target_lag_ms = 1000;
    let g = block(50, B256::ZERO, now_ms(), vec![], false);
    let sg = block(50, B256::ZERO, g.header.timestamp_millis(), vec![], true);
    let source = Mock::start(vec![g.clone()], false).await;
    let shadow = Mock::start(vec![sg.clone()], true).await;
    attach_shadow(&mut c, &g, &sg);
    c.source.consensus_ws = source.url.replacen("http://", "ws://", 1);
    let journal = Arc::new(Mutex::new(
        Journal::open_replay(&c, Some(51), None).unwrap(),
    ));
    let stop = CancellationToken::new();
    let mut tasks = start(&c, &source, &shadow, &journal, &stop);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!tasks.is_empty());
    assert!(shadow.state.lock().unwrap().sent.is_empty());
    assert!(
        lock(&journal)
            .unwrap()
            .state
            .cursors
            .captured_through
            .is_none()
    );
    let next = block(
        51,
        g.header.hash_slow(),
        now_ms(),
        vec![legacy(0, 1)],
        false,
    );
    source.state.lock().unwrap().blocks.insert(51, next);
    included(&journal, 51).await;
    assert_eq!(shadow.state.lock().unwrap().sent.len(), 1);
    shutdown(&mut tasks, &stop).await;
    source.close().await;
    shadow.close().await;
}

#[test]
fn replay_height_matches_snapshot_and_can_reuse_an_earlier_capture_journal() {
    let directory = tempfile::tempdir().unwrap();
    let mut c = config(directory.path());
    let g = block(100, B256::ZERO, 1000, vec![], false);
    attach_shadow(&mut c, &g, &block(100, B256::ZERO, 1000, vec![], true));
    assert!(Journal::open_replay(&c, Some(100), None).is_err());
    assert!(Journal::open_replay(&c, Some(102), None).is_err());
    assert!(Journal::open_replay(&c, Some(101), Some(100)).is_err());
    assert!(
        !directory.path().join("db").exists(),
        "invalid start must fail before creating a journal"
    );
    drop(Journal::open(&c, Some(90)).unwrap());
    let journal = Journal::open_replay(&c, Some(101), None).unwrap();
    assert_eq!(journal.state.first_height, 90);
    drop(journal);
    c.checkpoint.as_mut().unwrap().source_height = u64::MAX;
    assert!(Journal::open_replay(&c, None, None).is_err());
}
