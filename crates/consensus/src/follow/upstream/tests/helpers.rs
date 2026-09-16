use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::sync::oneshot;

use super::super::actor::{RECONNECT_MAX_BACKOFF, reconnect_backoff, respond_until_closed};

struct DropGuard(Arc<AtomicBool>);

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn reconnect_backoff_linearly_increases_and_caps() {
    assert_eq!(reconnect_backoff(0), Duration::from_secs(0));
    assert_eq!(reconnect_backoff(1), Duration::from_secs(2));
    assert_eq!(reconnect_backoff(2), Duration::from_secs(4));
    assert_eq!(reconnect_backoff(3), Duration::from_secs(6));
    assert_eq!(reconnect_backoff(4), Duration::from_secs(8));
    assert_eq!(reconnect_backoff(5), Duration::from_secs(10));
    assert_eq!(reconnect_backoff(10), RECONNECT_MAX_BACKOFF);
    assert_eq!(reconnect_backoff(u64::MAX), RECONNECT_MAX_BACKOFF);
}

#[tokio::test]
async fn closing_response_cancels_request() {
    let (response, receiver) = oneshot::channel::<()>();
    let (started_tx, started_rx) = oneshot::channel();
    let dropped = Arc::new(AtomicBool::new(false));
    let request_dropped = dropped.clone();

    let task = tokio::spawn(async move {
        let request = async move {
            let _guard = DropGuard(request_dropped);
            let _ = started_tx.send(());
            std::future::pending::<eyre::Result<()>>().await
        };
        respond_until_closed(response, request).await
    });

    started_rx.await.unwrap();
    drop(receiver);

    task.await.unwrap().unwrap();
    assert!(dropped.load(Ordering::SeqCst));
}
