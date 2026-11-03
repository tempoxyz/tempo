use super::*;
use alloy_primitives::B256;
use jsonrpsee::{
    core::EmptyServerParams,
    server::{Server, ServerConfig},
    ws_client::WsClientBuilder,
};
use reth_primitives_traits::SealedBlock;
use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempo_primitives::Block;
use tokio::sync::broadcast;

/// A feed with no publisher of its own, modelling a node whose finalization has stalled.
/// Tests that need events send them on `events_tx` directly.
#[derive(Clone)]
struct IdleFeed {
    events_tx: broadcast::Sender<Arc<SharedEvent>>,
}

impl ConsensusFeed for IdleFeed {
    async fn get_finalization(&self, _query: Query) -> types::Response<CertifiedBlock> {
        types::Response::NotReady
    }

    async fn get_latest(&self) -> ConsensusState {
        ConsensusState {
            finalized: None,
            notarized: None,
        }
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Arc<SharedEvent>>> {
        Some(self.events_tx.subscribe())
    }
}

/// Each live subscription task holds exactly one feed receiver, so the receiver count
/// tracks how many subscription tasks are still alive.
async fn wait_for_live_subscriptions(
    events_tx: &broadcast::Sender<Arc<SharedEvent>>,
    expected: usize,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while events_tx.receiver_count() != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {expected} live subscription tasks, found {}",
            events_tx.receiver_count()
        )
    });
}

#[tokio::test]
async fn subscription_task_exits_on_disconnect_without_events() {
    let (events_tx, _) = broadcast::channel(1);
    let module = TempoConsensusRpc::new(
        IdleFeed {
            events_tx: events_tx.clone(),
        },
        SubscriptionLimits::default(),
    )
    .into_rpc();

    let subscription = module
        .subscribe_unbounded("consensus_subscribe", EmptyServerParams::new())
        .await
        .unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;

    drop(subscription);
    wait_for_live_subscriptions(&events_tx, 0).await;
}

#[tokio::test]
async fn unsubscribe_releases_permit_without_events() {
    let (events_tx, _) = broadcast::channel(1);
    let module = TempoConsensusRpc::new(
        IdleFeed {
            events_tx: events_tx.clone(),
        },
        SubscriptionLimits::default(),
    )
    .into_rpc();

    let server = Server::builder()
        .set_config(
            ServerConfig::builder()
                .max_subscriptions_per_connection(1)
                .build(),
        )
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let _handle = server.start(module);

    let client = WsClientBuilder::default()
        .build(format!("ws://{addr}"))
        .await
        .unwrap();

    let subscription = client.subscribe_events().await.unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;

    subscription.unsubscribe().await.unwrap();
    wait_for_live_subscriptions(&events_tx, 0).await;

    // The only permit on this connection must be available again.
    let _subscription = client.subscribe_events().await.unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;
}

#[tokio::test]
async fn subscription_notification_carries_event() {
    let (events_tx, _) = broadcast::channel(1);
    let module = TempoConsensusRpc::new(
        IdleFeed {
            events_tx: events_tx.clone(),
        },
        SubscriptionLimits::default(),
    )
    .into_rpc();

    let mut subscription = module
        .subscribe_unbounded("consensus_subscribe", EmptyServerParams::new())
        .await
        .unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;

    let block = CertifiedBlock {
        epoch: 7,
        view: 11,
        digest: B256::repeat_byte(0x11),
        certificate: "0x1234".to_string(),
        block: SealedBlock::seal_slow(Block::default()).into(),
    };
    events_tx
        .send(SharedEvent::new(Event::Finalized {
            block: block.clone(),
            seen: 42,
        }))
        .unwrap();

    let (received, _) = subscription.next::<Event>().await.unwrap().unwrap();
    let Event::Finalized {
        block: received_block,
        seen,
    } = received
    else {
        panic!("expected a finalized event, got {received:?}");
    };
    assert_eq!(received_block, block);
    assert_eq!(seen, 42);
}

fn finalized_event() -> Arc<SharedEvent> {
    SharedEvent::new(Event::Finalized {
        block: CertifiedBlock {
            epoch: 1,
            view: 1,
            digest: B256::ZERO,
            certificate: "0x".to_string(),
            block: SealedBlock::seal_slow(Block::default()).into(),
        },
        seen: 0,
    })
}

#[tokio::test]
async fn subscribe_is_rejected_as_busy_once_limit_is_reached() {
    let (events_tx, _) = broadcast::channel(1);
    let module = TempoConsensusRpc::new(
        IdleFeed {
            events_tx: events_tx.clone(),
        },
        SubscriptionLimits {
            max_subscriptions: NonZeroUsize::MIN,
            ..Default::default()
        },
    )
    .into_rpc();

    let first = module
        .subscribe_unbounded("consensus_subscribe", EmptyServerParams::new())
        .await
        .unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;

    let err = module
        .subscribe_unbounded("consensus_subscribe", EmptyServerParams::new())
        .await
        .expect_err("second subscription must be rejected");
    let jsonrpsee::core::server::MethodsError::JsonRpc(err) = err else {
        panic!("expected a JSON-RPC error, got {err:?}");
    };
    assert_eq!(err.code(), SERVER_IS_BUSY_CODE);
    assert_eq!(events_tx.receiver_count(), 1);

    // Dropping the live subscription frees its permit.
    drop(first);
    wait_for_live_subscriptions(&events_tx, 0).await;
    let _again = module
        .subscribe_unbounded("consensus_subscribe", EmptyServerParams::new())
        .await
        .unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;
}

#[tokio::test]
async fn subscriber_that_stops_reading_is_dropped() {
    let (events_tx, _) = broadcast::channel(256);
    let module = TempoConsensusRpc::new(
        IdleFeed {
            events_tx: events_tx.clone(),
        },
        SubscriptionLimits::default(),
    )
    .into_rpc();

    // Never read from the subscription, so its notifications pile up in the buffer.
    let _subscription = module
        .subscribe("consensus_subscribe", EmptyServerParams::new(), 256)
        .await
        .unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;

    for _ in 0..=MAX_PENDING_NOTIFICATIONS + 1 {
        events_tx.send(finalized_event()).unwrap();
    }
    wait_for_live_subscriptions(&events_tx, 0).await;
}

/// A feed whose single subscriber's channel closes once the test drops the sender.
struct ClosingFeed {
    rx: std::sync::Mutex<Option<broadcast::Receiver<Arc<SharedEvent>>>>,
}

impl ConsensusFeed for ClosingFeed {
    async fn get_finalization(&self, _query: Query) -> types::Response<CertifiedBlock> {
        types::Response::NotReady
    }

    async fn get_latest(&self) -> ConsensusState {
        ConsensusState::default()
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Arc<SharedEvent>>> {
        self.rx.lock().unwrap().take()
    }
}

#[tokio::test]
async fn server_ended_subscription_closes_client_stream() {
    let (events_tx, events_rx) = broadcast::channel(1);
    let module = TempoConsensusRpc::new(
        ClosingFeed {
            rx: std::sync::Mutex::new(Some(events_rx)),
        },
        SubscriptionLimits::default(),
    )
    .into_rpc();

    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let _handle = server.start(module);
    let client = WsClientBuilder::default()
        .build(format!("ws://{addr}"))
        .await
        .unwrap();

    let mut subscription = client.subscribe_events().await.unwrap();
    // The server ends the subscription while the connection stays open; the client must see its
    // stream end so it can resubscribe.
    drop(events_tx);
    let next = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await
        .expect("client stream must end once the server closes the subscription");
    assert!(next.is_none(), "expected the stream to end, got {next:?}");
    assert!(client.is_connected());
}

#[tokio::test]
async fn subscriptions_are_capped_per_connection() {
    let (events_tx, _) = broadcast::channel(1);
    let module = TempoConsensusRpc::new(
        IdleFeed {
            events_tx: events_tx.clone(),
        },
        SubscriptionLimits::default(),
    )
    .into_rpc();

    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let _handle = server.start(module);
    let connect = || WsClientBuilder::default().build(format!("ws://{addr}"));

    let first = connect().await.unwrap();
    let mut held = Vec::new();
    for _ in 0..DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get() {
        held.push(first.subscribe_events().await.unwrap());
    }
    wait_for_live_subscriptions(&events_tx, DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get()).await;

    let jsonrpsee::core::client::Error::Call(err) = first
        .subscribe_events()
        .await
        .expect_err("subscription over the per-connection cap must be rejected")
    else {
        panic!("expected a JSON-RPC error");
    };
    assert_eq!(err.code(), TOO_MANY_SUBSCRIPTIONS_CODE);

    // Another connection still gets its own share.
    let second = connect().await.unwrap();
    let _other = second.subscribe_events().await.unwrap();
    wait_for_live_subscriptions(
        &events_tx,
        DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get() + 1,
    )
    .await;

    // Ending one subscription frees a slot on the first connection.
    held.pop().unwrap().unsubscribe().await.unwrap();
    wait_for_live_subscriptions(&events_tx, DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get()).await;
    let _again = first.subscribe_events().await.unwrap();
}

#[tokio::test]
async fn handler_without_connection_cap_allows_more_per_connection() {
    let (events_tx, _) = broadcast::channel(1);
    let module = TempoConsensusRpc::new(
        IdleFeed {
            events_tx: events_tx.clone(),
        },
        SubscriptionLimits::default(),
    )
    .without_connection_cap()
    .into_rpc();

    // In-process subscriptions all share one connection ID.
    let mut held = Vec::new();
    for _ in 0..=DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get() {
        held.push(
            module
                .subscribe_unbounded("consensus_subscribe", EmptyServerParams::new())
                .await
                .unwrap(),
        );
    }
    wait_for_live_subscriptions(
        &events_tx,
        DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get() + 1,
    )
    .await;
}

/// A feed whose height lookups never finish, modelling a marshal stuck behind a long queue.
/// `started` counts lookups that reached the feed and `dropped` those whose future was dropped.
#[derive(Clone, Default)]
struct StalledFeed {
    started: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

/// Counts a dropped lookup future.
struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl ConsensusFeed for StalledFeed {
    async fn get_finalization(&self, query: Query) -> types::Response<CertifiedBlock> {
        if matches!(query, Query::Latest) {
            return types::Response::NotReady;
        }
        let _guard = DropCounter(self.dropped.clone());
        self.started.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }

    async fn get_latest(&self) -> ConsensusState {
        ConsensusState::default()
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Arc<SharedEvent>>> {
        None
    }
}

async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while counter.load(Ordering::SeqCst) != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {expected}, found {}",
            counter.load(Ordering::SeqCst)
        )
    });
}

fn expect_rpc_error(err: jsonrpsee::core::server::MethodsError) -> ErrorObject<'static> {
    let jsonrpsee::core::server::MethodsError::JsonRpc(err) = err else {
        panic!("expected a JSON-RPC error, got {err:?}");
    };
    err
}

#[tokio::test]
async fn height_lookups_are_rejected_as_busy_once_limit_is_reached() {
    let feed = StalledFeed::default();
    let rpc = TempoConsensusRpc::new(feed.clone(), SubscriptionLimits::default());
    let module = rpc.clone().into_rpc();
    // IPC's handler shares the cap with HTTP and WS.
    let ipc_module = rpc.without_connection_cap().into_rpc();

    let held: Vec<_> = (0..MAX_CONCURRENT_LOOKUPS as u64)
        .map(|height| {
            let module = module.clone();
            tokio::spawn(async move {
                module
                    .call::<_, CertifiedBlock>(
                        "consensus_getFinalization",
                        (Query::Height(height),),
                    )
                    .await
            })
        })
        .collect();
    wait_for_count(&feed.started, MAX_CONCURRENT_LOOKUPS).await;

    for module in [&module, &ipc_module] {
        let err = module
            .call::<_, CertifiedBlock>("consensus_getFinalization", (Query::Height(0),))
            .await
            .expect_err("lookup over the cap must be rejected");
        assert_eq!(expect_rpc_error(err).code(), SERVER_IS_BUSY_CODE);
    }
    assert_eq!(feed.started.load(Ordering::SeqCst), MAX_CONCURRENT_LOOKUPS);

    // `Latest` does not reach the marshal and is not capped.
    let err = module
        .call::<_, CertifiedBlock>("consensus_getFinalization", (Query::Latest,))
        .await
        .expect_err("idle feed has no latest finalization");
    assert_eq!(expect_rpc_error(err).code(), ErrorCode::NoContent as i32);

    for task in held {
        task.abort();
    }
}

#[tokio::test]
async fn timed_out_height_lookup_is_dropped_and_releases_its_permit() {
    let feed = StalledFeed::default();
    let rpc = TempoConsensusRpc::new(feed.clone(), SubscriptionLimits::default());
    let module = rpc.clone().into_rpc();

    let err = module
        .call::<_, CertifiedBlock>("consensus_getFinalization", (Query::Height(1),))
        .await
        .expect_err("stalled lookup must time out");
    let err = expect_rpc_error(err);
    assert_eq!(err.code(), ErrorCode::ServiceUnavailable as i32);
    assert_eq!(
        err.data().map(|data| data.get()),
        Some(r#""lookup timed out""#)
    );
    // Dropping the lookup closes the marshal's response channel, so a queued request is discarded.
    assert_eq!(feed.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(rpc.lookups.available_permits(), MAX_CONCURRENT_LOOKUPS);
}
