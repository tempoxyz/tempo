use super::*;
use alloy_primitives::B256;
use jsonrpsee::{
    core::EmptyServerParams,
    server::{Server, ServerConfig},
    ws_client::WsClientBuilder,
};
use reth_primitives_traits::SealedBlock;
use std::{sync::Arc, time::Duration};
use tempo_primitives::Block;
use tokio::sync::broadcast;

/// A feed with no publisher of its own, modelling a node whose finalization has stalled.
/// Tests that need events send them on `events_tx` directly.
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
    let module = TempoConsensusRpc::new(IdleFeed {
        events_tx: events_tx.clone(),
    })
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
    let module = TempoConsensusRpc::new(IdleFeed {
        events_tx: events_tx.clone(),
    })
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
    let module = TempoConsensusRpc::new(IdleFeed {
        events_tx: events_tx.clone(),
    })
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
    let module = TempoConsensusRpc::with_max_subscriptions(
        IdleFeed {
            events_tx: events_tx.clone(),
        },
        1,
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
    let module = TempoConsensusRpc::new(IdleFeed {
        events_tx: events_tx.clone(),
    })
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
    let module = TempoConsensusRpc::new(ClosingFeed {
        rx: std::sync::Mutex::new(Some(events_rx)),
    })
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
    let module = TempoConsensusRpc::new(IdleFeed {
        events_tx: events_tx.clone(),
    })
    .into_rpc();

    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let _handle = server.start(module);
    let connect = || WsClientBuilder::default().build(format!("ws://{addr}"));

    let first = connect().await.unwrap();
    let mut held = Vec::new();
    for _ in 0..MAX_SUBSCRIPTIONS_PER_CONNECTION {
        held.push(first.subscribe_events().await.unwrap());
    }
    wait_for_live_subscriptions(&events_tx, MAX_SUBSCRIPTIONS_PER_CONNECTION).await;

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
    wait_for_live_subscriptions(&events_tx, MAX_SUBSCRIPTIONS_PER_CONNECTION + 1).await;

    // Ending one subscription frees a slot on the first connection.
    held.pop().unwrap().unsubscribe().await.unwrap();
    wait_for_live_subscriptions(&events_tx, MAX_SUBSCRIPTIONS_PER_CONNECTION).await;
    let _again = first.subscribe_events().await.unwrap();
}
