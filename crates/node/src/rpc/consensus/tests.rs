use super::*;
use alloy_primitives::B256;
use alloy_provider::RootProvider;
use alloy_rpc_client::{RpcClient, WsConnect};
use alloy_transport::TransportResult;
use jsonrpsee::{
    Methods,
    server::{Server, ServerConfig},
    types::{
        Response,
        response::{SubscriptionResponse, Success},
    },
};
use reth_primitives_traits::SealedBlock;
use std::{net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};
use tempo_alloy::TempoNetwork;
use tempo_primitives::Block;
use tokio::sync::broadcast;

async fn connect(addr: SocketAddr) -> RootProvider<TempoNetwork> {
    RootProvider::new(
        RpcClient::connect_pubsub(WsConnect::new(format!("ws://{addr}")))
            .await
            .unwrap(),
    )
}

/// Sends \`consensus_subscribe\` as a plain call and returns the server's subscription ID, so the
/// test can end it with \`consensus_unsubscribe\` (alloy only sends \`eth_unsubscribe\`).
async fn open_subscription(
    client: &RootProvider<TempoNetwork>,
) -> TransportResult<serde_json::Value> {
    client
        .client()
        .request_noparams("consensus_subscribe")
        .await
}

async fn close_subscription(client: &RootProvider<TempoNetwork>, id: serde_json::Value) {
    let closed: bool = client
        .client()
        .request("consensus_unsubscribe", (id,))
        .await
        .unwrap();
    assert!(closed);
}

async fn subscribe(
    module: &Methods,
) -> Result<tokio::sync::mpsc::Receiver<String>, jsonrpsee::types::ErrorObjectOwned> {
    let (response, receiver) = module
        .raw_json_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"consensus_subscribe","params":[]}"#,
            256,
        )
        .await
        .unwrap();
    Success::<serde_json::Value>::try_from(
        serde_json::from_str::<Response<'_, serde_json::Value>>(&response).unwrap(),
    )?;
    Ok(receiver)
}

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

    let subscription = subscribe(&module).await.unwrap();
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

    let client = connect(addr).await;

    let id = open_subscription(&client).await.unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;

    close_subscription(&client, id).await;
    wait_for_live_subscriptions(&events_tx, 0).await;

    // The only permit on this connection must be available again.
    let _id = open_subscription(&client).await.unwrap();
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

    let mut subscription = subscribe(&module).await.unwrap();
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

    let notification = subscription.recv().await.unwrap();
    let received = serde_json::from_str::<SubscriptionResponse<'_, Event>>(&notification)
        .unwrap()
        .params
        .result;
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

    let first = subscribe(&module).await.unwrap();
    wait_for_live_subscriptions(&events_tx, 1).await;

    let err = subscribe(&module)
        .await
        .expect_err("second subscription must be rejected");
    assert_eq!(err.code(), SERVER_IS_BUSY_CODE);
    assert_eq!(events_tx.receiver_count(), 1);

    // Dropping the live subscription frees its permit.
    drop(first);
    wait_for_live_subscriptions(&events_tx, 0).await;
    let _again = subscribe(&module).await.unwrap();
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
    let _subscription = subscribe(&module).await.unwrap();
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
async fn server_ended_subscription_sends_close_notification() {
    let (events_tx, events_rx) = broadcast::channel(1);
    let module = TempoConsensusRpc::new(
        ClosingFeed {
            rx: std::sync::Mutex::new(Some(events_rx)),
        },
        SubscriptionLimits::default(),
    )
    .into_rpc();

    let mut subscription = subscribe(&module).await.unwrap();
    // The server ends the subscription; the close notification tells the subscriber to resubscribe
    // and backfill.
    drop(events_tx);
    let notification = tokio::time::timeout(Duration::from_secs(5), subscription.recv())
        .await
        .expect("server must notify the subscriber once it closes the subscription")
        .expect("expected a close notification");
    let notification = serde_json::from_str::<serde_json::Value>(&notification).unwrap();
    assert_eq!(notification["params"]["error"], "consensus feed closed");
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
    let first = connect(addr).await;
    let mut held = Vec::new();
    for _ in 0..DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get() {
        held.push(open_subscription(&first).await.unwrap());
    }
    wait_for_live_subscriptions(&events_tx, DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get()).await;

    let err = open_subscription(&first)
        .await
        .expect_err("subscription over the per-connection cap must be rejected");
    assert_eq!(
        err.as_error_resp().expect("expected a JSON-RPC error").code,
        i64::from(TOO_MANY_SUBSCRIPTIONS_CODE)
    );

    // Another connection still gets its own share.
    let second = connect(addr).await;
    let _other = open_subscription(&second).await.unwrap();
    wait_for_live_subscriptions(
        &events_tx,
        DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get() + 1,
    )
    .await;

    // Ending one subscription frees a slot on the first connection.
    close_subscription(&first, held.pop().unwrap()).await;
    wait_for_live_subscriptions(&events_tx, DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get()).await;
    let _again = open_subscription(&first).await.unwrap();
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
        held.push(subscribe(&module).await.unwrap());
    }
    wait_for_live_subscriptions(
        &events_tx,
        DEFAULT_MAX_SUBSCRIPTIONS_PER_CONNECTION.get() + 1,
    )
    .await;
}
