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
