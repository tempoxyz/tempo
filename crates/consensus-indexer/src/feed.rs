use eyre::WrapErr;
use jsonrpsee::ws_client::WsClientBuilder;
use std::time::Duration;
use tempo_node::rpc::consensus::{Event, TempoConsensusApiClient};
use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct ConsensusFeed {
    events_tx: broadcast::Sender<Event>,
}

impl ConsensusFeed {
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(1024);
        Self { events_tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events_tx.subscribe()
    }

    pub fn events_tx(&self) -> broadcast::Sender<Event> {
        self.events_tx.clone()
    }

    pub async fn run(self, ws_url: String, shutdown: watch::Receiver<bool>) -> eyre::Result<()> {
        let mut shutdown = shutdown;
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }

            match self.connect_and_stream(&ws_url, &mut shutdown).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    warn!(?err, "consensus websocket stream failed; reconnecting");
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                return Ok(());
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                    }
                }
            }
        }
    }

    async fn connect_and_stream(
        &self,
        ws_url: &str,
        shutdown: &mut watch::Receiver<bool>,
    ) -> eyre::Result<()> {
        let client = WsClientBuilder::default()
            .build(ws_url)
            .await
            .wrap_err("connect consensus ws")?;
        info!(%ws_url, "connected consensus ws");

        let mut subscription = client
            .subscribe_events()
            .await
            .wrap_err("subscribe events")?;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                }
                maybe_event = subscription.next() => {
                    let event = match maybe_event {
                        Some(Ok(event)) => event,
                        Some(Err(err)) => return Err(err.into()),
                        None => return Err(eyre::eyre!("subscription ended")),
                    };
                    let _ = self.events_tx.send(event);
                }
            }
        }
    }
}

impl Default for ConsensusFeed {
    fn default() -> Self {
        Self::new()
    }
}
