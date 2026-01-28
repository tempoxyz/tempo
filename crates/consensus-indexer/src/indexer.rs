use eyre::WrapErr;
use futures::future::try_join_all;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder};
use tempo_node::rpc::consensus::{CertifiedBlock, Event, Query, TempoConsensusApiClient};
use tokio::sync::{broadcast, watch};
use tracing::{debug, warn};

use crate::{db::ConsensusDb, identity, state::ConsensusCache};

#[derive(Clone, Debug)]
pub struct ConsensusIndexer {
    db: ConsensusDb,
    http_url: String,
    cache: ConsensusCache,
}

impl ConsensusIndexer {
    pub fn new(db: ConsensusDb, http_url: String, cache: ConsensusCache) -> Self {
        Self {
            db,
            http_url,
            cache,
        }
    }

    pub async fn seed_cache(&self) -> eyre::Result<()> {
        let client = self.http_client()?;
        let latest = client.get_latest().await.wrap_err("fetch latest")?;
        if let Some(finalized) = latest.finalized.clone() {
            self.verify_finalization(&client, &finalized).await?;
            self.cache.update_finalized(finalized).await;
        }
        if let Some(notarized) = latest.notarized.clone() {
            self.cache.update_notarized(notarized).await;
        }
        Ok(())
    }

    pub async fn fill_gaps(&self) -> eyre::Result<()> {
        let client = self.http_client()?;
        let latest = client.get_latest().await.wrap_err("fetch latest")?;
        let Some(finalized) = latest.finalized else {
            tracing::info!("no finalized block available; skipping gap fill");
            return Ok(());
        };
        let Some(latest_height) = finalized.height else {
            tracing::info!("latest finalized block missing height; skipping gap fill");
            return Ok(());
        };
        let start_height = self
            .db
            .latest_finalized_height()
            .await?
            .map(|height| height + 1)
            .unwrap_or(1);

        if start_height > latest_height {
            return Ok(());
        }

        tracing::info!(start_height, latest_height, "filling finalized height gaps");
        let mut processed = 0u64;
        let mut height = start_height;
        while height <= latest_height {
            let end = (height + 499).min(latest_height);
            debug!(height, end, "gap fill batch start");
            let mut batch = jsonrpsee::core::params::BatchRequestBuilder::new();
            for h in height..=end {
                batch
                    .insert(
                        "consensus_getFinalization",
                        jsonrpsee::rpc_params![Query::Height(h)],
                    )
                    .wrap_err("build batch request")?;
            }
            let responses = client
                .batch_request::<Option<CertifiedBlock>>(batch)
                .await
                .wrap_err("fetch finalization batch")?;
            debug!(
                height,
                end,
                response_count = responses.len(),
                "gap fill batch fetched"
            );
            let blocks: Vec<CertifiedBlock> = responses
                .into_iter()
                .filter_map(|response| response.ok().flatten())
                .collect();
            if !blocks.is_empty() {
                try_join_all(
                    blocks
                        .iter()
                        .map(|block| self.verify_finalization(&client, block)),
                )
                .await?;
                for block in blocks {
                    self.db.upsert_finalized_block(&block, now_millis()).await?;
                    self.cache.update_finalized(block).await;
                }
            }
            processed += end - height + 1;
            debug!(processed, latest_height, "gap fill batch stored");
            if processed.is_multiple_of(10_000) {
                tracing::info!(processed, latest_height, "gap fill progress");
            }
            height = end + 1;
        }
        tracing::info!(processed, "gap fill complete");
        Ok(())
    }

    pub async fn run(
        &self,
        mut events: broadcast::Receiver<Event>,
        shutdown: watch::Receiver<bool>,
    ) -> eyre::Result<()> {
        let mut shutdown = shutdown;
        let client = self.http_client()?;
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                }
                event = events.recv() => {
                    match event {
                        Ok(event) => {
                            if let Err(err) = self.handle_event(&client, &event).await {
                                warn!(?err, "failed to handle consensus event");
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
            }
        }
    }

    async fn handle_event(
        &self,
        client: &jsonrpsee::http_client::HttpClient,
        event: &Event,
    ) -> eyre::Result<()> {
        tracing::debug!(?event, "consensus event");
        match event {
            Event::Notarized { block, .. } => {
                self.cache.update_notarized(block.clone()).await;
            }
            Event::Finalized { block, seen } => {
                let mut updated_block = block.clone();
                if updated_block.height.is_none() {
                    let fetched = client.get_finalization(Query::Latest).await?;
                    if let Some(fetched) = fetched
                        && fetched.digest == block.digest
                    {
                        updated_block.height = fetched.height;
                    }
                }
                self.verify_finalization(client, &updated_block).await?;
                self.db
                    .upsert_finalized_block(&updated_block, *seen)
                    .await?;
                self.cache.update_finalized(updated_block.clone()).await;
                if let Err(err) = self.fill_gaps().await {
                    debug!(?err, "failed to fill gaps");
                }

                if let Some(height) = updated_block.height {
                    let _ = sqlx::query(
                        r#"
                        UPDATE certified_blocks
                        SET height = ?1
                        WHERE digest = ?2;
                        "#,
                    )
                    .bind(height as i64)
                    .bind(updated_block.digest.as_slice())
                    .execute(self.db.pool())
                    .await;
                }

                if let Err(err) = identity::refresh_identity_transitions(&self.db, client).await {
                    debug!(?err, "failed to refresh identity transitions");
                }
            }
            Event::Nullified { epoch, view, seen } => {
                self.db.insert_nullification(*epoch, *view, *seen).await?;
            }
        }
        Ok(())
    }

    async fn verify_finalization(
        &self,
        client: &jsonrpsee::http_client::HttpClient,
        block: &CertifiedBlock,
    ) -> eyre::Result<()> {
        let response = client
            .get_identity_transition_proof(Some(block.epoch), Some(true))
            .await
            .wrap_err("fetch identity transitions for verification")?;
        match identity::verify_finalization(block, &response.identity) {
            Ok(()) => Ok(()),
            Err(primary) => {
                let fallback_identity = response
                    .transitions
                    .first()
                    .map(|transition| transition.old_identity.as_str());
                if let Some(fallback_identity) = fallback_identity {
                    identity::verify_finalization(block, fallback_identity).map_err(
                        |fallback| {
                            eyre::eyre!("{primary}; fallback verification failed with {fallback}")
                        },
                    )?;
                    Ok(())
                } else {
                    Err(primary.into())
                }
            }
        }
    }

    fn http_client(&self) -> eyre::Result<jsonrpsee::http_client::HttpClient> {
        HttpClientBuilder::default()
            .build(&self.http_url)
            .wrap_err("build consensus http client")
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
