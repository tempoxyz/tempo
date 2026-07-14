//! Resolver for follow mode.
//!
//! Implements [`Resolver`] for marshal's gap-repair machinery. Checks the
//! local execution node first and falls back to the upstream abstraction.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use bytes::Bytes;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::resolver::handler,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::Height,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{Clock, ContextCell, Spawner, spawn_cell};
use commonware_utils::{
    channel::{fallible::FallibleExt as _, mpsc},
    futures::{AbortablePool, Aborter},
    vec::NonEmptyVec,
};
use eyre::Report;
use reth_provider::{BlockReader as _, BlockSource};
use tempo_node::TempoFullNode;
use tokio::select;
use tracing::{debug, error, instrument, warn};

use crate::consensus::{Block, Digest};

const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

fn retry_delay(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }

    let multiplier = 2u32.saturating_pow(attempt.saturating_sub(1));
    INITIAL_RETRY_DELAY
        .saturating_mul(multiplier)
        .min(MAX_RETRY_DELAY)
}

pub(crate) fn try_init<TContext>(
    context: TContext,
    config: Config,
) -> (
    Resolver<TContext>,
    Mailbox,
    mpsc::Receiver<handler::Message<Digest>>,
) {
    let (handler_tx, handler_rx) = mpsc::channel(config.mailbox_size);
    let (mailbox_tx, mailbox_rx) = mpsc::unbounded_channel();
    let actor = Resolver {
        context: ContextCell::new(context),
        config,
        mailbox: mailbox_rx,
        handler_tx,
        requests: BTreeMap::new(),
        fetches: AbortablePool::default(),
    };
    let mailbox = Mailbox { inner: mailbox_tx };
    (actor, mailbox, handler_rx)
}

#[derive(Clone)]
pub(crate) struct Mailbox {
    // FIXME: This should probably not be an unbounded channel - but how do
    // we exert backpressure?
    inner: mpsc::UnboundedSender<Message>,
}

type Predicate<K> = Box<dyn Fn(&K) -> bool + Send>;

/// Messages sent to the resolver.
enum Message {
    /// Initiate fetch requests.
    Fetch { keys: Vec<handler::Request<Digest>> },

    /// Cancel a fetch request by key.
    Cancel { key: handler::Request<Digest> },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain {
        predicate: Predicate<handler::Request<Digest>>,
    },
}

pub(crate) struct Config {
    /// For reading blocks locally from the execution layer.
    pub(super) execution_node: Arc<TempoFullNode>,
    /// For reading blocks and certificates from the connected node.
    pub(super) upstream: super::upstream::Mailbox,
    pub(super) mailbox_size: usize,
}

type FetchPool = AbortablePool<(handler::Request<Digest>, u32, Result<Bytes, bool>)>;

pub(crate) struct Resolver<TContext> {
    context: ContextCell<TContext>,
    config: Config,
    /// To send messages to the application/actor relying on the resolver.
    handler_tx: mpsc::Sender<handler::Message<Digest>>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    requests: BTreeMap<handler::Request<Digest>, Aborter>,
    fetches: FetchPool,
}

impl<TContext> Resolver<TContext>
where
    TContext: Clock + Spawner,
{
    async fn run(mut self) {
        loop {
            select!(
                biased;

                response = self.fetches.next_completed() => {
                    // Error case is aborting the future, no need to track.
                    if let Ok(resolution) = response {
                        self.handle_fetch_resolution(resolution);
                    }
                }

                Some(msg) = self.mailbox.recv() => {
                    match msg {
                        Message::Fetch { keys } => {
                            self.handle_fetch_request(keys);
                        }
                        Message::Cancel { key } => {
                            self.requests.remove(&key);
                        }
                        Message::Clear => {
                            self.requests.clear();
                        }
                        Message::Retain { predicate } => {
                            self.requests.retain(move |key, _| predicate(key));
                        }
                    }
                }
            )
        }
    }

    pub(crate) fn start(mut self) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    #[instrument(skip_all)]
    fn handle_fetch_request(&mut self, keys: Vec<handler::Request<Digest>>) {
        for key in keys {
            self.schedule_request(key, 0);
        }
    }

    #[instrument(skip_all)]
    fn handle_fetch_resolution(
        &mut self,
        (key, attempt, resolution): (handler::Request<Digest>, u32, Result<Bytes, bool>),
    ) {
        match resolution {
            Ok(value) => {
                debug!(%key, "fetched value, delivering to client");
                self.requests.remove(&key);
                // Fire and forget; there is no mechanism to retry
                // sending the response.
                let (response, _) = commonware_utils::channel::oneshot::channel();
                let _ = self.handler_tx.try_send(handler::Message::Deliver {
                    key,
                    value,
                    response,
                });
            }
            Err(true) => {
                debug!(%key, attempt, "fetch failed, rescheduling");
                self.requests.remove(&key);
                self.schedule_request(key, attempt.saturating_add(1));
            }
            Err(false) => {
                debug!(%key, "fetch failed permanently, dropping");
                self.requests.remove(&key);
            }
        }
    }

    fn schedule_request(&mut self, key: handler::Request<Digest>, attempt: u32) {
        if !self.requests.contains_key(&key) {
            let delay = retry_delay(attempt);
            let aborter = match &key {
                handler::Request::Block(digest) => {
                    let context = self.context.clone();
                    let execution_node = self.config.execution_node.clone();
                    let upstream = self.config.upstream.clone();
                    let digest = *digest;
                    let key = key.clone();
                    self.fetches.push(async move {
                        if !delay.is_zero() {
                            context.sleep(delay).await;
                        }

                        let response = resolve_block(&execution_node, upstream, digest).await;
                        (key, attempt, response)
                    })
                }
                handler::Request::Finalized { height } => {
                    let context = self.context.clone();
                    let upstream = self.config.upstream.clone();
                    let height = *height;
                    let key = key.clone();
                    self.fetches.push(async move {
                        if !delay.is_zero() {
                            context.sleep(delay).await;
                        }
                        let response = resolve_finalized(upstream, height).await;
                        (key, attempt, response)
                    })
                }
                handler::Request::Notarized { .. } => {
                    debug!("ignoring requests for notarized blocks");
                    return;
                }
            };
            debug!(%key, attempt, ?delay, "scheduled new request");
            self.requests.insert(key, aborter);
        } else {
            debug!(%key, "request already scheduled");
        }
    }
}

/// Resolves an encoded block from the execution layer, falling back to the upstream node.
#[instrument(skip(execution_node, upstream))]
async fn resolve_block(
    execution_node: &TempoFullNode,
    upstream: super::upstream::Mailbox,
    block_digest: Digest,
) -> Result<Bytes, bool> {
    match execution_node
        .provider
        .find_sealed_or_recovered_block(block_digest.0, BlockSource::Any)
        .map_err(Report::new)
        .inspect_err(|error| error!(%error, "execution layer error looking up block"))
    {
        Err(_) => Err(true),
        Ok(Some(block)) => {
            let consensus_block = Block::from_execution_block_unchecked(block, None);
            Ok(consensus_block.encode())
        }
        Ok(None) => {
            let Some(block) = upstream.get_block(block_digest).await else {
                return Err(true);
            };

            Ok(block.encode())
        }
    }
}

/// Resolves a finalization (cert + block) by height from the upstream node.
#[instrument(skip_all, fields(%height))]
async fn resolve_finalized(
    upstream: super::upstream::Mailbox,
    height: Height,
) -> Result<Bytes, bool> {
    let certified_block = match upstream.get_finalization(height).await {
        Some(certified_block) => certified_block,
        None => return Err(true),
    };

    let Ok(finalization) = alloy_primitives::hex::decode(&certified_block.certificate)
        .map_err(Report::new)
        .and_then(|bytes| {
            <Finalization<Scheme<PublicKey, MinSig>, Digest>>::decode(&*bytes).map_err(Report::new)
        })
        .inspect_err(|error| warn!(%error, "failed decoding certificate"))
    else {
        return Err(false);
    };

    // Upstream finalization responses carry persisted EL blocks only; no p2p BAL
    // is available when reconstructing this consensus block.
    let consensus_block = Block::from_execution_block_unchecked(certified_block.block, None);
    Ok((finalization, consensus_block).encode())
}

impl commonware_resolver::Resolver for Mailbox {
    type Key = handler::Request<Digest>;
    type PublicKey = PublicKey;

    async fn fetch(&mut self, key: Self::Key) {
        self.fetch_all(vec![key]).await;
    }

    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        self.inner.send_lossy(Message::Fetch { keys });
    }

    async fn fetch_targeted(&mut self, key: Self::Key, _targets: NonEmptyVec<Self::PublicKey>) {
        self.fetch(key).await;
    }

    async fn fetch_all_targeted(
        &mut self,
        requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
    ) {
        self.fetch_all(requests.into_iter().map(|(k, _)| k).collect())
            .await;
    }

    async fn cancel(&mut self, key: Self::Key) {
        self.inner.send_lossy(Message::Cancel { key });
    }

    async fn clear(&mut self) {
        self.inner.send_lossy(Message::Clear);
    }

    async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
        self.inner.send_lossy(Message::Retain {
            predicate: Box::new(predicate),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_RETRY_DELAY, retry_delay};
    use std::time::Duration;

    #[test]
    fn retry_delay_grows_exponentially_and_caps() {
        assert_eq!(retry_delay(0), Duration::ZERO);
        assert_eq!(retry_delay(1), Duration::from_millis(250));
        assert_eq!(retry_delay(2), Duration::from_millis(500));
        assert_eq!(retry_delay(3), Duration::from_secs(1));
        assert_eq!(retry_delay(7), Duration::from_secs(16));
        assert_eq!(retry_delay(8), MAX_RETRY_DELAY);
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY_DELAY);
    }
}
