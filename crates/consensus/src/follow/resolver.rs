//! Resolver for follow mode.
//!
//! Implements [`Resolver`] for marshal's gap-repair machinery. Checks the
//! local execution node first and falls back to the upstream abstraction.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::resolver::handler,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::Height,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_resolver::Consumer as _;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner, spawn_cell};
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
) -> (Resolver<TContext>, Mailbox, handler::Receiver<Digest>)
where
    TContext: commonware_runtime::Supervisor + Metrics,
{
    let mailbox_size = NonZeroUsize::new(config.mailbox_size)
        .expect("follow resolver mailbox size must be non-zero");
    let (handler_rx, handler_tx) = handler::init(context.child("handler"), mailbox_size);
    let (mailbox_tx, mailbox_rx) = mpsc::unbounded_channel();
    let actor = Resolver {
        context: ContextCell::new(context),
        config,
        mailbox: mailbox_rx,
        handler_tx,
        requests: Vec::new(),
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
    Fetch {
        keys: Vec<commonware_resolver::Fetch<handler::Key<Digest>, handler::Annotation>>,
    },

    /// Cancel a fetch request by key.
    Cancel { key: handler::Key<Digest> },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain {
        predicate: Predicate<(handler::Key<Digest>, handler::Annotation)>,
    },
}

pub(crate) struct Config {
    /// For reading blocks locally from the execution layer.
    pub(super) execution_node: Arc<TempoFullNode>,
    /// For reading blocks and certificates from the connected node.
    pub(super) upstream: super::upstream::Mailbox,
    pub(super) mailbox_size: usize,
}

type FetchPool = AbortablePool<(
    commonware_resolver::Fetch<handler::Key<Digest>, handler::Annotation>,
    u32,
    Result<Bytes, bool>,
)>;

pub(crate) struct Resolver<TContext> {
    context: ContextCell<TContext>,
    config: Config,
    /// To send messages to the application/actor relying on the resolver.
    handler_tx: handler::Handler<Digest>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    requests: Vec<((handler::Key<Digest>, handler::Annotation), Aborter)>,
    fetches: FetchPool,
}

impl<TContext> Resolver<TContext>
where
    TContext: Clock + Metrics + Spawner,
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
                            self.requests.retain(|((k, _), _)| *k != key);
                        }
                        Message::Clear => {
                            self.requests.clear();
                        }
                        Message::Retain { predicate } => {
                            self.requests.retain(move |((key, annotation), _)| {
                                predicate(&(key.clone(), annotation.clone()))
                            });
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
    fn handle_fetch_request(
        &mut self,
        keys: Vec<commonware_resolver::Fetch<handler::Key<Digest>, handler::Annotation>>,
    ) {
        for fetch in keys {
            self.schedule_request(fetch, 0);
        }
    }

    #[instrument(skip_all)]
    fn handle_fetch_resolution(
        &mut self,
        (fetch, attempt, resolution): (
            commonware_resolver::Fetch<handler::Key<Digest>, handler::Annotation>,
            u32,
            Result<Bytes, bool>,
        ),
    ) {
        let request = (fetch.key.clone(), fetch.subscriber);
        match resolution {
            Ok(value) => {
                debug!(?fetch.key, "fetched value, delivering to client");
                self.requests.retain(|(k, _)| *k != request);
                // Fire and forget; there is no mechanism to retry
                // sending the response.
                let _ = self.handler_tx.deliver(
                    commonware_resolver::Delivery {
                        key: fetch.key,
                        subscribers: NonEmptyVec::new((fetch.subscriber, fetch.span)),
                    },
                    value,
                );
            }
            Err(true) => {
                debug!(?fetch.key, attempt, "fetch failed, rescheduling");
                self.requests.retain(|(k, _)| *k != request);
                self.schedule_request(fetch, attempt.saturating_add(1));
            }
            Err(false) => {
                debug!(?fetch.key, "fetch failed permanently, dropping");
                self.requests.retain(|(k, _)| *k != request);
            }
        }
    }

    fn schedule_request(
        &mut self,
        fetch: commonware_resolver::Fetch<handler::Key<Digest>, handler::Annotation>,
        attempt: u32,
    ) {
        let request = (fetch.key.clone(), fetch.subscriber);
        if !self.requests.iter().any(|(k, _)| *k == request) {
            let delay = retry_delay(attempt);
            let aborter = match fetch.key {
                handler::Key::Block(digest) => {
                    let execution_node = self.config.execution_node.clone();
                    let upstream = self.config.upstream.clone();
                    let fetch = fetch.clone();
                    self.fetches.push(async move {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }

                        let response = resolve_block(&execution_node, upstream, digest).await;
                        (fetch, attempt, response)
                    })
                }
                handler::Key::Finalized { height } => {
                    let upstream = self.config.upstream.clone();
                    let fetch = fetch.clone();
                    self.fetches.push(async move {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        let response = resolve_finalized(upstream, height).await;
                        (fetch, attempt, response)
                    })
                }
                handler::Key::Notarized { .. } => {
                    debug!("ignoring requests for notarized blocks");
                    return;
                }
            };
            debug!(?fetch.key, attempt, ?delay, "scheduled new request");
            self.requests.push((request, aborter));
        } else {
            debug!(?fetch.key, "request already scheduled");
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
    type Key = handler::Key<Digest>;
    type Subscriber = handler::Annotation;

    fn fetch<F>(&mut self, key: F) -> Feedback
    where
        F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.fetch_all(vec![key])
    }

    fn fetch_all<F>(&mut self, keys: Vec<F>) -> Feedback
    where
        F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let keys = keys.into_iter().map(|fetch| fetch.into()).collect();
        if self.inner.send_lossy(Message::Fetch { keys }) {
            Feedback::Ok
        } else {
            Feedback::Closed
        }
    }

    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        if self.inner.send_lossy(Message::Retain {
            predicate: Box::new(move |(key, subscriber)| predicate(key, subscriber)),
        }) {
            Feedback::Ok
        } else {
            Feedback::Closed
        }
    }
}

impl commonware_resolver::TargetedResolver for Mailbox {
    type PublicKey = PublicKey;

    fn fetch_targeted(
        &mut self,
        fetch: impl Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        <Self as commonware_resolver::Resolver>::fetch(self, fetch)
    }

    fn fetch_all_targeted<F>(
        &mut self,
        requests: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
    ) -> Feedback
    where
        F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        <Self as commonware_resolver::Resolver>::fetch_all(
            self,
            requests.into_iter().map(|(fetch, _)| fetch).collect(),
        )
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
