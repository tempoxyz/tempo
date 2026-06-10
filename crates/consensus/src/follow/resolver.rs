//! Resolver for follow mode.
//!
//! Implements [`Resolver`] for marshal's gap-repair machinery. Checks the
//! local execution node first and falls back to the upstream abstraction.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::Arc,
};

use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::resolver::handler::{self, Annotation, Key},
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::Height,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_resolver::{Consumer as _, Delivery, Fetch};
use commonware_runtime::{ContextCell, Metrics, Spawner, spawn_cell};
use commonware_utils::{
    channel::{fallible::FallibleExt as _, mpsc},
    futures::{AbortablePool, Aborter, Pool},
    vec::NonEmptyVec,
};
use eyre::Report;
use reth_provider::{BlockReader as _, BlockSource};
use tempo_node::TempoFullNode;
use tokio::select;
use tracing::{debug, error, instrument, warn};

use crate::consensus::{Digest, block::Block};

pub(crate) fn try_init<TContext>(
    context: TContext,
    config: Config,
) -> (Resolver<TContext>, Mailbox, handler::Receiver<Digest>)
where
    TContext: Metrics,
{
    let (mailbox_tx, mailbox_rx) = mpsc::unbounded_channel();
    let (handler_rx, handler) = handler::init(context.child("handler"), config.mailbox_size);

    let actor = Resolver {
        context: ContextCell::new(context),
        config,
        mailbox: mailbox_rx,
        handler,
        requests: BTreeMap::new(),
        fetches: AbortablePool::default(),
        deliveries: Pool::default(),
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

type ResolverFetch = Fetch<Key<Digest>, Annotation>;
type RetainPredicate = dyn Fn(&Key<Digest>, &Annotation) -> bool + Send;

/// Messages sent to the resolver.
enum Message {
    /// Initiate fetch requests.
    Fetch { keys: Vec<ResolverFetch> },

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain { predicate: Box<RetainPredicate> },
}

pub(crate) struct Config {
    /// For reading blocks locally from the execution layer.
    pub(super) execution_node: Arc<TempoFullNode>,
    /// For reading blocks and certificates from the connected node.
    pub(super) upstream: super::upstream::Mailbox,
    pub(super) mailbox_size: NonZeroUsize,
}

struct PendingRequest {
    subscribers: BTreeSet<Annotation>,
    _aborter: Aborter,
}

pub(crate) struct Resolver<TContext> {
    context: ContextCell<TContext>,
    config: Config,
    /// To send messages to the application/actor relying on the resolver.
    handler: handler::Handler<Digest>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    requests: BTreeMap<Key<Digest>, PendingRequest>,
    fetches: AbortablePool<(Key<Digest>, Result<Bytes, bool>)>,
    deliveries: Pool<(Key<Digest>, bool)>,
}

impl<TContext> Resolver<TContext>
where
    TContext: Spawner,
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

                delivery = self.deliveries.next_completed() => {
                    let (key, valid) = delivery;
                    if !valid {
                        debug!(%key, "delivered fetched value was rejected or canceled");
                    }
                }

                Some(msg) = self.mailbox.recv() => {
                    match msg {
                        Message::Fetch { keys, } => {
                            self.handle_fetch_request(keys);
                        }
                        Message::Retain { predicate } => {
                            self.requests.retain(|key, request| {
                                request
                                    .subscribers
                                    .retain(|subscriber| predicate(key, subscriber));
                                !request.subscribers.is_empty()
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
    fn handle_fetch_request(&mut self, fetches: Vec<ResolverFetch>) {
        for fetch in fetches {
            self.schedule_request(fetch);
        }
    }

    #[instrument(skip_all)]
    fn handle_fetch_resolution(&mut self, (key, resolution): (Key<Digest>, Result<Bytes, bool>)) {
        let Some(request) = self.requests.remove(&key) else {
            return;
        };

        match resolution {
            Ok(value) => {
                debug!(%key, "fetched value, delivering to client");
                let subscribers =
                    NonEmptyVec::from_unchecked(request.subscribers.into_iter().collect());

                // Keep the receiver alive until marshal validates the delivery;
                // otherwise the handler treats the response as canceled.
                let receiver = self.handler.deliver(Delivery { key, subscribers }, value);
                self.deliveries.push(async move {
                    let valid = receiver.await.unwrap_or(false);
                    (key, valid)
                });
            }
            Err(true) => {
                debug!(%key, "fetch failed, rescheduling");
                for subscriber in request.subscribers {
                    self.schedule_request(Fetch { key, subscriber });
                }
            }
            Err(false) => {
                debug!(%key, "fetch failed, dropping");
            }
        }
    }

    fn schedule_request(&mut self, fetch: ResolverFetch) {
        let Fetch { key, subscriber } = fetch;
        if !self.requests.contains_key(&key) {
            let aborter = match &key {
                Key::Block(digest) => {
                    let execution_node = self.config.execution_node.clone();
                    let digest = *digest;
                    self.fetches.push(async move {
                        let response = resolve_block(&execution_node, digest);
                        (key, response)
                    })
                }
                Key::Finalized { height } => {
                    let upstream = self.config.upstream.clone();
                    let height = *height;
                    self.fetches.push(async move {
                        let response = resolve_finalized_new(upstream, height).await;
                        (key, response)
                    })
                }
                Key::Notarized { .. } => {
                    debug!("ignoring requests for notarized blocks");
                    return;
                }
            };
            debug!(%key, "scheduled new request");
            self.requests.insert(
                key,
                PendingRequest {
                    subscribers: BTreeSet::from([subscriber]),
                    _aborter: aborter,
                },
            );
        } else {
            self.requests
                .get_mut(&key)
                .expect("checked above")
                .subscribers
                .insert(subscriber);
            debug!(%key, "request already scheduled");
        }
    }
}

/// Resolves an encoded block from the local execution layer.
#[instrument(skip(execution_node))]
fn resolve_block(execution_node: &TempoFullNode, block_digest: Digest) -> Result<Bytes, bool> {
    let Ok(Some(block)) = execution_node
        .provider
        .find_sealed_or_recovered_block(block_digest.0, BlockSource::Any)
        .map_err(Report::new)
        .inspect_err(
            |error| error!(%error, "unable to communicate with execution layer to lookup block"),
        )
    else {
        return Err(false);
    };
    // Follow-mode recovery reads from the EL database, which persists only the block.
    // BAL is p2p side data, so it is unavailable here.
    let consensus_block = Block::from_execution_block_unchecked(block, None);
    Ok(consensus_block.encode())
}

/// Resolves a request for a finalized.
#[instrument(skip_all, fields(%height))]
async fn resolve_finalized_new(
    upstream: super::upstream::Mailbox,
    height: Height,
) -> Result<Bytes, bool> {
    let certified_block = match upstream.get_finalization(height).await {
        Some(certified_block) => certified_block,
        None => return Err(false),
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
    type Key = Key<Digest>;
    type Subscriber = Annotation;

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
        self.inner.send_lossy(Message::Fetch {
            keys: keys.into_iter().map(Into::into).collect(),
        });
        Feedback::Ok
    }

    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        self.inner.send_lossy(Message::Retain {
            predicate: Box::new(predicate),
        });
        Feedback::Ok
    }
}

impl commonware_resolver::TargetedResolver for Mailbox {
    type PublicKey = PublicKey;

    fn fetch_targeted(
        &mut self,
        key: impl Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        <Self as commonware_resolver::Resolver>::fetch(self, key)
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
            requests.into_iter().map(|(key, _)| key).collect(),
        )
    }
}
