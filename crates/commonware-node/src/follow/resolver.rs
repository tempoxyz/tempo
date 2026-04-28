//! Resolver for follow mode.
//!
//! Implements [`Resolver`] for marshal's gap-repair machinery. Checks the
//! local execution node first and falls back to the upstream abstraction.

use std::{collections::BTreeMap, sync::Arc};

use bytes::Bytes;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::resolver::handler,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::Height,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{ContextCell, Spawner, spawn_cell};
use commonware_utils::{
    channel::{fallible::FallibleExt as _, mpsc},
    futures::{AbortablePool, Aborter},
    vec::NonEmptyVec,
};
use reth_node_core::primitives::SealedBlock;
use reth_provider::{BlockReader as _, BlockSource};
use tempo_node::{TempoFullNode, rpc::consensus::Query};
use tokio::select;
use tracing::{debug, error, instrument, warn};

use super::upstream::UpstreamNode;
use crate::consensus::{Digest, block::Block};

pub(crate) fn try_init<TContext, TUpstream>(
    context: TContext,
    config: Config<TUpstream>,
) -> (
    Resolver<TContext, TUpstream>,
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
        predicate: Box<dyn Fn(&handler::Request<Digest>) -> bool + Send>,
    },
}

pub(crate) struct Config<TUpstream> {
    /// For reading blocks locally from the execution layer.
    pub(crate) execution_node: Arc<TempoFullNode>,
    /// For reading blocks and certificates from the connected node.
    pub(crate) upstream: TUpstream,
    pub(crate) mailbox_size: usize,
}

pub(crate) struct Resolver<TContext, TUpstream> {
    context: ContextCell<TContext>,
    config: Config<TUpstream>,
    /// To send messages to the application/actor relying on the resolver.
    handler_tx: mpsc::Sender<handler::Message<Digest>>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    requests: BTreeMap<handler::Request<Digest>, Aborter>,
    fetches: AbortablePool<Result<(handler::Request<Digest>, Bytes), handler::Request<Digest>>>,
}

impl<TContext, TUpstream> Resolver<TContext, TUpstream>
where
    TContext: Spawner,
    TUpstream: UpstreamNode,
{
    async fn run(mut self) {
        loop {
            select!(
                biased;

                response = self.fetches.next_completed() => {
                    match response {
                        Ok(resolution) => self.handle_fetch_resolution(resolution),
                        // We abort futures by dropping their handles; no need
                        // to track this.
                        Err(futures::future::Aborted) => {}
                    }
                }

                Some(msg) = self.mailbox.recv() => {
                    match msg {
                        Message::Fetch { keys, } => {
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
        spawn_cell!(self.context, self.run().await)
    }

    #[instrument(skip_all)]
    fn handle_fetch_request(&mut self, keys: Vec<handler::Request<Digest>>) {
        for key in keys {
            if !self.requests.contains_key(&key) {
                let aborter = match &key {
                    handler::Request::Block(digest) => {
                        let execution_node = self.config.execution_node.clone();
                        let digest = *digest;
                        let key = key.clone();
                        self.fetches.push(async move {
                            resolve_block(&execution_node, digest)
                                .ok_or(key.clone())
                                .map(move |response| (key, response))
                        })
                    }
                    handler::Request::Finalized { height } => {
                        let upstream = self.config.upstream.clone();
                        let height = *height;
                        let key = key.clone();
                        self.fetches.push(async move {
                            resolve_finalized(&upstream, height)
                                .await
                                .ok_or(key.clone())
                                .map(move |response| (key, response))
                        })
                    }
                    handler::Request::Notarized { .. } => {
                        debug!("ignoring requests for notarized blocks");
                        continue;
                    }
                };
                debug!(%key, "scheduled new request");
                self.requests.insert(key, aborter);
            } else {
                debug!(%key, "request already scheduled");
            }
        }
    }

    #[instrument(skip_all)]
    fn handle_fetch_resolution(
        &mut self,
        resolution: Result<(handler::Request<Digest>, Bytes), handler::Request<Digest>>,
    ) {
        match resolution {
            Ok((key, value)) => {
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
            Err(key) => {
                debug!(%key, "fetch failed, dropping");
                self.requests.remove(&key);
            }
        }
    }
}

#[instrument(skip(execution_node))]
fn resolve_block(execution_node: &TempoFullNode, block_digest: Digest) -> Option<Bytes> {
    let block = execution_node
        .provider
        .find_block_by_hash(block_digest.0, BlockSource::Any)
        .map_err(eyre::Report::new)
        .inspect_err(
            |error| error!(%error, "unable to communicate with execution layer to lookup block"),
        )
        .ok()??;
    let consensus_block = Block::from_execution_block(SealedBlock::seal_slow(block));
    Some(consensus_block.encode())
}

#[instrument(skip(upstream_node))]
async fn resolve_finalized(upstream_node: &impl UpstreamNode, height: Height) -> Option<Bytes> {
    let certified_block = match upstream_node
        .get_finalization(Query::Height(height.get()))
        .await
    {
        Ok(Some(cert)) => cert,
        Ok(None) | Err(_) => return None,
    };

    let finalization = <Finalization<Scheme<PublicKey, MinSig>, Digest>>::decode(
        &*alloy_primitives::hex::decode(&certified_block.certificate)
            .map_err(eyre::Report::new)
            .inspect_err(|error| warn!(%error, "failed decoding certificate"))
            .ok()?,
    )
    .map_err(eyre::Report::new)
    .inspect_err(|error| warn!(%error, "failed decoding certificate"))
    .ok()?;

    let consensus_block =
        Block::from_execution_block(SealedBlock::seal_slow(certified_block.block));
    Some((finalization, consensus_block).encode())
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
