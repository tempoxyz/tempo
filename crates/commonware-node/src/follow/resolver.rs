//! Resolver for follow mode.
//!
//! Implements [`Resolver`] for marshal's gap-repair machinery. Checks the
//! local execution node first and falls back to the upstream abstraction.

use std::{collections::HashSet, sync::Arc};

use bytes::Bytes;
use commonware_codec::{Encode, ReadExt as _};
use commonware_consensus::{
    marshal::ingress::handler,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_resolver::Resolver;
use commonware_runtime::Spawner;
use commonware_utils::{
    channel::{mpsc, oneshot},
    vec::NonEmptyVec,
};
use eyre::WrapErr as _;
use reth_primitives_traits::Block as _;
use reth_provider::{BlockReader as _, BlockSource};
use tempo_node::{TempoFullNode, rpc::consensus::Query};
use tokio::sync::Mutex;
use tracing::{debug, warn, warn_span};

use super::upstream::UpstreamNode;
use crate::consensus::{Digest, block::Block};

type Request = handler::Request<Block>;
type Message = handler::Message<Block>;

pub(crate) struct FollowResolver<TContext: Spawner + Clone + Send + 'static, U: UpstreamNode> {
    context: TContext,
    upstream: Arc<U>,
    sender: mpsc::Sender<Message>,
    pending: Arc<Mutex<HashSet<Request>>>,
    execution_node: TempoFullNode,
}

impl<TContext: Spawner + Clone + Send + 'static, U: UpstreamNode> Clone
    for FollowResolver<TContext, U>
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            upstream: self.upstream.clone(),
            sender: self.sender.clone(),
            pending: self.pending.clone(),
            execution_node: self.execution_node.clone(),
        }
    }
}

impl<TContext: Spawner + Clone + Send + 'static, U: UpstreamNode> FollowResolver<TContext, U> {
    pub(crate) fn new(
        context: TContext,
        upstream: Arc<U>,
        sender: mpsc::Sender<Message>,
        execution_node: TempoFullNode,
    ) -> Self {
        Self {
            context,
            upstream,
            sender,
            pending: Arc::new(Mutex::new(HashSet::new())),
            execution_node,
        }
    }

    // ── Gap-repair internals ────────────────────────────────────────────

    fn spawn_fetch(&self, key: Request) {
        let resolver = self.clone();
        let key_clone = key;

        self.context.clone().spawn(move |_| async move {
            {
                let p = resolver.pending.lock().await;
                if !p.contains(&key_clone) {
                    return;
                }
            }

            let result = match &key_clone {
                handler::Request::Finalized { height } => resolver.resolve_finalized(*height).await,
                handler::Request::Block(commitment) => resolver.resolve_block(*commitment).await,
                other => {
                    warn_span!("follow")
                        .in_scope(|| warn!(?other, "unexpected resolver request type"));
                    return;
                }
            };

            {
                let p = resolver.pending.lock().await;
                if !p.contains(&key_clone) {
                    return;
                }
            }

            match result {
                Ok(Some(value)) => {
                    let (response_tx, response_rx) = oneshot::channel();
                    let msg = Message::Deliver {
                        key: key_clone.clone(),
                        value,
                        response: response_tx,
                    };

                    if resolver.sender.send(msg).await.is_ok()
                        && let Ok(true) = response_rx.await
                    {
                        resolver.pending.lock().await.remove(&key_clone);
                    }
                }
                Ok(None) => {
                    debug!(?key_clone, "data not yet available from upstream");
                }
                Err(e) => {
                    warn!(?key_clone, error = %e, "failed to fetch from upstream");
                }
            }
        });
    }

    async fn resolve_finalized(
        &self,
        height: commonware_consensus::types::Height,
    ) -> eyre::Result<Option<Bytes>> {
        let h = height.get();
        let Some(certified) = self.upstream.get_finalization(Query::Height(h)).await? else {
            return Ok(None);
        };

        let block = self
            .execution_node
            .provider
            .block_by_number(h)
            .map_err(|e| eyre::eyre!("local provider error: {e}"))?
            .map(|b| Block::from_execution_block(b.seal()));

        let block = match block {
            Some(b) => b,
            None => match self.upstream.get_block_by_number(h).await? {
                Some(b) => b,
                None => return Ok(None),
            },
        };

        let cert_bytes = alloy_primitives::hex::decode(&certified.certificate)
            .wrap_err("failed to decode certificate hex")?;

        let finalization: Finalization<Scheme<PublicKey, MinSig>, Digest> =
            Finalization::read(&mut &cert_bytes[..])
                .map_err(|e| eyre::eyre!("failed to decode finalization: {e:?}"))?;

        Ok(Some((finalization, block).encode()))
    }

    async fn resolve_block(&self, commitment: Digest) -> eyre::Result<Option<Bytes>> {
        let block = self
            .execution_node
            .provider
            .find_block_by_hash(commitment.0, BlockSource::Any)
            .map_err(|e| eyre::eyre!("local provider error: {e}"))?
            .map(|b| Block::from_execution_block(b.seal()));

        let block = match block {
            Some(b) => b,
            None => match self.upstream.get_block_by_hash(commitment.0).await? {
                Some(b) => b,
                None => return Ok(None),
            },
        };

        Ok(Some(block.encode()))
    }
}

// ── Resolver trait impl ─────────────────────────────────────────────────────

impl<TContext: Spawner + Clone + Send + 'static, U: UpstreamNode> Resolver
    for FollowResolver<TContext, U>
{
    type Key = Request;
    type PublicKey = PublicKey;

    async fn fetch(&mut self, key: Self::Key) {
        self.pending.lock().await.insert(key.clone());
        self.spawn_fetch(key);
    }

    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        let mut pending = self.pending.lock().await;
        for key in &keys {
            pending.insert(key.clone());
        }
        drop(pending);
        for key in keys {
            self.spawn_fetch(key);
        }
    }

    async fn fetch_targeted(&mut self, key: Self::Key, _targets: NonEmptyVec<Self::PublicKey>) {
        Resolver::fetch(self, key).await;
    }

    async fn fetch_all_targeted(
        &mut self,
        requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
    ) {
        let keys: Vec<Self::Key> = requests.into_iter().map(|(k, _)| k).collect();
        self.fetch_all(keys).await;
    }

    async fn cancel(&mut self, key: Self::Key) {
        self.pending.lock().await.remove(&key);
    }

    async fn clear(&mut self) {
        self.pending.lock().await.clear();
    }

    async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
        self.pending.lock().await.retain(|k| predicate(k));
    }
}
