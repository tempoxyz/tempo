//! Resolver for follow mode.
//!
//! Checks the local execution provider first and falls back to the upstream abstraction.

use std::{
    collections::BTreeMap,
    future::{Future, pending},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    marshal::resolver::handler,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::Height,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_resolver::opaque;
use commonware_runtime::{Clock, Metrics, Spawner};
use eyre::Report;
use parking_lot::Mutex;
use reth_ethereum::provider::db::DatabaseEnv;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::NodePrimitives;
use reth_provider::{
    BlockReader as _, BlockSource,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use tempo_node::{node::TempoNode, rpc::consensus::CertifiedBlock};
use tempo_primitives::Block as TempoBlock;
use tracing::{debug, error, instrument, warn};

use crate::consensus::{Block, Digest};

#[cfg(test)]
mod test;

const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

// Opaque does not notify the fetcher when retain-based cancellation removes a
// key. Expire idle entries to prevent canceled keys from accumulating.
const RETRY_STATE_TTL: Duration = Duration::from_secs(60);

type Key = handler::Key<Digest>;

pub(super) type Mailbox = opaque::Resolver<Key, handler::Annotation, PublicKey>;

pub(super) struct Config<
    P = BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>,
    U = super::upstream::Mailbox,
> {
    pub(super) execution_provider: P,
    pub(super) upstream: U,
    pub(super) mailbox_size: NonZeroUsize,
}

pub(super) fn try_init<TContext, P, U>(
    context: TContext,
    config: Config<P, U>,
) -> (Mailbox, handler::Receiver<Digest>)
where
    TContext: Clock + Metrics + Spawner,
    P: BlockProvider + Clone + 'static,
    U: Upstream + Clone + 'static,
{
    let mailbox_size = config.mailbox_size;
    let (receiver, consumer) = handler::init(context.child("handler"), mailbox_size);
    let resolver = opaque::init(
        context.child("opaque"),
        Fetcher {
            context: Arc::new(context.child("fetcher")),
            execution_provider: config.execution_provider,
            upstream: config.upstream,
            retries: Arc::new(Mutex::new(RetryState::default())),
        },
        consumer,
        mailbox_size,
        // Applied by the fetcher so it can preserve the exponential retry policy
        Duration::ZERO,
    );
    (resolver, receiver)
}

struct Fetcher<TContext, P, U> {
    context: Arc<TContext>,
    execution_provider: P,
    upstream: U,
    retries: Arc<Mutex<RetryState>>,
}

impl<TContext, P, U> Clone for Fetcher<TContext, P, U>
where
    P: Clone,
    U: Clone,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            execution_provider: self.execution_provider.clone(),
            upstream: self.upstream.clone(),
            retries: self.retries.clone(),
        }
    }
}

impl<TContext, P, U> opaque::Fetcher for Fetcher<TContext, P, U>
where
    TContext: Clock,
    P: BlockProvider + Clone + 'static,
    U: Upstream + Clone + 'static,
{
    type Key = Key;
    type Value = Bytes;

    fn fetch(&self, key: Self::Key) -> impl Future<Output = Option<Self::Value>> + Send {
        let context = self.context.clone();
        let execution_provider = self.execution_provider.clone();
        let upstream = self.upstream.clone();
        let retries = self.retries.clone();

        async move {
            // Follow mode does not resolve notarizations. Keeping the fetch
            // pending lets opaque cancel it when marshal advances its floor,
            // without polling the upstream.
            if matches!(key, handler::Key::Notarized { .. }) {
                return pending().await;
            }

            let delay = retries.lock().begin(key, context.current());
            if !delay.is_zero() {
                debug!(%key, ?delay, "delaying resolver retry");
                context.sleep(delay).await;
            }

            let value = match key {
                handler::Key::Block(digest) => {
                    resolve_block(&execution_provider, &upstream, digest).await
                }
                handler::Key::Finalized { height } => resolve_finalized(&upstream, height).await,
                handler::Key::Notarized { .. } => unreachable!(),
            };

            let now = context.current();
            if value.is_some() {
                retries.lock().succeeded(&key);
            } else {
                retries.lock().failed(key, delay, now);
            }

            value
        }
    }
}

#[derive(Default)]
struct RetryState {
    entries: BTreeMap<Key, RetryEntry>,
}

struct RetryEntry {
    delay: Duration,
    last_used: SystemTime,
}

impl RetryState {
    fn begin(&mut self, key: Key, now: SystemTime) -> Duration {
        self.entries.retain(|_, retry| {
            now.duration_since(retry.last_used)
                .is_ok_and(|age| age < RETRY_STATE_TTL)
        });

        let retry = self.entries.entry(key).or_insert(RetryEntry {
            delay: Duration::ZERO,
            last_used: now,
        });

        retry.last_used = now;
        retry.delay
    }

    fn failed(&mut self, key: Key, used: Duration, now: SystemTime) {
        let delay = if used.is_zero() {
            INITIAL_RETRY_DELAY
        } else {
            used.saturating_mul(2).min(MAX_RETRY_DELAY)
        };

        self.entries.insert(
            key,
            RetryEntry {
                delay,
                last_used: now,
            },
        );
    }

    fn succeeded(&mut self, key: &Key) {
        self.entries.remove(key);
    }
}

/// Resolves an encoded block from the execution layer, falling back to the upstream node.
#[instrument(skip(execution_provider, upstream))]
async fn resolve_block<P: BlockProvider, U: Upstream>(
    execution_provider: &P,
    upstream: &U,
    block_digest: Digest,
) -> Option<Bytes> {
    match execution_provider
        .block_by_hash(block_digest)
        .inspect_err(|error| error!(%error, "execution layer error looking up block"))
    {
        Err(_) => None,
        Ok(Some(block)) => Some(block.encode()),
        Ok(None) => upstream
            .get_block(block_digest)
            .await
            .map(|block| block.encode()),
    }
}

/// Resolves a finalization (certificate and block) by height from the upstream node.
#[instrument(skip_all, fields(%height))]
async fn resolve_finalized<U: Upstream>(upstream: &U, height: Height) -> Option<Bytes> {
    let certified_block = upstream.get_finalization(height).await?;

    let finalization = alloy_primitives::hex::decode(&certified_block.certificate)
        .map_err(Report::new)
        .and_then(|bytes| {
            <Finalization<Scheme<PublicKey, MinSig>, Digest>>::decode(&*bytes).map_err(Report::new)
        })
        .inspect_err(|error| warn!(%error, "failed decoding certificate"))
        .ok()?;

    // Upstream finalization responses carry persisted EL blocks only; no p2p BAL
    // is available when reconstructing this consensus block.
    let consensus_block = Block::from_execution_block_unchecked(certified_block.block, None);
    Some((finalization, consensus_block).encode())
}

/// Local execution-layer block lookup needed by the resolver.
pub(super) trait BlockProvider: Send + Sync {
    fn block_by_hash(&self, digest: Digest) -> eyre::Result<Option<Block>>;
}

/// Upstream reads needed by the resolver.
pub(super) trait Upstream: Send + Sync {
    fn get_block(&self, digest: Digest) -> impl Future<Output = Option<Block>> + Send;
    fn get_finalization(&self, h: Height) -> impl Future<Output = Option<CertifiedBlock>> + Send;
}

impl<N> BlockProvider for BlockchainProvider<N>
where
    N: ProviderNodeTypes,
    N::Primitives: NodePrimitives<Block = TempoBlock>,
{
    fn block_by_hash(&self, digest: Digest) -> eyre::Result<Option<Block>> {
        self.find_sealed_or_recovered_block(digest.0, BlockSource::Any)
            .map_err(eyre::Report::new)
            .map(|block| block.map(|block| Block::from_execution_block_unchecked(block, None)))
    }
}

impl Upstream for super::upstream::Mailbox {
    fn get_block(&self, digest: Digest) -> impl Future<Output = Option<Block>> + Send {
        let upstream = self.clone();
        async move { upstream.get_block(digest).await }
    }

    fn get_finalization(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<CertifiedBlock>> + Send {
        let upstream = self.clone();
        async move { upstream.get_finalization(height).await }
    }
}
