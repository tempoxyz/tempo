use std::{collections::BTreeMap, time::Duration};

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
    channel::mpsc,
    futures::{AbortablePool, Aborter},
};
use eyre::Report;
use tokio::select;
use tracing::{debug, error, instrument, warn};

use super::{BlockProvider, Config, Mailbox, Upstream, ingress::Message};
use crate::consensus::{Block, Digest};

const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
pub(super) const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

pub(super) fn retry_delay(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }

    let multiplier = 2u32.saturating_pow(attempt.saturating_sub(1));
    INITIAL_RETRY_DELAY
        .saturating_mul(multiplier)
        .min(MAX_RETRY_DELAY)
}

pub(super) fn try_init<TContext, P, U>(
    context: TContext,
    config: Config<P, U>,
) -> (
    Resolver<TContext, P, U>,
    Mailbox,
    mpsc::Receiver<handler::Message<Digest>>,
)
where
    TContext: Clock + Spawner,
    P: BlockProvider + Clone + 'static,
    U: Upstream + Clone + 'static,
{
    let (handler_tx, handler_rx) = mpsc::channel(config.mailbox_size);
    let (mailbox_tx, mailbox_rx) = mpsc::unbounded_channel();
    let actor = Resolver {
        context: ContextCell::new(context),
        execution_provider: config.execution_provider,
        upstream: config.upstream,
        mailbox: mailbox_rx,
        handler_tx,
        requests: BTreeMap::new(),
        fetches: AbortablePool::default(),
    };
    let mailbox = Mailbox { inner: mailbox_tx };
    (actor, mailbox, handler_rx)
}

type FetchPool = AbortablePool<(handler::Request<Digest>, u32, Result<Bytes, bool>)>;

pub(crate) struct Resolver<
    TContext,
    P = reth_provider::providers::BlockchainProvider<
        reth_node_builder::NodeTypesWithDBAdapter<
            tempo_node::node::TempoNode,
            reth_ethereum::provider::db::DatabaseEnv,
        >,
    >,
    U = super::super::upstream::Mailbox,
> {
    context: ContextCell<TContext>,
    execution_provider: P,
    upstream: U,
    /// To send messages to the application/actor relying on the resolver.
    handler_tx: mpsc::Sender<handler::Message<Digest>>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    requests: BTreeMap<handler::Request<Digest>, Aborter>,
    fetches: FetchPool,
}

impl<TContext, P, U> Resolver<TContext, P, U>
where
    TContext: Clock + Spawner,
    P: BlockProvider + Clone + 'static,
    U: Upstream + Clone + 'static,
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
                    let execution_provider = self.execution_provider.clone();
                    let upstream = self.upstream.clone();
                    let digest = *digest;
                    let key = key.clone();
                    self.fetches.push(async move {
                        if !delay.is_zero() {
                            context.sleep(delay).await;
                        }

                        let response = resolve_block(&execution_provider, &upstream, digest).await;
                        (key, attempt, response)
                    })
                }
                handler::Request::Finalized { height } => {
                    let context = self.context.clone();
                    let upstream = self.upstream.clone();
                    let height = *height;
                    let key = key.clone();
                    self.fetches.push(async move {
                        if !delay.is_zero() {
                            context.sleep(delay).await;
                        }
                        let response = resolve_finalized(&upstream, height).await;
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
#[instrument(skip(execution_provider, upstream))]
async fn resolve_block<P: BlockProvider, U: Upstream>(
    execution_provider: &P,
    upstream: &U,
    block_digest: Digest,
) -> Result<Bytes, bool> {
    match execution_provider
        .block_by_hash(block_digest)
        .inspect_err(|error| error!(%error, "execution layer error looking up block"))
    {
        Err(_) => Err(true),
        Ok(Some(block)) => Ok(block.encode()),
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
async fn resolve_finalized<U: Upstream>(upstream: &U, height: Height) -> Result<Bytes, bool> {
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
