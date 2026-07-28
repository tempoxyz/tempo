//! Local RPC feed for follower mode.
//!
//! Unlike the validator feed, this feed receives complete, verified
//! `(block, finalization)` pairs from the upstream driver. It does not depend
//! on marshal updates for live delivery.

use std::{
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_primitives::hex;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Heightable as _,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
    types::Height,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use futures::{StreamExt as _, channel::mpsc};
use parking_lot::RwLock;
use tempo_node::rpc::consensus::{
    CertifiedBlock, ConsensusFeed, ConsensusState, Event, Query, types::Response,
};
use tokio::sync::broadcast;
use tracing::{Level, debug, error, info_span, instrument};

use crate::{
    alias::marshal,
    consensus::{Block, Digest},
};

pub(super) type ConsensusFinalization = Finalization<Scheme<PublicKey, MinSig>, Digest>;
type Certified = (Block, ConsensusFinalization);
const BROADCAST_CHANNEL_SIZE: usize = 1024;

#[derive(Default)]
struct FeedState {
    latest_finalized: Option<CertifiedBlock>,
}

#[derive(Clone)]
pub struct FeedStateHandle {
    state: Arc<RwLock<FeedState>>,
    marshal: Arc<OnceLock<marshal::Mailbox>>,
    events_tx: broadcast::Sender<Event>,
}

impl FeedStateHandle {
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);
        Self {
            state: Arc::new(RwLock::new(FeedState::default())),
            marshal: Arc::new(OnceLock::new()),
            events_tx,
        }
    }

    fn set_marshal(&self, marshal: marshal::Mailbox) {
        let _ = self.marshal.set(marshal);
    }

    fn publish(&self, finalized: CertifiedBlock, seen: u64) -> usize {
        self.state.write().latest_finalized = Some(finalized.clone());
        let subscribers = self.events_tx.receiver_count();
        let _ = self.events_tx.send(Event::Finalized {
            block: finalized,
            seen,
        });
        subscribers
    }

    fn marshal(&self) -> Option<marshal::Mailbox> {
        self.marshal.get().cloned()
    }
}

impl Default for FeedStateHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FeedStateHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FollowerFeedStateHandle")
            .field("latest_finalized", &self.state.read().latest_finalized)
            .field("marshal_set", &self.marshal.get().is_some())
            .field("subscriber_count", &self.events_tx.receiver_count())
            .finish()
    }
}

impl ConsensusFeed for FeedStateHandle {
    #[instrument(skip_all, fields(%query), ret(level = Level::DEBUG, Display))]
    async fn get_finalization(&self, query: Query) -> Response<CertifiedBlock> {
        match query {
            Query::Latest => self
                .state
                .read()
                .latest_finalized
                .clone()
                .map_or(Response::Missing("certifications"), Response::Success),
            Query::Height(height) => 'process: {
                let Some(marshal) = self.marshal() else {
                    break 'process Response::NotReady;
                };
                let height = Height::new(height);
                let Some(finalization) = marshal.get_finalization(height).await else {
                    break 'process Response::Missing("certificate");
                };
                let Some(block) = marshal.get_block(height).await else {
                    break 'process Response::Missing("block");
                };
                Response::Success(CertifiedBlock {
                    epoch: finalization.proposal.round.epoch().get(),
                    view: finalization.proposal.round.view().get(),
                    block: block.into_execution_block(),
                    digest: finalization.proposal.payload.0,
                    certificate: hex::encode(finalization.encode()),
                })
            }
        }
    }

    async fn get_latest(&self) -> ConsensusState {
        ConsensusState {
            finalized: self.state.read().latest_finalized.clone(),
            notarized: None,
        }
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Event>> {
        Some(self.events_tx.subscribe())
    }
}

#[derive(Clone, Debug)]
pub(super) struct Mailbox(mpsc::UnboundedSender<Certified>);

impl Mailbox {
    pub(super) fn report(&self, block: Block, finalization: ConsensusFinalization) {
        if self.0.unbounded_send((block, finalization)).is_err() {
            error!("failed sending certified block to follower feed");
        }
    }
}

pub(super) struct Actor<TContext> {
    context: ContextCell<TContext>,
    receiver: mpsc::UnboundedReceiver<Certified>,
    state: FeedStateHandle,
}

impl<TContext: Spawner> Actor<TContext> {
    pub(super) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(&mut self) {
        while let Some((block, finalization)) = self.receiver.next().await {
            self.publish(block, finalization);
        }

        info_span!("follower_feed_actor").in_scope(|| error!("mailbox closed; shutting down"));
    }

    #[instrument(skip_all, fields(height = %block.height(), digest = %block.digest()))]
    fn publish(&self, block: Block, finalization: ConsensusFinalization) {
        let height = block.height();
        let round = finalization.proposal.round;
        let finalized = CertifiedBlock {
            epoch: round.epoch().get(),
            view: round.view().get(),
            block: block.into_execution_block(),
            digest: finalization.proposal.payload.0,
            certificate: hex::encode(finalization.encode()),
        };

        let subscribers = self.state.publish(finalized, now_millis());
        debug!(
            subscribers,
            height = height.get(),
            "sending follower finalized block event"
        );
    }
}

pub(super) fn init<TContext: Spawner>(
    context: TContext,
    marshal: marshal::Mailbox,
    state: FeedStateHandle,
) -> (Actor<TContext>, Mailbox) {
    state.set_marshal(marshal);
    let (sender, receiver) = mpsc::unbounded();
    (
        Actor {
            context: ContextCell::new(context),
            receiver,
            state,
        },
        Mailbox(sender),
    )
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
