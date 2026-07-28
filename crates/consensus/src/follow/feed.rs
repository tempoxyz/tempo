//! Local RPC feed for follower mode.
//!
//! Unlike the validator feed, this feed receives complete, verified
//! `(block, finalization)` pairs from the upstream driver. It does not depend
//! on marshal updates for live delivery.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::hex;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Heightable as _,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use futures::{StreamExt as _, channel::mpsc};
use tempo_node::rpc::consensus::CertifiedBlock;
use tracing::{debug, error, info_span, instrument};

use crate::{
    alias::marshal,
    consensus::{Block, Digest},
    feed::FeedStateHandle,
};

pub(super) type ConsensusFinalization = Finalization<Scheme<PublicKey, MinSig>, Digest>;
type Certified = (Block, ConsensusFinalization);

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
    last_published_height: Option<commonware_consensus::types::Height>,
}

impl<TContext: Spawner> Actor<TContext> {
    pub(super) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some((block, finalization)) = self.receiver.next().await {
            self.publish(block, finalization);
        }

        info_span!("follower_feed_actor").in_scope(|| error!("mailbox closed; shutting down"));
    }

    #[instrument(skip_all, fields(height = %block.height(), digest = %block.digest()))]
    fn publish(&mut self, block: Block, finalization: ConsensusFinalization) {
        let height = block.height();
        if self
            .last_published_height
            .is_some_and(|last_height| height <= last_height)
        {
            return;
        }
        self.last_published_height = Some(height);
        let round = finalization.proposal.round;
        let finalized = CertifiedBlock {
            epoch: round.epoch().get(),
            view: round.view().get(),
            block: block.into_execution_block(),
            digest: finalization.proposal.payload.0,
            certificate: hex::encode(finalization.encode()),
        };

        let subscribers = self.state.publish_finalized(finalized, now_millis());
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
            last_published_height: None,
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
