//! The validator side of the top-of-block channel.

use std::time::SystemTime;

use alloy_consensus::transaction::SignerRecoverable as _;
use alloy_eips::eip2718::Decodable2718 as _;
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::types::Round;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use tempo_payload_types::{TopOfBlockLane, TopOfBlockSubmission, TopOfBlockSubmitError};
use tempo_primitives::TempoTxEnvelope;
use tracing::{debug, warn};

use super::{
    Config, RegistryHandle,
    wire::{Ack, AckStatus, Message, Submit},
};
use crate::utils::public_key_to_b256;

pub(super) fn init<TContext>(context: TContext, config: Config) -> (Actor<TContext>, Mailbox) {
    let mailbox = Mailbox {
        lane: config.lane.clone(),
        registry: config.registry.clone(),
    };
    let actor = Actor {
        context: ContextCell::new(context),
        registry: config.registry,
        lane: config.lane,
    };
    (actor, mailbox)
}

/// Opens the lane when this node proposes.
#[derive(Clone)]
pub(crate) struct Mailbox {
    lane: TopOfBlockLane,
    registry: RegistryHandle,
}

impl Mailbox {
    /// Opens the lane for `round`, which this node proposes.
    ///
    /// Operators do not wait for this: they derive the leader from the
    /// certificate of the previous view and submit ahead of the round.
    ///
    /// Does nothing if the registry has no active operators or a zero window,
    /// so the builder does not wait.
    pub(crate) fn open(&self, round: Round) {
        let registry = self.registry.get();
        if registry.window.is_zero() || registry.active(SystemTime::now()).is_empty() {
            return;
        }
        self.lane
            .open(round.epoch().get(), round.view().get(), registry.window);
    }
}

pub(crate) struct Actor<TContext> {
    context: ContextCell<TContext>,
    registry: RegistryHandle,
    lane: TopOfBlockLane,
}

impl<TContext: Clock + Spawner> Actor<TContext> {
    pub(crate) fn start(
        mut self,
        channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(channel))
    }

    async fn run(
        self,
        (mut sender, mut receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        while let Ok((peer, mut bytes)) = receiver.recv().await {
            match Message::read(&mut bytes) {
                Ok(Message::Submit(submit)) => {
                    let ack = self.submit(&peer, submit);
                    sender.send(Recipients::One(peer), Message::Ack(ack).encode(), true);
                }
                Ok(_) => debug!(%peer, "ignoring unexpected top-of-block message"),
                Err(error) => debug!(%peer, %error, "failed decoding top-of-block message"),
            }
        }
        warn!("top-of-block channel closed");
    }

    fn submit(&self, operator: &PublicKey, submit: Submit) -> Ack {
        let Submit {
            epoch,
            view,
            id,
            txs,
        } = submit;
        let mut ack = Ack {
            epoch,
            view,
            id,
            status: AckStatus::Ok,
            accepted: 0,
            replaced: 0,
            rejected: 0,
            since_open_us: 0,
        };
        let registry = self.registry.get();
        let Some(policy) = registry.authorize(operator, self.context.current()) else {
            ack.status = AckStatus::Unauthorized;
            return ack;
        };

        let submitted = txs.len();
        let txs: Vec<_> = txs
            .into_iter()
            .filter_map(|submitted| {
                Some(TopOfBlockSubmission {
                    tx: TempoTxEnvelope::decode_2718_exact(&submitted.tx)
                        .ok()?
                        .try_into_recovered()
                        .ok()?,
                    seq: submitted.seq,
                    expires_at_ms: submitted.expires_at_ms,
                })
            })
            .collect();
        let malformed = (submitted - txs.len()) as u32;

        match self.lane.submit(
            epoch,
            view,
            public_key_to_b256(operator),
            policy.limits,
            txs,
        ) {
            Ok(outcome) => {
                ack.accepted = outcome.accepted;
                ack.replaced = outcome.replaced;
                ack.rejected = outcome.rejected + malformed;
                ack.since_open_us = outcome.since_open.as_micros() as u64;
                debug!(
                    %operator,
                    epoch,
                    view,
                    id,
                    accepted = ack.accepted,
                    replaced = ack.replaced,
                    rejected = ack.rejected,
                    since_open_us = ack.since_open_us,
                    "accepted top-of-block submission",
                );
            }
            Err(TopOfBlockSubmitError::NotOpen) => ack.status = AckStatus::NotOpen,
            Err(TopOfBlockSubmitError::Closed) => ack.status = AckStatus::Closed,
        }
        ack
    }
}
