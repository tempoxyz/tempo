//! Byzantine participant that behaves correctly except increments the epoch by 1
//! in all outgoing votes (notarize/finalize/nullify). This helps ensure peers
//! reject messages from an unexpected epoch.

use crate::simplex::{
    scheme,
    types::{Finalize, Notarize, Nullify, Vote},
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{certificate::Scheme, Hasher};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: Scheme> {
    pub scheme: S,
}

pub struct Reconfigurer<E: Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,
    _hasher: PhantomData<H>,
}

impl<E, S, H> Reconfigurer<E, S, H>
where
    E: Spawner,
    S: scheme::Scheme<H::Digest>,
    H: Hasher,
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context: ContextCell::new(context),
            scheme: cfg.scheme,
            _hasher: PhantomData,
        }
    }

    pub fn start(mut self, vote_network: (impl Sender, impl Receiver)) -> Handle<()> {
        spawn_cell!(self.context, self.run(vote_network))
    }

    async fn run(self, vote_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = vote_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match Vote::<S, _>::decode(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = ?s, "failed to decode message");
                    continue;
                }
            };

            // Process message
            match msg {
                Vote::Notarize(notarize) => {
                    // Build identical proposal but with epoch incremented by 1
                    let mut proposal = notarize.proposal.clone();
                    let old_round = proposal.round;
                    let new_epoch = old_round.epoch().next();
                    proposal.round = (new_epoch, old_round.view()).into();

                    // Sign and broadcast
                    let n = Notarize::sign(&self.scheme, proposal).unwrap();
                    let msg = Vote::Notarize(n).encode();
                    sender.send(Recipients::All, msg, true);
                }
                Vote::Finalize(finalize) => {
                    // Build identical proposal but with epoch incremented by 1
                    let mut proposal = finalize.proposal.clone();
                    let old_round = proposal.round;
                    let new_epoch = old_round.epoch().next();
                    proposal.round = (new_epoch, old_round.view()).into();

                    // Sign and broadcast
                    let f = Finalize::sign(&self.scheme, proposal).unwrap();
                    let msg = Vote::Finalize(f).encode();
                    sender.send(Recipients::All, msg, true);
                }
                Vote::Nullify(nullify) => {
                    // Re-sign nullify for the next epoch
                    let old_round = nullify.round;
                    let new_epoch = old_round.epoch().next();
                    let new_round = (new_epoch, old_round.view()).into();

                    let n = Nullify::sign(&self.scheme, new_round).unwrap();
                    let msg = Vote::<S, H::Digest>::Nullify(n).encode();
                    sender.send(Recipients::All, msg, true);
                }
            }
        }
    }
}
