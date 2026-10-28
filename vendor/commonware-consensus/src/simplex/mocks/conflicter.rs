//! Byzantine participant that sends conflicting notarize/finalize messages.

use crate::simplex::{
    scheme,
    types::{Finalize, Notarize, Proposal, Vote},
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, certificate::Scheme};
use commonware_math::algebra::Random;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use rand_core::CryptoRng;
use std::marker::PhantomData;
use tracing::debug;

pub struct Config<S: Scheme> {
    pub scheme: S,
}

pub struct Conflicter<E: Clock + CryptoRng + Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,
    _hasher: PhantomData<H>,
}

impl<E, S, H> Conflicter<E, S, H>
where
    E: Clock + CryptoRng + Spawner,
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

    async fn run(mut self, vote_network: (impl Sender, impl Receiver)) {
        let (mut sender, mut receiver) = vote_network;
        while let Ok((s, msg)) = receiver.recv().await {
            // Parse message
            let msg = match Vote::<S, H::Digest>::decode(msg) {
                Ok(msg) => msg,
                Err(err) => {
                    debug!(?err, sender = ?s, "failed to decode message");
                    continue;
                }
            };

            // Process message
            match msg {
                Vote::Notarize(notarize) => {
                    // Notarize random digest
                    let payload = H::Digest::random(self.context.as_mut());
                    let proposal =
                        Proposal::new(notarize.round(), notarize.proposal.parent, payload);
                    let n = Notarize::<S, _>::sign(&self.scheme, proposal).unwrap();
                    let msg = Vote::Notarize(n).encode();
                    sender.send(Recipients::All, msg, true);

                    // Notarize received digest
                    let n = Notarize::<S, _>::sign(&self.scheme, notarize.proposal).unwrap();
                    let msg = Vote::Notarize(n).encode();
                    sender.send(Recipients::All, msg, true);
                }
                Vote::Finalize(finalize) => {
                    // Finalize random digest
                    let payload = H::Digest::random(self.context.as_mut());
                    let proposal =
                        Proposal::new(finalize.round(), finalize.proposal.parent, payload);
                    let f = Finalize::<S, _>::sign(&self.scheme, proposal).unwrap();
                    let msg = Vote::Finalize(f).encode();
                    sender.send(Recipients::All, msg, true);

                    // Finalize provided digest
                    let f = Finalize::<S, _>::sign(&self.scheme, finalize.proposal).unwrap();
                    let msg = Vote::Finalize(f).encode();
                    sender.send(Recipients::All, msg, true);
                }
                _ => continue,
            }
        }
    }
}
