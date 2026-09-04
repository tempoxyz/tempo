//! Byzantine participant that sends nullify and finalize messages for the same view.

use crate::simplex::{
    scheme,
    types::{Finalize, Nullify, Vote},
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

pub struct Nuller<E: Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,
    _hasher: PhantomData<H>,
}

impl<E, S, H> Nuller<E, S, H>
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
                    // Nullify
                    let n = Nullify::sign(&self.scheme, notarize.round()).unwrap();
                    let msg = Vote::<S, H::Digest>::Nullify(n).encode();
                    sender.send(Recipients::All, msg, true);

                    // Finalize digest
                    let proposal = notarize.proposal;
                    let f = Finalize::<S, _>::sign(&self.scheme, proposal).unwrap();
                    let msg = Vote::Finalize(f).encode();
                    sender.send(Recipients::All, msg, true);
                }
                _ => continue,
            }
        }
    }
}
