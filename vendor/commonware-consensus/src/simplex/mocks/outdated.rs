//! Byzantine participant that sends outdated notarize and finalize messages.

use crate::{
    Viewable,
    simplex::{
        scheme,
        types::{Finalize, Notarize, Proposal, Vote},
    },
    types::{View, ViewDelta},
};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Hasher, certificate::Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use rand_core::CryptoRng;
use std::collections::HashMap;
use tracing::debug;

pub struct Config<S: Scheme> {
    pub scheme: S,
    pub view_delta: ViewDelta,
}

pub struct Outdated<E: Clock + CryptoRng + Spawner, S: Scheme, H: Hasher> {
    context: ContextCell<E>,
    scheme: S,

    history: HashMap<View, Proposal<H::Digest>>,
    view_delta: ViewDelta,
}

impl<E, S, H> Outdated<E, S, H>
where
    E: Clock + CryptoRng + Spawner,
    S: scheme::Scheme<H::Digest>,
    H: Hasher,
{
    pub fn new(context: E, cfg: Config<S>) -> Self {
        Self {
            context: ContextCell::new(context),
            scheme: cfg.scheme,

            history: HashMap::new(),
            view_delta: cfg.view_delta,
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
            let view = msg.view();

            // Process message
            match msg {
                Vote::Notarize(notarize) => {
                    // Store proposal
                    self.history.insert(view, notarize.proposal.clone());

                    // Notarize old digest
                    let view = view.saturating_sub(self.view_delta);
                    let Some(proposal) = self.history.get(&view) else {
                        continue;
                    };
                    debug!(%view, "notarizing old proposal");
                    let n = Notarize::<S, _>::sign(&self.scheme, proposal.clone()).unwrap();
                    let msg = Vote::Notarize(n).encode();
                    sender.send(Recipients::All, msg, true);
                }
                Vote::Finalize(finalize) => {
                    // Store proposal
                    self.history.insert(view, finalize.proposal.clone());

                    // Finalize old digest
                    let view = view.saturating_sub(self.view_delta);
                    let Some(proposal) = self.history.get(&view) else {
                        continue;
                    };
                    debug!(%view, "finalizing old proposal");
                    let f = Finalize::<S, _>::sign(&self.scheme, proposal.clone()).unwrap();
                    let msg = Vote::Finalize(f).encode();
                    sender.send(Recipients::All, msg, true);
                }
                _ => continue,
            }
        }
    }
}
