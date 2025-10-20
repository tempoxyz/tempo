//! Epoch aware schemes and peers.

use std::sync::Arc;

use commonware_consensus::{marshal, simplex::signing_scheme::bls12381_threshold};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_resolver::p2p;
use commonware_utils::set::Set;

/// Implements trait `[p2p::Cordinatoor]` and is passed to the marshal actor.
#[derive(Clone)]
pub(crate) struct Coordinator {
    static_peers: Set<PublicKey>,
}

impl Coordinator {
    pub(crate) fn new(static_peers: Set<PublicKey>) -> Self {
        Self { static_peers }
    }
}

impl p2p::Coordinator for Coordinator {
    type PublicKey = PublicKey;

    fn peers(&self) -> &[Self::PublicKey] {
        self.static_peers.as_ref()
    }

    fn peer_set_id(&self) -> u64 {
        0
    }
}
