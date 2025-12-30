//! Epoch aware schemes and peers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use commonware_consensus::{simplex::scheme::bls12381_threshold::Scheme, types::Epoch};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider, ed25519::PublicKey,
};

#[derive(Clone)]
#[expect(clippy::type_complexity)]
pub(crate) struct SchemeProvider {
    inner: Arc<Mutex<HashMap<Epoch, Arc<Scheme<PublicKey, MinSig>>>>>,
}

impl SchemeProvider {
    pub(crate) fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    pub(crate) fn register(&self, epoch: Epoch, scheme: Scheme<PublicKey, MinSig>) -> bool {
        self.inner
            .lock()
            .unwrap()
            .insert(epoch, Arc::new(scheme))
            .is_none()
    }

    pub(crate) fn delete(&self, epoch: &Epoch) -> bool {
        self.inner.lock().unwrap().remove(epoch).is_some()
    }
}

impl Provider for SchemeProvider {
    type Scope = Epoch;
    type Scheme = Scheme<PublicKey, MinSig>;

    fn scoped(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.inner.lock().unwrap().get(&scope).cloned()
    }

    /// Always returned `None`.
    ///
    /// While we are using bls12-381 threshold cryptography, the constant term
    /// of the public polynomial can change in a full re-dkg and so tempo can
    /// never verify certificates from all epochs.
    fn all(&self) -> Option<Arc<Self::Scheme>> {
        None
    }
}
