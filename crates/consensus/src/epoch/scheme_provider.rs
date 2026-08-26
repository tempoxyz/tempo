//! Epoch aware schemes and peers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use commonware_consensus::{simplex::scheme::bls12381_threshold::vrf::Scheme, types::Epoch};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    certificate::{Provider, Scoped},
    ed25519::PublicKey,
};
use tokio::sync::broadcast;

const REGISTRATION_CHANNEL_CAPACITY: usize = 16;

#[derive(Clone)]
#[expect(clippy::type_complexity)]
pub(crate) struct SchemeProvider {
    inner: Arc<Mutex<HashMap<Epoch, Arc<Scheme<PublicKey, MinSig>>>>>,
    registrations: broadcast::Sender<Epoch>,
}

impl SchemeProvider {
    pub(crate) fn new() -> Self {
        let (registrations, _) = broadcast::channel(REGISTRATION_CHANNEL_CAPACITY);
        Self {
            inner: Default::default(),
            registrations,
        }
    }

    /// Registers or replaces a scheme.
    ///
    /// Subscribers are notified only when an epoch becomes available. The
    /// bounded stream is a wakeup, so consumers must read the provider state.
    pub(crate) fn register(&self, epoch: Epoch, scheme: Scheme<PublicKey, MinSig>) -> bool {
        let inserted = self
            .inner
            .lock()
            .unwrap()
            .insert(epoch, Arc::new(scheme))
            .is_none();
        if inserted {
            let _ = self.registrations.send(epoch);
        }
        inserted
    }

    pub(crate) fn delete(&self, epoch: &Epoch) -> bool {
        self.inner.lock().unwrap().remove(epoch).is_some()
    }

    pub(crate) fn contains(&self, epoch: Epoch) -> bool {
        self.inner.lock().unwrap().contains_key(&epoch)
    }

    pub(crate) fn subscribe_registrations(&self) -> broadcast::Receiver<Epoch> {
        self.registrations.subscribe()
    }
}

impl Provider for SchemeProvider {
    type Scope = Epoch;
    type Scheme = Scheme<PublicKey, MinSig>;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.inner
            .lock()
            .unwrap()
            .get(&scope)
            .cloned()
            .map(Scoped::scheme)
    }
}
