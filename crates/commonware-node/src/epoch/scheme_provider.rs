//! Epoch aware schemes and peers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use commonware_consensus::{
    marshal, simplex::signing_scheme::bls12381_threshold::Scheme, types::Epoch,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};

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

impl marshal::SchemeProvider for SchemeProvider {
    type Scheme = Scheme<PublicKey, MinSig>;

    fn scheme(&self, epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        self.inner.lock().unwrap().get(&epoch).cloned()
    }
}
