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
#[derive(Clone, Default)]
#[expect(clippy::type_complexity)]
pub struct SchemeProvider {
    inner: Arc<Mutex<HashMap<Epoch, Arc<Scheme<PublicKey, MinSig>>>>>,
}

impl SchemeProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace an epoch's scheme only if its network identity is unchanged.
    ///
    /// Panics if the epoch already has a scheme with a different network identity.
    pub fn register(&self, epoch: Epoch, scheme: Scheme<PublicKey, MinSig>) -> bool {
        let mut schemes = self.inner.lock().unwrap();
        if let Some(existing) = schemes.get(&epoch) {
            assert_eq!(
                existing.identity(),
                scheme.identity(),
                "network identity mismatch in epoch `{epoch}`: registered `{}`, got `{}`; \
                refusing to replace registered scheme",
                existing.identity(),
                scheme.identity(),
            );
        }
        schemes.insert(epoch, Arc::new(scheme)).is_none()
    }

    /// Discard cached epoch schemes. This affects every clone sharing this provider.
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    pub fn delete(&self, epoch: &Epoch) -> bool {
        self.inner.lock().unwrap().remove(epoch).is_some()
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
