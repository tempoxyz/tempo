//! Epoch aware schemes and peers.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use commonware_consensus::{simplex::scheme::bls12381_threshold::vrf::Scheme, types::Epoch};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider, ed25519::PublicKey,
};
use tempo_chainspec::NetworkIdentity;

#[derive(Clone)]
#[expect(clippy::type_complexity)]
pub(crate) struct SchemeProvider {
    inner: Arc<Mutex<Schemes>>,
}

#[derive(Default)]
struct Schemes {
    full: HashMap<Epoch, Arc<Scheme<PublicKey, MinSig>>>,
    certificate_verifiers: HashMap<Epoch, Arc<Scheme<PublicKey, MinSig>>>,
}

impl SchemeProvider {
    pub(crate) fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    pub(crate) fn register(&self, epoch: Epoch, scheme: Scheme<PublicKey, MinSig>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.certificate_verifiers.remove(&epoch);
        inner.full.insert(epoch, Arc::new(scheme)).is_none()
    }

    pub(crate) fn full_scheme(&self, epoch: Epoch) -> Option<Arc<Scheme<PublicKey, MinSig>>> {
        self.inner.lock().unwrap().full.get(&epoch).cloned()
    }

    pub(crate) fn register_network_identity_certificate_verifier(
        &self,
        epoch: Epoch,
        network_identity: &NetworkIdentity,
    ) -> bool {
        if epoch.get() < network_identity.from_epoch {
            return false;
        }

        let mut inner = self.inner.lock().unwrap();
        if inner.full.contains_key(&epoch) || inner.certificate_verifiers.contains_key(&epoch) {
            return false;
        }

        inner.certificate_verifiers.insert(
            epoch,
            Arc::new(Scheme::certificate_verifier(
                crate::config::NAMESPACE,
                network_identity.identity.clone(),
            )),
        );
        true
    }

    pub(crate) fn delete(&self, epoch: &Epoch) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.certificate_verifiers.remove(epoch);
        inner.full.remove(epoch).is_some()
    }
}

impl Provider for SchemeProvider {
    type Scope = Epoch;
    type Scheme = Scheme<PublicKey, MinSig>;

    fn scoped(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        let inner = self.inner.lock().unwrap();
        inner
            .full
            .get(&scope)
            .or_else(|| inner.certificate_verifiers.get(&scope))
            .cloned()
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
