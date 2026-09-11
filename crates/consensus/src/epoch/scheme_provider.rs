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

    /// Replace an epoch's scheme only if its network identity is unchanged.
    ///
    /// Panics if the epoch already has a scheme with a different network identity.
    pub(crate) fn register(&self, epoch: Epoch, scheme: Scheme<PublicKey, MinSig>) -> bool {
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

    pub(crate) fn delete(&self, epoch: &Epoch) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::NAMESPACE, test_utils::dkg_fixture};
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn registered_identity_allows_scheme_upgrades() {
        deterministic::Runner::default().start(|mut context| async move {
            let epoch = Epoch::new(2);
            let fixture = dkg_fixture(&mut context, epoch);
            let provider = SchemeProvider::new();
            assert!(provider.register(
                epoch,
                Scheme::certificate_verifier(NAMESPACE, *fixture.outcome.network_identity()),
            ));
            assert!(!provider.register(
                epoch,
                Scheme::verifier(
                    NAMESPACE,
                    fixture.outcome.players().clone(),
                    fixture.outcome.sharing().clone(),
                ),
            ));
            assert_eq!(
                provider.scheme(epoch).unwrap().participants(),
                fixture.outcome.players(),
            );
            assert!(!provider.register(epoch, fixture.schemes[0].clone()));
            let installed = provider.scheme(epoch).unwrap();
            assert_eq!(installed.identity(), fixture.outcome.network_identity());
            assert!(installed.share().is_some());
        });
    }

    #[test]
    fn registered_identity_allows_later_rotation() {
        deterministic::Runner::default().start(|mut context| async move {
            let epoch = Epoch::new(2);
            let fixture = dkg_fixture(&mut context, epoch);
            let rotated = dkg_fixture(&mut context, epoch.next());
            let provider = SchemeProvider::new();
            provider.register(
                epoch,
                Scheme::certificate_verifier(NAMESPACE, *fixture.outcome.network_identity()),
            );
            assert!(provider.register(epoch.next(), rotated.schemes[0].clone()));
        });
    }

    fn register_conflicting_identity(kind: usize) {
        deterministic::Runner::default().start(|mut context| async move {
            let epoch = Epoch::new(2);
            let fixture = dkg_fixture(&mut context, epoch);
            let rotated = dkg_fixture(&mut context, epoch.next());
            let provider = SchemeProvider::new();
            provider.register(
                epoch,
                Scheme::certificate_verifier(NAMESPACE, *fixture.outcome.network_identity()),
            );
            let candidate = match kind {
                0 => Scheme::certificate_verifier(NAMESPACE, *rotated.outcome.network_identity()),
                1 => Scheme::verifier(
                    NAMESPACE,
                    rotated.outcome.players().clone(),
                    rotated.outcome.sharing().clone(),
                ),
                _ => rotated.schemes[0].clone(),
            };
            provider.clone().register(epoch, candidate);
        });
    }

    #[test]
    #[should_panic(expected = "network identity mismatch")]
    fn conflicting_certificate_verifier_panics() {
        register_conflicting_identity(0);
    }

    #[test]
    #[should_panic(expected = "network identity mismatch")]
    fn conflicting_verifier_panics() {
        register_conflicting_identity(1);
    }

    #[test]
    #[should_panic(expected = "network identity mismatch")]
    fn conflicting_signer_panics() {
        register_conflicting_identity(2);
    }
}
