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
    pub(crate) fn register(
        &self,
        epoch: Epoch,
        scheme: Scheme<PublicKey, MinSig>,
    ) -> eyre::Result<bool> {
        let mut schemes = self.inner.lock().unwrap();
        if let Some(existing) = schemes.get(&epoch) {
            eyre::ensure!(
                existing.identity() == scheme.identity(),
                "network identity mismatch in epoch `{epoch}`: registered `{}`, got `{}`; \
                refusing to replace registered scheme",
                existing.identity(),
                scheme.identity(),
            );
        }
        Ok(schemes.insert(epoch, Arc::new(scheme)).is_none())
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
            assert!(
                provider
                    .register(
                        epoch,
                        Scheme::certificate_verifier(
                            NAMESPACE,
                            *fixture.outcome.network_identity()
                        ),
                    )
                    .unwrap()
            );
            assert!(
                !provider
                    .register(
                        epoch,
                        Scheme::verifier(
                            NAMESPACE,
                            fixture.outcome.players().clone(),
                            fixture.outcome.sharing().clone(),
                        ),
                    )
                    .unwrap()
            );
            assert_eq!(
                provider.scheme(epoch).unwrap().participants(),
                fixture.outcome.players(),
            );
            assert!(
                !provider
                    .register(epoch, fixture.schemes[0].clone())
                    .unwrap()
            );
            let installed = provider.scheme(epoch).unwrap();
            assert_eq!(installed.identity(), fixture.outcome.network_identity());
            assert!(installed.share().is_some());
        });
    }

    #[test]
    fn conflicting_registration_preserves_identity_and_allows_later_rotation() {
        deterministic::Runner::default().start(|mut context| async move {
            let epoch = Epoch::new(2);
            let fixture = dkg_fixture(&mut context, epoch);
            let rotated = dkg_fixture(&mut context, epoch.next());
            let provider = SchemeProvider::new();
            provider
                .register(
                    epoch,
                    Scheme::certificate_verifier(NAMESPACE, *fixture.outcome.network_identity()),
                )
                .unwrap();
            let original = provider.scheme(epoch).unwrap();
            let shared = provider.clone();
            for candidate in [
                Scheme::certificate_verifier(NAMESPACE, *rotated.outcome.network_identity()),
                Scheme::verifier(
                    NAMESPACE,
                    rotated.outcome.players().clone(),
                    rotated.outcome.sharing().clone(),
                ),
                rotated.schemes[0].clone(),
            ] {
                let error = shared.register(epoch, candidate).unwrap_err();
                assert!(error.to_string().contains("network identity mismatch"));
                assert!(Arc::ptr_eq(&original, &provider.scheme(epoch).unwrap()));
            }
            assert!(
                provider
                    .register(epoch.next(), rotated.schemes[0].clone())
                    .unwrap()
            );
        });
    }
}
