//! Shared epoch-aware certificate schemes.

pub(crate) use tempo_finality::SchemeProvider;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::NAMESPACE, test_utils::dkg_fixture};
    use commonware_consensus::{simplex::scheme::bls12381_threshold::vrf::Scheme, types::Epoch};
    use commonware_cryptography::certificate::Provider as _;
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
    fn registered_identity_allows_earlier_and_later_epochs() {
        deterministic::Runner::default().start(|mut context| async move {
            let epoch = Epoch::new(2);
            let fixture = dkg_fixture(&mut context, epoch);
            let rotated = dkg_fixture(&mut context, epoch.next());
            let provider = SchemeProvider::new();
            provider.register(
                epoch,
                Scheme::certificate_verifier(NAMESPACE, *fixture.outcome.network_identity()),
            );
            assert!(provider.register(epoch.previous().unwrap(), rotated.schemes[0].clone()));
            assert!(provider.register(epoch.next(), rotated.schemes[0].clone()));
            assert_eq!(
                provider.scheme(epoch).unwrap().identity(),
                fixture.outcome.network_identity()
            );
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
            provider.register(epoch, candidate);
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
