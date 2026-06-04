use super::ZkTlsVerifier;
use crate::{Precompile, charge_input_cost, dispatch_call, mutate, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IZkTlsVerifier::IZkTlsVerifierCalls;

impl Precompile for ZkTlsVerifier {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            IZkTlsVerifierCalls::abi_decode,
            |call| match call {
                IZkTlsVerifierCalls::verifyTempoClaim(call) => view(call, |c| {
                    self.verify_tempo_claim(c.claim, c.policy, c.signature)
                }),
                IZkTlsVerifierCalls::verifyAndMarkTempoClaim(call) => {
                    mutate(call, msg_sender, |_, c| {
                        self.verify_and_mark_tempo_claim(c.claim, c.policy, c.signature)
                    })
                }
                IZkTlsVerifierCalls::hashTempoClaim(call) => {
                    view(call, |c| self.hash_tempo_claim(c.claim))
                }
                IZkTlsVerifierCalls::isNonceUsed(call) => {
                    view(call, |c| self.is_nonce_used(c.subject, c.nonce))
                }
                IZkTlsVerifierCalls::owner(call) => view(call, |_| self.owner()),
                IZkTlsVerifierCalls::isAttestorApproved(call) => {
                    view(call, |c| self.is_attestor_approved(c.attestorPublicKey))
                }
                IZkTlsVerifierCalls::isProviderHashApproved(call) => {
                    view(call, |c| self.is_provider_hash_approved(c.providerHash))
                }
                IZkTlsVerifierCalls::isMeasurementApproved(call) => {
                    view(call, |c| self.is_measurement_approved(c.measurement))
                }
                IZkTlsVerifierCalls::setAttestorApproved(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_attestor_approved(s, c.attestorPublicKey, c.approved)
                    })
                }
                IZkTlsVerifierCalls::setProviderHashApproved(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_provider_hash_approved(s, c.providerHash, c.approved)
                    })
                }
                IZkTlsVerifierCalls::setMeasurementApproved(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_measurement_approved(s, c.measurement, c.approved)
                    })
                }
                IZkTlsVerifierCalls::transferOwnership(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.transfer_ownership(s, c.newOwner)
                    })
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_zktls_verifier_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZkTlsVerifier::new();
            verifier.initialize(Address::random())?;

            let unsupported = check_selector_coverage(
                &mut verifier,
                IZkTlsVerifierCalls::SELECTORS,
                "IZkTlsVerifier",
                IZkTlsVerifierCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
