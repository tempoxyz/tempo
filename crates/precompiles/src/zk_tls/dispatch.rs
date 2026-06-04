use super::ZkTlsVerifier;
use crate::{Precompile, charge_input_cost, dispatch_call, mutate, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IZkTlsVerifier::{self, IZkTlsVerifierCalls};

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
                    let (claim_hash, tee_signer) =
                        self.verify_tempo_claim(c.claim, c.policy, c.rawQuote, c.signature)?;
                    Ok(IZkTlsVerifier::verifyTempoClaimReturn {
                        claimHash: claim_hash,
                        teeSigner: tee_signer,
                    })
                }),
                IZkTlsVerifierCalls::verifyAndMarkTempoClaim(call) => {
                    mutate(call, msg_sender, |_, c| {
                        let (claim_hash, tee_signer) = self.verify_and_mark_tempo_claim(
                            c.claim,
                            c.policy,
                            c.rawQuote,
                            c.signature,
                        )?;
                        Ok(IZkTlsVerifier::verifyAndMarkTempoClaimReturn {
                            claimHash: claim_hash,
                            teeSigner: tee_signer,
                        })
                    })
                }
                IZkTlsVerifierCalls::hashTempoClaim(call) => {
                    view(call, |c| self.hash_tempo_claim(c.claim))
                }
                IZkTlsVerifierCalls::toEthSignedMessageHash(call) => {
                    view(call, |c| self.to_eth_signed_message_hash(c.claimHash))
                }
                IZkTlsVerifierCalls::isNonceUsed(call) => {
                    view(call, |c| self.is_nonce_used(c.subject, c.nonce))
                }
                IZkTlsVerifierCalls::owner(call) => view(call, |_| self.owner()),
                IZkTlsVerifierCalls::isProviderHashApproved(call) => {
                    view(call, |c| self.is_provider_hash_approved(c.providerHash))
                }
                IZkTlsVerifierCalls::claimTypeForProviderHash(call) => {
                    view(call, |c| self.claim_type_for_provider_hash(c.providerHash))
                }
                IZkTlsVerifierCalls::isDstackAppApproved(call) => {
                    view(call, |c| self.is_dstack_app_approved(c.dstackApp))
                }
                IZkTlsVerifierCalls::isDstackComposeHashApproved(call) => view(call, |c| {
                    self.is_dstack_compose_hash_approved(c.dstackApp, c.composeHash)
                }),
                IZkTlsVerifierCalls::isDstackDeviceApproved(call) => view(call, |c| {
                    self.is_dstack_device_approved(c.dstackApp, c.deviceId)
                }),
                IZkTlsVerifierCalls::isDstackAnyDeviceAllowed(call) => {
                    view(call, |c| self.is_dstack_any_device_allowed(c.dstackApp))
                }
                IZkTlsVerifierCalls::isDstackSignerApproved(call) => view(call, |c| {
                    self.is_dstack_signer_approved(c.dstackApp, c.teeSigner)
                }),
                IZkTlsVerifierCalls::setProviderHashApproved(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_provider_hash_approved(s, c.providerHash, c.claimType, c.approved)
                    })
                }
                IZkTlsVerifierCalls::setDstackAppApproved(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_dstack_app_approved(s, c.dstackApp, c.approved)
                    })
                }
                IZkTlsVerifierCalls::setDstackComposeHashApproved(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_dstack_compose_hash_approved(
                            s,
                            c.dstackApp,
                            c.composeHash,
                            c.approved,
                        )
                    })
                }
                IZkTlsVerifierCalls::setDstackDeviceApproved(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_dstack_device_approved(s, c.dstackApp, c.deviceId, c.approved)
                    })
                }
                IZkTlsVerifierCalls::setDstackAllowAnyDevice(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_dstack_allow_any_device(s, c.dstackApp, c.approved)
                    })
                }
                IZkTlsVerifierCalls::setDstackSignerApproved(call) => {
                    mutate_void(call, msg_sender, |s, c| {
                        self.set_dstack_signer_approved(s, c.dstackApp, c.teeSigner, c.approved)
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
