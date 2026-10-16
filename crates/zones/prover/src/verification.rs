//! Local use of the native verifier's shared logic with the approved hardfork PCR policy.

use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    zone_factory::portal_address,
    zone_verifier::{IZoneVerifier, ZoneVerifier, approved_pcrs},
};

/// Failure to select the trusted hardfork measurements or run native Nitro verification.
#[derive(Debug, thiserror::Error)]
pub enum ShadowProofVerificationError {
    /// No compiled-in policy is effective at the requested L1 hardfork.
    #[error("no approved prover PCRs for L1 hardfork {0}")]
    MissingMeasurements(TempoHardfork),
    #[error("Nitro verification failed: {0}")]
    Verification(#[from] TempoPrecompileError),
}

/// Verify the complete Nitro attestation and batch commitments against the compiled-in
/// measurements effective at `hardfork`. Missing measurements return an error.
/// Uses the machine wall clock for certificate and attestation time checks.
pub fn verify_shadow_proof(
    call: IZoneVerifier::verifyCall,
    parent_chain_id: u64,
    hardfork: TempoHardfork,
) -> Result<bool, ShadowProofVerificationError> {
    let pcrs = approved_pcrs(hardfork)
        .ok_or(ShadowProofVerificationError::MissingMeasurements(hardfork))?;
    let mut storage = HashMapStorageProvider::new_with_spec(parent_chain_id, hardfork);
    StorageCtx::enter(&mut storage, || {
        ZoneVerifier::new().verify_with_pcrs(portal_address(call.zoneId), call, pcrs)
    })
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes, U256};
    use tempo_contracts::{
        precompiles::NITRO_VERIFIER_CONFIG_V1,
        zones::{BlockTransition, DepositQueueTransition, TokenEnablementTransition},
    };

    #[test]
    fn rejects_unapproved_forks_and_invalid_proofs() {
        for &hardfork in TempoHardfork::VARIANTS {
            let call = IZoneVerifier::verifyCall {
                zoneId: 1,
                tempoBlockNumber: 0,
                anchorBlockNumber: 0,
                anchorBlockHash: B256::ZERO,
                expectedWithdrawalBatchIndex: 0,
                nextZoneHeight: U256::ZERO,
                blockTransition: BlockTransition {
                    prevBlockHash: B256::ZERO,
                    nextBlockHash: B256::ZERO,
                },
                depositQueueTransition: DepositQueueTransition {
                    prevProcessedHash: B256::ZERO,
                    nextProcessedHash: B256::ZERO,
                    prevDepositNumber: 0,
                    nextDepositNumber: 0,
                },
                tokenEnablementTransition: TokenEnablementTransition {
                    prevProcessedTokenCount: 0,
                    nextProcessedTokenCount: 0,
                },
                withdrawalQueueHash: B256::ZERO,
                verifierConfig: Bytes::from_static(NITRO_VERIFIER_CONFIG_V1),
                proof: Bytes::from_static(&[1]),
            };
            let result = verify_shadow_proof(call, 42431, hardfork);
            if approved_pcrs(hardfork).is_some() {
                assert!(!result.unwrap());
            } else {
                assert!(matches!(result,
                    Err(ShadowProofVerificationError::MissingMeasurements(fork)) if fork == hardfork));
            }
        }
    }
}
