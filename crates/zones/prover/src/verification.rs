//! Local use of the native verifier's shared logic, independent of L1 fork activation.

use std::str::FromStr;

use alloy_primitives::FixedBytes;
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    zone_factory::portal_address,
    zone_verifier::{IZoneVerifier, ZoneVerifier},
};

/// Independently pinned PCR0, PCR1 and PCR2 for observational Nitro verification.
///
/// These measurements must come from the approved EIF build, never from a prover response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowProofVerifier {
    pcrs: [[u8; 48]; 3],
}

#[derive(Debug, thiserror::Error)]
pub enum ShadowProofVerificationError {
    #[error("expected three comma-separated 48-byte PCR measurements (PCR0,PCR1,PCR2)")]
    InvalidMeasurements,
    #[error("zero/debug enclave PCR measurements are not permitted")]
    DebugMeasurements,
    #[error("Nitro verification failed: {0}")]
    Verification(#[from] TempoPrecompileError),
}

impl FromStr for ShadowProofVerifier {
    type Err = ShadowProofVerificationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let values = value
            .split(',')
            .map(|part| part.trim().parse::<FixedBytes<48>>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ShadowProofVerificationError::InvalidMeasurements)?;
        let values: [FixedBytes<48>; 3] = values
            .try_into()
            .map_err(|_| ShadowProofVerificationError::InvalidMeasurements)?;
        if values.iter().any(FixedBytes::is_zero) {
            return Err(ShadowProofVerificationError::DebugMeasurements);
        }
        Ok(Self {
            pcrs: values.map(|value| value.0),
        })
    }
}

impl ShadowProofVerifier {
    /// Verify the complete attestation and its batch commitments using the native verifier's
    /// implementation, using the machine wall clock for certificate and attestation time checks.
    pub fn verify(
        &self,
        call: IZoneVerifier::verifyCall,
        parent_chain_id: u64,
    ) -> Result<bool, ShadowProofVerificationError> {
        let mut storage = HashMapStorageProvider::new(parent_chain_id);
        StorageCtx::enter(&mut storage, || {
            ZoneVerifier::new().verify_with_pcrs(portal_address(call.zoneId), call, self.pcrs)
        })
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_complete_non_debug_measurements() {
        let pcr = "11".repeat(48);
        assert!(
            format!("{pcr},{pcr},{pcr}")
                .parse::<ShadowProofVerifier>()
                .is_ok()
        );
        for invalid in [
            String::new(),
            pcr.clone(),
            format!("{pcr},{pcr}"),
            format!("{pcr},{pcr},{pcr},{pcr}"),
            format!("{pcr},{pcr},00"),
            format!("{pcr},{pcr},{}", "00".repeat(48)),
        ] {
            assert!(invalid.parse::<ShadowProofVerifier>().is_err());
        }
    }
}
