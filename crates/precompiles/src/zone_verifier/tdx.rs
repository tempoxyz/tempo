//! Opt-in devnet TDX verifier; no production activation or compiled-in measurements.

use super::{IZoneVerifier, ZoneVerifier, batch_commitment};
use crate::{
    error::{Result, TempoPrecompileError},
    zone_factory::portal_address,
};
use alloy::primitives::Address;
use tempo_chainspec::{
    constants::{mainnet::MAINNET_CHAIN_ID, moderato::MODERATO_CHAIN_ID},
    hardfork::TempoHardfork,
};
use tempo_tdx_attestation::Policy;

/// Startup policy must be identical across every validator of the development chain.
#[derive(Clone, Debug)]
pub struct DevPolicy {
    pub activation: TempoHardfork,
    pub measurements: Policy,
}
impl DevPolicy {
    /// Forbid overrides on public production/test networks and validate all measurement tuples.
    pub fn validate(&self, chain_id: u64) -> std::result::Result<(), String> {
        if matches!(chain_id, MAINNET_CHAIN_ID | MODERATO_CHAIN_ID) {
            return Err(format!(
                "custom TDX policy is forbidden on chain {chain_id}"
            ));
        }
        if self.activation < TempoHardfork::T13 {
            return Err("TDX requires the native verifier at T13 or later".into());
        }
        self.measurements.validate().map_err(|e| e.to_string())
    }
}
/// Set once by the node's development-only startup flags.
pub static CUSTOM_TDX: std::sync::OnceLock<DevPolicy> = std::sync::OnceLock::new();

/// Provisional development gas schedule: charge before parsing/cryptography.
pub const PARSE_GAS: u64 = 50_000;
/// Covers the bounded certificate, CRL, QE, TCB and quote verification work.
pub const VERIFY_GAS: u64 = 3_000_000;

impl ZoneVerifier {
    pub(super) fn verify_tdx(
        &self,
        portal: Address,
        call: &IZoneVerifier::verifyCall,
        policy: Option<&DevPolicy>,
    ) -> Result<bool> {
        if portal != portal_address(call.zoneId) || call.verifierConfig.as_ref() != [3] {
            return Ok(false);
        }
        let Some(policy) = policy else {
            return Ok(false);
        };
        policy
            .validate(self.storage.chain_id())
            .map_err(TempoPrecompileError::Fatal)?;
        if self.storage.spec() < policy.activation
            || call.proof.len() > tempo_tdx_attestation::MAX_EVIDENCE_BYTES
        {
            return Ok(false);
        }
        self.storage.deduct_gas(PARSE_GAS)?;
        if tempo_tdx_attestation::raw_quote(&call.proof).is_err() {
            return Ok(false);
        }
        self.storage.deduct_gas(VERIFY_GAS)?;
        let mut report_data = [0; 64];
        report_data[..32]
            .copy_from_slice(batch_commitment(self.storage.chain_id(), call).as_slice());
        Ok(tempo_tdx_attestation::verify(
            &call.proof,
            &report_data,
            &policy.measurements,
            self.storage.timestamp().saturating_to::<u64>(),
        )
        .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::{Bytes, FixedBytes};
    fn policy() -> DevPolicy {
        DevPolicy {
            activation: TempoHardfork::T13,
            measurements: Policy {
                measurements: vec![tempo_tdx_attestation::Measurements {
                    mr_td: FixedBytes::repeat_byte(1),
                    mr_config_id: FixedBytes::ZERO,
                    mr_owner: FixedBytes::ZERO,
                    mr_owner_config: FixedBytes::ZERO,
                    rtmrs: [FixedBytes::ZERO; 4],
                    td_attributes: 0,
                    xfam: 3,
                }],
            },
        }
    }
    #[test]
    fn activation_requires_native_fork_and_development_chain() {
        let mut policy = policy();
        assert!(policy.validate(MAINNET_CHAIN_ID).is_err());
        assert!(policy.validate(MODERATO_CHAIN_ID).is_err());
        assert!(policy.validate(12345).is_ok());
        policy.activation = TempoHardfork::T12;
        assert!(policy.validate(12345).is_err());
    }
    #[test]
    fn unavailable_policy_wrong_portal_and_early_fork_reject() {
        let mut call = super::super::tests::call();
        call.verifierConfig = Bytes::from_static(&[3]);
        let portal = portal_address(call.zoneId);
        let mut storage = HashMapStorageProvider::new_with_spec(12345, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || {
            let verifier = ZoneVerifier::new();
            assert!(!verifier.verify_tdx(portal, &call, None).unwrap());
            assert!(!verifier.verify_tdx(portal, &call, Some(&policy())).unwrap());
        });
        let mut storage = HashMapStorageProvider::new_with_spec(12345, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let verifier = ZoneVerifier::new();
            assert!(
                !verifier
                    .verify_tdx(Address::ZERO, &call, Some(&policy()))
                    .unwrap()
            );
            assert!(!verifier.verify_tdx(portal, &call, Some(&policy())).unwrap());
            call.proof = vec![0; tempo_tdx_attestation::MAX_EVIDENCE_BYTES + 1].into();
            assert!(!verifier.verify_tdx(portal, &call, Some(&policy())).unwrap());
        });
    }
}
