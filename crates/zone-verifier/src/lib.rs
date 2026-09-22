//! The ZoneVerifier's verification logic, shared by the native precompile and shadow observers.
//!
//! Observers supply independently pinned PCR measurements and a trusted parent-chain ID and
//! verification timestamp. Calling this library does not activate a fork or settle a batch.

mod attestation;

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::SolStruct;
pub use attestation::{AWS_NITRO_ROOT_DER, BASE_GAS, SIGNATURE_GAS, verify_attestation_with_root};
pub use tempo_contracts::precompiles::{
    IZoneVerifier, NitroBatchAttestation, ZONE_VERIFIER_ADDRESS,
};

/// PCR0, PCR1 and PCR2 of an independently approved enclave image, in that order.
pub type ApprovedPcrs = [[u8; 48]; 3];
/// The supported Nitro proof configuration.
pub const CONFIG_V1: &[u8] = &[1];
/// Maximum future skew accepted by the native verifier.
pub const MAX_FUTURE_SKEW_MILLIS: u64 = 300_000;

/// Verify using the AWS trust root and an explicit measurement policy.
///
/// `charge_gas` preserves the native precompile's parse/verification charging order. An observer
/// may supply a bounded local budget. None of these arguments may be trusted from the prover.
pub fn verify<E>(
    chain_id: u64,
    timestamp: u64,
    caller: Address,
    call: &IZoneVerifier::verifyCall,
    approved_pcrs: Option<ApprovedPcrs>,
    charge_gas: impl FnMut(u64) -> Result<(), E>,
) -> Result<bool, E> {
    verify_with_root(
        chain_id,
        timestamp,
        caller,
        call,
        AWS_NITRO_ROOT_DER,
        approved_pcrs,
        charge_gas,
    )
}

/// Verify against an explicitly trusted root. Production callers should use [`verify`].
/// This entry point also lets the precompile's existing synthetic-certificate tests exercise
/// exactly the implementation used by observers.
#[allow(clippy::too_many_arguments)]
pub fn verify_with_root<E>(
    chain_id: u64,
    timestamp: u64,
    caller: Address,
    call: &IZoneVerifier::verifyCall,
    root_der: &[u8],
    approved_pcrs: Option<ApprovedPcrs>,
    charge_gas: impl FnMut(u64) -> Result<(), E>,
) -> Result<bool, E> {
    if caller != portal_address(call.zoneId)
        || call.verifierConfig.as_ref() != CONFIG_V1
        || call.proof.is_empty()
    {
        return Ok(false);
    }
    let Some(attestation) =
        verify_attestation_with_root(&call.proof, timestamp, root_der, charge_gas)?
    else {
        return Ok(false);
    };
    let Some(approved_pcrs) = approved_pcrs else {
        return Ok(false);
    };
    if !approved_pcrs.iter().enumerate().all(|(index, expected)| {
        attestation
            .pcrs
            .iter()
            .find(|pcr| usize::from(pcr.index) == index)
            .is_some_and(|pcr| pcr.value.as_slice() == expected)
    }) {
        return Ok(false);
    }
    let max_timestamp = timestamp
        .saturating_mul(1_000)
        .saturating_add(MAX_FUTURE_SKEW_MILLIS);
    if attestation.timestamp > max_timestamp || attestation.user_data.len() != 32 {
        return Ok(false);
    }
    Ok(attestation.user_data.as_slice() == batch_commitment(chain_id, call).as_slice())
}

/// Canonical caller domain for the Zone verifier.
pub fn portal_address(zone_id: u32) -> Address {
    // Same protocol address derivation as ZoneFactory, without an EVM dependency.
    let mut address = [0u8; 20];
    address[0] = 0x5a;
    address[1] = 0xd0;
    address[16..].copy_from_slice(&zone_id.to_be_bytes());
    Address::from(address)
}

/// Digest bound by the Nitro attestation's user_data.
pub fn batch_commitment(chain_id: u64, call: &IZoneVerifier::verifyCall) -> B256 {
    NitroBatchAttestation {
        parentChainId: U256::from(chain_id),
        verifier: ZONE_VERIFIER_ADDRESS,
        zoneId: call.zoneId,
        tempoBlockNumber: call.tempoBlockNumber,
        anchorBlockNumber: call.anchorBlockNumber,
        anchorBlockHash: call.anchorBlockHash,
        expectedWithdrawalBatchIndex: call.expectedWithdrawalBatchIndex,
        nextZoneHeight: call.nextZoneHeight,
        prevBlockHash: call.blockTransition.prevBlockHash,
        nextBlockHash: call.blockTransition.nextBlockHash,
        prevProcessedHash: call.depositQueueTransition.prevProcessedHash,
        nextProcessedHash: call.depositQueueTransition.nextProcessedHash,
        prevDepositNumber: call.depositQueueTransition.prevDepositNumber,
        nextDepositNumber: call.depositQueueTransition.nextDepositNumber,
        prevProcessedTokenCount: call.tokenEnablementTransition.prevProcessedTokenCount,
        nextProcessedTokenCount: call.tokenEnablementTransition.nextProcessedTokenCount,
        withdrawalQueueHash: call.withdrawalQueueHash,
        verifierConfigHash: keccak256(&call.verifierConfig),
    }
    .eip712_hash_struct()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn fixture() -> Vec<u8> {
        let encoded: String =
            include_str!("../../nitro-attestation/testdata/aws_attestation_2026_01_03.b64")
                .split_whitespace()
                .collect();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap()
    }

    #[test]
    fn verifies_real_nitro_document_and_charges_before_crypto() {
        let proof = fixture();
        let mut charges = Vec::new();
        let result =
            verify_attestation_with_root(&proof, 1_767_472_867, AWS_NITRO_ROOT_DER, |gas| {
                charges.push(gas);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(result.is_some());
        assert_eq!(charges[0], BASE_GAS);
        assert_eq!(charges.len(), 2);
        assert!(charges[1] >= SIGNATURE_GAS);
        let result =
            verify_attestation_with_root(&proof, 1_767_472_867, AWS_NITRO_ROOT_DER, |_| {
                Err("out of gas")
            });
        assert_eq!(result.unwrap_err(), "out of gas");
    }

    #[test]
    fn rejects_changed_document_and_untrusted_root() {
        let mut proof = fixture();
        let result =
            verify_attestation_with_root(&proof, 1_767_472_867, &[], |_| Ok::<_, ()>(())).unwrap();
        assert!(result.is_none());
        let last = proof.len() - 1;
        proof[last] ^= 1;
        let result =
            verify_attestation_with_root(&proof, 1_767_472_867, AWS_NITRO_ROOT_DER, |_| {
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn caller_domain_uses_canonical_portal() {
        assert_eq!(
            portal_address(2),
            alloy_primitives::address!("5ad0000000000000000000000000000000000002")
        );
        assert_eq!(
            portal_address(u32::MAX),
            alloy_primitives::address!("5ad00000000000000000000000000000ffffffff")
        );
    }
}
