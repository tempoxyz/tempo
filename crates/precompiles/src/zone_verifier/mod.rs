//! TIP-1098 native Nitro-backed Zone verifier.

#[cfg(test)]
mod attestation;
pub mod dispatch;

#[cfg(test)]
use crate::zone_factory::portal_address;
use crate::{error::Result, storage::StorageCtx};
use alloy::primitives::Address;
#[cfg(test)]
use alloy::{
    primitives::{B256, U256, keccak256},
    sol_types::SolStruct,
};
#[cfg(test)]
use tempo_contracts::precompiles::NitroBatchAttestation;
use tempo_contracts::precompiles::{IZoneVerifier, ZONE_VERIFIER_ADDRESS};
use tempo_precompiles_macros::contract;
use tempo_zone_verifier::AWS_NITRO_ROOT_DER;
#[cfg(test)]
use tempo_zone_verifier::{CONFIG_V1, MAX_FUTURE_SKEW_MILLIS, batch_commitment};

/// Production measurements remain deliberately unset until the reproducible T13 EIF is finalized.
const APPROVED_PCRS: Option<[[u8; 48]; 3]> = None;

#[contract(addr = ZONE_VERIFIER_ADDRESS)]
pub struct ZoneVerifier {}

impl ZoneVerifier {
    pub fn verify(&self, portal: Address, call: IZoneVerifier::verifyCall) -> Result<bool> {
        self.verify_with_policy(portal, call, AWS_NITRO_ROOT_DER, APPROVED_PCRS)
    }

    fn verify_with_policy(
        &self,
        portal: Address,
        call: IZoneVerifier::verifyCall,
        root_der: &[u8],
        approved_pcrs: Option<[[u8; 48]; 3]>,
    ) -> Result<bool> {
        tempo_zone_verifier::verify_with_root(
            self.storage.chain_id(),
            self.storage.timestamp().saturating_to::<u64>(),
            portal,
            &call,
            root_der,
            approved_pcrs,
            |gas| StorageCtx.deduct_gas(gas),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::{primitives::Bytes, sol_types::SolCall};
    use tempo_chainspec::hardfork::TempoHardfork;

    const BLOCK_TIMESTAMP: u64 = attestation::tests::BLOCK_TIMESTAMP;

    fn call() -> IZoneVerifier::verifyCall {
        IZoneVerifier::verifyCall {
            zoneId: 12,
            tempoBlockNumber: 9,
            anchorBlockNumber: 10,
            anchorBlockHash: B256::with_last_byte(11),
            expectedWithdrawalBatchIndex: 13,
            nextZoneHeight: U256::from(14),
            blockTransition: IZoneVerifier::BlockTransition {
                prevBlockHash: B256::with_last_byte(1),
                nextBlockHash: B256::with_last_byte(2),
            },
            depositQueueTransition: IZoneVerifier::DepositQueueTransition {
                prevProcessedHash: B256::with_last_byte(3),
                nextProcessedHash: B256::with_last_byte(4),
                prevDepositNumber: 5,
                nextDepositNumber: 6,
            },
            tokenEnablementTransition: IZoneVerifier::TokenEnablementTransition {
                prevProcessedTokenCount: 7,
                nextProcessedTokenCount: 8,
            },
            withdrawalQueueHash: B256::with_last_byte(9),
            verifierConfig: Bytes::from_static(CONFIG_V1),
            proof: Bytes::new(),
        }
    }

    #[test]
    fn batch_commitment_type_hash_is_stable() {
        assert_eq!(
            IZoneVerifier::verifyCall::SELECTOR,
            [0xeb, 0xb2, 0xdd, 0xc9]
        );
        assert_eq!(
            keccak256(NitroBatchAttestation::eip712_encode_type().as_bytes()),
            B256::from(alloy::primitives::hex!(
                "b6f39555cba9bf38842c669ea0c90bca6aad793881d75a0034e33352fbecb25e"
            ))
        );
        assert_eq!(
            batch_commitment(42_431, &call()),
            B256::from(alloy::primitives::hex!(
                "1a703e80dd395e4720d1c88c877ed9f7d77c03052a985133b25cbf3e2b745b9d"
            ))
        );
    }

    #[test]
    fn batch_commitment_binds_all_fields() {
        let original = call();
        let expected = batch_commitment(1, &original);
        assert_ne!(batch_commitment(2, &original), expected);

        let mutations: [fn(&mut IZoneVerifier::verifyCall); 16] = [
            |call| call.zoneId += 1,
            |call| call.tempoBlockNumber += 1,
            |call| call.anchorBlockNumber += 1,
            |call| call.anchorBlockHash[0] ^= 1,
            |call| call.expectedWithdrawalBatchIndex += 1,
            |call| call.nextZoneHeight += U256::ONE,
            |call| call.blockTransition.prevBlockHash[0] ^= 1,
            |call| call.blockTransition.nextBlockHash[0] ^= 1,
            |call| call.depositQueueTransition.prevProcessedHash[0] ^= 1,
            |call| call.depositQueueTransition.nextProcessedHash[0] ^= 1,
            |call| call.depositQueueTransition.prevDepositNumber += 1,
            |call| call.depositQueueTransition.nextDepositNumber += 1,
            |call| call.tokenEnablementTransition.prevProcessedTokenCount += 1,
            |call| call.tokenEnablementTransition.nextProcessedTokenCount += 1,
            |call| call.withdrawalQueueHash[0] ^= 1,
            |call| call.verifierConfig = Bytes::from_static(&[2]),
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(
                batch_commitment(1, &changed),
                expected,
                "field mutation {index} was not bound"
            );
        }
    }

    #[test]
    fn valid_attestation_binds_every_zone_input() {
        let mut call = call();
        let portal = portal_address(call.zoneId);
        let commitment = batch_commitment(1, &call);
        let (proof, root, pcrs) = attestation::tests::fixture(commitment.as_ref());
        call.proof = proof.into();

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        storage.set_timestamp(U256::from(BLOCK_TIMESTAMP));
        StorageCtx::enter(&mut storage, || {
            let verifier = ZoneVerifier::new();
            assert!(
                verifier
                    .verify_with_policy(portal, call.clone(), &root, Some(pcrs))
                    .unwrap()
            );

            for caller in [Address::repeat_byte(0x77), portal_address(call.zoneId + 1)] {
                assert!(
                    !verifier
                        .verify_with_policy(caller, call.clone(), &root, Some(pcrs))
                        .unwrap()
                );
            }

            let mut other_zone = call.clone();
            other_zone.zoneId += 1;
            assert!(
                !verifier
                    .verify_with_policy(
                        portal_address(other_zone.zoneId),
                        other_zone,
                        &root,
                        Some(pcrs),
                    )
                    .unwrap()
            );

            let mut altered = call.clone();
            altered.anchorBlockNumber += 1;
            assert!(
                !verifier
                    .verify_with_policy(portal, altered, &root, Some(pcrs))
                    .unwrap()
            );
            // Reusing the same proof must not let a quorum store a height different
            // from the executed header, including values that alias after u64 truncation.
            for height in [
                call.nextZoneHeight + U256::ONE,
                call.nextZoneHeight + (U256::ONE << 64),
                U256::MAX,
            ] {
                let mut altered = call.clone();
                altered.nextZoneHeight = height;
                assert!(
                    !verifier
                        .verify_with_policy(portal, altered, &root, Some(pcrs))
                        .unwrap(),
                    "accepted a proof for a different Zone height: {height}"
                );
            }
            assert!(
                !verifier
                    .verify_with_policy(portal, call, &root, None)
                    .unwrap()
            );
        });
    }

    #[test]
    fn future_skew_boundary_is_inclusive() {
        let call = call();
        let portal = portal_address(call.zoneId);
        let commitment = batch_commitment(1, &call);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        storage.set_timestamp(U256::from(BLOCK_TIMESTAMP));
        StorageCtx::enter(&mut storage, || {
            for (skew, expected) in [
                (MAX_FUTURE_SKEW_MILLIS, true),
                (MAX_FUTURE_SKEW_MILLIS + 1, false),
            ] {
                let (proof, root, pcrs) = attestation::tests::fixture_at(
                    commitment.as_ref(),
                    BLOCK_TIMESTAMP * 1_000 + skew,
                );
                let mut candidate = call.clone();
                candidate.proof = proof.into();
                assert_eq!(
                    ZoneVerifier::new()
                        .verify_with_policy(portal, candidate, &root, Some(pcrs))
                        .unwrap(),
                    expected
                );
            }
        });
    }

    #[test]
    fn local_observer_uses_native_policy_without_fork_activation() {
        let mut call = call();
        let portal = portal_address(call.zoneId);
        assert_eq!(portal, tempo_zone_verifier::portal_address(call.zoneId));
        let commitment = batch_commitment(1, &call);
        let (proof, root, pcrs) = attestation::tests::fixture(commitment.as_ref());
        call.proof = proof.into();
        // No EVM, StorageCtx, precompile registration, or activated T13 is needed by the observer.
        let verify = |chain_id, measurements| {
            tempo_zone_verifier::verify_with_root(
                chain_id,
                BLOCK_TIMESTAMP,
                portal,
                &call,
                &root,
                measurements,
                |_| Ok::<_, ()>(()),
            )
            .unwrap()
        };
        assert!(verify(1, Some(pcrs)));
        assert!(!verify(2, Some(pcrs)));
        assert!(!verify(1, None));
        for index in 0..3 {
            let mut wrong_pcrs = pcrs;
            wrong_pcrs[index][0] ^= 1;
            assert!(!verify(1, Some(wrong_pcrs)));
        }
    }
}
