//! TIP-1098 native Nitro-backed Zone verifier.

mod attestation;
pub mod dispatch;

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol_types::SolValue,
};
use tempo_contracts::precompiles::{IZoneVerifier, ZONE_VERIFIER_ADDRESS};
use tempo_precompiles_macros::contract;

use crate::error::Result;

use self::attestation::{AWS_NITRO_ROOT_DER, AttestationError, verify_attestation_with_root};

const CONFIG_V1: &[u8] = &[1];
const MAX_FUTURE_SKEW_MILLIS: u64 = 300_000;

/// Measurements for the T11 EIF built from `tempoxyz/zones` PR 1258 at commit
/// `b1fb22706409e730b6863b8b3da6e7fef517a0f7`.
const APPROVED_PCRS: Option<[[u8; 48]; 3]> = Some([
    alloy::primitives::hex!(
        "b4f039505618f3da8ca8884a048bcee39864b7ad8b861f48e9abb313ee3f32d0f80df102baf45f00e60ddc1cc8a2a768"
    ),
    alloy::primitives::hex!(
        "baa774ff6af9362bc5c4ecafa99c98c371d3d1e1e040e99890b9ba13d81ded18408fa2a65affa148ee2aaafa09142c81"
    ),
    alloy::primitives::hex!(
        "e98c7b002bc4d34cfe39149b69cac66b1adf2fca340e32112bc4e13125f2921f3e567b4a032778d6b42db1a489131d1d"
    ),
]);

const BATCH_ATTESTATION_TYPE: &str = "NitroBatchAttestation(uint256 parentChainId,address verifier,address portal,uint32 zoneId,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,uint64 expectedWithdrawalBatchIndex,bytes32 prevBlockHash,bytes32 nextBlockHash,bytes32 prevProcessedHash,bytes32 nextProcessedHash,uint64 prevDepositNumber,uint64 nextDepositNumber,uint64 prevProcessedTokenCount,uint64 nextProcessedTokenCount,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)";

#[contract(addr = ZONE_VERIFIER_ADDRESS)]
pub struct ZoneVerifier {}

impl ZoneVerifier {
    pub fn verify(&mut self, portal: Address, call: IZoneVerifier::verifyCall) -> Result<bool> {
        self.verify_with_policy(portal, call, AWS_NITRO_ROOT_DER, APPROVED_PCRS)
    }

    fn verify_with_policy(
        &mut self,
        portal: Address,
        call: IZoneVerifier::verifyCall,
        root_der: &[u8],
        approved_pcrs: Option<[[u8; 48]; 3]>,
    ) -> Result<bool> {
        if call.verifierConfig.as_ref() != CONFIG_V1 || call.proof.is_empty() {
            return Ok(false);
        }

        let block_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let attestation = match verify_attestation_with_root(
            &mut self.storage,
            call.proof.as_ref(),
            block_timestamp,
            root_der,
        ) {
            Ok(attestation) => attestation,
            Err(AttestationError::OutOfGas) => {
                return Err(crate::error::TempoPrecompileError::OutOfGas);
            }
            Err(_) => return Ok(false),
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

        let max_timestamp = self
            .storage
            .timestamp()
            .saturating_to::<u64>()
            .saturating_mul(1_000)
            .saturating_add(MAX_FUTURE_SKEW_MILLIS);
        if attestation.timestamp > max_timestamp || attestation.user_data.len() != 32 {
            return Ok(false);
        }

        let commitment = batch_commitment(self.storage.chain_id(), portal, &call);
        Ok(attestation.user_data.as_slice() == commitment.as_slice())
    }
}

fn batch_commitment(chain_id: u64, portal: Address, call: &IZoneVerifier::verifyCall) -> B256 {
    keccak256(
        (
            keccak256(BATCH_ATTESTATION_TYPE),
            U256::from(chain_id),
            ZONE_VERIFIER_ADDRESS,
            portal,
            call.zoneId,
            call.tempoBlockNumber,
            call.anchorBlockNumber,
            call.anchorBlockHash,
            call.expectedWithdrawalBatchIndex,
            call.blockTransition.prevBlockHash,
            call.blockTransition.nextBlockHash,
            call.depositQueueTransition.prevProcessedHash,
            call.depositQueueTransition.nextProcessedHash,
            call.depositQueueTransition.prevDepositNumber,
            call.depositQueueTransition.nextDepositNumber,
            call.tokenEnablementTransition.prevProcessedTokenCount,
            call.tokenEnablementTransition.nextProcessedTokenCount,
            call.withdrawalQueueHash,
            keccak256(&call.verifierConfig),
        )
            .abi_encode(),
    )
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
            [0xe5, 0x7a, 0x63, 0x66]
        );
        assert_eq!(
            keccak256(BATCH_ATTESTATION_TYPE),
            B256::from(alloy::primitives::hex!(
                "d09980465a50a967b8b5b35dc6b3d8f9eb9245916e285a7555f3937ceda0ac68"
            ))
        );
        assert_eq!(
            batch_commitment(
                42_431,
                Address::from([0x11; 20]),
                &call(),
            ),
            B256::from(alloy::primitives::hex!(
                "764c1f24b00b253ae1a06fe31ba8858a2352e9350e09a6c6028bea47233c0cb9"
            ))
        );
    }

    #[test]
    fn batch_commitment_binds_all_fields() {
        let portal = Address::repeat_byte(0x77);
        let original = call();
        let expected = batch_commitment(1, portal, &original);
        assert_ne!(batch_commitment(2, portal, &original), expected);
        assert_ne!(
            batch_commitment(1, Address::repeat_byte(0x78), &original),
            expected
        );

        let mutations: [fn(&mut IZoneVerifier::verifyCall); 15] = [
            |call| call.zoneId += 1,
            |call| call.tempoBlockNumber += 1,
            |call| call.anchorBlockNumber += 1,
            |call| call.anchorBlockHash[0] ^= 1,
            |call| call.expectedWithdrawalBatchIndex += 1,
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
                batch_commitment(1, portal, &changed),
                expected,
                "field mutation {index} was not bound"
            );
        }
    }

    #[test]
    fn valid_attestation_binds_every_zone_input() {
        let portal = Address::repeat_byte(0x77);
        let mut call = call();
        let commitment = batch_commitment(1, portal, &call);
        let (proof, root, pcrs) = attestation::tests::fixture(commitment.as_ref());
        call.proof = proof.into();

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        storage.set_timestamp(U256::from(BLOCK_TIMESTAMP));
        StorageCtx::enter(&mut storage, || {
            let mut verifier = ZoneVerifier::new();
            assert!(
                verifier
                    .verify_with_policy(portal, call.clone(), &root, Some(pcrs))
                    .unwrap()
            );

            let mut altered = call.clone();
            altered.anchorBlockNumber += 1;
            assert!(
                !verifier
                    .verify_with_policy(portal, altered, &root, Some(pcrs))
                    .unwrap()
            );
            assert!(
                !verifier
                    .verify_with_policy(portal, call, &root, None)
                    .unwrap()
            );
        });
    }

    #[test]
    fn future_skew_boundary_is_inclusive() {
        let portal = Address::repeat_byte(0x77);
        let call = call();
        let commitment = batch_commitment(1, portal, &call);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
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
}
