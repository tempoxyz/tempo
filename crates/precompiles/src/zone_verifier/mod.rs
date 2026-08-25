//! TIP-1098 native Nitro-backed Zone verifier.

mod attestation;
pub mod dispatch;

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolValue,
};
use tempo_contracts::precompiles::{IZoneVerifier, ZONE_VERIFIER_ADDRESS};
use tempo_precompiles_macros::contract;

use crate::error::Result;

use self::attestation::{AWS_NITRO_ROOT_DER, AttestationError, verify_attestation_with_root};

const CONFIG_V1: &[u8] = &[1];
const MAX_FUTURE_SKEW_MILLIS: u64 = 300_000;

/// Measurements for the T11 EIF built from `tempoxyz/zones` PR 1258 at merge commit
/// `4e58b924224b89e705c74aa41ad2b9d33b63b2f4`.
const APPROVED_PCRS: Option<[[u8; 48]; 3]> = Some([
    alloy::primitives::hex!(
        "aacfa461849093d9b9eb1a652787352eb5ebe2e24b9efc4a605fc3699aab5e5503cd2e23c5f0ba01781fa361f3e97d27"
    ),
    alloy::primitives::hex!(
        "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"
    ),
    alloy::primitives::hex!(
        "00a45c0d7641c9bf4c90369f03034a3d71ed47f2e115985315f962a52a00bcd46f1b8b14b6dcef58904c3109aedfa444"
    ),
]);

const BATCH_ATTESTATION_TYPE: &str = "NitroBatchAttestation(uint256 parentChainId,address verifier,address portal,uint32 zoneId,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,uint64 expectedWithdrawalBatchIndex,bytes32 prevBlockHash,bytes32 nextBlockHash,bytes32 prevProcessedHash,bytes32 nextProcessedHash,uint64 prevDepositNumber,uint64 nextDepositNumber,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)";

/// Detailed result of evaluating a Zone verifier call.
///
/// The ABI deliberately collapses every policy rejection to `false`. This type is for offline
/// diagnostics and is not returned by the consensus precompile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneVerifierDiagnostic {
    Valid,
    InvalidConfiguration {
        actual: Bytes,
    },
    EmptyProof,
    InvalidAttestation(tempo_nitro_attestation::Error),
    MissingApprovedPcrs,
    PcrMismatch {
        index: usize,
        expected: [u8; 48],
        actual: Option<Vec<u8>>,
    },
    FutureAttestation {
        timestamp: u64,
        maximum_timestamp: u64,
    },
    InvalidUserDataLength {
        actual: usize,
    },
    CommitmentMismatch {
        expected: B256,
        actual: Bytes,
    },
}

impl ZoneVerifierDiagnostic {
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[contract(addr = ZONE_VERIFIER_ADDRESS)]
pub struct ZoneVerifier {}

impl ZoneVerifier {
    pub fn verify(&mut self, portal: Address, call: IZoneVerifier::verifyCall) -> Result<bool> {
        self.verify_with_policy(portal, call, AWS_NITRO_ROOT_DER, APPROVED_PCRS)
    }

    /// Runs the production verifier policy while retaining its rejection reason.
    pub fn diagnose(
        &mut self,
        portal: Address,
        call: IZoneVerifier::verifyCall,
    ) -> Result<ZoneVerifierDiagnostic> {
        self.diagnose_with_policy(portal, call, AWS_NITRO_ROOT_DER, APPROVED_PCRS)
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
            &call.proof,
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

    fn diagnose_with_policy(
        &mut self,
        portal: Address,
        call: IZoneVerifier::verifyCall,
        root_der: &[u8],
        approved_pcrs: Option<[[u8; 48]; 3]>,
    ) -> Result<ZoneVerifierDiagnostic> {
        if call.verifierConfig.as_ref() != CONFIG_V1 {
            return Ok(ZoneVerifierDiagnostic::InvalidConfiguration {
                actual: call.verifierConfig,
            });
        }
        if call.proof.is_empty() {
            return Ok(ZoneVerifierDiagnostic::EmptyProof);
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
            Err(AttestationError::Validation(error)) => {
                return Ok(ZoneVerifierDiagnostic::InvalidAttestation(error));
            }
        };

        let Some(approved_pcrs) = approved_pcrs else {
            return Ok(ZoneVerifierDiagnostic::MissingApprovedPcrs);
        };
        for (index, expected) in approved_pcrs.iter().enumerate() {
            let actual = attestation
                .pcrs
                .iter()
                .find(|pcr| usize::from(pcr.index) == index)
                .map(|pcr| pcr.value.clone());
            if actual.as_deref() != Some(expected.as_slice()) {
                return Ok(ZoneVerifierDiagnostic::PcrMismatch {
                    index,
                    expected: *expected,
                    actual,
                });
            }
        }

        let max_timestamp = self
            .storage
            .timestamp()
            .saturating_to::<u64>()
            .saturating_mul(1_000)
            .saturating_add(MAX_FUTURE_SKEW_MILLIS);
        if attestation.timestamp > max_timestamp {
            return Ok(ZoneVerifierDiagnostic::FutureAttestation {
                timestamp: attestation.timestamp,
                maximum_timestamp: max_timestamp,
            });
        }
        if attestation.user_data.len() != 32 {
            return Ok(ZoneVerifierDiagnostic::InvalidUserDataLength {
                actual: attestation.user_data.len(),
            });
        }

        let commitment = batch_commitment(self.storage.chain_id(), portal, &call);
        if attestation.user_data.as_slice() != commitment.as_slice() {
            return Ok(ZoneVerifierDiagnostic::CommitmentMismatch {
                expected: commitment,
                actual: attestation.user_data.into(),
            });
        }

        Ok(ZoneVerifierDiagnostic::Valid)
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
            zoneId: 7,
            tempoBlockNumber: 100,
            anchorBlockNumber: 99,
            anchorBlockHash: B256::repeat_byte(0x21),
            expectedWithdrawalBatchIndex: 3,
            blockTransition: IZoneVerifier::BlockTransition {
                prevBlockHash: B256::repeat_byte(0x31),
                nextBlockHash: B256::repeat_byte(0x32),
            },
            depositQueueTransition: IZoneVerifier::DepositQueueTransition {
                prevProcessedHash: B256::repeat_byte(0x41),
                nextProcessedHash: B256::repeat_byte(0x42),
                prevDepositNumber: 4,
                nextDepositNumber: 9,
            },
            withdrawalQueueHash: B256::repeat_byte(0x51),
            verifierConfig: Bytes::from_static(CONFIG_V1),
            proof: Bytes::new(),
        }
    }

    #[test]
    fn batch_commitment_type_hash_is_stable() {
        assert_eq!(
            IZoneVerifier::verifyCall::SELECTOR,
            [0x71, 0x06, 0xa4, 0x3e]
        );
        assert_eq!(
            keccak256(BATCH_ATTESTATION_TYPE),
            B256::from(alloy::primitives::hex!(
                "2499a8e67450aa54a0f713d04bc99117224746a9b4c56cadc6b2ac87234573d7"
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

        let mutations: [fn(&mut IZoneVerifier::verifyCall); 13] = [
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
            assert_eq!(
                verifier
                    .diagnose_with_policy(portal, call.clone(), &root, Some(pcrs))
                    .unwrap(),
                ZoneVerifierDiagnostic::Valid
            );

            let mut altered = call.clone();
            altered.anchorBlockNumber += 1;
            assert!(
                !verifier
                    .verify_with_policy(portal, altered.clone(), &root, Some(pcrs))
                    .unwrap()
            );
            assert!(matches!(
                verifier
                    .diagnose_with_policy(portal, altered, &root, Some(pcrs))
                    .unwrap(),
                ZoneVerifierDiagnostic::CommitmentMismatch { .. }
            ));
            assert!(
                !verifier
                    .verify_with_policy(portal, call.clone(), &root, None)
                    .unwrap()
            );
            assert_eq!(
                verifier
                    .diagnose_with_policy(portal, call, &root, None)
                    .unwrap(),
                ZoneVerifierDiagnostic::MissingApprovedPcrs
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
                        .verify_with_policy(portal, candidate.clone(), &root, Some(pcrs))
                        .unwrap(),
                    expected
                );
                let diagnostic = ZoneVerifier::new()
                    .diagnose_with_policy(portal, candidate, &root, Some(pcrs))
                    .unwrap();
                assert_eq!(diagnostic.is_valid(), expected);
                if !expected {
                    assert!(matches!(
                        diagnostic,
                        ZoneVerifierDiagnostic::FutureAttestation { .. }
                    ));
                }
            }
        });
    }
}
