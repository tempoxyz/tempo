use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IZoneVerifier;

use crate::{Precompile, charge_input_cost, dispatch, view};

use super::ZoneVerifier;

// selector + 17 static ABI words + one-byte config tail + maximum proof tail.
const MAX_CALLDATA_LEN: usize =
    4 + 17 * 32 + 2 * 32 + 32 + tempo_nitro_attestation::MAX_DOCUMENT_SIZE;

impl Precompile for ZoneVerifier {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut self.storage, calldata) {
            return error;
        }
        if calldata.len() > MAX_CALLDATA_LEN
            && calldata.starts_with(&IZoneVerifier::verifyCall::SELECTOR)
        {
            return Ok(self
                .storage
                .success_output(IZoneVerifier::verifyCall::abi_encode_returns(&false).into()));
        }

        dispatch!(
            calldata,
            |call| match call {
                IZoneVerifier::IZoneVerifierCalls {
                    verify(call) => view(call, |call| self.verify(msg_sender, call)),
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy::primitives::{B256, Bytes, U256};
    use tempo_chainspec::hardfork::TempoHardfork;

    fn call(proof: Vec<u8>) -> IZoneVerifier::verifyCall {
        IZoneVerifier::verifyCall {
            zoneId: 1,
            tempoBlockNumber: 1,
            anchorBlockNumber: 1,
            anchorBlockHash: B256::ZERO,
            expectedWithdrawalBatchIndex: 0,
            nextZoneHeight: U256::ZERO,
            blockTransition: IZoneVerifier::BlockTransition {
                prevBlockHash: B256::ZERO,
                nextBlockHash: B256::ZERO,
            },
            depositQueueTransition: IZoneVerifier::DepositQueueTransition {
                prevProcessedHash: B256::ZERO,
                nextProcessedHash: B256::ZERO,
                prevDepositNumber: 0,
                nextDepositNumber: 0,
            },
            tokenEnablementTransition: IZoneVerifier::TokenEnablementTransition {
                prevProcessedTokenCount: 0,
                nextProcessedTokenCount: 0,
            },
            withdrawalQueueHash: B256::ZERO,
            verifierConfig: Bytes::from_static(&[1]),
            proof: proof.into(),
        }
    }

    #[test]
    fn empty_and_oversized_proofs_return_false() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            for call in [
                call(Vec::new()),
                call(vec![0; tempo_nitro_attestation::MAX_DOCUMENT_SIZE + 1]),
            ] {
                let output = ZoneVerifier::new()
                    .call(
                        &call.abi_encode(),
                        crate::zone_factory::portal_address(call.zoneId),
                    )
                    .unwrap();
                assert!(output.is_success());
                assert!(!IZoneVerifier::verifyCall::abi_decode_returns(&output.bytes).unwrap());
            }
        });
    }

    #[test]
    fn calldata_limit_applies_before_decoding() {
        let call = call(vec![0; tempo_nitro_attestation::MAX_DOCUMENT_SIZE]);
        let portal = crate::zone_factory::portal_address(call.zoneId);
        let mut calldata = call.abi_encode();
        assert_eq!(calldata.len(), 25_220);

        // Corrupt the final head word (the proof offset). At the exact maximum
        // length this must reach ABI decoding and revert; one extra byte must
        // take the oversized-input path and return false before decoding.
        calldata[4 + 16 * 32..4 + 17 * 32].fill(0xff);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            assert!(
                ZoneVerifier::new()
                    .call(&calldata, portal)
                    .unwrap()
                    .is_revert()
            );

            calldata.push(0);
            let output = ZoneVerifier::new().call(&calldata, portal).unwrap();
            assert!(output.is_success());
            assert!(!IZoneVerifier::verifyCall::abi_decode_returns(&output.bytes).unwrap());
        });
    }

    #[test]
    fn height_free_selector_is_rejected() {
        let call = call(Vec::new());
        let mut calldata = call.abi_encode();
        calldata[..4].copy_from_slice(&[0xe5, 0x7a, 0x63, 0x66]);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let output = ZoneVerifier::new()
                .call(&calldata, crate::zone_factory::portal_address(call.zoneId))
                .unwrap();
            assert!(output.is_revert());
        });
    }
}
