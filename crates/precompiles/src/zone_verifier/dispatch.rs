use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IZoneVerifier;

use crate::{Precompile, charge_input_cost, dispatch, view};

use super::ZoneVerifier;

// selector + 14 static ABI words + one-byte config tail + maximum proof tail.
const MAX_CALLDATA_LEN: usize = 4 + 14 * 32 + 2 * 32 + 32 + super::attestation::MAX_DOCUMENT_LEN;

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
    use alloy::primitives::{B256, Bytes};
    use tempo_chainspec::hardfork::TempoHardfork;

    fn call(proof: Vec<u8>) -> IZoneVerifier::verifyCall {
        IZoneVerifier::verifyCall {
            zoneId: 1,
            tempoBlockNumber: 1,
            anchorBlockNumber: 1,
            anchorBlockHash: B256::ZERO,
            expectedWithdrawalBatchIndex: 0,
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
            withdrawalQueueHash: B256::ZERO,
            verifierConfig: Bytes::from_static(&[1]),
            proof: proof.into(),
        }
    }

    #[test]
    fn empty_and_oversized_proofs_return_false() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            for call in [
                call(Vec::new()),
                call(vec![0; super::super::attestation::MAX_DOCUMENT_LEN + 1]),
            ] {
                let output = ZoneVerifier::new()
                    .call(&call.abi_encode(), Address::repeat_byte(1))
                    .unwrap();
                assert!(output.is_success());
                assert!(!IZoneVerifier::verifyCall::abi_decode_returns(&output.bytes).unwrap());
            }
        });
    }
}
