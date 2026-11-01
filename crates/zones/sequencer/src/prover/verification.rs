//! Proof checks shared by settlement and shadow proving.

use alloy_contract::CallBuilder;
use alloy_primitives::U256;
use alloy_provider::DynProvider;
use alloy_sol_types::SolCall as _;
use eyre::{Context as _, Result};
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::IZoneVerifier;
use tempo_precompiles::zone_factory::portal_address;
use zone_chainspec::ZoneChainSpec;
use zone_prover::{ProofBundle, ShadowProofVerifier};
use zone_spf::{BatchOutput, PublicInputs};

use crate::{SettlementAbi, abi::ZonePortal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProofVerification {
    Verified,
    Rejected,
    SkippedBeforeT13,
}

/// Apply the local PCR policy when supplied, otherwise simulate the deployed L1 verifier.
/// The call's commitments were checked against the expected batch before reaching this point.
pub(super) async fn verify_proof(
    provider: &DynProvider<TempoNetwork>,
    chain_spec: &ZoneChainSpec,
    local: Option<&ShadowProofVerifier>,
    parent_chain_id: u64,
    call: IZoneVerifier::verifyCall,
) -> Result<ProofVerification> {
    let accepted = if let Some(verifier) = local {
        let verifier = verifier.clone();
        tokio::task::spawn_blocking(move || verifier.verify(call, parent_chain_id))
            .await
            .wrap_err("proof verification worker panicked")?
            .wrap_err("local proof verification failed")?
    } else {
        if SettlementAbi::from_l1(provider, chain_spec).await? != SettlementAbi::T13 {
            return Ok(ProofVerification::SkippedBeforeT13);
        }
        let portal_address = portal_address(call.zoneId);
        // Refresh the verifier each time: the portal's verifier can change independently of PCRs.
        let verifier = ZonePortal::new(portal_address, provider)
            .verifier()
            .call()
            .await
            .wrap_err("failed to read portal verifier")?;
        let output = CallBuilder::new_raw(provider, call.abi_encode().into())
            .to(verifier)
            .from(portal_address)
            .call()
            .await
            .wrap_err("verifier call failed")?;
        IZoneVerifier::verifyCall::abi_decode_returns(&output)
            .wrap_err("failed to decode verifier response")?
    };
    Ok(if accepted {
        ProofVerification::Verified
    } else {
        ProofVerification::Rejected
    })
}

/// Build the verifier call from trusted public inputs and SPF output already compared with
/// the expected batch. Local verification and L1 simulation use this same commitment mapping.
pub(super) fn verifier_call(
    inputs: &PublicInputs,
    output: &BatchOutput,
    bundle: &ProofBundle,
) -> IZoneVerifier::verifyCall {
    IZoneVerifier::verifyCall {
        zoneId: inputs.zone_id,
        tempoBlockNumber: inputs.tempo_block_number,
        anchorBlockNumber: inputs.anchor_block_number,
        anchorBlockHash: inputs.anchor_block_hash,
        expectedWithdrawalBatchIndex: inputs.expected_withdrawal_batch_index,
        nextZoneHeight: U256::from(output.next_zone_height),
        blockTransition: output.block_transition.clone(),
        depositQueueTransition: output.deposit_queue_transition.clone(),
        tokenEnablementTransition: output.token_enablement_transition.clone(),
        withdrawalQueueHash: output.withdrawal_queue_hash,
        verifierConfig: bundle.verifier_config.clone(),
        proof: bundle.proof.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, Bytes};
    use alloy_provider::{Provider as _, ProviderBuilder};
    use alloy_sol_types::SolValue as _;
    use alloy_transport::mock::Asserter;
    use tempo_chainspec::hardfork::TempoHardfork;
    use zone_chainspec::test_utils::set_tempo_fork;
    use zone_prover::VerifierMode;
    use zone_spf::{
        BlockTransition, DepositQueueTransition, LastBatchCommitment, TokenEnablementTransition,
    };

    fn chain_spec() -> ZoneChainSpec {
        let mut genesis = tempo_chainspec::spec::DEV.inner.genesis.clone();
        set_tempo_fork(&mut genesis, TempoHardfork::T13, 1_000);
        ZoneChainSpec {
            inner: std::sync::Arc::new(tempo_chainspec::TempoChainSpec::from_genesis(genesis)),
        }
    }

    fn fork_header(timestamp: u64) -> tempo_alloy::rpc::TempoHeaderResponse {
        tempo_alloy::rpc::TempoHeaderResponse {
            inner: alloy_rpc_types_eth::Header {
                hash: B256::ZERO,
                inner: tempo_primitives::TempoHeader {
                    inner: alloy_consensus::Header {
                        timestamp,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                total_difficulty: None,
                size: None,
            },
            timestamp_millis: 0,
        }
    }

    fn call() -> IZoneVerifier::verifyCall {
        verifier_call(
            &PublicInputs {
                parent_chain_id: 42431,
                zone_id: 42,
                tempo_block_number: 100,
                anchor_block_number: 150,
                anchor_block_hash: B256::repeat_byte(0xaa),
                expected_withdrawal_batch_index: 1,
            },
            &BatchOutput {
                next_zone_height: 20,
                block_transition: BlockTransition {
                    prevBlockHash: B256::repeat_byte(1),
                    nextBlockHash: B256::repeat_byte(2),
                },
                deposit_queue_transition: DepositQueueTransition {
                    prevProcessedHash: B256::ZERO,
                    nextProcessedHash: B256::ZERO,
                    prevDepositNumber: 0,
                    nextDepositNumber: 0,
                },
                token_enablement_transition: TokenEnablementTransition {
                    prevProcessedTokenCount: 0,
                    nextProcessedTokenCount: 0,
                },
                withdrawal_queue_hash: B256::ZERO,
                last_batch_commitment: LastBatchCommitment {
                    withdrawal_batch_index: 1,
                },
            },
            &ProofBundle {
                verifier_config: Bytes::from_static(VerifierMode::NitroV1.config()),
                proof: Bytes::from_static(&[1]),
            },
        )
    }

    fn provider(asserter: &Asserter) -> DynProvider<TempoNetwork> {
        ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased()
    }

    #[tokio::test]
    async fn proof_verification_skips_onchain_before_t13() {
        let rpc = Asserter::new();
        rpc.push_success(&fork_header(999));
        assert_eq!(
            verify_proof(&provider(&rpc), &chain_spec(), None, 42431, call())
                .await
                .unwrap(),
            ProofVerification::SkippedBeforeT13,
        );
        assert!(rpc.read_q().is_empty());
    }

    async fn verify_l1_response(
        response: Result<Bytes, &'static str>,
    ) -> Result<ProofVerification> {
        let rpc = Asserter::new();
        rpc.push_success(&fork_header(1_000));
        rpc.push_success(&Bytes::from(Address::repeat_byte(0x44).abi_encode()));
        match response {
            Ok(output) => rpc.push_success(&output),
            Err(message) => rpc.push_failure_msg(message),
        }
        let result = verify_proof(&provider(&rpc), &chain_spec(), None, 42431, call()).await;
        assert!(rpc.read_q().is_empty());
        result
    }

    #[tokio::test]
    async fn proof_verification_decodes_l1_verdicts_and_propagates_errors() {
        assert!(matches!(
            verify_l1_response(Ok(Bytes::from(true.abi_encode()))).await,
            Ok(ProofVerification::Verified)
        ));
        assert!(matches!(
            verify_l1_response(Ok(Bytes::from(false.abi_encode()))).await,
            Ok(ProofVerification::Rejected)
        ));
        for response in [Ok(Bytes::new()), Err("execution reverted: out of gas")] {
            assert!(verify_l1_response(response).await.is_err());
        }
    }

    #[tokio::test]
    async fn proof_verification_propagates_setup_failures() {
        for fail_verifier_lookup in [false, true] {
            let rpc = Asserter::new();
            if fail_verifier_lookup {
                rpc.push_success(&fork_header(1_000));
            }
            rpc.push_failure_msg("L1 unavailable");
            let error = verify_proof(&provider(&rpc), &chain_spec(), None, 42431, call())
                .await
                .unwrap_err();
            assert!(error.root_cause().to_string().contains("L1 unavailable"));
            assert!(rpc.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn proof_verification_with_pcrs_uses_local_verifier_without_l1_rpc() {
        let rpc = Asserter::new();
        // No responses are queued: local verification must not make any L1 RPC calls.
        let pcr = "11".repeat(48);
        let local: ShadowProofVerifier = format!("{pcr},{pcr},{pcr}").parse().unwrap();
        let verdict = verify_proof(&provider(&rpc), &chain_spec(), Some(&local), 42431, call())
            .await
            .unwrap();
        assert_eq!(verdict, ProofVerification::Rejected);
        assert!(rpc.read_q().is_empty());
        // Ensure the same native ABI carries the trusted batch and resolved anchor for both paths.
        let call = call();
        assert_eq!(
            IZoneVerifier::verifyCall::SELECTOR,
            [0xeb, 0xb2, 0xdd, 0xc9]
        );
        assert_eq!(
            (call.zoneId, call.anchorBlockNumber, call.anchorBlockHash),
            (42, 150, B256::repeat_byte(0xaa))
        );
        assert_eq!(call.nextZoneHeight, U256::from(20));
    }
    #[test]
    fn verifier_maps_batch_inputs_and_rejects_fake_proof() {
        let inputs = PublicInputs {
            parent_chain_id: 4217,
            zone_id: 2,
            tempo_block_number: 10,
            anchor_block_number: 11,
            anchor_block_hash: B256::repeat_byte(1),
            expected_withdrawal_batch_index: 12,
        };
        let output = BatchOutput {
            next_zone_height: 13,
            block_transition: BlockTransition {
                prevBlockHash: B256::repeat_byte(2),
                nextBlockHash: B256::repeat_byte(3),
            },
            deposit_queue_transition: DepositQueueTransition {
                prevProcessedHash: B256::repeat_byte(4),
                nextProcessedHash: B256::repeat_byte(5),
                prevDepositNumber: 14,
                nextDepositNumber: 15,
            },
            token_enablement_transition: TokenEnablementTransition {
                prevProcessedTokenCount: 16,
                nextProcessedTokenCount: 17,
            },
            withdrawal_queue_hash: B256::repeat_byte(6),
            last_batch_commitment: LastBatchCommitment {
                withdrawal_batch_index: 12,
            },
        };
        let bundle = ProofBundle {
            verifier_config: Bytes::from_static(&[1]),
            proof: Bytes::from_static(&[1, 2, 3]),
        };
        let call = verifier_call(&inputs, &output, &bundle);
        assert_eq!(call.zoneId, inputs.zone_id);
        assert_eq!(call.tempoBlockNumber, inputs.tempo_block_number);
        assert_eq!(call.anchorBlockNumber, inputs.anchor_block_number);
        assert_eq!(call.anchorBlockHash, inputs.anchor_block_hash);
        assert_eq!(
            call.expectedWithdrawalBatchIndex,
            inputs.expected_withdrawal_batch_index
        );
        assert_eq!(call.nextZoneHeight, U256::from(output.next_zone_height));
        assert_eq!(
            call.blockTransition.prevBlockHash,
            output.block_transition.prevBlockHash
        );
        assert_eq!(
            call.blockTransition.nextBlockHash,
            output.block_transition.nextBlockHash
        );
        assert_eq!(
            call.depositQueueTransition.prevProcessedHash,
            output.deposit_queue_transition.prevProcessedHash
        );
        assert_eq!(
            call.depositQueueTransition.nextProcessedHash,
            output.deposit_queue_transition.nextProcessedHash
        );
        assert_eq!(
            call.depositQueueTransition.prevDepositNumber,
            output.deposit_queue_transition.prevDepositNumber
        );
        assert_eq!(
            call.depositQueueTransition.nextDepositNumber,
            output.deposit_queue_transition.nextDepositNumber
        );
        assert_eq!(
            call.tokenEnablementTransition.prevProcessedTokenCount,
            output.token_enablement_transition.prevProcessedTokenCount
        );
        assert_eq!(
            call.tokenEnablementTransition.nextProcessedTokenCount,
            output.token_enablement_transition.nextProcessedTokenCount
        );
        assert_eq!(call.withdrawalQueueHash, output.withdrawal_queue_hash);
        assert_eq!(call.verifierConfig, bundle.verifier_config);
        assert_eq!(call.proof, bundle.proof);
        let pcr = "11".repeat(48);
        let verifier: ShadowProofVerifier = format!("{pcr},{pcr},{pcr}").parse().unwrap();
        assert!(!verifier.verify(call, inputs.parent_chain_id).unwrap());
    }
}
