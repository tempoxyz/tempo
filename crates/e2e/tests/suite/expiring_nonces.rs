use crate::{Setup, execution_runtime::TEST_MNEMONIC, setup_validators};
use alloy::{
    consensus::BlockHeader,
    eips::Encodable2718,
    network::ReceiptResponse,
    primitives::{Address, Bytes, TxKind, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{
        BlockOverrides, TransactionRequest,
        simulate::{SimBlock, SimulatePayload},
    },
    signers::{SignerSync, local::MnemonicBuilder},
};
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use tempo_alloy::{TempoNetwork, provider::TempoProviderExt, rpc::TempoTransactionRequest};
use tempo_primitives::{TempoTransaction, TempoTxEnvelope, transaction::Call};

#[test_traced("WARN")]
fn expiring_nonce_replay_is_rejected_after_execution_node_restart() {
    let _ = tempo_eyre::install();
    Runner::from(Config::default().with_seed(1009)).start(|mut context| async move {
        let setup = Setup::new(crate::VERIFICATION_MODE)
            .how_many_signers(1)
            .epoch_length(100)
            .seed(1009);
        let (mut nodes, execution_runtime) = setup_validators(&mut context, setup).await;
        nodes[0].start(&context).await;
        let url = nodes[0].execution().rpc_server_handle().http_url().unwrap();
        let raw = execution_runtime
            .run_async(async move {
                let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                    .connect_http(url.parse().unwrap());
                let latest = provider
                    .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
                    .await?
                    .unwrap();
                let signer = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
                let mut call = TempoTransactionRequest {
                    inner: TransactionRequest {
                        from: Some(signer.address()),
                        to: Some(Address::with_last_byte(4).into()),
                        gas: Some(1_000_000),
                        ..Default::default()
                    },
                    nonce_key: Some(U256::MAX),
                    valid_before: std::num::NonZeroU64::new(latest.header.timestamp() + 10),
                    ..Default::default()
                };
                // txgen samples gas with eth_simulateV1. Its block time can be
                // earlier than Reth's default pending timestamp (parent + 12s).
                let payload = SimulatePayload::default().extend(
                    SimBlock::default()
                        .with_block_overrides(BlockOverrides {
                            time: Some(latest.header.timestamp() + 1),
                            ..Default::default()
                        })
                        .call(call.clone()),
                );
                let simulation = provider
                    .simulate_v1(&payload)
                    .hash(latest.header.hash)
                    .await?;
                assert!(simulation[0].calls[0].status);
                // eth_call applies overrides directly to an existing environment.
                // Its expiry window must also use the overridden timestamp.
                call.valid_before = std::num::NonZeroU64::new(latest.header.timestamp() + 310);
                provider
                    .call(call)
                    .block(latest.header.hash.into())
                    .with_block_overrides(BlockOverrides {
                        time: Some(latest.header.timestamp() + 10),
                        ..Default::default()
                    })
                    .await?;
                let tx = TempoTransaction {
                    chain_id: provider.get_chain_id().await?,
                    nonce_key: U256::MAX,
                    valid_before: std::num::NonZeroU64::new(latest.header.timestamp() + 300),
                    gas_limit: 1_000_000,
                    max_fee_per_gas: u128::from(tempo_chainspec::spec::TEMPO_T1_BASE_FEE),
                    calls: vec![Call {
                        to: TxKind::Call(Address::with_last_byte(4)),
                        value: U256::ZERO,
                        input: Bytes::new(),
                    }],
                    ..Default::default()
                };
                let signature = signer.sign_hash_sync(&tx.signature_hash())?;
                let tx: TempoTxEnvelope = tx.into_signed(signature.into()).into();
                let raw = tx.encoded_2718();
                let receipt = provider
                    .send_raw_transaction(&raw)
                    .await?
                    .get_receipt()
                    .await?;
                assert!(receipt.status());
                let block = provider
                    .get_block_by_hash(receipt.block_hash.unwrap())
                    .await?
                    .unwrap();
                assert!(block.header.inner.expiring_nonce_root.is_some());
                eyre::Ok(raw)
            })
            .await
            .unwrap()
            .unwrap();

        nodes[0].stop().await;
        nodes[0].start(&context).await;
        let url = nodes[0].execution().rpc_server_handle().http_url().unwrap();
        execution_runtime
            .run_async(async move {
                let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                    .connect_http(url.parse().unwrap());
                let error = provider
                    .send_raw_transaction(&raw)
                    .await
                    .err()
                    .expect("live replay must be rejected after restart");
                assert!(
                    error.to_string().contains("replay"),
                    "unexpected rejection: {error}"
                );
            })
            .await
            .unwrap();
    });
}
