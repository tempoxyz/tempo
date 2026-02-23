//! Testnet RPC transaction checks.
//!
//! These tests target a live RPC endpoint and cover the same core transaction
//! matrices as the local integration tests, using the testnet faucet for funding.
use alloy::{
    consensus::BlockHeader,
    primitives::{Address, B256, Bytes, U256},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use alloy_eips::Encodable2718;
use reth_primitives_traits::transaction::TxHashRef;
use tempo_primitives::{TempoTxEnvelope, transaction::tempo_transaction::Call};

use super::helpers::*;

/// Testnet RPC url (unpermissioned).
const TESTNET_RPC_URL: &str = "https://rpc.moderato.tempo.xyz";

/// Maximum number of 1-second poll iterations when waiting for testnet RPC state to settle.
const RPC_POLL_RETRIES: usize = 30;

pub(super) struct Testnet {
    provider: alloy::providers::RootProvider,
    chain_id: u64,
}

impl Testnet {
    pub(super) async fn new() -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();
        let rpc_url =
            std::env::var("TEMPO_TESTNET_RPC_URL").unwrap_or_else(|_| TESTNET_RPC_URL.to_string());
        let provider = alloy::providers::RootProvider::new_http(rpc_url.parse()?);
        let chain_id = provider.get_chain_id().await?;
        Ok(Self { provider, chain_id })
    }
}

impl super::types::TestEnv for Testnet {
    type P = alloy::providers::RootProvider;

    fn provider(&self) -> &Self::P {
        &self.provider
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    async fn fund_account(&mut self, addr: Address) -> eyre::Result<U256> {
        let tx_hashes: Vec<B256> = self
            .provider
            .raw_request("tempo_fundAddress".into(), [addr])
            .await?;

        for tx_hash in tx_hashes {
            wait_for_receipt(&self.provider, tx_hash).await?;
        }

        let balance = tempo_precompiles::tip20::ITIP20::new(
            tempo_contracts::precompiles::DEFAULT_FEE_TOKEN,
            &self.provider,
        )
        .balanceOf(addr)
        .call()
        .await?;

        Ok(balance)
    }

    async fn submit_tx(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        let raw_result: B256 = self
            .provider
            .raw_request("eth_sendRawTransaction".into(), [encoded])
            .await?;
        assert_eq!(raw_result, tx_hash, "RPC should return tx hash");
        let receipt = wait_for_receipt(&self.provider, tx_hash).await?;
        let status = receipt["status"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Receipt missing status field for {tx_hash}"))?;
        assert_eq!(status, "0x1", "Receipt status mismatch for {tx_hash}");
        Ok(receipt)
    }

    async fn submit_tx_excluded_by_builder(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<()> {
        let _ = self
            .provider
            .raw_request::<_, B256>("eth_sendRawTransaction".into(), [encoded])
            .await?;

        // Verify the tx is known to the RPC (confirms it entered the mempool).
        let tx_obj: Option<serde_json::Value> = self
            .provider
            .raw_request("eth_getTransactionByHash".into(), [tx_hash])
            .await?;
        assert!(
            tx_obj.is_some(),
            "Transaction {tx_hash} should be known to RPC after submission"
        );

        // Record the starting block to prove liveness (blocks are advancing).
        let start_block: u64 = self.provider.get_block_number().await?;

        // Poll — tx should never be included
        for _ in 0..RPC_POLL_RETRIES {
            let receipt: Option<serde_json::Value> = self
                .provider
                .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
                .await?;
            if let Some(receipt) = receipt {
                let status = receipt["status"].as_str().unwrap_or("?");
                panic!(
                    "Transaction {tx_hash} was mined (status={status}), \
                     expected exclusion by builder"
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }

        // Confirm blocks actually advanced (liveness check).
        let end_block: u64 = self.provider.get_block_number().await?;
        assert!(
            end_block > start_block,
            "Blocks did not advance during polling ({start_block} → {end_block}); \
             testnet may be stalled"
        );

        Ok(())
    }

    async fn bump_protocol_nonce(
        &mut self,
        signer: &PrivateKeySigner,
        signer_addr: Address,
        count: u64,
    ) -> eyre::Result<()> {
        let recipient = Address::random();
        let start_nonce = self.provider.get_transaction_count(signer_addr).await?;

        for i in 0..count {
            let tx = create_basic_aa_tx(
                self.chain_id,
                start_nonce + i,
                vec![Call {
                    to: recipient.into(),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                300_000,
            );

            let signature = sign_aa_tx_secp256k1(&tx, signer)?;
            let envelope: TempoTxEnvelope = tx.into_signed(signature).into();
            let tx_hash = *envelope.tx_hash();
            self.provider
                .raw_request::<_, B256>("eth_sendRawTransaction".into(), [envelope.encoded_2718()])
                .await?;
            wait_for_receipt(&self.provider, tx_hash).await?;
        }

        let expected = start_nonce + count;
        let mut final_nonce = 0;
        for _ in 0..RPC_POLL_RETRIES {
            final_nonce = self.provider.get_transaction_count(signer_addr).await?;
            if final_nonce >= expected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        assert_eq!(final_nonce, expected, "Protocol nonce should have bumped");
        Ok(())
    }

    async fn current_block_timestamp(&mut self) -> eyre::Result<u64> {
        let block = self
            .provider
            .get_block_by_number(Default::default())
            .await?
            .ok_or_else(|| eyre::eyre!("latest block missing"))?;
        Ok(block.header.timestamp())
    }

    async fn submit_tx_unchecked(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        let _: B256 = self
            .provider
            .raw_request("eth_sendRawTransaction".into(), [encoded])
            .await?;
        wait_for_receipt(&self.provider, tx_hash).await
    }

    async fn submit_tx_sync(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        let _: serde_json::Value = self
            .provider
            .raw_request("eth_sendRawTransactionSync".into(), [encoded])
            .await?;
        let receipt = wait_for_receipt(&self.provider, tx_hash).await?;
        let status = receipt["status"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Receipt missing status field for {tx_hash}"))?;
        assert_eq!(status, "0x1", "Receipt status mismatch for {tx_hash}");
        Ok(receipt)
    }
}

async fn wait_for_receipt(
    provider: &impl Provider,
    tx_hash: B256,
) -> eyre::Result<serde_json::Value> {
    for _ in 0..RPC_POLL_RETRIES {
        let receipt: Option<serde_json::Value> = provider
            .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
            .await?;
        if let Some(receipt) = receipt {
            return Ok(receipt);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(eyre::eyre!("timed out waiting for receipt {tx_hash}"))
}
