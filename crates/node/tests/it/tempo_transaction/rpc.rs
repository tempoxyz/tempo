//! Remote RPC transaction checks (testnet & devnet).
//!
//! These tests target a live RPC endpoint and cover the same core transaction
//! matrices as the local integration tests, using the faucet for funding.
//!
//! Uses alloy's [`RetryBackoffLayer`] to automatically retry transient RPC
//! errors (429 rate-limits, connection errors) with backoff at the transport
//! level, so individual call sites don't need manual retry logic.
use alloy::{
    consensus::BlockHeader,
    primitives::{Address, B256, Bytes, U256},
    providers::Provider,
    signers::local::PrivateKeySigner,
    transports::{
        RpcError, TransportErrorKind,
        layers::{RateLimitRetryPolicy, RetryBackoffLayer},
    },
};
use alloy_eips::Encodable2718;
use reth_primitives_traits::transaction::TxHashRef;
use tempo_chainspec::{
    hardfork::{TempoHardfork, TempoHardforks},
    spec::{DEV, MODERATO, PRESTO},
};
use tempo_primitives::{TempoTxEnvelope, transaction::tempo_transaction::Call};

use super::helpers::*;

/// Maximum number of 1-second poll iterations when waiting for RPC state to settle.
const RPC_POLL_RETRIES: usize = 30;

/// Sends a raw transaction with duplicate-submission handling.
///
/// If the request reached the node but the response was lost, the retry layer
/// will resend — which may return "already known". We treat that as success
/// and fall through to `wait_for_receipt`.
///
/// Uses `serde_json::Value` for deserialization because `eth_sendRawTransaction`
/// returns a `B256` hash while `eth_sendRawTransactionSync` returns a full
/// receipt object.
async fn send_raw_tx(
    provider: &alloy::providers::RootProvider,
    method: &'static str,
    encoded: Vec<u8>,
) -> eyre::Result<()> {
    match provider
        .raw_request::<_, serde_json::Value>(method.into(), [encoded])
        .await
    {
        Ok(_) => Ok(()),
        Err(e) if is_already_known(&e) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Returns `true` if the error indicates the tx was already accepted.
fn is_already_known(err: &RpcError<TransportErrorKind>) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("already known") || msg.contains("known transaction")
}

pub(super) struct RpcEnv {
    provider: alloy::providers::RootProvider,
    chain_id: u64,
    hardfork: TempoHardfork,
}

impl RpcEnv {
    async fn connect(rpc_url: &str) -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();

        // Extend the default rate-limit policy to also retry connection errors.
        let policy =
            RateLimitRetryPolicy::default().or(|err: &alloy::transports::TransportError| {
                let msg = err.to_string();
                msg.contains("connection error")
                    || msg.contains("SendRequest")
                    || msg.contains("error sending request")
            });
        let retry = RetryBackoffLayer::new_with_policy(4, 100, 330, policy);
        let client = alloy::rpc::client::RpcClient::builder()
            .layer(retry)
            .http(rpc_url.parse()?);
        let provider = alloy::providers::RootProvider::new(client);

        let chain_id = provider.get_chain_id().await?;

        // Chain IDs from genesis/*.json (mirrors bootnodes() in spec.rs)
        let chain_spec = match chain_id {
            4217 => PRESTO.clone(), // mainnet
            42431 => MODERATO.clone(),
            _ => DEV.clone(),
        };
        let latest_block: alloy::rpc::types::Block = provider
            .get_block_by_number(Default::default())
            .await?
            .ok_or_else(|| eyre::eyre!("latest block missing"))?;
        let hardfork = chain_spec.tempo_hardfork_at(latest_block.header.timestamp());

        Ok(Self {
            provider,
            chain_id,
            hardfork,
        })
    }

    pub(super) async fn testnet() -> eyre::Result<Option<Self>> {
        match std::env::var("TEMPO_TESTNET_RPC_URL") {
            Ok(url) => Self::connect(&url).await.map(Some),
            Err(_) => Ok(None),
        }
    }

    pub(super) async fn devnet() -> eyre::Result<Option<Self>> {
        match std::env::var("TEMPO_DEVNET_RPC_URL") {
            Ok(url) => Self::connect(&url).await.map(Some),
            Err(_) => Ok(None),
        }
    }
}

impl super::types::TestEnv for RpcEnv {
    type P = alloy::providers::RootProvider;

    fn provider(&self) -> &Self::P {
        &self.provider
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn hardfork(&self) -> TempoHardfork {
        self.hardfork
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
        send_raw_tx(&self.provider, "eth_sendRawTransaction", encoded).await?;
        let receipt = wait_for_receipt(&self.provider, tx_hash).await?;
        let status = receipt["status"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Receipt missing status field for {tx_hash}"))?;
        assert_eq!(status, "0x1", "Receipt status mismatch for {tx_hash}");
        Ok(receipt)
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
            let encoded = envelope.encoded_2718();
            send_raw_tx(&self.provider, "eth_sendRawTransaction", encoded).await?;
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

    async fn submit_tx_expecting_rejection(
        &self,
        encoded: Vec<u8>,
        expected_reason: Option<&str>,
    ) -> eyre::Result<()> {
        // The retry layer handles transient errors transparently. After it
        // exhausts retries, any remaining error is either a real RPC rejection
        // (what we're testing for) or a persistent transport failure.
        let result = self
            .provider
            .raw_request::<_, B256>("eth_sendRawTransaction".into(), [encoded])
            .await;

        match result {
            Ok(_) => Err(eyre::eyre!(
                "Transaction should be rejected, but was accepted"
            )),
            Err(RpcError::Transport(_)) => {
                // Transport error that persisted through all retries — not a
                // real rejection, so we must not count it as a test pass.
                Err(eyre::eyre!(
                    "Rejection test failed: persistent transport error after retries: {}",
                    result.unwrap_err()
                ))
            }
            Err(e) => {
                // Non-retryable error = real RPC validation rejection.
                if let Some(reason) = expected_reason {
                    let err_str = e.to_string().to_lowercase();
                    assert!(
                        err_str.contains(&reason.to_lowercase()),
                        "Rejection error should contain '{reason}', got: {e}"
                    );
                }
                Ok(())
            }
        }
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
        send_raw_tx(&self.provider, "eth_sendRawTransaction", encoded).await?;
        wait_for_receipt(&self.provider, tx_hash).await
    }

    async fn submit_tx_sync(
        &mut self,
        encoded: Vec<u8>,
        tx_hash: B256,
    ) -> eyre::Result<serde_json::Value> {
        send_raw_tx(&self.provider, "eth_sendRawTransactionSync", encoded).await?;
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
