//! Remote RPC transaction checks (testnet & devnet).
//!
//! These tests target a live RPC endpoint and cover the same core transaction
//! matrices as the local integration tests, using the faucet for funding.
//!
//! Uses alloy's [`RetryBackoffLayer`] to automatically retry transient RPC
//! errors (429 rate-limits, connection errors) with backoff at the transport
//! level, so individual call sites don't need manual retry logic.
//!
//! [`MonotonicReadsLayer`] keeps state reads from going behind blocks the test has
//! already observed when the endpoint balances requests across backends.
use alloy::{
    consensus::BlockHeader,
    primitives::{Address, B256, Bytes, U64, U256},
    providers::Provider,
    rpc::json_rpc::{
        Request, RequestPacket, Response, ResponsePacket, ResponsePayload, SerializedRequest,
    },
    signers::local::PrivateKeySigner,
    transports::{
        RpcError, TransportError, TransportErrorKind, TransportFut,
        layers::{RateLimitRetryPolicy, RetryBackoffLayer},
    },
};
use alloy_eips::Encodable2718;
use reth_e2e_test_utils::wait::{PollOpts, poll_until_with};
use reth_primitives_traits::transaction::TxHashRef;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tempo_chainspec::{
    hardfork::{TempoHardfork, TempoHardforks},
    spec::{DEV, MODERATO, PRESTO},
};
use tempo_primitives::{TempoTxEnvelope, transaction::tempo_transaction::Call};

use super::helpers::*;

/// Polls RPC state every 250ms for up to 30 seconds while waiting for it to settle.
///
/// The interval stays under the ~0.6s block time: the matrices wait for a few hundred
/// receipts one after another, so a coarser interval adds up to minutes per run.
const RPC_POLL: PollOpts = PollOpts {
    timeout: Duration::from_secs(30),
    interval: Duration::from_millis(250),
};

/// Sends a raw transaction with duplicate-submission handling.
///
/// If the request reached the node but the response was lost, the retry layer
/// will resend — which may return "already known", or "nonce too low" once the
/// first submission is included. We treat that as success and fall through to
/// `wait_for_receipt`, which fails if the tx never landed.
///
/// Uses `serde_json::Value` for deserialization because `eth_sendRawTransaction`
/// returns a `B256` hash while `eth_sendRawTransactionSync` returns a full
/// receipt object.
///
/// "insufficient funds" is retried: the endpoint can route the submission to a
/// backend that has not imported the block funding the sender yet.
async fn send_raw_tx(
    provider: &alloy::providers::RootProvider,
    method: &'static str,
    encoded: Vec<u8>,
) -> eyre::Result<()> {
    poll_until_with(
        RPC_POLL,
        format!("{method} to see the sender's funds"),
        || async {
            match provider
                .raw_request::<_, serde_json::Value>(method.into(), [&encoded])
                .await
            {
                Ok(_) => Ok(Some(())),
                Err(e) if is_already_known(&e) => Ok(Some(())),
                Err(e) if e.to_string().contains("insufficient funds") => Ok(None),
                Err(e) => Err(e.into()),
            }
        },
    )
    .await
}

/// Returns `true` if the error indicates the tx may already have been accepted.
fn is_already_known(err: &RpcError<TransportErrorKind>) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("already known")
        || msg.contains("known transaction")
        || msg.contains("nonce too low")
}

/// JSON-RPC error code reth returns for a block it does not have.
const UNKNOWN_BLOCK_CODE: i64 = -32001;

/// Keeps state reads from going behind blocks the test has already observed.
///
/// The endpoint can route consecutive requests to backends at different heights, so a
/// balance read right after a receipt can land on a backend that has not imported the
/// receipt's block yet. This layer records the highest block seen in receipts and block
/// responses, pins `latest` state reads to it, and retries them while the backend
/// answering does not have that block.
#[derive(Clone, Default)]
struct MonotonicReadsLayer {
    seen_block: Arc<AtomicU64>,
}

impl<S> tower::Layer<S> for MonotonicReadsLayer {
    type Service = MonotonicReads<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MonotonicReads {
            inner,
            seen_block: self.seen_block.clone(),
        }
    }
}

#[derive(Clone)]
struct MonotonicReads<S> {
    inner: S,
    seen_block: Arc<AtomicU64>,
}

impl<S> tower::Service<RequestPacket> for MonotonicReads<S>
where
    S: tower::Service<
            RequestPacket,
            Response = ResponsePacket,
            Error = TransportError,
            Future = TransportFut<'static>,
        > + Clone
        + Send
        + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        let seen_block = self.seen_block.clone();
        Box::pin(async move {
            let RequestPacket::Single(request) = request else {
                return inner.call(request).await;
            };

            let Some(pinned) = pin_state_read(&request, seen_block.load(Ordering::Relaxed)) else {
                let method = request.method_clone();
                let response = inner.call(request.into()).await?;
                if let Some(block) = observed_block(&method, &response) {
                    seen_block.fetch_max(block, Ordering::Relaxed);
                }
                return Ok(response);
            };

            let deadline = tokio::time::Instant::now() + RPC_POLL.timeout;
            loop {
                let response = inner.call(pinned.clone().into()).await;
                let unknown_block = match &response {
                    Ok(response) => response.first_error_code() == Some(UNKNOWN_BLOCK_CODE),
                    Err(err) => err
                        .as_error_resp()
                        .is_some_and(|err| err.code == UNKNOWN_BLOCK_CODE),
                };
                if !unknown_block || tokio::time::Instant::now() >= deadline {
                    return response;
                }
                tokio::time::sleep(RPC_POLL.interval).await;
            }
        })
    }
}

/// Rewrites a `latest` state read to read at `block`, or returns `None` if the request is
/// not a state read at `latest`.
fn pin_state_read(request: &SerializedRequest, block: u64) -> Option<SerializedRequest> {
    let block_param = match request.method() {
        "eth_call" | "eth_getTransactionCount" | "eth_getBalance" | "eth_getCode" => 1,
        "eth_getStorageAt" => 2,
        _ => return None,
    };
    if block == 0 {
        return None;
    }

    let mut params: Vec<serde_json::Value> = serde_json::from_str(request.params()?.get()).ok()?;
    let pinned = serde_json::Value::from(format!("{block:#x}"));
    match params.get(block_param) {
        // alloy omits the block parameter when it is `latest`.
        None if params.len() == block_param => params.push(pinned),
        Some(param) if param == "latest" => params[block_param] = pinned,
        _ => return None,
    }
    Request::new(request.method_clone(), request.id().clone(), params)
        .serialize()
        .ok()
}

/// Returns the block number a receipt or block response shows the endpoint has reached.
fn observed_block(method: &str, response: &ResponsePacket) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct BlockRef {
        #[serde(rename = "blockNumber", alias = "number")]
        number: U64,
    }

    let ResponsePacket::Single(Response {
        payload: ResponsePayload::Success(result),
        ..
    }) = response
    else {
        return None;
    };
    let number = match method {
        "eth_blockNumber" => serde_json::from_str::<U64>(result.get()).ok()?,
        "eth_getBlockByNumber"
        | "eth_getBlockByHash"
        | "eth_getTransactionReceipt"
        | "eth_sendRawTransactionSync" => {
            serde_json::from_str::<Option<BlockRef>>(result.get())
                .ok()??
                .number
        }
        _ => return None,
    };
    Some(number.to())
}

pub(super) struct RpcEnv {
    provider: alloy::providers::RootProvider,
    chain_id: u64,
    hardfork: TempoHardfork,
}

impl RpcEnv {
    async fn connect(rpc_url: &str) -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();

        // Extend the default rate-limit policy to also retry connection errors and
        // gateway errors from the proxy in front of the node.
        let policy =
            RateLimitRetryPolicy::default().or(|err: &alloy::transports::TransportError| {
                let msg = err.to_string();
                msg.contains("connection error")
                    || msg.contains("SendRequest")
                    || msg.contains("error sending request")
                    || err
                        .as_transport_err()
                        .and_then(TransportErrorKind::as_http_error)
                        .is_some_and(|http| matches!(http.status, 502 | 504))
            });
        let retry = RetryBackoffLayer::new_with_policy(4, 100, 330, policy);
        let client = alloy::rpc::client::RpcClient::builder()
            .layer(MonotonicReadsLayer::default())
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

    fn supports_scoped_key_auth_rpc(&self) -> bool {
        self.hardfork.is_t3()
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
        let final_nonce = poll_until_with(
            RPC_POLL,
            format!("protocol nonce of {signer_addr} to reach {expected}"),
            || async {
                let nonce = self.provider.get_transaction_count(signer_addr).await?;
                Ok((nonce >= expected).then_some(nonce))
            },
        )
        .await?;
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
                    assert!(
                        rpc_error_contains_reason(&e, reason),
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
    poll_until_with(RPC_POLL, format!("receipt {tx_hash}"), || async {
        Ok(provider
            .raw_request("eth_getTransactionReceipt".into(), [tx_hash])
            .await?)
    })
    .await
}
