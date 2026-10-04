//! Trust-neutral HTTP evidence transport. No unverified read or `latest` storage fallback.

use crate::{config::Limits, proof::ProofTargets};
use alloy_primitives::B256;
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use futures::{StreamExt as _, TryStreamExt as _};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tempo_finality::CertifiedHeader;
use url::Url;

struct Endpoint {
    url: Url,
    standard_only: AtomicBool,
}

/// Endpoint state is capability/availability only. All providers share the client's verifier.
/// Deliberately has no Debug/Display implementation exposing URLs or credentials.
pub struct Upstreams {
    http: reqwest::Client,
    endpoints: Vec<Endpoint>,
    max_bytes: usize,
}

impl Upstreams {
    pub fn new(urls: Vec<Url>, limits: &Limits) -> Result<Self, Error> {
        if urls.is_empty()
            || urls.len() > 8
            || urls
                .iter()
                .any(|url| !matches!(url.scheme(), "http" | "https") || url.fragment().is_some())
        {
            return Err(Error::Configuration);
        }
        let http = reqwest::Client::builder()
            .timeout(limits.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            http,
            max_bytes: limits.max_response_bytes,
            endpoints: urls
                .into_iter()
                .map(|url| Endpoint {
                    url,
                    standard_only: AtomicBool::new(false),
                })
                .collect(),
        })
    }

    pub fn count(&self) -> usize {
        self.endpoints.len()
    }

    pub async fn finalized_header(
        &self,
        provider: usize,
        height: Option<u64>,
    ) -> Result<CertifiedHeader, Error> {
        let query = height.map_or_else(|| json!("latest"), |height| json!({"height": height}));
        let budget = AtomicUsize::new(self.max_bytes);
        let evidence: CertifiedHeader = self
            .call(
                provider,
                "consensus_getFinalizedHeader",
                json!([query]),
                &budget,
            )
            .await?;
        if height.is_some_and(|height| evidence.header.inner.number != height) {
            return Err(Error::MalformedResponse(provider));
        }
        Ok(evidence)
    }

    pub async fn proofs(
        &self,
        provider: usize,
        hash: B256,
        targets: &ProofTargets,
    ) -> Result<Vec<EIP1186AccountProofResponse>, Error> {
        let budget = AtomicUsize::new(self.max_bytes);
        let selector = json!({"blockHash": hash, "requireCanonical": true});
        let endpoint = self.endpoints.get(provider).ok_or(Error::Configuration)?;
        let grouped = targets
            .iter()
            .map(|(address, slots)| (*address, slots.iter().copied().collect::<Vec<_>>()))
            .collect::<Vec<_>>();
        if !endpoint.standard_only.load(Ordering::Relaxed) {
            match self
                .call(
                    provider,
                    "eth_getMultiProof",
                    json!([grouped, selector]),
                    &budget,
                )
                .await
            {
                Ok(response) => return Ok(response),
                Err(Error::Capability { code: -32601, .. }) => {
                    endpoint.standard_only.store(true, Ordering::Relaxed)
                }
                Err(error) => return Err(error),
            }
        }
        // Falling back to standard proofs changes transport only, never root binding or verification.
        futures::stream::iter(grouped.into_iter().map(|(address, slots)| {
            let selector = selector.clone();
            let budget = &budget;
            async move {
                self.call(
                    provider,
                    "eth_getProof",
                    json!([address, slots, selector]),
                    budget,
                )
                .await
            }
        }))
        .buffer_unordered(2)
        .try_collect()
        .await
    }

    async fn call<T: DeserializeOwned>(
        &self,
        provider: usize,
        method: &str,
        params: Value,
        budget: &AtomicUsize,
    ) -> Result<T, Error> {
        let endpoint = self.endpoints.get(provider).ok_or(Error::Configuration)?;
        let body = serde_json::to_vec(
            &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        )
        .map_err(|_| Error::Configuration)?;
        // No reqwest source is retained: such errors can include endpoint credentials in URLs.
        let mut response = self
            .http
            .post(endpoint.url.clone())
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| Error::Unavailable(provider))?;
        if !response.status().is_success() {
            return Err(Error::Unavailable(provider));
        }
        if response
            .content_length()
            .is_some_and(|size| size > self.max_bytes as u64)
        {
            return Err(Error::ResponseSize(provider));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error::Unavailable(provider))?
        {
            // Shared across standard account requests: malicious responses cannot multiply the
            // aggregate allocation bound by the number of accounts in a batch.
            budget
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    remaining.checked_sub(chunk.len())
                })
                .map_err(|_| Error::ResponseSize(provider))?;
            bytes.extend_from_slice(&chunk);
        }
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| Error::MalformedResponse(provider))?;
        if envelope.jsonrpc != "2.0" || envelope.id != 1 {
            return Err(Error::MalformedResponse(provider));
        }
        match (envelope.result, envelope.error) {
            (Some(result), None) => {
                serde_json::from_value(result).map_err(|_| Error::MalformedResponse(provider))
            }
            (None, Some(error)) => {
                // Reth uses InvalidParams for its recent-proof-window admission failure. That
                // is unavailable historical state, not evidence that hash selectors are unsupported.
                // Do not expose an untrusted error message (it can contain endpoint credentials).
                let proof_window = matches!(method, "eth_getProof" | "eth_getMultiProof")
                    && error.message == "distance to target block exceeds maximum proof window";
                if matches!(error.code, -32601 | -32602) && !proof_window {
                    Err(Error::Capability {
                        provider,
                        code: error.code,
                    })
                } else {
                    Err(Error::RpcUnavailable {
                        provider,
                        code: error.code,
                    })
                }
            }
            _ => Err(Error::MalformedResponse(provider)),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    jsonrpc: String,
    id: u64,
    result: Option<Value>,
    error: Option<RpcFailure>,
}
#[derive(Deserialize)]
struct RpcFailure {
    code: i32,
    message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configure between one and eight HTTP(S) upstream endpoints")]
    Configuration,
    #[error("upstream {0} request unavailable or timed out")]
    Unavailable(usize),
    #[error("upstream {provider} RPC evidence unavailable (code {code})")]
    RpcUnavailable { provider: usize, code: i32 },
    #[error("upstream {provider} lacks required method or hash-selector capability (code {code})")]
    Capability { provider: usize, code: i32 },
    #[error("upstream {0} response exceeds byte limit")]
    ResponseSize(usize),
    #[error("upstream {0} returned malformed or inconsistently bound RPC evidence")]
    MalformedResponse(usize),
}
