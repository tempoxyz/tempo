//! Chain selection for embedded multi-chain relays, with fail-closed conflict checks.

use crate::{Backend, Relay, Request, RpcError, wire::Rlp};
use alloy_primitives::Bytes;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;

/// Embeddable router. Each chain has its own signer policy and namespaced storage.
#[derive(Default)]
pub struct ChainRouter {
    relays: BTreeMap<u64, Relay>,
    default: Option<u64>,
}

impl ChainRouter {
    /// Adds a relay whose upstream and signer have been verified for this chain.
    pub fn with_chain(mut self, chain_id: u64, relay: Relay) -> Result<Self, RpcError> {
        if chain_id == 0 || chain_id > 9_007_199_254_740_991 || self.relays.contains_key(&chain_id)
        {
            return Err(RpcError::invalid("Expected a unique valid chain ID"));
        }
        self.relays.insert(chain_id, relay);
        Ok(self)
    }

    /// Selects a configured chain for requests without a body-level chain ID.
    pub fn with_default(mut self, chain_id: u64) -> Result<Self, RpcError> {
        if !self.relays.contains_key(&chain_id) {
            return Err(RpcError::invalid("Chain is not configured"));
        }
        self.default = Some(chain_id);
        Ok(self)
    }

    /// Resolves an explicit request override, rejecting conflicts with the body.
    pub async fn handle(&self, request: Request, chain_id: Option<u64>) -> Result<Value, RpcError> {
        let body = body_chain(&request)?;
        if let (Some(explicit), Some(body)) = (chain_id, body)
            && explicit != body
        {
            return Err(RpcError::invalid("Conflicting chain IDs"));
        }
        let chain_id = chain_id.or(body).or(self.default).ok_or_else(|| {
            RpcError::invalid("A chain ID is required to resolve the downstream client")
        })?;
        let relay = self
            .relays
            .get(&chain_id)
            .ok_or_else(|| RpcError::invalid("Chain is not configured"))?;
        relay.handle(request).await
    }
}

#[async_trait]
impl Backend for ChainRouter {
    async fn request(&self, request: Request) -> Result<Value, RpcError> {
        self.handle(request, None).await
    }
}

pub(crate) fn body_chain(request: &Request) -> Result<Option<u64>, RpcError> {
    if request.method == "eth_fillTransaction" {
        return request
            .transaction()?
            .get("chainId")
            .map(|value| {
                let chain = value
                    .as_u64()
                    .or_else(|| {
                        value.as_str().and_then(|value| {
                            if let Some(hex) = value.strip_prefix("0x") {
                                u64::from_str_radix(hex, 16).ok()
                            } else {
                                value.parse().ok()
                            }
                        })
                    })
                    .filter(|chain| *chain > 0 && *chain <= 9_007_199_254_740_991)
                    .ok_or_else(|| RpcError::invalid("Expected a valid chain ID"))?;
                Ok(chain)
            })
            .transpose();
    }
    if matches!(
        request.method.as_str(),
        "eth_signRawTransaction"
            | "eth_sendRawTransaction"
            | "eth_sendRawTransactionSync"
            | "multisig_approveRawTransaction"
            | "multisig_approveRawTransactionSync"
    ) {
        let bytes: Bytes =
            serde_json::from_value(request.params.first().cloned().unwrap_or(Value::Null))
                .map_err(|_| RpcError::invalid("Expected a serialized transaction"))?;
        if matches!(bytes.first(), Some(0x76 | 0x78)) {
            let fields = Rlp::decode(&bytes[1..])?;
            return fields
                .list()?
                .first()
                .ok_or_else(|| RpcError::invalid("Missing chain ID"))?
                .integer()
                .map(Some);
        }
    }
    Ok(None)
}
