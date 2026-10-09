//! Explicitly allowlisted external fee payers. No arbitrary URL forwarding or redirects.

use crate::{Backend, Next, Plugin, Request, RpcError};
use async_trait::async_trait;
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};
use url::{Host, Url};

/// Normalizes fee-payer URLs using viem's safe default restrictions.
pub fn normalize(value: &str, allow_unsafe: bool) -> Result<String, RpcError> {
    let mut url = Url::parse(value).map_err(|_| RpcError::invalid("Invalid fee payer URL"))?;
    if !matches!(url.scheme(), "http" | "https") || !allow_unsafe && url.scheme() != "https" {
        return Err(RpcError::invalid("Invalid fee payer URL protocol"));
    }
    if !allow_unsafe {
        let unsafe_host = match url.host() {
            Some(Host::Domain(host)) => {
                let host = host.trim_end_matches('.').to_lowercase();
                host == "localhost" || host.ends_with(".localhost")
            }
            Some(Host::Ipv4(ip)) => unsafe_ipv4(ip.octets()),
            Some(Host::Ipv6(ip)) => {
                ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_multicast()
                    || ip.segments()[0] & 0xfe00 == 0xfc00
                    || ip.segments()[0] & 0xffc0 == 0xfe80
                    || ip.segments()[0] & 0xffc0 == 0xfec0
                    || ip.to_ipv4().is_some_and(|ip| unsafe_ipv4(ip.octets()))
            }
            None => true,
        };
        if unsafe_host {
            return Err(RpcError::invalid("Invalid fee payer URL host"));
        }
    }
    url.set_username("")
        .map_err(|_| RpcError::invalid("Invalid fee payer URL"))?;
    url.set_password(None)
        .map_err(|_| RpcError::invalid("Invalid fee payer URL"))?;
    url.set_fragment(None);
    Ok(url.to_string())
}

fn unsafe_ipv4([a, b, _, _]: [u8; 4]) -> bool {
    matches!(a, 0 | 10 | 127)
        || a == 100 && (64..=127).contains(&b)
        || a == 169 && b == 254
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && b == 168
        || a >= 224
}

/// External fee-payer routing configured by operators, never by untrusted RPC callers.
pub struct ExternalFeePayers {
    allowed: BTreeMap<String, Arc<dyn Backend>>,
    allow_unsafe: bool,
}

impl ExternalFeePayers {
    /// Creates an empty allowlist. Unsafe URLs are for isolated development tests only.
    pub fn new(allow_unsafe: bool) -> Self {
        Self {
            allowed: BTreeMap::new(),
            allow_unsafe,
        }
    }
    /// Adds a preconfigured transport that refuses redirects.
    pub fn allow(mut self, url: &str, backend: Arc<dyn Backend>) -> Result<Self, RpcError> {
        self.allowed
            .insert(normalize(url, self.allow_unsafe)?, backend);
        Ok(self)
    }
}

#[async_trait]
impl Plugin for ExternalFeePayers {
    async fn handle(&self, mut request: Request, next: Next<'_>) -> Result<Value, RpcError> {
        if request.method != "eth_fillTransaction" {
            return next.run(request).await;
        }
        let Some(url) = request
            .transaction()?
            .get("feePayer")
            .and_then(Value::as_str)
        else {
            return next.run(request).await;
        };
        let url = normalize(url, self.allow_unsafe)?;
        let backend = self
            .allowed
            .get(&url)
            .ok_or_else(|| RpcError::invalid("External fee payer URL is not allowed"))?;
        request
            .transaction_mut()?
            .insert("feePayer".into(), Value::Bool(true));
        backend.request(request).await
    }
}
