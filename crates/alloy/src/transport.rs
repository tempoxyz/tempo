//! Relay transport for routing sponsored transactions through a fee payer service.
//!
//! [`RelayTransport`] wraps two transports: a default one for reads/gas/nonce and a
//! relay one for `eth_sendRawTransaction`. The relay URL points to a fee payer service
//! (e.g. `https://sponsor.tempo.xyz/tp_<key>`) that adds a fee payer signature and
//! broadcasts the transaction.
//!
//! This mirrors viem's `withRelay` / `withFeePayer` transport decorator.
//!
//! # Example
//!
//! ```rust,ignore
//! use alloy_transport_http::Http;
//! use tempo_alloy::transport::RelayTransport;
//!
//! let transport = RelayTransport::new(
//!     Http::new("https://rpc.tempo.xyz".parse()?),
//!     Http::new("https://sponsor.tempo.xyz/tp_abc123".parse()?),
//! );
//!
//! // Use with ProviderBuilder — all sendRawTransaction calls
//! // go through the sponsor service automatically.
//! let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
//!     .on_provider(RootProvider::new(RpcClient::new(transport, true)));
//! ```

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{TransportError, TransportFut};

/// The RPC method routed to the relay transport.
const SEND_RAW_TX: &str = "eth_sendRawTransaction";

/// A transport that routes `eth_sendRawTransaction` to a relay (sponsor) transport
/// and all other RPC methods to a default transport.
///
/// This is the Alloy equivalent of viem's `withRelay` / `withFeePayer` transport decorator.
/// The relay transport should point to a fee payer service
/// (e.g. `https://sponsor.tempo.xyz/tp_<key>`) that accepts `eth_sendRawTransaction`,
/// adds a fee payer signature, and broadcasts the transaction.
#[derive(Debug, Clone)]
pub struct RelayTransport<D, R> {
    default: D,
    relay: R,
}

impl<D, R> RelayTransport<D, R> {
    /// Create a new relay transport.
    ///
    /// - `default` — transport for reads, gas estimation, nonce fetches, and all non-send RPCs.
    /// - `relay` — transport for `eth_sendRawTransaction` (the sponsor/fee-payer service URL).
    pub const fn new(default: D, relay: R) -> Self {
        Self { default, relay }
    }
}

impl<D, R> tower::Service<RequestPacket> for RelayTransport<D, R>
where
    D: tower::Service<
            RequestPacket,
            Response = ResponsePacket,
            Error = TransportError,
            Future = TransportFut<'static>,
        > + Clone
        + Send
        + Sync
        + 'static,
    R: tower::Service<
            RequestPacket,
            Response = ResponsePacket,
            Error = TransportError,
            Future = TransportFut<'static>,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        match self.default.poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => {}
            other => return other,
        }
        self.relay.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let use_relay = match &request {
            RequestPacket::Single(req) => req.method() == SEND_RAW_TX,
            RequestPacket::Batch(reqs) => reqs.iter().all(|r| r.method() == SEND_RAW_TX),
        };

        if use_relay {
            self.relay.call(request)
        } else {
            self.default.call(request)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_json_rpc::{Id, Request};
    use alloy_transport::mock::{Asserter, MockTransport};

    fn make_request(method: &'static str) -> RequestPacket {
        RequestPacket::Single(
            Request::new(method, Id::Number(1), None::<&serde_json::value::RawValue>)
                .try_into()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn routes_send_raw_tx_to_relay() {
        let default_asserter = Asserter::new();
        let relay_asserter = Asserter::new();

        let default = MockTransport::new(default_asserter.clone());
        let relay = MockTransport::new(relay_asserter.clone());

        let mut transport = RelayTransport::new(default, relay);

        relay_asserter.push_success(&alloy_primitives::B256::ZERO);

        let resp = tower::Service::call(&mut transport, make_request("eth_sendRawTransaction"))
            .await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn routes_other_methods_to_default() {
        let default_asserter = Asserter::new();
        let relay_asserter = Asserter::new();

        let default = MockTransport::new(default_asserter.clone());
        let relay = MockTransport::new(relay_asserter.clone());

        let mut transport = RelayTransport::new(default, relay);

        default_asserter.push_success(&alloy_primitives::U64::from(42));

        let resp =
            tower::Service::call(&mut transport, make_request("eth_getTransactionCount")).await;
        assert!(resp.is_ok());
    }
}
