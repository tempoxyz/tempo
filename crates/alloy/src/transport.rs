//! Relay transport for routing sponsored transactions through a fee payer service.
//!
//! [`RelayTransport`] wraps two transports: a default one for all RPC calls and a
//! relay one for fee payer signing. When the user sends `eth_sendRawTransaction`,
//! the transport first calls `eth_signRawTransaction` on the relay to obtain a
//! fee-payer-cosigned version of the tx, then broadcasts the result via the
//! default transport's `eth_sendRawTransaction`.
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
//! // are automatically cosigned by the sponsor before broadcast.
//! let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
//!     .on_provider(RootProvider::new(RpcClient::new(transport, true)));
//! ```

use alloy_json_rpc::{Request, RequestPacket, ResponsePacket};
#[cfg(test)]
use alloy_json_rpc::Id;
use alloy_transport::{TransportError, TransportErrorKind, TransportFut};

/// A transport that adds fee payer sponsorship to `eth_sendRawTransaction`.
///
/// When `eth_sendRawTransaction` is called:
/// 1. The raw tx bytes are sent to the relay via `eth_signRawTransaction`
/// 2. The relay (sponsor service) adds a `fee_payer_signature` and returns the signed bytes
/// 3. The signed bytes are broadcast via `eth_sendRawTransaction` on the default transport
///
/// All other RPC methods go directly to the default transport.
///
/// This is the Alloy equivalent of viem's `withRelay` / `withFeePayer` transport decorator.
/// The relay transport should point to a fee payer service
/// (e.g. `https://sponsor.tempo.xyz/tp_<key>`).
#[derive(Debug, Clone)]
pub struct RelayTransport<D, R> {
    default: D,
    relay: R,
}

impl<D, R> RelayTransport<D, R> {
    /// Create a new relay transport.
    ///
    /// - `default` — transport for all RPC calls and broadcasting.
    /// - `relay` — transport pointing at the sponsor/fee-payer service URL.
    pub const fn new(default: D, relay: R) -> Self {
        Self { default, relay }
    }
}

const SEND_RAW_TX: &str = "eth_sendRawTransaction";
const SIGN_RAW_TX: &str = "eth_signRawTransaction";

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
        let is_send_raw = matches!(
            &request,
            RequestPacket::Single(req) if req.method() == SEND_RAW_TX
        );

        if !is_send_raw {
            return self.default.call(request);
        }

        let mut default = self.default.clone();
        let mut relay = self.relay.clone();

        Box::pin(async move {
            let original = request
                .as_single()
                .ok_or_else(|| TransportErrorKind::custom_str("expected single request"))?;
            let id = original.id().clone();

            // Extract the raw tx param from the original request JSON.
            let raw_json: serde_json::Value =
                serde_json::from_str(original.serialized().get())
                    .map_err(|e| TransportErrorKind::custom(e))?;
            let params = raw_json.get("params").cloned().unwrap_or_default();

            // Step 1: Send eth_signRawTransaction to the relay.
            let sign_req: alloy_json_rpc::SerializedRequest =
                Request::new(SIGN_RAW_TX, id.clone(), Some(params))
                    .try_into()
                    .map_err(|e: serde_json::Error| TransportErrorKind::custom(e))?;
            let sign_response = relay.call(RequestPacket::Single(sign_req)).await?;

            // Step 2: Extract the signed raw tx from the response payload.
            let signed_raw = extract_success_string(&sign_response)?;

            // Step 3: Broadcast via eth_sendRawTransaction on the default transport.
            let send_req: alloy_json_rpc::SerializedRequest =
                Request::new(SEND_RAW_TX, id, Some([&signed_raw]))
                    .try_into()
                    .map_err(|e: serde_json::Error| TransportErrorKind::custom(e))?;
            default.call(RequestPacket::Single(send_req)).await
        })
    }
}

/// Extract a string value from a successful `ResponsePacket::Single`.
fn extract_success_string(response: &ResponsePacket) -> Result<String, TransportError> {
    use alloy_json_rpc::ResponsePayload;

    let resp = match response {
        ResponsePacket::Single(r) => r,
        _ => {
            return Err(TransportErrorKind::custom_str(
                "unexpected batch response from relay",
            ))
        }
    };

    match &resp.payload {
        ResponsePayload::Success(raw) => {
            // The RawValue is a JSON string like `"0xdeadbeef"` — deserialize it.
            serde_json::from_str::<String>(raw.get())
                .map_err(|e| TransportErrorKind::custom(e))
        }
        ResponsePayload::Failure(err) => Err(TransportErrorKind::custom_str(&format!(
            "sponsor relay error (code {}): {}",
            err.code, err.message
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_transport::mock::{Asserter, MockTransport};

    fn make_request(method: &'static str) -> RequestPacket {
        RequestPacket::Single(
            Request::new(method, Id::Number(1), None::<&serde_json::value::RawValue>)
                .try_into()
                .unwrap(),
        )
    }

    fn make_send_raw_tx_request() -> RequestPacket {
        RequestPacket::Single(
            Request::new(SEND_RAW_TX, Id::Number(1), Some(["0xaa"]))
                .try_into()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn routes_non_send_to_default() {
        let default_asserter = Asserter::new();
        let relay_asserter = Asserter::new();
        let mut transport = RelayTransport::new(
            MockTransport::new(default_asserter.clone()),
            MockTransport::new(relay_asserter.clone()),
        );

        default_asserter.push_success(&alloy_primitives::U64::from(42));

        let resp =
            tower::Service::call(&mut transport, make_request("eth_getTransactionCount")).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn send_raw_tx_signs_then_broadcasts() {
        let default_asserter = Asserter::new();
        let relay_asserter = Asserter::new();
        let mut transport = RelayTransport::new(
            MockTransport::new(default_asserter.clone()),
            MockTransport::new(relay_asserter.clone()),
        );

        // Relay returns a signed raw tx string
        relay_asserter.push_success(&"0xdeadbeef");

        // Default transport accepts the broadcast
        default_asserter.push_success(&alloy_primitives::B256::ZERO);

        let resp = tower::Service::call(&mut transport, make_send_raw_tx_request()).await;
        assert!(resp.is_ok(), "relay sign + broadcast should succeed");
    }

    #[tokio::test]
    async fn relay_error_propagates() {
        let default_asserter = Asserter::new();
        let relay_asserter = Asserter::new();
        let mut transport = RelayTransport::new(
            MockTransport::new(default_asserter.clone()),
            MockTransport::new(relay_asserter.clone()),
        );

        relay_asserter.push_failure_msg("sponsor account broke");

        let resp = tower::Service::call(&mut transport, make_send_raw_tx_request()).await;
        assert!(resp.is_err(), "relay error should propagate");
    }
}
