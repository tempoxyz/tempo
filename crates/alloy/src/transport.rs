//! Relay transport for routing sponsored transactions through a fee payer service.
//!
//! [`RelayTransport`] wraps two transports:
//! - a default Tempo RPC transport for ordinary requests;
//! - a sponsor relay transport for `eth_sendRawTransaction`.
//!
//! When a single `eth_sendRawTransaction` request is submitted, the raw unsigned Tempo AA
//! transaction is locally preflighted and then forwarded unchanged to the sponsor relay. The relay
//! applies policy, adds the Tempo `fee_payer_signature`, broadcasts, and returns the transaction
//! hash. Non-transaction requests are forwarded unchanged to the default transport. JSON-RPC
//! batches containing `eth_sendRawTransaction` are rejected; use Tempo AA native call batching
//! instead.

use alloy_consensus::transaction::SignerRecoverable;
use alloy_eips::Decodable2718;
use alloy_json_rpc::{RequestPacket, ResponsePacket, SerializedRequest};
use alloy_primitives::hex;
use alloy_rpc_client::BuiltInConnectionString;
use alloy_transport::{
    BoxTransport, TransportConnect, TransportError, TransportErrorKind, TransportFut,
};
use std::str::FromStr;
use tempo_primitives::{AASigned, TempoTxEnvelope};

// TODO(rusowsky): Remove once alloy-transport publishes `TransportErrorKind::NonRetryable`
trait TransportErrorKindNonRetryableExt {
    fn non_retryable(err: impl std::error::Error + Send + Sync + 'static) -> TransportError;
}

// TODO(rusowsky): Remove once alloy-transport publishes `TransportErrorKind::NonRetryable`
impl TransportErrorKindNonRetryableExt for TransportErrorKind {
    fn non_retryable(err: impl std::error::Error + Send + Sync + 'static) -> TransportError {
        Self::custom(err)
    }
}

/// A Tempo transport that routes sponsored `eth_sendRawTransaction` requests.
///
/// Single `eth_sendRawTransaction` requests are validated as unsigned Tempo AA transactions and
/// forwarded unchanged to the sponsor relay. All other RPC methods go directly to the default
/// transport. Batched requests containing `eth_sendRawTransaction` are rejected; use Tempo AA native
/// batching instead.
///
/// The relay transport should point to a Tempo sponsor relay service.
#[derive(Debug, Clone)]
pub struct RelayTransport<D, R> {
    default: D,
    relay: R,
}

/// Tower layer that wraps a default transport with sponsor relay support.
#[derive(Debug, Clone)]
pub struct RelayLayer<R> {
    relay: R,
}

impl<R> RelayLayer<R> {
    /// Create a relay layer.
    pub fn new(relay: R) -> Self {
        Self { relay }
    }
}

impl<D, R> tower::Layer<D> for RelayLayer<R>
where
    R: Clone,
{
    type Service = RelayTransport<D, R>;

    fn layer(&self, default: D) -> Self::Service {
        RelayTransport::new(default, self.relay.clone())
    }
}

/// Transport connector that combines default and sponsor relay connectors into a [`RelayTransport`].
#[derive(Debug, Clone)]
pub struct RelayConnector<D, R> {
    default: D,
    relay: R,
}

impl<D, R> RelayConnector<D, R> {
    /// Create a connector from default RPC and sponsor relay connectors.
    pub fn new(default: D, relay: R) -> Self {
        Self { default, relay }
    }
}

impl RelayConnector<BuiltInConnectionString, BuiltInConnectionString> {
    /// Create a relay connector from Alloy built-in connection strings.
    pub fn builtin(default: &str, relay: &str) -> Result<Self, TransportError> {
        let default =
            BuiltInConnectionString::from_str(default).map_err(TransportErrorKind::custom)?;
        let relay = BuiltInConnectionString::from_str(relay).map_err(TransportErrorKind::custom)?;
        Ok(Self::new(default, relay))
    }

    /// Alias for [`Self::builtin`] for the common HTTP URL case.
    pub fn http(default: &str, relay: &str) -> Result<Self, TransportError> {
        Self::builtin(default, relay)
    }
}

impl<D, R> TransportConnect for RelayConnector<D, R>
where
    D: TransportConnect,
    R: TransportConnect,
{
    fn is_local(&self) -> bool {
        self.default.is_local()
    }

    async fn get_transport(&self) -> Result<BoxTransport, TransportError> {
        let default = self.default.get_transport().await?;
        let relay = self.relay.get_transport().await?;
        Ok(BoxTransport::new(RelayTransport::new(default, relay)))
    }
}

impl<D, R> RelayTransport<D, R> {
    /// Create a new Tempo relay transport.
    pub fn new(default: D, relay: R) -> Self {
        Self { default, relay }
    }
}

const SEND_RAW_TX: &str = "eth_sendRawTransaction";
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
        futures::ready!(self.default.poll_ready(cx))?;
        futures::ready!(self.relay.poll_ready(cx))?;
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        match request {
            RequestPacket::Single(req) if req.method() == SEND_RAW_TX => {
                let mut relay = self.relay.clone();
                Box::pin(async move {
                    validate_send_raw_request(&req)?;
                    relay.call(RequestPacket::Single(req)).await
                })
            }
            RequestPacket::Batch(reqs) if reqs.iter().any(|req| req.method() == SEND_RAW_TX) => {
                Box::pin(async move {
                    Err(TransportErrorKind::custom_str(
                        "RelayTransport does not support JSON-RPC batches containing eth_sendRawTransaction; use a single Tempo AA transaction with multiple calls",
                    ))
                })
            }
            other => self.default.call(other),
        }
    }
}

fn validate_send_raw_request(request: &SerializedRequest) -> Result<(), TransportError> {
    let raw_tx = extract_raw_transaction(request.serialized().get())?;
    decode_unsigned_tempo_aa(raw_tx)?;
    Ok(())
}

fn extract_raw_transaction(serialized_request: &str) -> Result<&str, TransportError> {
    #[derive(serde::Deserialize)]
    struct SendRawRequest<'a> {
        #[serde(borrow)]
        params: [&'a str; 1],
    }

    let request: SendRawRequest<'_> =
        serde_json::from_str(serialized_request).map_err(TransportErrorKind::non_retryable)?;
    Ok(request.params[0])
}

fn decode_tempo_envelope(raw_tx: &str) -> Result<TempoTxEnvelope, TransportError> {
    let raw_tx = raw_tx
        .strip_prefix("0x")
        .ok_or_else(|| TransportErrorKind::custom_str("raw transaction must be 0x-prefixed"))?;
    let bytes = hex::decode(raw_tx).map_err(TransportErrorKind::non_retryable)?;
    TempoTxEnvelope::decode_2718(&mut bytes.as_slice()).map_err(TransportErrorKind::non_retryable)
}

fn decode_unsigned_tempo_aa(raw_tx: &str) -> Result<AASigned, TransportError> {
    match decode_tempo_envelope(raw_tx)? {
        TempoTxEnvelope::AA(tx) if tx.tx().fee_payer_signature.is_none() => {
            tx.recover_signer()
                .map_err(TransportErrorKind::non_retryable)?;
            Ok(tx)
        }
        TempoTxEnvelope::AA(_) => Err(TransportErrorKind::custom_str(
            "raw transaction is already fee-payer signed",
        )),
        _ => Err(TransportErrorKind::custom_str(
            "raw transaction is not a Tempo AA transaction",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::Encodable2718;
    use alloy_json_rpc::{Id, Request, Response, ResponsePayload, SerializedRequest};
    use alloy_primitives::{Address, Bytes, TxKind, U256, hex};
    use alloy_signer::SignerSync;
    use serde_json::value::RawValue;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    use tempo_primitives::{
        TempoSignature, TempoTransaction, TempoTxEnvelope,
        transaction::{Call, PrimitiveSignature},
    };
    use tower::Layer;

    #[derive(Clone, Debug, Default)]
    struct RecordingTransport {
        requests: Arc<Mutex<Vec<SerializedRequest>>>,
        responses: Arc<Mutex<VecDeque<ResponsePayload>>>,
    }

    impl RecordingTransport {
        fn push_success<T: serde::Serialize>(&self, value: &T) {
            let raw = RawValue::from_string(serde_json::to_string(value).unwrap()).unwrap();
            self.responses
                .lock()
                .unwrap()
                .push_back(ResponsePayload::Success(raw));
        }
        fn push_failure(&self, message: &'static str) {
            self.responses
                .lock()
                .unwrap()
                .push_back(ResponsePayload::Failure(
                    alloy_json_rpc::ErrorPayload::internal_error_message(message.into()),
                ));
        }
        fn methods(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|req| req.method().to_string())
                .collect()
        }
        fn params(&self, index: usize) -> serde_json::Value {
            let requests = self.requests.lock().unwrap();
            let request: serde_json::Value =
                serde_json::from_str(requests[index].serialized().get()).unwrap();
            request.get("params").cloned().unwrap_or_default()
        }
        fn ids(&self) -> Vec<Id> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|req| req.id().clone())
                .collect()
        }
        fn header_value(&self, index: usize, name: &str) -> Option<String> {
            self.requests.lock().unwrap()[index]
                .headers()
                .and_then(|headers| headers.get(name))
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)
        }
        fn record(&self, req: SerializedRequest) -> Result<Response, TransportError> {
            let payload = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| TransportErrorKind::custom_str("missing mock response"))?;
            self.requests.lock().unwrap().push(req.clone());
            if let ResponsePayload::Failure(err) = payload {
                return Err(TransportErrorKind::custom_str(&err.message));
            }
            Ok(Response {
                id: req.id().clone(),
                payload,
            })
        }
    }

    impl tower::Service<RequestPacket> for RecordingTransport {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = TransportFut<'static>;
        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: RequestPacket) -> Self::Future {
            let this = self.clone();
            Box::pin(async move {
                Ok(match req {
                    RequestPacket::Single(req) => ResponsePacket::Single(this.record(req)?),
                    RequestPacket::Batch(reqs) => ResponsePacket::Batch(
                        reqs.into_iter()
                            .map(|req| this.record(req))
                            .collect::<Result<_, _>>()?,
                    ),
                })
            })
        }
    }

    #[derive(Clone, Debug)]
    struct ConnectForTest(RecordingTransport);
    impl TransportConnect for ConnectForTest {
        fn is_local(&self) -> bool {
            true
        }
        async fn get_transport(&self) -> Result<BoxTransport, TransportError> {
            Ok(BoxTransport::new(self.0.clone()))
        }
    }

    fn make_request(method: &'static str) -> RequestPacket {
        RequestPacket::Single(
            Request::new(method, Id::Number(1), None::<&RawValue>)
                .try_into()
                .unwrap(),
        )
    }
    fn send_req_with_id(raw_tx: &str, id: Id) -> SerializedRequest {
        Request::new(SEND_RAW_TX, id, Some([raw_tx]))
            .try_into()
            .unwrap()
    }
    fn make_send_raw_tx_request(raw_tx: &str) -> RequestPacket {
        RequestPacket::Single(send_req_with_id(raw_tx, Id::Number(1)))
    }
    fn make_batch_no_send() -> RequestPacket {
        RequestPacket::Batch(vec![
            Request::new("eth_chainId", Id::Number(1), None::<&RawValue>)
                .try_into()
                .unwrap(),
            Request::new("eth_blockNumber", Id::Number(2), None::<&RawValue>)
                .try_into()
                .unwrap(),
        ])
    }
    fn make_batch_with_send_raw_tx(raw_tx: &str) -> RequestPacket {
        RequestPacket::Batch(vec![
            Request::new("eth_chainId", Id::Number(1), None::<&RawValue>)
                .try_into()
                .unwrap(),
            Request::new(SEND_RAW_TX, Id::Number(2), Some([raw_tx]))
                .try_into()
                .unwrap(),
        ])
    }

    const USER_PK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const FEE_PAYER_PK: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

    fn signed_tempo_aa_raw_tx(fee_payer_signed: bool) -> String {
        let user: alloy_signer_local::PrivateKeySigner = USER_PK.parse().unwrap();
        let fee_payer: alloy_signer_local::PrivateKeySigner = FEE_PAYER_PK.parse().unwrap();
        let mut tx = TempoTransaction {
            chain_id: 42431,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 21_000,
            calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x11)),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            nonce: 1,
            ..Default::default()
        };
        let user_sig = user.sign_hash_sync(&tx.signature_hash()).unwrap();
        if fee_payer_signed {
            tx.fee_payer_signature = Some(
                fee_payer
                    .sign_hash_sync(&tx.fee_payer_signature_hash(user.address()))
                    .unwrap(),
            );
        }
        let envelope = TempoTxEnvelope::AA(tx.into_signed(TempoSignature::Primitive(
            PrimitiveSignature::Secp256k1(user_sig),
        )));
        let mut encoded = Vec::new();
        envelope.encode_2718(&mut encoded);
        format!("0x{}", hex::encode(encoded))
    }

    #[test]
    fn decodes_unsigned_tempo_aa_raw_transaction_for_sdk_users() {
        let raw_tx = signed_tempo_aa_raw_tx(false);
        let user: alloy_signer_local::PrivateKeySigner = USER_PK.parse().unwrap();

        let tx = decode_unsigned_tempo_aa(&raw_tx).unwrap();
        let signer = tx.recover_signer().unwrap();

        assert_eq!(signer, user.address());
        assert!(tx.tx().fee_payer_signature.is_none());
    }

    #[test]
    fn decode_unsigned_tempo_aa_raw_transaction_rejects_fee_payer_signed_tx() {
        let err = decode_unsigned_tempo_aa(&signed_tempo_aa_raw_tx(true))
            .expect_err("fee-payer signed tx should be rejected");

        assert!(err.to_string().contains("already fee-payer signed"));
    }

    #[tokio::test]
    async fn routes_non_send_to_default_only() {
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        default.push_success(&alloy_primitives::U64::from(42));
        let mut transport = RelayTransport::new(default.clone(), relay.clone());
        assert!(
            tower::Service::call(&mut transport, make_request("eth_getTransactionCount"))
                .await
                .is_ok()
        );
        assert_eq!(default.methods(), vec!["eth_getTransactionCount"]);
        assert!(relay.methods().is_empty());
    }

    #[tokio::test]
    async fn batch_without_send_forwards_to_default_unchanged() {
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        default.push_success(&alloy_primitives::U64::from(42431));
        default.push_success(&alloy_primitives::U64::from(7));
        let mut transport = RelayTransport::new(default.clone(), relay.clone());
        assert!(
            tower::Service::call(&mut transport, make_batch_no_send())
                .await
                .is_ok()
        );
        assert_eq!(default.methods(), vec!["eth_chainId", "eth_blockNumber"]);
        assert!(relay.methods().is_empty());
    }

    #[tokio::test]
    async fn send_raw_tx_forwards_original_to_relay_only() {
        let raw_tx = signed_tempo_aa_raw_tx(false);
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        relay.push_success(&alloy_primitives::B256::ZERO);
        let mut transport = RelayTransport::new(default.clone(), relay.clone());
        assert!(
            tower::Service::call(&mut transport, make_send_raw_tx_request(&raw_tx))
                .await
                .is_ok()
        );
        assert_eq!(relay.methods(), vec![SEND_RAW_TX]);
        assert_eq!(relay.params(0), serde_json::json!([raw_tx]));
        assert!(default.methods().is_empty());
    }

    #[tokio::test]
    async fn rejects_non_tempo_aa_before_relay() {
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        let mut transport = RelayTransport::new(default.clone(), relay.clone());
        assert!(
            tower::Service::call(&mut transport, make_send_raw_tx_request("0x01"))
                .await
                .is_err()
        );
        assert!(default.methods().is_empty());
        assert!(relay.methods().is_empty());
    }

    #[tokio::test]
    async fn rejects_already_fee_payer_signed_tx_before_relay() {
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        let mut transport = RelayTransport::new(default.clone(), relay.clone());
        assert!(
            tower::Service::call(
                &mut transport,
                make_send_raw_tx_request(&signed_tempo_aa_raw_tx(true))
            )
            .await
            .is_err()
        );
        assert!(default.methods().is_empty());
        assert!(relay.methods().is_empty());
    }

    #[tokio::test]
    async fn relay_error_propagates_without_default_call() {
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        relay.push_failure("sponsor account broke");
        let mut transport = RelayTransport::new(default.clone(), relay.clone());
        assert!(
            tower::Service::call(
                &mut transport,
                make_send_raw_tx_request(&signed_tempo_aa_raw_tx(false))
            )
            .await
            .is_err()
        );
        assert_eq!(relay.methods(), vec![SEND_RAW_TX]);
        assert!(default.methods().is_empty());
    }

    #[tokio::test]
    async fn preserves_request_id_when_forwarding_to_relay() {
        let raw_tx = signed_tempo_aa_raw_tx(false);
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        relay.push_success(&alloy_primitives::B256::ZERO);
        let mut transport = RelayTransport::new(default, relay.clone());
        let req = RequestPacket::Single(send_req_with_id(&raw_tx, Id::String("abc".into())));
        assert!(tower::Service::call(&mut transport, req).await.is_ok());
        assert_eq!(relay.ids(), vec![Id::String("abc".into())]);
    }

    #[tokio::test]
    async fn preserves_request_headers_when_forwarding_to_relay() {
        let raw_tx = signed_tempo_aa_raw_tx(false);
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        relay.push_success(&alloy_primitives::B256::ZERO);
        let mut transport = RelayTransport::new(default, relay.clone());
        let mut req = send_req_with_id(&raw_tx, Id::Number(1));
        req.headers_mut()
            .insert("authorization", "Bearer token".parse().unwrap());
        assert!(
            tower::Service::call(&mut transport, RequestPacket::Single(req))
                .await
                .is_ok()
        );
        assert_eq!(
            relay.header_value(0, "authorization"),
            Some("Bearer token".to_string())
        );
    }

    #[tokio::test]
    async fn rejects_batch_containing_send_before_any_transport_call() {
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        let mut transport = RelayTransport::new(default.clone(), relay.clone());
        let err = tower::Service::call(
            &mut transport,
            make_batch_with_send_raw_tx(&signed_tempo_aa_raw_tx(false)),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not support JSON-RPC batches containing eth_sendRawTransaction")
        );
        assert!(default.methods().is_empty());
        assert!(relay.methods().is_empty());
    }

    #[tokio::test]
    async fn relay_layer_wraps_default_transport() {
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        default.push_success(&alloy_primitives::U64::from(42));
        let mut transport = RelayLayer::new(relay.clone()).layer(default.clone());
        assert!(
            tower::Service::call(&mut transport, make_request("eth_chainId"))
                .await
                .is_ok()
        );
        assert_eq!(default.methods(), vec!["eth_chainId"]);
        assert!(relay.methods().is_empty());
    }

    #[tokio::test]
    async fn relay_connector_builds_boxed_relay_transport() {
        let default = RecordingTransport::default();
        let relay = RecordingTransport::default();
        default.push_success(&alloy_primitives::U64::from(42));
        let connect = RelayConnector::new(
            ConnectForTest(default.clone()),
            ConnectForTest(relay.clone()),
        );
        assert!(connect.is_local());
        let mut transport = connect.get_transport().await.unwrap();
        assert!(
            tower::Service::call(&mut transport, make_request("eth_chainId"))
                .await
                .is_ok()
        );
        assert_eq!(default.methods(), vec!["eth_chainId"]);
        assert!(relay.methods().is_empty());
    }

    #[test]
    fn relay_connector_parses_builtin_urls() {
        let connect =
            RelayConnector::http("http://localhost:8545", "https://sponsor.testnet.tempo.xyz")
                .unwrap();
        assert!(connect.is_local());
    }
}
