use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U256},
    providers::ProviderBuilder,
};
use alloy_json_rpc::{RequestPacket, Response, ResponsePacket, ResponsePayload, SerializedRequest};
use alloy_provider::fillers::TxFiller;
use alloy_rpc_client::RpcClient;
use alloy_transport::{BoxTransport, TransportError, TransportFut};
use serde_json::value::RawValue;
use std::sync::{Arc, Mutex};
use tempo_alloy::{
    TempoNetwork, fillers::NonceKeyFiller, provider::TempoProviderExt, rpc::TempoTransactionRequest,
};

#[derive(Clone, Debug, Default)]
struct RecordingTransport {
    requests: Arc<Mutex<Vec<SerializedRequest>>>,
}

impl RecordingTransport {
    fn params(&self) -> serde_json::Value {
        let requests = self.requests.lock().unwrap();
        let request: serde_json::Value =
            serde_json::from_str(requests[0].serialized().get()).unwrap();
        request.get("params").cloned().unwrap_or_default()
    }

    fn record(&self, request: SerializedRequest) -> Response {
        self.requests.lock().unwrap().push(request.clone());
        Response {
            id: request.id().clone(),
            payload: ResponsePayload::Success(
                RawValue::from_string(serde_json::to_string("0x5").unwrap()).unwrap(),
            ),
        }
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

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            Ok(match request {
                RequestPacket::Single(request) => ResponsePacket::Single(this.record(request)),
                RequestPacket::Batch(requests) => ResponsePacket::Batch(
                    requests
                        .into_iter()
                        .map(|request| this.record(request))
                        .collect(),
                ),
            })
        })
    }
}

fn provider() -> (
    impl alloy::providers::Provider<TempoNetwork>,
    RecordingTransport,
) {
    let transport = RecordingTransport::default();
    let client = RpcClient::new(BoxTransport::new(transport.clone()), true);
    let provider = ProviderBuilder::<_, _, TempoNetwork>::default().connect_client(client);
    (provider, transport)
}

#[tokio::test]
async fn protocol_nonce_filler_uses_pending_transaction_count() -> eyre::Result<()> {
    let (provider, transport) = provider();
    let filler = NonceKeyFiller::default();
    let account = Address::repeat_byte(0x11);
    let mut request = TempoTransactionRequest::default().with_nonce_key(U256::ZERO);
    request.set_from(account);

    let nonce = TxFiller::<TempoNetwork>::prepare(&filler, &provider, &request).await?;
    assert_eq!(nonce, 5);

    let params = transport.params();
    assert_eq!(
        params.as_array().and_then(|values| values.get(1)),
        Some(&serde_json::json!("pending"))
    );

    Ok(())
}

#[tokio::test]
async fn protocol_nonce_key_query_uses_pending_transaction_count() -> eyre::Result<()> {
    let (provider, transport) = provider();
    let account = Address::repeat_byte(0x11);

    let nonce = provider
        .get_transaction_count_with_nonce_key(account, U256::ZERO)
        .await?;
    assert_eq!(nonce, 5);

    let params = transport.params();
    assert_eq!(
        params.as_array().and_then(|values| values.get(1)),
        Some(&serde_json::json!("pending"))
    );

    Ok(())
}
