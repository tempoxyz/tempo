use alloy_consensus::transaction::SignerRecoverable;
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_primitives::{
    AASigned, TempoTransaction,
    transaction::{Call, FEE_PAYER_SIGNATURE_MARKER},
};
use tempo_relay::{
    Backend, Next, Plugin, Relay, Request, RpcError,
    http::serve,
    plugins::{FeeToken, Preflight},
    sponsor::{FeePayer, Observer, Policy, Sponsor, SponsoredEvent},
};

const TOKEN: Address = Address::repeat_byte(0x20);

#[derive(Default)]
struct RecordingBackend {
    requests: Mutex<Vec<Request>>,
    result: Value,
}

struct RejectPolicy;
#[async_trait]
impl Policy for RejectPolicy {
    async fn validate(&self, _: &Value) -> Result<Option<String>, RpcError> {
        Ok(Some("spend_limit_exceeded".into()))
    }
}

struct BrokenRecorder;
#[async_trait]
impl Observer for BrokenRecorder {
    async fn on_sponsored(&self, _: SponsoredEvent) -> Result<(), RpcError> {
        Err(RpcError::new(-32603, "Recording unavailable"))
    }
}

#[tokio::test]
async fn sponsorship_refusal_and_recording_failure_never_broadcast() {
    let signed = signed_transaction(transaction());
    for (configured, expected) in [
        (
            sponsor().with_policy(Arc::new(RejectPolicy)),
            "Spend limit exceeded.",
        ),
        (
            sponsor().with_observer(Arc::new(BrokenRecorder)),
            "Recording unavailable",
        ),
    ] {
        let backend = Arc::new(RecordingBackend::default());
        let relay = Relay::new(backend.clone())
            .with_sponsor(configured)
            .unwrap();
        let error = relay
            .handle(Request::new(
                "eth_sendRawTransaction",
                vec![json!(Bytes::from(signed.encoded_2718()))],
            ))
            .await
            .unwrap_err();
        assert_eq!(error.message, expected);
        assert!(backend.requests.lock().unwrap().is_empty());
    }
}

#[async_trait]
impl Backend for RecordingBackend {
    async fn request(&self, request: Request) -> Result<Value, RpcError> {
        self.requests.lock().unwrap().push(request);
        Ok(self.result.clone())
    }
}

fn sender() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap()
}

fn payer() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap()
}

fn sponsor() -> Sponsor {
    Sponsor::new(Arc::new(payer()), 1337, TOKEN, 1_000_000, 1_000_000_000).unwrap()
}

fn transaction() -> TempoTransaction {
    TempoTransaction {
        chain_id: 1337,
        gas_limit: 100_000,
        max_fee_per_gas: 100_000_000,
        max_priority_fee_per_gas: 0,
        calls: vec![Call {
            to: sender().address().into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        fee_payer_signature: Some(FEE_PAYER_SIGNATURE_MARKER),
        ..Default::default()
    }
}

fn signed_transaction(transaction: TempoTransaction) -> AASigned {
    let signature = sender()
        .sign_hash_sync(&transaction.signature_hash())
        .unwrap();
    transaction.into_signed(signature.into())
}

fn decode(value: Value) -> AASigned {
    let bytes: Bytes = serde_json::from_value(value).unwrap();
    let mut remaining = bytes.as_ref();
    let signed = AASigned::decode_2718(&mut remaining).unwrap();
    assert!(remaining.is_empty());
    signed
}

#[tokio::test]
async fn native_grant_preserves_outer_signature_and_authorization() {
    let fixture: Value = serde_json::from_str(include_str!("multisig-fixtures.json")).unwrap();
    let original: Bytes = serde_json::from_value(fixture["nativeGrantSigned"].clone()).unwrap();
    let original_fields = tempo_relay::wire::Rlp::decode(&original[1..]).unwrap();
    let original_fields = original_fields.list().unwrap();
    let backend = Arc::new(RecordingBackend::default());
    let relay = Relay::new(backend).with_sponsor(sponsor()).unwrap();
    let result = relay
        .handle(Request::new(
            "eth_signRawTransaction",
            vec![json!(original)],
        ))
        .await
        .unwrap();
    let sponsored: Bytes = serde_json::from_value(result).unwrap();
    assert_eq!(sponsored[0], 0x76);
    let fields = tempo_relay::wire::Rlp::decode(&sponsored[1..]).unwrap();
    let fields = fields.list().unwrap();
    assert_eq!(fields[13], original_fields[13]);
    assert_eq!(fields[14], original_fields[14]);
    assert_eq!(&fields[..10], &original_fields[..10]);
    assert_eq!(fields[12], original_fields[12]);
    assert_eq!(fields[10].bytes().unwrap(), TOKEN.as_slice());
    let sender: Address = serde_json::from_value(fixture["account"].clone()).unwrap();
    let mut payload = fields[..14].to_vec();
    payload[11] = tempo_relay::wire::Rlp::Bytes(sender.to_vec());
    let hash = alloy_primitives::keccak256(
        [&[0x78][..], &tempo_relay::wire::Rlp::List(payload).encode()].concat(),
    );
    let signature = fields[11].list().unwrap();
    let signature = alloy_primitives::Signature::new(
        U256::from_be_slice(signature[1].bytes().unwrap()),
        U256::from_be_slice(signature[2].bytes().unwrap()),
        signature[0].integer().unwrap() != 0,
    );
    assert_eq!(
        signature.recover_address_from_prehash(&hash).unwrap(),
        payer().address()
    );
}

#[tokio::test]
async fn native_grant_rejects_spoofed_sender_and_missing_quorum() {
    let fixture: Value = serde_json::from_str(include_str!("multisig-fixtures.json")).unwrap();
    let original: Bytes = serde_json::from_value(fixture["nativeGrantSigned"].clone()).unwrap();
    let backend = Arc::new(RecordingBackend::default());
    let relay = Relay::new(backend.clone()).with_sponsor(sponsor()).unwrap();
    let mut fields = tempo_relay::wire::Rlp::decode(&original[1..])
        .unwrap()
        .list()
        .unwrap()
        .to_vec();
    fields[11] = tempo_relay::wire::Rlp::Bytes(sender().address().to_vec());
    let spoofed =
        Bytes::from([&[0x78][..], &tempo_relay::wire::Rlp::List(fields).encode()].concat());
    let error = relay
        .handle(Request::new("eth_sendRawTransaction", vec![json!(spoofed)]))
        .await
        .unwrap_err();
    assert_eq!(
        error.message,
        "Fee-payer service sender differs from recovered signer"
    );
    let mut fields = tempo_relay::wire::Rlp::decode(&original[1..])
        .unwrap()
        .list()
        .unwrap()
        .to_vec();
    let mut grant = tempo_relay::wire::Envelope::decode(&fields[13].encode(), false).unwrap();
    grant.witness.approvals.truncate(1);
    fields[13] = tempo_relay::wire::Rlp::decode(&grant.serialize(Some(&grant.witness))).unwrap();
    let partial =
        Bytes::from([&[0x78][..], &tempo_relay::wire::Rlp::List(fields).encode()].concat());
    let error = relay
        .handle(Request::new("eth_sendRawTransaction", vec![json!(partial)]))
        .await
        .unwrap_err();
    assert_eq!(
        error.message,
        "Multisig grant quorum is required before sponsorship"
    );
    assert!(backend.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn native_grant_policy_and_recording_failure_never_broadcast() {
    let fixture: Value = serde_json::from_str(include_str!("multisig-fixtures.json")).unwrap();
    for (configured, expected) in [
        (
            sponsor().with_policy(Arc::new(RejectPolicy)),
            "Spend limit exceeded.",
        ),
        (
            sponsor().with_observer(Arc::new(BrokenRecorder)),
            "Recording unavailable",
        ),
    ] {
        let backend = Arc::new(RecordingBackend::default());
        let relay = Relay::new(backend.clone())
            .with_sponsor(configured)
            .unwrap();
        let error = relay
            .handle(Request::new(
                "eth_sendRawTransaction",
                vec![fixture["nativeGrantSigned"].clone()],
            ))
            .await
            .unwrap_err();
        assert_eq!(error.message, expected);
        assert!(backend.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn canonical_and_alloy_service_encodings_preserve_the_sender_signature() {
    let backend = Arc::new(RecordingBackend::default());
    let relay = Relay::new(backend.clone()).with_sponsor(sponsor()).unwrap();
    let original = signed_transaction(transaction());
    let mut service = Vec::new();
    original.encode_for_fee_payer_service(&mut service);
    for bytes in [original.encoded_2718(), service] {
        let result = relay
            .handle(Request::new(
                "eth_signRawTransaction",
                vec![json!(Bytes::from(bytes))],
            ))
            .await
            .unwrap();
        let sponsored = decode(result);
        assert_eq!(sponsored.signature(), original.signature());
        assert_eq!(sponsored.recover_signer().unwrap(), sender().address());
        assert_eq!(
            sponsored
                .tx()
                .recover_fee_payer(sender().address())
                .unwrap(),
            payer().address()
        );
        assert_eq!(sponsored.tx().fee_token, Some(TOKEN));
        assert_eq!(sponsored.signature_hash(), original.signature_hash());
    }
    assert!(backend.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ox_fixtures_cover_viem_markers_and_fee_payer_magic() {
    let relay = Relay::new(Arc::new(RecordingBackend::default()))
        .with_sponsor(sponsor())
        .unwrap();
    let fixtures = [
        "0x76f871820539808405f5e100830186a0d8d7941a642f0e3c3af545e7acbd38b07251b3990914f18080c0808080808000c0b841cdbc7f2285098bd9269bcdc699c7c75ac5dd702e50ccb23f9da6cce5079172887b1a48311c78dc24835bfa69714d30a612ffe250b21104a5ef52fa38162841051b",
        "0x78f885820539808405f5e100830186a0d8d7941a642f0e3c3af545e7acbd38b07251b3990914f18080c08080808080941a642f0e3c3af545e7acbd38b07251b3990914f1c0b841cdbc7f2285098bd9269bcdc699c7c75ac5dd702e50ccb23f9da6cce5079172887b1a48311c78dc24835bfa69714d30a612ffe250b21104a5ef52fa38162841051b",
    ];
    for raw in fixtures {
        let result = relay
            .handle(Request::new("eth_signRawTransaction", vec![json!(raw)]))
            .await
            .unwrap();
        let signed = decode(result);
        assert_eq!(signed.recover_signer().unwrap(), sender().address());
        assert_eq!(
            signed.tx().recover_fee_payer(sender().address()).unwrap(),
            payer().address()
        );
        assert_eq!(
            signed.signature_hash(),
            "0xf443715d47f1e233f6108e75f83bd623871c8ac869edf248ea804b571674940b"
                .parse::<B256>()
                .unwrap()
        );
    }
    let spoofed = fixtures[1].replacen(
        "941a642f0e3c3af545e7acbd38b07251b3990914f1c0",
        "942222222222222222222222222222222222222222c0",
        1,
    );
    let error = relay
        .handle(Request::new("eth_signRawTransaction", vec![json!(spoofed)]))
        .await
        .unwrap_err();
    assert_eq!(
        error.message,
        "Fee-payer service sender differs from recovered signer"
    );
}

#[tokio::test]
async fn broadcasts_once_and_never_overwrites_a_real_fee_payer() {
    let backend = Arc::new(RecordingBackend {
        result: json!(B256::repeat_byte(9)),
        ..Default::default()
    });
    let relay = Relay::new(backend.clone()).with_sponsor(sponsor()).unwrap();
    let raw = json!(Bytes::from(
        signed_transaction(transaction()).encoded_2718()
    ));
    let sponsored = relay
        .handle(Request::new("eth_signRawTransaction", vec![raw]))
        .await
        .unwrap();
    relay
        .handle(Request::new(
            "eth_sendRawTransactionSync",
            vec![sponsored.clone(), json!(5000)],
        ))
        .await
        .unwrap();
    let requests = backend.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "eth_sendRawTransactionSync");
    assert_eq!(requests[0].params, vec![sponsored, json!(5000)]);
}

#[tokio::test]
async fn rejects_wrong_chain_excess_fees_trailing_data_and_unsigned_requests() {
    let backend = Arc::new(RecordingBackend::default());
    let relay = Relay::new(backend.clone()).with_sponsor(sponsor()).unwrap();
    let mut wrong_chain = transaction();
    wrong_chain.chain_id = 4217;
    let mut excess_gas = transaction();
    excess_gas.gas_limit = 1_000_001;
    let mut excess_fee = transaction();
    excess_fee.max_fee_per_gas = 1_000_000_001;
    let mut not_sponsored = transaction();
    not_sponsored.fee_payer_signature = None;
    for transaction in [wrong_chain, excess_gas, excess_fee, not_sponsored] {
        let error = relay
            .handle(Request::new(
                "eth_signRawTransaction",
                vec![json!(Bytes::from(
                    signed_transaction(transaction).encoded_2718()
                ))],
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code, -32602);
    }
    let mut trailing = signed_transaction(transaction()).encoded_2718();
    trailing.push(0);
    assert_eq!(
        relay
            .handle(Request::new(
                "eth_signRawTransaction",
                vec![json!(Bytes::from(trailing))]
            ))
            .await
            .unwrap_err()
            .code,
        -32602
    );
    assert!(backend.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn fill_preserves_access_key_metadata_and_returns_a_valid_fee_payer_signature() {
    let mut filled_transaction = TempoTransactionRequest::from(transaction());
    filled_transaction.fee_payer_signature = None;
    let backend = Arc::new(RecordingBackend {
        result: json!({"tx": filled_transaction}),
        ..Default::default()
    });
    let relay = Relay::new(backend.clone())
        .with_plugin(FeeToken(TOKEN))
        .with_sponsor(sponsor())
        .unwrap();
    let result = relay
        .handle(Request::new(
            "eth_fillTransaction",
            vec![json!({
                "from": sender().address(), "calls": [{"to": sender().address()}],
                "keyType": "p256", "keyId": Address::repeat_byte(3), "feePayer": true
            })],
        ))
        .await
        .unwrap();
    let requests = backend.requests.lock().unwrap();
    assert_eq!(requests[0].params[0]["keyType"], "p256");
    assert_eq!(
        requests[0].params[0]["keyId"],
        json!(Address::repeat_byte(3))
    );
    assert_eq!(requests[0].params[0]["feePayer"], true);
    assert!(requests[0].params[0].get("feeToken").is_none());
    let request: TempoTransactionRequest = serde_json::from_value(result["tx"].clone()).unwrap();
    let transaction = request.build_aa().unwrap();
    assert_eq!(
        transaction.recover_fee_payer(sender().address()).unwrap(),
        payer().address()
    );
    assert_eq!(result["capabilities"]["sponsored"], true);
    assert_eq!(
        result["capabilities"]["sponsor"]["address"],
        json!(payer().address())
    );
}

#[tokio::test]
async fn sponsored_preflight_preserves_key_hints_without_charging_the_sender() {
    let mut filled_transaction = TempoTransactionRequest::from(transaction());
    filled_transaction.fee_payer_signature = None;
    let backend = Arc::new(RecordingBackend {
        result: json!({"tx": filled_transaction}),
        ..Default::default()
    });
    let relay = Relay::new(backend.clone())
        .with_plugin(Preflight)
        .with_sponsor(sponsor())
        .unwrap();
    let result = relay
        .handle(Request::new(
            "eth_fillTransaction",
            vec![json!({
                "from": sender().address(), "calls": [{"to": sender().address()}],
                "keyType": "p256", "keyId": Address::repeat_byte(3), "feePayer": true
            })],
        ))
        .await
        .unwrap();
    let requests = backend.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].method, "eth_estimateGas");
    let estimate = &requests[1].params[0];
    assert_eq!(estimate["keyType"], "p256");
    assert_eq!(estimate["keyId"], json!(Address::repeat_byte(3)));
    assert_eq!(estimate["from"], json!(sender().address()));
    assert_eq!(estimate["feeToken"], json!(TOKEN));
    assert_eq!(estimate["maxFeePerGas"], "0x0");
    assert_eq!(estimate["maxPriorityFeePerGas"], "0x0");
    let request: TempoTransactionRequest = serde_json::from_value(result["tx"].clone()).unwrap();
    let final_transaction = request.build_aa().unwrap();
    assert_eq!(
        final_transaction.max_fee_per_gas,
        transaction().max_fee_per_gas
    );
    assert_eq!(
        final_transaction
            .recover_fee_payer(sender().address())
            .unwrap(),
        payer().address()
    );
}

#[tokio::test]
async fn explicit_opt_out_and_fee_token_are_preserved() {
    let backend = Arc::new(RecordingBackend {
        result: json!({"tx": {}}),
        ..Default::default()
    });
    let relay = Relay::new(backend.clone())
        .with_plugin(FeeToken(TOKEN))
        .with_sponsor(sponsor())
        .unwrap();
    let explicit = Address::repeat_byte(4);
    let result = relay
        .handle(Request::new(
            "eth_fillTransaction",
            vec![json!({"feePayer": false, "feeToken": explicit})],
        ))
        .await
        .unwrap();
    assert_eq!(result["tx"]["feeToken"], json!(explicit));
    assert!(result["tx"].get("feePayerSignature").is_none());
    assert_eq!(
        backend.requests.lock().unwrap()[0].params[0]["feeToken"],
        json!(explicit)
    );
}

struct Capability;

#[async_trait]
impl Plugin for Capability {
    async fn after_fill(
        &self,
        _request: &Request,
        _filled: &Value,
        _backend: &dyn Backend,
    ) -> Result<serde_json::Map<String, Value>, RpcError> {
        Ok(serde_json::Map::from_iter([("test".into(), json!(true))]))
    }
}

struct CountingPayer(AtomicUsize);

#[async_trait]
impl FeePayer for CountingPayer {
    fn address(&self) -> Address {
        payer().address()
    }
    async fn sign_hash(&self, hash: B256) -> Result<alloy_primitives::Signature, RpcError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(payer().sign_hash_sync(&hash).unwrap())
    }
}

#[tokio::test]
async fn conflicting_capabilities_are_rejected_before_signing() {
    let mut request = TempoTransactionRequest::from(transaction());
    request.fee_payer_signature = None;
    let backend = Arc::new(RecordingBackend {
        result: json!({"tx": request}),
        ..Default::default()
    });
    let payer = Arc::new(CountingPayer(AtomicUsize::new(0)));
    let relay = Relay::new(backend)
        .with_plugin(Capability)
        .with_plugin(Capability)
        .with_sponsor(Sponsor::new(payer.clone(), 1337, TOKEN, 1_000_000, 1_000_000_000).unwrap())
        .unwrap();
    let error = relay
        .handle(Request::new(
            "eth_fillTransaction",
            vec![json!({"from": sender().address()})],
        ))
        .await
        .unwrap_err();
    assert_eq!(error.message, "Conflicting relay capability: test");
    assert_eq!(payer.0.load(Ordering::SeqCst), 0);
}

struct OrderPlugin {
    name: &'static str,
    order: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl Plugin for OrderPlugin {
    async fn handle(&self, request: Request, next: Next<'_>) -> Result<Value, RpcError> {
        self.order
            .lock()
            .unwrap()
            .push(format!("{} before", self.name));
        let result = next.run(request).await;
        self.order
            .lock()
            .unwrap()
            .push(format!("{} after", self.name));
        result
    }
}

#[tokio::test]
async fn middleware_executes_in_order() {
    let backend = Arc::new(RecordingBackend {
        result: json!(1),
        ..Default::default()
    });
    let order = Arc::new(Mutex::new(Vec::new()));
    let relay = Relay::new(backend.clone())
        .with_plugin(OrderPlugin {
            name: "first",
            order: order.clone(),
        })
        .with_plugin(OrderPlugin {
            name: "second",
            order: order.clone(),
        });
    assert_eq!(
        relay
            .handle(Request::new("eth_chainId", vec![]))
            .await
            .unwrap(),
        json!(1)
    );
    assert_eq!(
        *order.lock().unwrap(),
        vec![
            "first before",
            "second before",
            "second after",
            "first after"
        ]
    );
    assert_eq!(backend.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn http_preserves_ids_batches_notifications_and_error_data() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    struct ErrorBackend;
    #[async_trait]
    impl Backend for ErrorBackend {
        async fn request(&self, request: Request) -> Result<Value, RpcError> {
            if request.method == "fail" {
                Err(RpcError {
                    code: 3,
                    message: "execution reverted".into(),
                    data: Some(json!("0xdeadbeef")),
                })
            } else {
                Ok(json!("0x539"))
            }
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve(listener, Relay::new(Arc::new(ErrorBackend)), async {
        let _ = stopped.await;
    }));
    let client = reqwest::Client::new();
    let response: Value = client
        .post(&url)
        .json(&json!([
            {"jsonrpc":"2.0","id":"hello","method":"eth_chainId"},
            {"jsonrpc":"2.0","method":"eth_chainId"},
            {"jsonrpc":"2.0","id":2,"method":"fail"}
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        response,
        json!([
            {"jsonrpc":"2.0","id":"hello","result":"0x539"},
            {"jsonrpc":"2.0","id":2,"error":{"code":3,"message":"execution reverted","data":"0xdeadbeef"}}
        ])
    );
    let response = client
        .post(&url)
        .json(&json!({"jsonrpc":"2.0","method":"eth_chainId"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    let malformed: Value = client
        .post(&url)
        .body("{")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(malformed["error"]["code"], -32700);
    let empty: Value = client
        .post(&url)
        .json(&json!([]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(empty["error"]["code"], -32600);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}
