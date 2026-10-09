use alloy_primitives::{B256, Bytes, Signature, U256, address, keccak256};
use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tempo_relay::{
    Backend, Relay, Request, RpcError,
    store::{MemoryStore, Store},
    wire::{self, Envelope},
};
use tokio::sync::Notify;

fn fixture() -> Value {
    serde_json::from_str(include_str!("multisig-fixtures.json")).unwrap()
}
fn bytes(value: &Value) -> Bytes {
    serde_json::from_value(value.clone()).unwrap()
}

#[derive(Default)]
struct NativeNode {
    broadcasts: AtomicUsize,
    accepted: Mutex<Option<B256>>,
    commitment: Mutex<B256>,
    block_broadcast: AtomicBool,
    started: Notify,
    finish: Notify,
    envelopes: Mutex<Vec<Bytes>>,
}

#[async_trait]
impl Backend for NativeNode {
    async fn request(&self, request: Request) -> Result<Value, RpcError> {
        match request.method.as_str() {
            "eth_blockNumber" => Ok(json!("0x1")),
            "eth_call" => Ok(json!(*self.commitment.lock().unwrap())),
            "eth_sendRawTransaction" | "eth_sendRawTransactionSync" => {
                self.broadcasts.fetch_add(1, Ordering::SeqCst);
                let serialized = bytes(&request.params[0]);
                let hash = keccak256(&serialized);
                self.envelopes.lock().unwrap().push(serialized);
                *self.accepted.lock().unwrap() = Some(hash);
                self.started.notify_one();
                if self.block_broadcast.load(Ordering::SeqCst) {
                    self.finish.notified().await;
                }
                if request.method.ends_with("Sync") {
                    Ok(json!({"transactionHash": hash, "status": "0x1"}))
                } else {
                    Ok(json!(hash))
                }
            }
            "eth_getTransactionByHash" | "eth_getTransactionReceipt" => {
                let hash: B256 = serde_json::from_value(request.params[0].clone()).unwrap();
                if *self.accepted.lock().unwrap() == Some(hash) {
                    Ok(json!({"hash": hash, "transactionHash": hash, "status": "0x1"}))
                } else {
                    Ok(Value::Null)
                }
            }
            _ => Err(RpcError::new(-32601, "Method not found")),
        }
    }
}

fn relay(store: Arc<dyn Store>, backend: Arc<NativeNode>) -> Relay {
    Relay::new(backend).with_multisig(store, 1337)
}

#[test]
fn ox_wire_hashes_accounts_commitments_and_final_envelopes_match() {
    let fixture = fixture();
    for index in 0..2 {
        let envelope = Envelope::decode(&bytes(&fixture["signed"][index]), true).unwrap();
        assert_eq!(
            json!(wire::account(&envelope.witness.config).unwrap()),
            fixture["account"]
        );
        assert_eq!(
            json!(wire::commitment(&envelope.witness.config)),
            fixture["commitment"]
        );
        assert_eq!(json!(envelope.unsigned()), fixture["unsigned"]);
        let hash = envelope.witness.digest(envelope.payload_hash());
        assert_eq!(json!(hash), fixture["hash"]);
        let approvals: Vec<Bytes> = serde_json::from_value(fixture["approvals"].clone()).unwrap();
        let selected = envelope.witness.select(hash, &approvals).unwrap();
        assert_eq!(selected.weight, 2);
        let mut witness = envelope.witness.clone();
        witness.approvals = selected.selected;
        assert_eq!(json!(envelope.serialize(Some(&witness))), fixture["final"]);
        let authorization =
            Envelope::decode(&bytes(&fixture["signedAuthorization"][index]), false).unwrap();
        assert_eq!(
            json!(authorization.unsigned()),
            fixture["unsignedAuthorization"]
        );
        let hash = authorization.witness.digest(authorization.payload_hash());
        assert_eq!(json!(hash), fixture["authorizationHash"]);
        let approvals: Vec<Bytes> =
            serde_json::from_value(fixture["authorizationApprovals"].clone()).unwrap();
        let mut witness = authorization.witness.clone();
        witness.approvals = witness.select(hash, &approvals).unwrap().selected;
        assert_eq!(
            json!(authorization.serialize(Some(&witness))),
            fixture["finalAuthorization"]
        );
    }
}

#[tokio::test]
async fn concurrent_approvals_submit_once_and_receipts_use_operation_hash() {
    let fixture = fixture();
    let node = Arc::new(NativeNode::default());
    let relay = relay(Arc::new(MemoryStore::default()), node.clone());
    let requests = (0..20)
        .map(|index| {
            let relay = relay.clone();
            let signed = fixture["signed"][index % 2].clone();
            tokio::spawn(async move {
                relay
                    .handle(Request::new("multisig_approveRawTransaction", vec![signed]))
                    .await
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    for request in requests {
        assert_eq!(request.await.unwrap(), fixture["hash"]);
    }
    assert_eq!(node.broadcasts.load(Ordering::SeqCst), 1);
    assert_eq!(json!(node.envelopes.lock().unwrap()[0]), fixture["final"]);
    let operation = relay
        .handle(Request::new(
            "multisig_getOperation",
            vec![fixture["hash"].clone()],
        ))
        .await
        .unwrap();
    assert_eq!(operation["status"], "success");
    assert_eq!(operation["weight"], 2);
    let receipt = relay
        .handle(Request::new(
            "eth_getTransactionReceipt",
            vec![fixture["hash"].clone()],
        ))
        .await
        .unwrap();
    assert_eq!(receipt["multisig"], operation);
    assert!(operation.get("finalTransaction").is_none());
}

#[tokio::test]
async fn key_authorizations_aggregate_and_configuration_updates_invalidate_approvals() {
    let fixture = fixture();
    let node = Arc::new(NativeNode::default());
    let relay = relay(Arc::new(MemoryStore::default()), node.clone());
    let pending = relay
        .handle(Request::new(
            "multisig_approveKeyAuthorization",
            vec![json!({"keyAuthorization": fixture["rpcAuthorization"][0]})],
        ))
        .await
        .unwrap();
    assert_eq!(pending["status"], "pending");
    let complete = relay.handle(Request::new("multisig_approveKeyAuthorization", vec![json!({"hash": fixture["authorizationHash"], "signature": fixture["authorizationApprovals"][1]})])).await.unwrap();
    assert_eq!(complete["status"], "success");
    assert_eq!(complete["keyAuthorization"], fixture["finalAuthorization"]);
    relay
        .handle(Request::new(
            "multisig_approveRawTransaction",
            vec![fixture["signed"][0].clone()],
        ))
        .await
        .unwrap();
    let config = relay
        .handle(Request::new(
            "multisig_getConfig",
            vec![json!({"address": fixture["account"]})],
        ))
        .await
        .unwrap();
    let actual: tempo_alloy::provider::relay::RelayMultisigConfig =
        serde_json::from_value(config).unwrap();
    let expected: tempo_alloy::provider::relay::RelayMultisigConfig =
        serde_json::from_value(fixture["config"].clone()).unwrap();
    assert_eq!(actual, expected);
    *node.commitment.lock().unwrap() = B256::repeat_byte(0xff);
    let error = relay
        .handle(Request::new(
            "multisig_approveRawTransaction",
            vec![fixture["signed"][1].clone()],
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code, -32602);
    assert_eq!(node.broadcasts.load(Ordering::SeqCst), 0);
    assert_eq!(
        relay
            .handle(Request::new(
                "multisig_getConfig",
                vec![json!({"address": fixture["account"]})]
            ))
            .await
            .unwrap(),
        Value::Null
    );
}

#[tokio::test]
async fn restart_during_submission_reconciles_exact_persisted_hash_without_rebroadcast() {
    let fixture = fixture();
    let node = Arc::new(NativeNode::default());
    node.block_broadcast.store(true, Ordering::SeqCst);
    let store = Arc::new(MemoryStore::default());
    let first = relay(store.clone(), node.clone());
    first
        .handle(Request::new(
            "multisig_approveRawTransaction",
            vec![fixture["signed"][0].clone()],
        ))
        .await
        .unwrap();
    let signed = fixture["signed"][1].clone();
    let task = tokio::spawn(async move {
        first
            .handle(Request::new("multisig_approveRawTransaction", vec![signed]))
            .await
    });
    node.started.notified().await;
    task.abort();
    let _ = task.await;
    let restarted = relay(store, node.clone());
    let operation = restarted
        .handle(Request::new(
            "multisig_getOperation",
            vec![fixture["hash"].clone()],
        ))
        .await
        .unwrap();
    assert_eq!(operation["status"], "submitting");
    let receipt = restarted
        .handle(Request::new(
            "eth_getTransactionReceipt",
            vec![fixture["hash"].clone()],
        ))
        .await
        .unwrap();
    assert_eq!(receipt["multisig"]["status"], "success");
    assert_eq!(node.broadcasts.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn sqlite_compare_and_set_is_atomic_across_independent_pools_and_restarts() {
    use tempo_relay::store::{now, sql::SqliteStore};
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}",
        directory.path().join("relay.sqlite").display()
    );
    let one = Arc::new(SqliteStore::connect(&url).await.unwrap());
    let two = Arc::new(SqliteStore::connect(&url).await.unwrap());
    let tasks = (0..20)
        .map(|i| {
            let store = if i % 2 == 0 { one.clone() } else { two.clone() };
            tokio::spawn(async move {
                store
                    .compare_and_set("absent", None, Some("winner"), None)
                    .await
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let mut won = 0;
    for task in tasks {
        if task.await.unwrap() {
            won += 1;
        }
    }
    assert_eq!(won, 1);
    drop(one);
    drop(two);
    let reopened = SqliteStore::connect(&url).await.unwrap();
    assert_eq!(reopened.get("absent").await.unwrap(), Some("winner".into()));
    assert!(
        reopened
            .compare_and_set("expired", None, Some("old"), Some(now() - 1))
            .await
            .unwrap()
    );
    assert_eq!(reopened.get("expired").await.unwrap(), None);
    assert!(
        reopened
            .compare_and_set("expired", None, Some("new"), None)
            .await
            .unwrap()
    );
}

#[cfg(feature = "storage")]
#[tokio::test]
async fn sqlite_reopen_recovers_accepted_submission_without_duplicate_broadcast() {
    use tempo_relay::store::sql::SqliteStore;
    let fixture = fixture();
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}",
        directory.path().join("relay.sqlite").display()
    );
    let node = Arc::new(NativeNode::default());
    node.block_broadcast.store(true, Ordering::SeqCst);
    let store = Arc::new(SqliteStore::connect(&url).await.unwrap());
    let first = relay(store.clone(), node.clone());
    first
        .handle(Request::new(
            "multisig_approveRawTransaction",
            vec![fixture["signed"][0].clone()],
        ))
        .await
        .unwrap();
    let signed = fixture["signed"][1].clone();
    let task = tokio::spawn(async move {
        first
            .handle(Request::new("multisig_approveRawTransaction", vec![signed]))
            .await
    });
    node.started.notified().await;
    task.abort();
    let _ = task.await;
    drop(store);
    let restarted = relay(
        Arc::new(SqliteStore::connect(&url).await.unwrap()),
        node.clone(),
    );
    let receipt = restarted
        .handle(Request::new(
            "eth_getTransactionReceipt",
            vec![fixture["hash"].clone()],
        ))
        .await
        .unwrap();
    assert_eq!(receipt["multisig"]["status"], "success");
    assert_eq!(node.broadcasts.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "http")]
#[tokio::test]
#[ignore = "requires npm ci in tests/interop"]
async fn unchanged_viem_client_coordinates_over_http() {
    let node = Arc::new(NativeNode::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(tempo_relay::http::serve(
        listener,
        relay(Arc::new(MemoryStore::default()), node.clone()),
        async {
            let _ = stopped.await;
        },
    ));
    let output = tokio::process::Command::new("node")
        .arg("multisig.mjs")
        .arg(url)
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/interop"))
        .output()
        .await
        .unwrap();
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(node.broadcasts.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "storage")]
#[tokio::test]
#[ignore = "requires a disposable loopback Postgres database and TEMPO_RELAY_TEST_POSTGRES"]
async fn postgres_multi_instance_cas_and_submission_recovery() {
    use tempo_relay::store::sql::PostgresStore;
    let url = std::env::var("TEMPO_RELAY_TEST_POSTGRES")
        .expect("TEMPO_RELAY_TEST_POSTGRES must name a disposable test database");
    let parsed = url::Url::parse(&url).unwrap();
    assert!(matches!(
        parsed.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    ));
    assert_eq!(parsed.path(), "/tempo_relay_test");
    let one = Arc::new(PostgresStore::connect(&url).await.unwrap());
    let two = Arc::new(PostgresStore::connect(&url).await.unwrap());
    let key = format!("relay-test:{}", B256::random());
    let tasks = (0..20)
        .map(|i| {
            let store = if i % 2 == 0 { one.clone() } else { two.clone() };
            let key = key.clone();
            tokio::spawn(async move {
                store
                    .compare_and_set(&key, None, Some("winner"), None)
                    .await
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let mut winners = 0;
    for task in tasks {
        winners += u8::from(task.await.unwrap());
    }
    assert_eq!(winners, 1);
    let fixture = fixture();
    // This isolated test database may retain a prior run's operation: clear only that exact key.
    let operation_key = format!(
        "multisig:1337:operation:{}",
        fixture["hash"].as_str().unwrap()
    );
    let previous = one.get(&operation_key).await.unwrap();
    one.compare_and_set(&operation_key, previous.as_deref(), None, None)
        .await
        .unwrap();
    let node = Arc::new(NativeNode::default());
    node.block_broadcast.store(true, Ordering::SeqCst);
    let first = relay(one.clone(), node.clone());
    first
        .handle(Request::new(
            "multisig_approveRawTransaction",
            vec![fixture["signed"][0].clone()],
        ))
        .await
        .unwrap();
    let signed = fixture["signed"][1].clone();
    let task = tokio::spawn(async move {
        first
            .handle(Request::new("multisig_approveRawTransaction", vec![signed]))
            .await
    });
    node.started.notified().await;
    task.abort();
    let _ = task.await;
    drop(one);
    drop(two);
    let restarted_store = Arc::new(PostgresStore::connect(&url).await.unwrap());
    let restarted = relay(restarted_store.clone(), node.clone());
    let receipt = restarted
        .handle(Request::new(
            "eth_getTransactionReceipt",
            vec![fixture["hash"].clone()],
        ))
        .await
        .unwrap();
    assert_eq!(receipt["multisig"]["status"], "success");
    assert_eq!(node.broadcasts.load(Ordering::SeqCst), 1);
    restarted_store
        .compare_and_set(&key, Some("winner"), None, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn native_fee_payer_signs_once_only_after_owner_quorum() {
    use tempo_relay::{sponsor::Sponsor, wire::Rlp};
    let fixture = fixture();
    let node = Arc::new(NativeNode::default());
    let payer = PrivateKeySigner::from_bytes(&B256::repeat_byte(3)).unwrap();
    let payer_address = payer.address();
    let token = address!("20c0000000000000000000000000000000000000");
    let relay = relay(Arc::new(MemoryStore::default()), node.clone())
        .with_sponsor(
            Sponsor::new(Arc::new(payer), 1337, token, 1_000_000, 100_000_000_000).unwrap(),
        )
        .unwrap();
    let hash = relay
        .handle(Request::new(
            "multisig_approveRawTransaction",
            vec![fixture["sponsoredSigned"][0].clone()],
        ))
        .await
        .unwrap();
    assert_eq!(hash, fixture["sponsoredHash"]);
    assert_eq!(node.broadcasts.load(Ordering::SeqCst), 0);
    relay
        .handle(Request::new(
            "multisig_approveRawTransaction",
            vec![fixture["sponsoredSigned"][1].clone()],
        ))
        .await
        .unwrap();
    assert_eq!(node.broadcasts.load(Ordering::SeqCst), 1);
    let bytes = node.envelopes.lock().unwrap()[0].clone();
    let envelope = Envelope::decode(&bytes, true).unwrap();
    assert_eq!(
        json!(envelope.witness.digest(envelope.payload_hash())),
        fixture["sponsoredHash"]
    );
    assert_eq!(envelope.fields[10], Rlp::Bytes(token.to_vec()));
    let signature = envelope.fields[11].list().unwrap();
    let signature = Signature::new(
        U256::from_be_slice(signature[1].bytes().unwrap()),
        U256::from_be_slice(signature[2].bytes().unwrap()),
        signature[0].integer().unwrap() == 1,
    );
    let mut payload = envelope.fields.clone();
    payload[11] = Rlp::Bytes(envelope.witness.account.to_vec());
    let digest = keccak256([&[0x78][..], &Rlp::List(payload).encode()].concat());
    assert_eq!(
        signature.recover_address_from_prehash(&digest).unwrap(),
        payer_address
    );
}
