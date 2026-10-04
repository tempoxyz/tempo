//! Wire/capability tests with real generated proof evidence, not devnet acceptance tests.
#![cfg(feature = "rpc-server")]

mod common;
use jsonrpsee::{RpcModule, server::Server, types::ErrorObjectOwned};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tempo_light::{
    HeadTracker,
    config::Limits,
    proof::ProofLimits,
    transport::{Error, Upstreams},
};

#[tokio::test]
async fn standard_fallback_is_hash_pinned_verified_and_remembers_capability() {
    let checkpoint = common::checkpoint();
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/mpt-finality-v1.json")).unwrap();
    let responses: Vec<alloy_rpc_types_eth::EIP1186AccountProofResponse> =
        serde_json::from_value(fixture["responses"].clone()).unwrap();
    let targets = serde_json::from_value(fixture["targets"].clone()).unwrap();
    let hash = checkpoint.head.digest;
    let multi = Arc::new(AtomicUsize::new(0));
    let standard = Arc::new(AtomicUsize::new(0));
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut module = RpcModule::new(());
    let count = multi.clone();
    module
        .register_method("eth_getMultiProof", move |_, _, _| {
            count.fetch_add(1, Ordering::Relaxed);
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32601,
                "method not found",
                None::<()>,
            ))
        })
        .unwrap();
    let count = standard.clone();
    let response = responses[0].clone();
    module
        .register_method("eth_getProof", move |params, _, _| {
            let params: Vec<Value> = params.parse().unwrap();
            assert_eq!(
                params[2],
                json!({"blockHash":hash, "requireCanonical":true})
            );
            assert_eq!(params[0], json!(response.address));
            count.fetch_add(1, Ordering::Relaxed);
            Ok::<_, ErrorObjectOwned>(response.clone())
        })
        .unwrap();
    let handle = server.start(module);
    let transport = Upstreams::new(
        vec![format!("http://{address}").parse().unwrap()],
        &Limits::default(),
    )
    .unwrap();
    let mut tracker = HeadTracker::new(checkpoint.network.anchor, checkpoint.network.epoch_length);
    let mut rng: rand::rngs::StdRng = rand::make_rng();
    let snapshot = tracker.accept(&mut rng, checkpoint.head).unwrap();
    for _ in 0..2 {
        let response = transport.proofs(0, hash, &targets).await.unwrap();
        snapshot
            .verify(&targets, &response, ProofLimits::default())
            .unwrap();
    }
    assert_eq!(multi.load(Ordering::Relaxed), 1);
    assert_eq!(standard.load(Ordering::Relaxed), 2);
    assert!(matches!(
        transport.proofs(99, hash, &targets).await,
        Err(Error::Configuration)
    ));
    let limits = Limits {
        max_response_bytes: 10,
        ..Default::default()
    };
    let bounded =
        Upstreams::new(vec![format!("http://{address}").parse().unwrap()], &limits).unwrap();
    assert!(matches!(
        bounded.proofs(0, hash, &targets).await,
        Err(Error::ResponseSize(_))
    ));
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn critical_publication_failure_pauses_reads_and_successful_refresh_recovers() {
    use tempo_light::{
        client::{Client, Error as ClientError, FailureKind},
        token::ReadRequest,
    };
    let checkpoint = common::checkpoint();
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("checkpoint.tmp")).unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut module = RpcModule::new(());
    let head = checkpoint.head.clone();
    module
        .register_method("consensus_getFinalizedHeader", move |_, _, _| {
            Ok::<_, ErrorObjectOwned>(head.clone())
        })
        .unwrap();
    let handle = server.start(module);
    let client = Client::open(
        checkpoint.network.clone(),
        vec![
            format!("http://{address}").parse().unwrap(),
            "http://127.0.0.1:1".parse().unwrap(),
        ],
        directory.path(),
        Limits::default(),
    )
    .unwrap();
    assert!(matches!(
        client.refresh().await,
        Err(ClientError::Checkpoint(_))
    ));
    let status = client.status().await;
    assert!(status.head.is_none());
    assert!(!status.durable);
    assert!(matches!(
        status.last_failure,
        Some(FailureKind::Persistence)
    ));
    let request = ReadRequest::TotalSupply {
        token: "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap(),
    };
    assert!(matches!(
        client.read(vec![request]).await.unwrap_err().as_ref(),
        ClientError::PersistencePaused
    ));
    std::fs::remove_dir(directory.path().join("checkpoint.tmp")).unwrap();
    client.refresh().await.unwrap();
    assert!(client.status().await.durable);
    // An available provider confirming retained evidence is a successful refresh, even when
    // another endpoint is down. Head age, not endpoint agreement, expresses freshness.
    client.refresh().await.unwrap();
    assert!(client.status().await.last_failure.is_none());
    drop(client);
    let store = tempo_light::checkpoint::Store::open(directory.path()).unwrap();
    assert_eq!(
        store.load(&checkpoint.network).unwrap().unwrap().head,
        checkpoint.head
    );
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn proof_window_expiry_is_availability_not_selector_capability() {
    let fixture: Value =
        serde_json::from_str(include_str!("../fixtures/mpt-finality-v1.json")).unwrap();
    let targets = serde_json::from_value(fixture["targets"].clone()).unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut module = RpcModule::new(());
    module
        .register_method("eth_getMultiProof", |_, _, _| {
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32602,
                "distance to target block exceeds maximum proof window",
                None::<()>,
            ))
        })
        .unwrap();
    let handle = server.start(module);
    let transport = Upstreams::new(
        vec![format!("http://{address}").parse().unwrap()],
        &Limits::default(),
    )
    .unwrap();
    assert!(matches!(
        transport
            .proofs(0, common::checkpoint().head.digest, &targets)
            .await,
        Err(Error::RpcUnavailable { code: -32602, .. })
    ));
    handle.stop().unwrap();
    handle.stopped().await;
}
