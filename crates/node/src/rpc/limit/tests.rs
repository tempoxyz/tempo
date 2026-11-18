use super::*;
use alloy_rpc_client::{RpcClient, WsConnect};
use alloy_transport::TransportResult;
use jsonrpsee::{
    RpcModule,
    server::{Server, ServerHandle, middleware::rpc::RpcServiceBuilder},
};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

/// Calls of `slow` that reached the handler, and the gate each one waits on before answering.
struct Gate {
    started: AtomicUsize,
    release: Semaphore,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            started: AtomicUsize::new(0),
            release: Semaphore::new(0),
        }
    }
}

/// Serves `slow`, which waits for the gate, and `fast`, behind `layer`.
async fn serve(layer: ConcurrencyLimitLayer) -> (RpcClient, Arc<Gate>, ServerHandle) {
    let gate = Arc::new(Gate::default());
    let mut module = RpcModule::from_arc(gate.clone());
    module
        .register_async_method("slow", |_, gate| async move {
            gate.started.fetch_add(1, Ordering::SeqCst);
            gate.release.acquire().await.unwrap().forget();
            "slow"
        })
        .unwrap();
    module.register_method("fast", |_, _| "fast").unwrap();

    let server = Server::builder()
        .set_rpc_middleware(RpcServiceBuilder::new().layer(layer))
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.start(module);
    let client = RpcClient::connect_pubsub(WsConnect::new(format!("ws://{addr}")))
        .await
        .unwrap();
    (client, gate, handle)
}

async fn call(client: &RpcClient, method: &'static str) -> TransportResult<String> {
    client.request_noparams(method).await
}

fn error_code(result: TransportResult<String>) -> i64 {
    result
        .expect_err("expected a JSON-RPC error")
        .as_error_resp()
        .expect("expected an error response")
        .code
}

async fn wait_for_started(gate: &Gate, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while gate.started.load(Ordering::SeqCst) < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("calls did not reach the handler");
}

fn slow_limit(max: usize) -> ConcurrencyLimitLayer {
    ConcurrencyLimitLayer::default().limit("slow", NonZeroUsize::new(max).unwrap())
}

#[tokio::test]
async fn calls_past_the_limit_are_rejected_as_busy() {
    let (client, gate, _server) = serve(slow_limit(2)).await;

    let held = (0..2)
        .map(|_| {
            tokio::spawn({
                let client = client.clone();
                async move { call(&client, "slow").await }
            })
        })
        .collect::<Vec<_>>();
    wait_for_started(&gate, 2).await;

    assert_eq!(
        error_code(call(&client, "slow").await),
        i64::from(SERVER_IS_BUSY_CODE)
    );
    assert_eq!(gate.started.load(Ordering::SeqCst), 2);
    // Methods without a limit are not affected.
    assert_eq!(call(&client, "fast").await.unwrap(), "fast");

    // A call that ends frees its slot.
    gate.release.add_permits(1);
    let mut held = futures::future::select_all(held).await;
    assert_eq!(held.0.unwrap().unwrap(), "slow");
    let admitted = tokio::spawn({
        let client = client.clone();
        async move { call(&client, "slow").await }
    });
    wait_for_started(&gate, 3).await;

    gate.release.add_permits(2);
    assert_eq!(admitted.await.unwrap().unwrap(), "slow");
    assert_eq!(held.2.pop().unwrap().await.unwrap().unwrap(), "slow");
}

#[tokio::test]
async fn batched_calls_take_the_same_slots() {
    let layer = slow_limit(1);
    let (client, gate, _server) = serve(layer.clone()).await;

    let held = tokio::spawn({
        let client = client.clone();
        async move { call(&client, "slow").await }
    });
    wait_for_started(&gate, 1).await;

    // Every slot is taken, so the batch's call is rejected and its other calls still run.
    let mut batch = client.new_batch();
    let slow = batch.add_call::<_, String>("slow", &()).unwrap();
    let fast = batch.add_call::<_, String>("fast", &()).unwrap();
    batch.send().await.unwrap();
    assert_eq!(error_code(slow.await), i64::from(SERVER_IS_BUSY_CODE));
    assert_eq!(fast.await.unwrap(), "fast");

    gate.release.add_permits(1);
    assert_eq!(held.await.unwrap().unwrap(), "slow");
    assert_eq!(layer.available("slow"), Some(1));

    // The server runs a batch's calls one after another, so a batch needs one slot for all of
    // its calls of a method, and holds it until the batch ends.
    let mut batch = client.new_batch();
    let first = batch.add_call::<_, String>("slow", &()).unwrap();
    let second = batch.add_call::<_, String>("slow", &()).unwrap();
    // Sending resolves once the whole batch is answered.
    let sent = tokio::spawn(batch.send());
    wait_for_started(&gate, 2).await;
    assert_eq!(layer.available("slow"), Some(0));
    gate.release.add_permits(1);
    wait_for_started(&gate, 3).await;
    assert_eq!(layer.available("slow"), Some(0));
    gate.release.add_permits(1);
    sent.await.unwrap().unwrap();
    assert_eq!(first.await.unwrap(), "slow");
    assert_eq!(second.await.unwrap(), "slow");
    assert_eq!(layer.available("slow"), Some(1));
}

#[test]
fn limit_above_semaphore_capacity_is_clamped() {
    let layer = ConcurrencyLimitLayer::default().limit("slow", NonZeroUsize::MAX);
    assert_eq!(layer.available("slow"), Some(Semaphore::MAX_PERMITS));
}

#[test]
fn only_height_queries_count_against_the_finalization_limit() {
    let params = |json: &str| RawValue::from_string(json.to_string()).unwrap();
    assert!(!is_height_query(Some(&params(r#"["latest"]"#))));
    assert!(is_height_query(Some(&params(r#"[{"height":7}]"#))));
    // Named params, which the handler accepts too.
    assert!(!is_height_query(Some(&params(r#"{"query":"latest"}"#))));
    assert!(is_height_query(Some(&params(r#"{"query":{"height":7}}"#))));
    assert!(is_height_query(Some(&params(r#"{"other":"latest"}"#))));
    // Params that don't decode are limited too.
    assert!(is_height_query(Some(&params(r#"["nonsense"]"#))));
    assert!(is_height_query(None));

    let layer = CallLimits::default().layer();
    assert_eq!(
        layer.available(CONSENSUS_GET_FINALIZATION),
        Some(DEFAULT_MAX_CONCURRENT_LOOKUPS.get())
    );
}
