//! Exercise the public JSON-RPC transport against distinct era backends. These tests check
//! routing semantics and policy, rather than a second implementation of EVM execution.
use std::{collections::HashMap, sync::Arc};

use jsonrpsee::{
    RpcModule,
    core::{
        RpcResult,
        client::{ClientT, Error as ClientError},
        params::BatchRequestBuilder,
    },
    http_client::{HttpClient, HttpClientBuilder},
    server::{ServerBuilder, ServerHandle},
};
use serde_json::{Value, json};
use tempo_metabinary::{
    manifest::{Era, Manifest},
    routing::{ExecutionInfo, Route, Router, RpcParams},
    server::{self, ServerOptions},
};

fn hash(number: u64) -> String {
    format!("0x{number:064x}")
}

fn block(number: u64) -> Value {
    let timestamp = [0, 50, 99, 100, 110, 199, 200, 210][number as usize];
    json!({"number": format!("0x{number:x}"), "hash": hash(number), "timestamp": format!("0x{timestamp:x}")})
}

struct Fixture {
    router: Arc<Router>,
    handles: Vec<ServerHandle>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for handle in &self.handles {
            let _ = handle.stop();
        }
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::with_eras(2, true).await
    }

    async fn with_eras(count: usize, history: bool) -> Self {
        let routed = [
            "eth_call",
            "eth_estimateGas",
            "eth_createAccessList",
            "eth_callMany",
            "eth_simulateV1",
            "tempo_simulateV1",
            "debug_traceCallMany",
            "debug_traceCall",
            "debug_traceBlockByNumber",
            "debug_traceBlockByHash",
            "debug_traceTransaction",
            "debug_executionWitness",
            "debug_accountInfoAt",
            "trace_transactionOpcodeGas",
            "trace_blockOpcodeGas",
            "trace_callMany",
            "trace_filter",
            "eth_futureExecution",
            "debug_traceBlock",
            "eth_getBlockAccessListByBlockHash",
            "eth_getBlockAccessListByBlockNumber",
            "eth_getBlockAccessList",
            "eth_getBlockAccessListRaw",
            "debug_getRawBlockAccessList",
        ];
        let mut handles = vec![];
        let mut clients = vec![];
        let mut eras = vec![];
        let mut metadata = vec![];
        for index in 0..count {
            let mut module = RpcModule::new(());
            let latest = if count == 2 { 4 } else { 7 };
            module
                .register_method("eth_getBlockByNumber", move |params, _, _| {
                    let (selector, _): (Value, bool) = params.parse().unwrap();
                    let n = match selector.as_str().unwrap() {
                        "latest" | "safe" | "finalized" => latest,
                        "earliest" => 0,
                        other => {
                            u64::from_str_radix(other.strip_prefix("0x").unwrap(), 16).unwrap()
                        }
                    };
                    if n > latest { Value::Null } else { block(n) }
                })
                .unwrap();
            module
                .register_method("eth_getBlockByHash", move |params, _, _| {
                    let (h, _): (String, bool) = params.parse().unwrap();
                    let n = u64::from_str_radix(h.trim_start_matches("0x"), 16).unwrap();
                    if n > latest { Value::Null } else { block(n) }
                })
                .unwrap();
            module
                .register_method("eth_getTransactionByHash", |params, _, _| {
                    let (h,): (String,) = params.parse().unwrap();
                    if h == hash(999) {
                        Value::Null
                    } else {
                        json!({"blockHash": hash(1)})
                    }
                })
                .unwrap();
            module
                .register_method("eth_getBalance", move |_, _, _| json!({"era":index}))
                .unwrap();
            module
                .register_method("eth_getCode", |_, _, _| "x".repeat(3000))
                .unwrap();
            for method in routed {
                module
                    .register_method(method, move |params, _, _| {
                        let params: Value = params.parse().unwrap_or(Value::Null);
                        json!({"era":index, "method":method, "params":params})
                    })
                    .unwrap();
            }
            let names = module.method_names().map(str::to_owned).collect();
            let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            handles.push(server.start(module));
            clients.push(
                HttpClientBuilder::default()
                    .build(format!("http://{address}"))
                    .unwrap(),
            );
            eras.push(Era {
                name: format!("era{index}"),
                binary: "/fake/tempo".into(),
                start_timestamp: (index * 100) as u64,
                node_args: vec![],
                rpc_port: address.port(),
                ws_port: None,
                bootstrap: None,
            });
            metadata.push(if index + 1 == count || history {
                Some(ExecutionInfo {
                    protocol_version: 1,
                    chain_id: "0xa410".into(),
                    genesis_hash: hash(0).parse().unwrap(),
                    read_only: index + 1 != count,
                    process_id: std::process::id(),
                    methods: names,
                })
            } else {
                None
            });
        }
        let manifest = Arc::new(Manifest {
            chain: "test".into(),
            datadir: "/fake/data".into(),
            chain_id: "0xa410".into(),
            genesis_hash: hash(0),
            eras,
        });
        Self {
            router: Arc::new(Router::new(manifest, clients, metadata).unwrap()),
            handles,
        }
    }

    async fn public(&mut self, api: &[&str], max_response: u32) -> HttpClient {
        let (address, handle) = server::start(
            self.router.clone(),
            ServerOptions {
                listen: "127.0.0.1:0".parse().unwrap(),
                api: api.iter().map(|s| (*s).to_owned()).collect(),
                max_response_bytes: max_response,
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
        self.handles.push(handle);
        HttpClientBuilder::default()
            .build(format!("http://{address}"))
            .unwrap()
    }

    async fn call(&self, method: &str, params: Value) -> Value {
        self.router.call(method, RpcParams(params)).await.unwrap()
    }

    async fn error_code(&self, method: &str, params: Value) -> i32 {
        self.router
            .call(method, RpcParams(params))
            .await
            .unwrap_err()
            .code()
    }

    async fn route(&self, method: &str, params: Value) -> RpcResult<Route> {
        self.router.route(method, RpcParams(params)).await
    }
}

#[tokio::test]
async fn debug_subscriptions_guard_the_included_range() {
    let f = Fixture::new().await;
    let live = f
        .route("debug_subscribe", json!(["traceChain", "0x2", "0x4"]))
        .await
        .unwrap();
    assert_eq!(live.era, 1); // 0x2 is exclusive and still belongs to the predecessor era.
    let error = f
        .route(
            "debug_subscribe",
            json!({"subscription":"traceChain", "startExclusive":"0x0", "endInclusive":"0x4"}),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), -32004);
    assert_eq!(
        f.route("debug_subscribe", json!(["native-invalid-subscription"]))
            .await
            .unwrap()
            .era,
        1
    );
}

#[tokio::test]
async fn historical_execution_and_stored_state_use_different_backends() {
    let f = Fixture::new().await;
    let old = f.call("eth_call", json!([{}, "0x1"])).await;
    assert_eq!(old["era"], 0);
    assert_eq!(old["params"][1], json!({"blockHash":hash(1)}));
    for (method, selector) in [
        ("eth_getBlockAccessListByBlockHash", json!(hash(1))),
        ("eth_getBlockAccessListByBlockNumber", json!("0x1")),
        ("eth_getBlockAccessList", json!("0x1")),
        ("eth_getBlockAccessListRaw", json!("0x1")),
        ("debug_getRawBlockAccessList", json!("0x1")),
    ] {
        assert_eq!(
            f.call(method, json!([selector])).await["era"],
            0,
            "{method}"
        );
    }
    assert_eq!(
        f.call("eth_call", json!([{}, "pending"])).await["params"][1],
        "pending"
    );
    for (method, params, era) in [
        ("eth_call", json!([{}, "0x3"]), 1),
        ("eth_getBalance", json!(["0x0", "0x1"]), 1),
        ("trace_transactionOpcodeGas", json!([hash(10)]), 0),
        ("trace_blockOpcodeGas", json!(["0x1"]), 0),
        ("debug_accountInfoAt", json!(["0x1", 0, "0x0"]), 0),
    ] {
        assert_eq!(f.call(method, params).await["era"], era, "{method}");
    }
}

#[tokio::test]
async fn named_params_pin_the_correct_field_and_preserve_canonical_hash_requirements() {
    let f = Fixture::new().await;
    for selector in ["block_number", "blockNumber"] {
        let response = f
            .call("eth_call", json!({"request":{}, selector:"earliest"}))
            .await;
        assert_eq!(response["era"], 0);
        assert_eq!(response["params"][selector], json!({"blockHash":hash(0)}));
        assert_eq!(response["params"].as_object().unwrap().len(), 2);
    }
    let id = json!({"blockHash":hash(1), "requireCanonical":true});
    let response = f.call("eth_call", json!([{}, id])).await;
    assert_eq!(response["params"][1], id);
    let bundle = f
        .call(
            "eth_callMany",
            json!([[{"transactions":[{}]}], {"blockNumber":id}]),
        )
        .await;
    assert_eq!(bundle["params"][1]["blockNumber"], id);
    let simulated = f
        .call(
            "eth_simulateV1",
            json!([{"blockStateCalls":[{"calls":[{}]}]}, id]),
        )
        .await;
    assert_eq!(simulated["params"][1], id);
    assert_eq!(
        f.call("debug_traceBlockByHash", json!([hash(1)])).await["params"][0],
        hash(1)
    );
}

#[tokio::test]
async fn simulations_select_the_child_era_and_reject_filler_or_bundle_crossings() {
    let f = Fixture::new().await;
    // Base state is the last old block, but the child belongs to the new era.
    for (method, payload_name, block_name) in [
        ("eth_simulateV1", "opts", "blockNumber"),
        ("tempo_simulateV1", "payload", "block"),
    ] {
        let response = f.call(method, json!({payload_name:{"blockStateCalls":[{"blockOverrides":{"time":"0x64"},"calls":[{}]}]}, block_name:"0x2"})).await;
        assert_eq!(response["era"], 1);
        assert_eq!(response["params"][block_name], json!({"blockHash":hash(2)}));
    }
    let cross = json!([{"blockStateCalls":[{"blockOverrides":{"time":"0x63"}},{"blockOverrides":{"time":"0x64"}}]},"0x1"]);
    assert_eq!(f.error_code("eth_simulateV1", cross).await, -32004);
    // Number gaps create intermediate blocks even if only the final requested block is new.
    let gap = json!([{"blockStateCalls":[{"blockOverrides":{"blockNumber":"0x40", "timestamp":"0x12c"}}]},"0x1"]);
    assert_eq!(f.error_code("eth_simulateV1", gap).await, -32004);
    let bundles = json!([[{"transactions":[{}]}, {"transactions":[{}]}], {"blockNumber":"0x2"}]);
    assert_eq!(f.error_code("debug_traceCallMany", bundles).await, -32004);
}

#[tokio::test]
async fn overrides_cannot_bypass_era_selection_and_nulls_keep_native_defaults() {
    let f = Fixture::new().await;
    for name in ["time", "timestamp"] {
        let overrides = json!([{}, "0x1", null, {name:"0x64"}]);
        assert_eq!(f.error_code("eth_call", overrides).await, -32004);
    }
    for (method, params, era) in [
        ("eth_call", json!([{}, "0x1", null, {"time":null}]), 0),
        (
            "eth_callMany",
            json!([[{"transactions":[{}]}], {"blockNumber":null}]),
            1,
        ),
        (
            "eth_simulateV1",
            json!([{"blockStateCalls":[{"blockOverrides":{"time":null,"number":null}}]}, "0x1"]),
            0,
        ),
        (
            "trace_filter",
            json!([{"fromBlock":null,"toBlock":null}]),
            1,
        ),
    ] {
        assert_eq!(f.call(method, params).await["era"], era, "{method}");
    }
}

#[tokio::test]
async fn trace_filter_defaults_each_bound_to_latest_and_requires_one_era() {
    let f = Fixture::new().await;
    assert_eq!(
        f.call("trace_filter", json!([{}])).await["params"][0],
        json!({"fromBlock":"0x4", "toBlock":"0x4"})
    );
    assert_eq!(
        f.call("trace_filter", json!([{"fromBlock":"0x1","toBlock":"0x2"}]))
            .await["era"],
        0
    );
    assert_eq!(
        f.error_code("trace_filter", json!([{"fromBlock":"0x1"}]))
            .await,
        -32004
    );
}

#[tokio::test]
async fn public_registry_enforces_namespaces_and_unknown_execution_fails_closed() {
    let mut f = Fixture::new().await;
    let client = f.public(&["eth", "rpc"], 10_000).await;
    let error = client
        .request::<Value, _>("debug_traceBlockByNumber", ("0x1",))
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::Call(e) if e.code() == -32601));
    let modules: HashMap<String, String> = client
        .request("rpc_modules", jsonrpsee::rpc_params![])
        .await
        .unwrap();
    assert!(modules.contains_key("eth"));
    assert!(!modules.contains_key("debug"));
    let error = client
        .request::<Value, _>("eth_futureExecution", ("0x1",))
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::Call(e) if e.code() == -32004));
}

#[tokio::test]
async fn batches_route_independently_and_response_limits_apply_to_all_backends() {
    let mut f = Fixture::new().await;
    let client = f.public(&["eth", "debug"], 10_000).await;
    let mut batch = BatchRequestBuilder::new();
    batch.insert("eth_call", (json!({}), "0x1")).unwrap();
    batch.insert("eth_call", (json!({}), "0x3")).unwrap();
    batch.insert("debug_traceBlockByNumber", ("0x1",)).unwrap();
    let response = client.batch_request::<Value>(batch).await.unwrap();
    let values: Vec<_> = response.into_iter().map(Result::unwrap).collect();
    assert_eq!(
        values
            .iter()
            .map(|v| v["era"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0, 1, 0]
    );

    let limited = f.public(&["eth"], 512).await;
    assert!(
        limited
            .request::<Value, _>("eth_getCode", ("0x0",))
            .await
            .is_err()
    );
    for target in ["0x1", "0x3"] {
        assert!(
            limited
                .request::<Value, _>("eth_call", (json!({"data":"x".repeat(3000)}), target))
                .await
                .is_err()
        );
    }
    let mut batch = BatchRequestBuilder::new();
    batch.insert("eth_getCode", ("0x0",)).unwrap();
    batch.insert("eth_call", (json!({}), "0x1")).unwrap();
    let response = limited.batch_request::<Value>(batch).await;
    assert!(response.is_err() || response.unwrap().into_iter().any(|r| r.is_err()));
    let mut batch = BatchRequestBuilder::new();
    for _ in 0..10 {
        batch.insert("eth_call", (json!({}), "0x1")).unwrap();
    }
    assert!(
        limited.batch_request::<Value>(batch).await.is_err(),
        "aggregate batch size must also be bounded"
    );
}

#[tokio::test]
async fn supports_three_eras_and_live_nodes_need_no_historical_worker() {
    let f = Fixture::with_eras(3, true).await;
    for (number, era) in [(1, 0), (3, 1), (6, 2)] {
        assert_eq!(
            f.call("eth_call", json!([{}, format!("0x{number:x}")]))
                .await["era"],
            era
        );
    }
    let live_only = Fixture::with_eras(3, false).await;
    assert_eq!(
        live_only.call("eth_call", json!([{}, "latest"])).await["era"],
        2
    );
    assert_eq!(
        live_only
            .call("eth_getBalance", json!(["0x0", "0x1"]))
            .await["era"],
        2
    );
    assert_eq!(
        live_only.error_code("eth_call", json!([{}, "0x1"])).await,
        -32004
    );
    assert_eq!(
        live_only
            .error_code("debug_traceBlock", json!(["0xc0"]))
            .await,
        -32004
    );
}

#[tokio::test]
async fn websocket_subscriptions_forward_live_events_and_unsubscribe() {
    use jsonrpsee::{
        core::{SubscriptionResult, client::SubscriptionClientT},
        ws_client::WsClientBuilder,
    };
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    let mut f = Fixture::new().await;
    let closed = Arc::new(AtomicBool::new(false));
    let observer = closed.clone();
    let mut module = RpcModule::new(());
    module
        .register_subscription(
            "eth_subscribe",
            "eth_subscription",
            "eth_unsubscribe",
            move |_, pending, _, _| {
                let observer = observer.clone();
                async move {
                    let sink = pending.accept().await?;
                    sink.send(serde_json::value::to_raw_value(&json!({"number":"0x5"}))?)
                        .await?;
                    sink.closed().await;
                    observer.store(true, Ordering::SeqCst);
                    Ok(()) as SubscriptionResult
                }
            },
        )
        .unwrap();
    let upstream = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    f.handles.push(upstream.start(module));
    let ws = Arc::new(
        WsClientBuilder::default()
            .build(format!("ws://{upstream_address}"))
            .await
            .unwrap(),
    );
    let (address, handle) = server::start(
        f.router.clone(),
        ServerOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
        Some(ws),
    )
    .await
    .unwrap();
    f.handles.push(handle);
    let public = WsClientBuilder::default()
        .build(format!("ws://{address}"))
        .await
        .unwrap();
    let mut subscription = public
        .subscribe::<Value, _>("eth_subscribe", ("newHeads",), "eth_unsubscribe")
        .await
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(2), subscription.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(event, json!({"number":"0x5"}));
    subscription.unsubscribe().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !closed.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
