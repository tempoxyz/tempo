//! Exercise the public JSON-RPC transport against distinct era backends. These tests check
//! routing semantics and policy, rather than a second implementation of EVM execution.
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use futures::future::BoxFuture;
use jsonrpsee::{
    RpcModule,
    core::{
        RpcResult,
        client::{ClientT, Error as ClientError},
        params::BatchRequestBuilder,
    },
    http_client::{HttpClient, HttpClientBuilder},
    server::{ServerBuilder, ServerHandle},
    types::ErrorObjectOwned,
};
use serde_json::{Value, json};
use tempo_metabinary::{
    catalog::{ChainEras, ReleaseEra},
    routing::{Backend, Router, RpcParams, upstream_error},
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
    resolutions: Arc<AtomicUsize>,
}

struct HttpBackend(Vec<Option<HttpClient>>);

impl Backend for HttpBackend {
    fn request<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Value>> {
        Box::pin(async move {
            let client = self.0[era].as_ref().ok_or_else(|| {
                ErrorObjectOwned::owned(-32004, "historical execution is disabled", None::<()>)
            })?;
            client.request(method, params).await.map_err(upstream_error)
        })
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::with_eras(2, true).await
    }

    async fn with_eras(count: usize, history: bool) -> Self {
        let routed = [
            "eth_call",
            "eth_callMany",
            "eth_simulateV1",
            "tempo_simulateV1",
            "debug_traceCallMany",
            "debug_traceBlockByNumber",
            "debug_traceBlockByHash",
            "debug_accountInfoAt",
            "trace_transactionOpcodeGas",
            "trace_blockOpcodeGas",
            "trace_filter",
            "eth_futureExecution",
            "eth_getBlockAccessListByBlockHash",
            "eth_getBlockAccessListByBlockNumber",
            "eth_getBlockAccessList",
            "eth_getBlockAccessListRaw",
            "debug_getRawBlockAccessList",
            "debug_storageRangeAt",
            "debug_standardTraceBlockToFile",
        ];
        let mut handles = vec![];
        let mut clients = vec![];
        let mut eras = vec![];
        let mut live_methods = HashSet::new();
        let resolutions = Arc::new(AtomicUsize::new(0));
        for index in 0..count {
            let mut module = RpcModule::new(());
            let latest = if count == 2 { 4 } else { 7 };
            // Deliberately expose headers without block-body RPCs. Resolution must not need them.
            for method in ["eth_getHeaderByNumber", "eth_getHeaderByHash"] {
                let resolutions = resolutions.clone();
                module
                    .register_method(method, move |params, _, _| {
                        resolutions.fetch_add(1, Ordering::SeqCst);
                        let (selector,): (String,) = params.parse().unwrap();
                        let n = match selector.as_str() {
                            "latest" | "safe" | "finalized" => latest,
                            "earliest" => 0,
                            other => {
                                u64::from_str_radix(other.strip_prefix("0x").unwrap(), 16).unwrap()
                            }
                        };
                        if n > latest { Value::Null } else { block(n) }
                    })
                    .unwrap();
            }
            module
                .register_method(
                    "eth_getTransactionByHash",
                    |_, _, _| json!({"blockHash":hash(1)}),
                )
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
                        json!({"era":index, "params":params})
                    })
                    .unwrap();
            }
            live_methods = module.method_names().map(str::to_owned).collect();
            let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            handles.push(server.start(module));
            clients.push((index + 1 == count || history).then(|| {
                HttpClientBuilder::default()
                    .build(format!("http://{address}"))
                    .unwrap()
            }));
            eras.push(ReleaseEra {
                name: format!("era{index}"),
                start_timestamp: (index * 100) as u64,
                binary: (index + 1 != count).then(|| "/fake/tempo".into()),
            });
        }
        let schedule = ChainEras {
            chain_id: "0xa410".into(),
            genesis_hash: hash(0),
            eras,
        };
        Self {
            router: Arc::new(
                Router::with_backend(schedule, Arc::new(HttpBackend(clients)), live_methods)
                    .unwrap(),
            ),
            handles,
            resolutions,
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

    async fn check(&self, method: &str, params: Value, era: usize, expected: Value) {
        let expected = json!({"era":era, "params":expected});
        assert_eq!(self.call(method, params).await, expected, "{method}");
    }
}

#[tokio::test]
async fn resolution_uses_headers_and_shares_trace_filter_defaults() {
    let f = Fixture::new().await;
    f.call("trace_filter", json!([{}])).await;
    assert_eq!(f.resolutions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_stubs_do_not_resolve_or_rewrite_execution_selectors() {
    let f = Fixture::new().await;
    for method in ["debug_storageRangeAt", "debug_standardTraceBlockToFile"] {
        // Selector validity belongs to the native stub, not the era router.
        let params = json!(["unavailable"]);
        f.check(method, params.clone(), 1, params).await;
    }
    assert_eq!(f.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn debug_subscriptions_guard_the_included_range() {
    let f = Fixture::new().await;
    for (params, expected) in [
        // The exclusive start belongs to the predecessor; all included blocks are live.
        (json!(["traceChain", "0x2", "0x4"]), Ok(1)),
        (
            json!({"subscription":"traceChain", "startExclusive":"0x0", "endInclusive":"0x4"}),
            Err(-32004),
        ),
        (json!(["native-invalid-subscription"]), Ok(1)),
    ] {
        assert_eq!(
            f.router
                .route("debug_subscribe", RpcParams(params))
                .await
                .map(|route| route.era)
                .map_err(|error| error.code()),
            expected
        );
    }
}

#[tokio::test]
async fn execution_routes_and_preserves_native_block_selectors() {
    let f = Fixture::new().await;
    f.check(
        "eth_call",
        json!([{}, "0x1"]),
        0,
        json!([{}, {"blockHash":hash(1)}]),
    )
    .await;
    for selector in ["block_number", "blockNumber"] {
        f.check(
            "eth_call",
            json!({"request":{}, selector:"earliest"}),
            0,
            json!({"request":{}, selector:{"blockHash":hash(0)}}),
        )
        .await;
    }
    let id = json!({"blockHash":hash(1), "requireCanonical":true});
    for (method, params, era) in [
        ("eth_call", json!([{}, id]), 0),
        ("eth_call", json!([{}, "pending"]), 1),
        (
            "eth_callMany",
            json!([[{"transactions":[{}]}], {"blockNumber":id}]),
            0,
        ),
        (
            "eth_simulateV1",
            json!([{"blockStateCalls":[{"calls":[{}]}]}, id]),
            0,
        ),
        ("debug_traceBlockByHash", json!([hash(1)]), 0),
    ] {
        f.check(method, params.clone(), era, params).await;
    }
    for (method, params, era) in [
        ("eth_getBlockAccessListByBlockHash", json!([hash(1)]), 0),
        ("eth_getBlockAccessListByBlockNumber", json!(["0x1"]), 0),
        ("eth_getBlockAccessList", json!(["0x1"]), 0),
        ("eth_getBlockAccessListRaw", json!(["0x1"]), 0),
        ("debug_getRawBlockAccessList", json!(["0x1"]), 0),
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
async fn simulations_ranges_and_overrides_stay_in_one_era() {
    let f = Fixture::new().await;
    // Base state is the last old block; the simulated child is in the new era.
    for (method, payload_name, block_name) in [
        ("eth_simulateV1", "opts", "blockNumber"),
        ("tempo_simulateV1", "payload", "block"),
    ] {
        let params = json!({payload_name:{"blockStateCalls":[{"blockOverrides":{"time":"0x64"},"calls":[{}]}]}, block_name:"0x2"});
        let mut expected = params.clone();
        expected[block_name] = json!({"blockHash":hash(2)});
        f.check(method, params, 1, expected).await;
    }
    f.check(
        "trace_filter",
        json!([{}]),
        1,
        json!([{"fromBlock":"0x4", "toBlock":"0x4"}]),
    )
    .await;
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
        (
            "trace_filter",
            json!([{"fromBlock":"0x1","toBlock":"0x2"}]),
            0,
        ),
    ] {
        assert_eq!(f.call(method, params).await["era"], era, "{method}");
    }
    for (method, params) in [
        ("eth_call", json!([{}, "0x1", null, {"time":"0x64"}])),
        ("eth_call", json!([{}, "0x1", null, {"timestamp":"0x64"}])),
        (
            "eth_simulateV1",
            json!([{"blockStateCalls":[{"blockOverrides":{"time":"0x63"}},{"blockOverrides":{"time":"0x64"}}]},"0x1"]),
        ),
        // Number gaps generate intermediate blocks, even if the requested block is new.
        (
            "eth_simulateV1",
            json!([{"blockStateCalls":[{"blockOverrides":{"blockNumber":"0x40", "timestamp":"0x12c"}}]},"0x1"]),
        ),
        (
            "debug_traceCallMany",
            json!([[{"transactions":[{}]}, {"transactions":[{}]}], {"blockNumber":"0x2"}]),
        ),
        ("trace_filter", json!([{"fromBlock":"0x1"}])),
    ] {
        assert_eq!(f.error_code(method, params).await, -32004, "{method}");
    }
}

#[tokio::test]
async fn public_registry_enforces_namespaces_and_unknown_execution_fails_closed() {
    let mut f = Fixture::new().await;
    let client = f.public(&["eth", "rpc"], 10_000).await;
    for (method, code) in [
        ("debug_traceBlockByNumber", -32601),
        ("eth_futureExecution", -32004),
    ] {
        assert!(
            matches!(client.request::<Value, _>(method, ("0x1",)).await.unwrap_err(),
            ClientError::Call(error) if error.code() == code),
            "{method}"
        );
    }
    assert_eq!(
        client
            .request::<Value, _>("rpc_modules", jsonrpsee::rpc_params![])
            .await
            .unwrap(),
        json!({"eth":"1.0", "rpc":"1.0"})
    );
}

#[tokio::test]
async fn batches_route_independently_and_response_limits_apply_to_all_backends() {
    let mut f = Fixture::new().await;
    let client = f.public(&["eth", "debug"], 10_000).await;
    let mut batch = BatchRequestBuilder::new();
    for (method, params) in [
        ("eth_call", json!([{}, "0x1"])),
        ("eth_call", json!([{}, "0x3"])),
        ("debug_traceBlockByNumber", json!(["0x1"])),
    ] {
        batch.insert(method, RpcParams(params)).unwrap();
    }
    let response = client.batch_request::<Value>(batch).await.unwrap();
    assert_eq!(
        response
            .into_iter()
            .map(|result| result.unwrap()["era"].clone())
            .collect::<Vec<_>>(),
        [0, 1, 0]
    );

    let limited = f.public(&["eth"], 512).await;
    for (method, params) in [
        ("eth_getCode", json!(["0x0"])),
        ("eth_call", json!([{"data":"x".repeat(3000)}, "0x1"])),
        ("eth_call", json!([{"data":"x".repeat(3000)}, "0x3"])),
    ] {
        assert!(
            limited
                .request::<Value, _>(method, RpcParams(params))
                .await
                .is_err(),
            "{method}"
        );
    }
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
    for (method, params) in [
        ("eth_call", json!([{}, "0x1"])),
        ("debug_traceBlock", json!(["0xc0"])),
    ] {
        assert_eq!(
            live_only.error_code(method, params).await,
            -32004,
            "{method}"
        );
    }
}

#[tokio::test]
async fn websocket_subscriptions_forward_live_events_and_unsubscribe() {
    use jsonrpsee::{
        core::{SubscriptionResult, client::SubscriptionClientT},
        ws_client::WsClientBuilder,
    };
    use std::time::Duration;
    let mut f = Fixture::new().await;
    let closed = Arc::new(tokio::sync::Notify::new());
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
                    observer.notify_one();
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
    tokio::time::timeout(Duration::from_secs(2), closed.notified())
        .await
        .unwrap();
}
