//! Decoration tests: fake native callbacks record what reached them, the fake backend serves
//! frozen eras. Block `n` has timestamp `n`.

mod common;

use common::{FakeBackend, ForwardFn, hash, hex};
use futures::FutureExt as _;
use jsonrpsee::{
    RpcModule,
    core::server::{
        ConnectionId, Extensions, MethodCallback, MethodResponse, Methods, ResponsePayload,
    },
    types::{ErrorObjectOwned, Id, Params},
};
use serde_json::{Value, json, value::RawValue};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempo_metabinary::{
    decorate::{RpcApi, decorate},
    routing::Router,
};
use tokio::sync::mpsc::Receiver;

const WAIT: Duration = Duration::from_secs(10);

/// What a native call callback received.
#[derive(Debug, Clone, PartialEq)]
struct Received {
    id: Id<'static>,
    params: Option<String>,
    conn_id: Option<ConnectionId>,
    max: usize,
    marker: Option<u32>,
}

#[derive(Default)]
struct Natives {
    received: Mutex<Vec<(&'static str, Received)>>,
    trace_filter_calls: AtomicUsize,
    /// `reth_getBlockExecutionOutcome` answers `null` when set.
    missing_outcome: bool,
}

/// Two traces for every block in `from..=to`.
fn traces(from: u64, to: u64) -> Vec<Value> {
    let block = |block| {
        [
            json!({"block": block, "i": 0}),
            json!({"block": block, "i": 1}),
        ]
    };
    (from..=to).flat_map(block).collect()
}

fn quantity(value: &Value) -> u64 {
    u64::from_str_radix(&value.as_str().unwrap()[2..], 16).unwrap()
}

fn respond(id: Id<'_>, result: Value, max: usize, ext: Extensions) -> MethodResponse {
    MethodResponse::response(id, ResponsePayload::success(result), max).with_extensions(ext)
}

fn record(
    natives: &Natives,
    name: &'static str,
    id: &Id<'_>,
    params: &Params<'_>,
    conn_id: Option<ConnectionId>,
    max: usize,
    ext: &Extensions,
) {
    let received = Received {
        id: id.clone().into_owned(),
        params: params.as_str().map(str::to_owned),
        conn_id,
        max,
        marker: ext.get::<u32>().copied(),
    };
    natives.received.lock().unwrap().push((name, received));
}

fn native_methods(natives: Arc<Natives>) -> Methods {
    let mut methods = Methods::new();
    let sync_natives = natives.clone();
    let eth_call = MethodCallback::Sync(Arc::new(move |id, params, max, ext| {
        record(&sync_natives, "eth_call", &id, &params, None, max, &ext);
        respond(id, json!("native"), max, ext)
    }));
    methods.verify_and_insert("eth_call", eth_call).unwrap();
    for name in [
        "trace_call",
        "trace_filter",
        "reth_getBlockExecutionOutcome",
    ] {
        let natives = natives.clone();
        let callback = MethodCallback::Async(Arc::new(move |id, params, conn_id, max, ext| {
            let natives = natives.clone();
            async move {
                record(&natives, name, &id, &params, Some(conn_id), max, &ext);
                let parsed: Value = params.parse().unwrap_or_default();
                let result = match name {
                    "trace_filter" => {
                        natives.trace_filter_calls.fetch_add(1, Ordering::SeqCst);
                        let filter = &parsed[0];
                        json!(traces(
                            quantity(&filter["fromBlock"]),
                            quantity(&filter["toBlock"])
                        ))
                    }
                    "reth_getBlockExecutionOutcome" if natives.missing_outcome => Value::Null,
                    "reth_getBlockExecutionOutcome" => json!({"part": parsed, "era": "live"}),
                    _ => json!("native"),
                };
                respond(id, result, max, ext)
            }
            .boxed()
        }));
        methods.verify_and_insert(name, callback).unwrap();
    }
    let mut module = RpcModule::new(());
    module
        .register_method("eth_blockNumber", |_, _, _| "0x1")
        .unwrap();
    module
        .register_async_method("engine_forkchoiceUpdatedV3", |_, _, _| async { "fcu" })
        .unwrap();
    module
        .register_subscription(
            "eth_subscribe",
            "eth_subscription",
            "eth_unsubscribe",
            |_, pending, _, _| async move {
                pending.accept().await?;
                Ok(())
            },
        )
        .unwrap();
    // Like native `traceChain`: odd blocks have traces, empty ones are skipped except the end.
    module
        .register_subscription(
            "debug_subscribe",
            "debug_subscription",
            "debug_unsubscribe",
            |params, pending, _, _| async move {
                let params: Value = params.parse()?;
                let (start, end) = (quantity(&params[1]), quantity(&params[2]));
                let sink = pending.accept().await?;
                for number in (start + 1..=end).filter(|n| n % 2 == 1 || *n == end) {
                    let traces = if number % 2 == 1 {
                        json!([1])
                    } else {
                        json!([])
                    };
                    let item =
                        json!({"block": hex(number), "hash": hash(number), "traces": traces});
                    sink.send(serde_json::value::to_raw_value(&item)?).await?;
                }
                sink.closed().await;
                Ok(())
            },
        )
        .unwrap();
    methods.merge(module).unwrap();
    methods
}

struct Fixture {
    natives: Arc<Natives>,
    backend: Arc<FakeBackend>,
    original: Methods,
    methods: Methods,
}

impl Fixture {
    fn new(boundaries: Vec<u64>, backend: FakeBackend, natives: Natives, api: RpcApi) -> Self {
        let (natives, backend) = (Arc::new(natives), Arc::new(backend));
        let original = native_methods(natives.clone());
        let router = Arc::new(Router::new(boundaries, 1000, backend.clone()));
        let methods = decorate(original.clone(), router, api).unwrap();
        Self {
            natives,
            backend,
            original,
            methods,
        }
    }

    /// Era `0` is frozen below timestamp 100, era `1` is live.
    fn two_eras(backend: FakeBackend) -> Self {
        Self::new(vec![100], backend, Natives::default(), RpcApi::Eth)
    }

    async fn raw_request(&self, method: &str, params: Value) -> (Value, Receiver<Box<RawValue>>) {
        let request =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let request = self.methods.raw_json_request(&request, 64);
        let (response, rx) = tokio::time::timeout(WAIT, request).await.unwrap().unwrap();
        (serde_json::from_str(response.get()).unwrap(), rx)
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, ErrorObjectOwned> {
        envelope(self.raw_request(method, params).await.0)
    }

    /// Calls the decorated callback directly with id 7 and a `u32` extension `marker`.
    async fn invoke(
        &self,
        method: &str,
        params: &str,
        conn_id: usize,
        max: usize,
        marker: u32,
    ) -> MethodResponse {
        let mut ext = Extensions::new();
        ext.insert(marker);
        let params = Params::new(Some(params)).into_owned();
        let MethodCallback::Async(callback) = self.methods.method(method).unwrap() else {
            panic!("{method} is not async")
        };
        callback(Id::Number(7), params, ConnectionId(conn_id), max, ext).await
    }
}

fn envelope(mut response: Value) -> Result<Value, ErrorObjectOwned> {
    match response.get("error") {
        Some(error) => Err(serde_json::from_value(error.clone()).unwrap()),
        None => Ok(response["result"].take()),
    }
}

fn parse(response: &MethodResponse) -> Result<Value, ErrorObjectOwned> {
    envelope(serde_json::from_str(response.as_json().get()).unwrap())
}

async fn next_notification(rx: &mut Receiver<Box<RawValue>>) -> Value {
    let item = tokio::time::timeout(WAIT, rx.recv())
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(item.get()).unwrap()
}

async fn assert_silent(rx: &mut Receiver<Box<RawValue>>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err()
    );
}

fn same_callback(a: &MethodCallback, b: &MethodCallback) -> bool {
    match (a, b) {
        (MethodCallback::Sync(a), MethodCallback::Sync(b)) => Arc::ptr_eq(a, b),
        (MethodCallback::Async(a), MethodCallback::Async(b)) => Arc::ptr_eq(a, b),
        (MethodCallback::Subscription(a), MethodCallback::Subscription(b)) => Arc::ptr_eq(a, b),
        (MethodCallback::Unsubscription(a), MethodCallback::Unsubscription(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

#[tokio::test]
async fn only_execution_callbacks_are_replaced() {
    let fixture = Fixture::two_eras(FakeBackend::default());
    let mut names: Vec<_> = fixture.methods.method_names().collect();
    let mut original: Vec<_> = fixture.original.method_names().collect();
    names.sort_unstable();
    original.sort_unstable();
    assert_eq!(names, original);
    for name in names {
        let replaced = matches!(
            name,
            "eth_call"
                | "trace_call"
                | "trace_filter"
                | "reth_getBlockExecutionOutcome"
                | "debug_subscribe"
                | "debug_unsubscribe"
        );
        let same = same_callback(
            fixture.methods.method(name).unwrap(),
            fixture.original.method(name).unwrap(),
        );
        assert_eq!(!same, replaced, "{name}");
    }
}

#[tokio::test]
async fn calls_run_natively_or_forward_raw_results() {
    let backend = FakeBackend {
        forward: Box::new(|_, _, params| match params.get(2) {
            None => Ok(r#"{"b": 1,   "a":[ 2 ]}"#.to_owned()),
            Some(_) => Err(ErrorObjectOwned::owned(
                -32000,
                "execution reverted",
                Some("0xdead"),
            )),
        }),
        ..Default::default()
    };
    let fixture = Fixture::two_eras(backend);

    // Live calls reach Sync and Async natives with the original id, params, limit, and extensions.
    let live = r#"[{"to":null}, "latest"]"#;
    for method in ["eth_call", "trace_call"] {
        let response = fixture.invoke(method, live, 3, 1234, 42).await;
        assert_eq!(response.extensions().get::<u32>(), Some(&42));
        assert_eq!(parse(&response).unwrap(), json!("native"));
    }
    let received = |conn_id| Received {
        id: Id::Number(7),
        params: Some(live.to_owned()),
        conn_id,
        max: 1234,
        marker: Some(42),
    };
    let expected = [
        ("eth_call", received(None)),
        ("trace_call", received(Some(ConnectionId(3)))),
    ];
    assert_eq!(*fixture.natives.received.lock().unwrap(), expected);

    // Historical results are embedded verbatim under the caller's limit.
    let historical = r#"[{}, "0x32"]"#;
    let response = fixture.invoke("eth_call", historical, 0, 1000, 9).await;
    assert_eq!(response.extensions().get::<u32>(), Some(&9));
    assert_eq!(
        response.as_json().get(),
        r#"{"jsonrpc":"2.0","id":7,"result":{"b": 1,   "a":[ 2 ]}}"#
    );
    assert_eq!(
        fixture.backend.forwarded(),
        [(
            0,
            "eth_call".to_owned(),
            json!([{}, {"blockHash": hash(50)}])
        )]
    );
    assert_eq!(
        fixture
            .invoke("eth_call", historical, 0, 10, 9)
            .await
            .as_error_code(),
        Some(-32008)
    );

    let reverted = fixture
        .invoke("eth_call", r#"[{}, "0x32", {"x": 1}]"#, 0, 1000, 9)
        .await;
    assert_eq!(reverted.extensions().get::<u32>(), Some(&9));
    let err = parse(&reverted).unwrap_err();
    assert_eq!(
        (err.code(), err.message(), err.data().map(|d| d.get())),
        (-32000, "execution reverted", Some(r#""0xdead""#))
    );
    let err = fixture
        .call("eth_call", json!([{}, "0x5000"]))
        .await
        .unwrap_err();
    assert_eq!((err.code(), err.message()), (-32001, "unknown block"));
    assert_eq!(fixture.natives.received.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn engine_eth_call_uses_the_public_selector_name() {
    let fixture = Fixture::new(
        vec![100],
        FakeBackend::default(),
        Natives::default(),
        RpcApi::Engine,
    );
    let pinned = json!({"blockHash": hash(50)});
    let overrides = json!({"time": "0x3e8"});
    for (params, expected) in [
        (
            json!({"request": {}, "block_id": "0x32"}),
            json!({"request": {}, "block_number": pinned}),
        ),
        (
            json!({"request": {}, "blockId": "0x32", "block_number": "0x99"}),
            json!({"request": {}, "blockNumber": pinned}),
        ),
        (
            json!({"request": {}, "block_id": "0x32", "blockNumber": "0x3e8", "block_overrides": overrides}),
            json!({"request": {}, "block_number": pinned, "block_overrides": overrides}),
        ),
        (json!([{}, "0x32"]), json!([{}, pinned])),
    ] {
        fixture.call("eth_call", params).await.unwrap();
        let forwarded = fixture.backend.forwarded.lock().unwrap().pop().unwrap();
        assert_eq!(forwarded, (0, "eth_call".to_owned(), expected));
    }

    let pending = r#"{"request":{},"block_id":"pending"}"#;
    assert_eq!(
        parse(&fixture.invoke("eth_call", pending, 0, 100, 1).await).unwrap(),
        json!("native")
    );
    assert_eq!(
        fixture.natives.received.lock().unwrap()[0]
            .1
            .params
            .as_deref(),
        Some(pending)
    );
}

#[tokio::test]
async fn split_trace_filters_paginate_like_one_call() {
    let frozen: fn() -> Box<ForwardFn> = || {
        Box::new(|_, _, params| {
            let filter = &params[0];
            assert!(filter.get("after").is_none() && filter.get("count").is_none());
            Ok(json!(traces(
                quantity(&filter["fromBlock"]),
                quantity(&filter["toBlock"])
            ))
            .to_string())
        })
    };
    let filter = |pagination: Value| {
        let mut filter = json!({"fromBlock": "0x5f", "toBlock": "0x68", "mode": "union"});
        filter
            .as_object_mut()
            .unwrap()
            .extend(pagination.as_object().unwrap().clone());
        json!([filter])
    };
    // Blocks 95..=104 hold 20 traces. A full page never runs later segments.
    let all = traces(95, 104);
    for (boundaries, pagination, expected, natives, forwards) in [
        (vec![100], json!({}), &all[..], 1, 1),
        (
            vec![100],
            json!({"after": 12, "count": 3}),
            &all[12..15],
            1,
            1,
        ),
        (vec![100], json!({"after": 20}), &[], 1, 1),
        (vec![100], json!({"after": 3, "count": 4}), &all[3..7], 0, 1),
        (vec![100, 200], json!({"count": 2}), &all[..2], 0, 1),
    ] {
        let backend = FakeBackend {
            forward: frozen(),
            ..Default::default()
        };
        let fixture = Fixture::new(boundaries, backend, Natives::default(), RpcApi::Eth);
        assert_eq!(
            fixture
                .call("trace_filter", filter(pagination.clone()))
                .await
                .unwrap(),
            json!(expected)
        );
        assert_eq!(
            fixture.natives.trace_filter_calls.load(Ordering::SeqCst),
            natives,
            "{pagination}"
        );
        assert_eq!(fixture.backend.forwarded().len(), forwards, "{pagination}");
    }

    // The merged response is limited by the caller's size limit.
    let fixture = Fixture::two_eras(FakeBackend {
        forward: frozen(),
        ..Default::default()
    });
    let response = fixture
        .invoke("trace_filter", &filter(json!({})).to_string(), 0, 100, 1)
        .await;
    assert_eq!(response.as_error_code(), Some(-32008));

    // A segment error is returned as is.
    let failing = FakeBackend {
        forward: Box::new(|_, _, _| {
            Err(ErrorObjectOwned::owned(
                -32000,
                "tracing failed",
                None::<()>,
            ))
        }),
        ..Default::default()
    };
    let fixture = Fixture::two_eras(failing);
    let err = fixture
        .call("trace_filter", filter(json!({})))
        .await
        .unwrap_err();
    assert_eq!((err.code(), err.message()), (-32000, "tracing failed"));
    assert_eq!(fixture.natives.trace_filter_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn split_execution_outcomes_merge_in_block_order() {
    let frozen_part = json!({"part": ["0x5f", "0x5"], "era": "frozen"});
    let live_part = json!({"part": ["0x64", "0x5"], "era": "live"});
    let frozen = || -> Box<ForwardFn> {
        Box::new(|_, _, params| Ok(json!({"part": params, "era": "frozen"}).to_string()))
    };
    // A missing tail truncates the merge, and a missing first part is `null`.
    for (forward, missing_outcome, expected) in [
        (frozen(), false, json!({"merged": [frozen_part, live_part]})),
        (frozen(), true, json!({"merged": [frozen_part]})),
        (
            Box::new(|_, _, _| Ok("null".to_owned())),
            false,
            Value::Null,
        ),
    ] {
        let backend = FakeBackend {
            forward,
            ..Default::default()
        };
        let natives = Natives {
            missing_outcome,
            ..Default::default()
        };
        let fixture = Fixture::new(vec![100], backend, natives, RpcApi::Eth);
        let result = fixture
            .call("reth_getBlockExecutionOutcome", json!(["0x5f", "0xa"]))
            .await;
        assert_eq!(result.unwrap(), expected);
    }
}

#[tokio::test]
async fn trace_chains_delegate_or_relay_historical_segments() {
    let frozen_chain = || FakeBackend {
        notifications: [(
            0,
            vec![
                json!({"block": hex(91), "traces": [1]}),
                json!({"block": hex(99), "traces": []}),
            ],
        )]
        .into(),
        ..Default::default()
    };
    let fixture = Fixture::two_eras(frozen_chain());
    let blocks = async |rx: &mut Receiver<Box<RawValue>>, id: &Value, count| {
        let mut blocks = Vec::new();
        for _ in 0..count {
            let notification = next_notification(rx).await;
            assert_eq!(notification["method"], "debug_subscription");
            assert_eq!(notification["params"]["subscription"], *id);
            blocks.push(notification["params"]["result"]["block"].clone());
        }
        blocks
    };

    // Live ranges delegate with the pre-allocated subscription ID.
    let (response, mut rx) = fixture
        .raw_request("debug_subscribe", json!(["traceChain", "0x3e0", "0x3e3"]))
        .await;
    let id = envelope(response).unwrap();
    assert_eq!(blocks(&mut rx, &id, 2).await, [993, 995].map(hex));
    assert!(fixture.backend.subscribed.lock().unwrap().is_empty());

    // Across the boundary, the frozen end block's empty notification is dropped.
    let (response, mut rx) = fixture
        .raw_request("debug_subscribe", json!(["traceChain", "0x5a", "0x6e"]))
        .await;
    let id = envelope(response).unwrap();
    assert_eq!(
        blocks(&mut rx, &id, 7).await,
        [91, 101, 103, 105, 107, 109, 110].map(hex)
    );
    assert_eq!(
        *fixture.backend.subscribed.lock().unwrap(),
        [(0, json!(["traceChain", "0x5a", "0x63"]))]
    );
    assert_silent(&mut rx).await;

    // A segment that ends early stops the relay before later segments.
    let early = FakeBackend {
        notifications: [(0, vec![json!({"block": hex(91), "traces": [1]})])].into(),
        end_streams: true,
        ..Default::default()
    };
    let fixture = Fixture::two_eras(early);
    let (response, mut rx) = fixture
        .raw_request("debug_subscribe", json!(["traceChain", "0x5a", "0x6e"]))
        .await;
    let id = envelope(response).unwrap();
    assert_eq!(blocks(&mut rx, &id, 1).await, [hex(91)]);
    assert_silent(&mut rx).await;
    assert_eq!(fixture.backend.subscribed.lock().unwrap().len(), 1);

    // Unsubscribing or disconnecting drops the upstream subscription of an unfinished relay.
    let fixture = Fixture::two_eras(frozen_chain());
    let frozen_only = json!(["traceChain", "0xa", "0x14"]);
    let closed = async || {
        tokio::time::timeout(WAIT, async {
            while fixture.backend.open_streams.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("upstream subscription was not dropped")
    };
    let (response, mut rx) = fixture
        .raw_request("debug_subscribe", frozen_only.clone())
        .await;
    next_notification(&mut rx).await;
    assert_eq!(fixture.backend.open_streams.load(Ordering::SeqCst), 1);
    let unsubscribe = json!([envelope(response).unwrap()]);
    assert_eq!(
        fixture
            .call("debug_unsubscribe", unsubscribe)
            .await
            .unwrap(),
        json!(true)
    );
    closed().await;
    let (_, mut rx) = fixture.raw_request("debug_subscribe", frozen_only).await;
    next_notification(&mut rx).await;
    drop(rx);
    closed().await;

    // Unknown subscriptions are the native callback's.
    let request =
        json!({"jsonrpc": "2.0", "id": 1, "method": "debug_unsubscribe", "params": ["0x1234"]});
    let (native, _) = fixture
        .original
        .raw_json_request(&request.to_string(), 1)
        .await
        .unwrap();
    let native = envelope(serde_json::from_str(native.get()).unwrap());
    assert_eq!(
        fixture.call("debug_unsubscribe", json!(["0x1234"])).await,
        native
    );
}
