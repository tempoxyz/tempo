//! Routing tests on a fake chain where block `n` has timestamp `n` and eras end at 100 and 200.

mod common;

use common::{FakeBackend, hash, hex};
use serde_json::{Value, json};
use std::sync::Arc;
use tempo_metabinary::routing::{Merge, RelaySegment, Route, Router, RpcParams, first_block_at};

const LIVE: usize = 2;
const TX: Value = Value::Null;

fn router_with(boundaries: Vec<u64>, backend: FakeBackend) -> (Router, Arc<FakeBackend>) {
    let backend = Arc::new(backend);
    (Router::new(boundaries, 100, backend.clone()), backend)
}

fn router() -> (Router, Arc<FakeBackend>) {
    router_with(vec![100, 200], FakeBackend::default())
}

async fn route(router: &Router, method: &str, params: Value) -> Route {
    router.route(method, RpcParams(params)).await.unwrap()
}

/// The expected route to era `era`, which runs natively with its original params if live.
fn era(era: usize, params: Value) -> Route {
    if era == LIVE {
        Route::Live
    } else {
        Route::Era(era, RpcParams(params))
    }
}

fn split(segments: Vec<(usize, Value)>, merge: Merge) -> Route {
    let segments = segments
        .into_iter()
        .map(|(era, params)| (era, RpcParams(params)))
        .collect();
    Route::Split { segments, merge }
}

fn named(pairs: &[(&str, Value)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect(),
    )
}

fn pinned(number: u64) -> Value {
    json!({ "blockHash": hash(number) })
}

/// `eth_simulateV1` payload whose generated blocks set `times`, plus one implicit block.
fn calls(times: &[u64]) -> Value {
    let calls = times
        .iter()
        .map(|time| json!({"blockOverrides": {"time": hex(*time)}}));
    json!({"blockStateCalls": calls.chain([json!({})]).collect::<Vec<_>>()})
}

#[tokio::test]
async fn block_methods_route_by_their_selector() {
    const BLOCK_ID: &[&str] = &["block_id", "blockId"];
    const RAW: &[&str] = &["block", "block_id", "blockId"];
    let cases: &[(&str, usize, &[&str], bool)] = &[
        ("eth_call", 1, &["block_number", "blockNumber"], false),
        (
            "eth_estimateGas",
            1,
            &["block_number", "blockNumber"],
            false,
        ),
        (
            "eth_createAccessList",
            1,
            &["block_number", "blockNumber"],
            false,
        ),
        ("debug_traceCall", 1, BLOCK_ID, false),
        ("trace_call", 2, BLOCK_ID, false),
        ("trace_rawTransaction", 2, BLOCK_ID, false),
        ("trace_callMany", 1, BLOCK_ID, false),
        ("debug_traceBlockByNumber", 0, &["block"], true),
        ("debug_traceBlockByHash", 0, &["block"], false),
        ("eth_getBlockAccessListByBlockHash", 0, &["hash"], false),
        ("eth_getBlockAccessListByBlockNumber", 0, &["number"], true),
        ("eth_getBlockAccessList", 0, BLOCK_ID, false),
        ("eth_getBlockAccessListRaw", 0, RAW, false),
        ("debug_getRawBlockAccessList", 0, RAW, false),
        ("debug_executionWitnessByBlockHash", 0, &["hash"], false),
        (
            "debug_intermediateRoots",
            0,
            &["block_hash", "blockHash"],
            false,
        ),
        ("debug_executionWitness", 0, &["block"], false),
        ("debug_accountAt", 0, BLOCK_ID, false),
        ("debug_accountInfoAt", 0, BLOCK_ID, false),
        ("trace_block", 0, BLOCK_ID, false),
        ("trace_replayBlockTransactions", 0, BLOCK_ID, false),
        ("trace_blockOpcodeGas", 0, BLOCK_ID, false),
    ];
    let (router, _) = router();
    for (method, index, names, number_only) in cases {
        let pin = |number| {
            if *number_only {
                hex(number)
            } else {
                pinned(number)
            }
        };
        let positional = |selector| json!([vec![TX; *index], vec![selector]].concat());
        assert_eq!(
            route(&router, method, positional(hex(150))).await,
            era(1, positional(pin(150))),
            "{method}"
        );
        for name in *names {
            assert_eq!(
                route(
                    &router,
                    method,
                    named(&[("other", json!(1)), (name, hex(50))])
                )
                .await,
                era(0, named(&[("other", json!(1)), (name, pin(50))])),
                "{method} {name}"
            );
        }
    }
}

#[tokio::test]
async fn requests_route_to_their_rule_era() {
    let (live_time, old_time) = (json!({"time": "0x3e8"}), json!({"time": "0x32"}));
    let canonical = json!({"blockHash": hash(50), "requireCanonical": true});
    let bundle = json!({"bundle": []});
    let segment = json!(["traceChain", "0xa", "0x14", null]);
    for (method, params, expected) in [
        // Explicit hashes are kept verbatim, other selectors pinned, missing ones default.
        (
            "eth_call",
            json!([TX, hash(50)]),
            era(0, json!([TX, hash(50)])),
        ),
        (
            "eth_call",
            json!([TX, canonical]),
            era(0, json!([TX, canonical])),
        ),
        (
            "eth_call",
            json!([TX, {"blockNumber": "0x32"}]),
            era(0, json!([TX, pinned(50)])),
        ),
        (
            "eth_call",
            json!([TX]),
            era(LIVE, json!([TX, pinned(1000)])),
        ),
        (
            "debug_traceBlockByNumber",
            json!(["earliest"]),
            era(0, json!(["0x0"])),
        ),
        // Block overrides never change the base block's era.
        (
            "eth_call",
            json!([TX, "0x32", null, live_time]),
            era(0, json!([TX, pinned(50), null, live_time])),
        ),
        (
            "debug_traceCall",
            json!([TX, "0x32", {"blockOverrides": live_time}]),
            era(0, json!([TX, pinned(50), {"blockOverrides": live_time}])),
        ),
        (
            "trace_call",
            json!([TX, ["trace"], "0x32", null, live_time]),
            era(0, json!([TX, ["trace"], pinned(50), null, live_time])),
        ),
        (
            "eth_call",
            json!([TX, "latest", null, old_time]),
            era(LIVE, json!([TX, pinned(1000), null, old_time])),
        ),
        (
            "eth_callMany",
            json!([[{"blockOverride": live_time}], {"blockNumber": "0x32"}]),
            era(
                0,
                json!([[{"blockOverride": live_time}], {"blockNumber": pinned(50)}]),
            ),
        ),
        (
            "eth_callBundle",
            json!([{"stateBlockNumber": "latest", "timestamp": 50}]),
            era(
                LIVE,
                json!([{"stateBlockNumber": hex(1000), "timestamp": 50}]),
            ),
        ),
        (
            "debug_traceCallMany",
            json!({"bundles": [], "stateContext": {"blockNumber": "0x96", "transactionIndex": 1}}),
            era(
                1,
                json!({"bundles": [], "stateContext": {"blockNumber": pinned(150), "transactionIndex": 1}}),
            ),
        ),
        (
            "eth_feeHistory",
            json!(["0x4", "0x96", [25]]),
            era(1, json!(["0x4", "0x96", [25]])),
        ),
        (
            "eth_feeHistory",
            json!({"blockCount": 4, "newestBlock": "pending"}),
            era(LIVE, json!({"blockCount": 4, "newestBlock": hex(1000)})),
        ),
        // Generated blocks follow their explicit times, else (and never before) the base era.
        (
            "eth_simulateV1",
            json!([calls(&[]), "0x32"]),
            era(0, json!([calls(&[]), pinned(50)])),
        ),
        (
            "eth_simulateV1",
            json!([calls(&[900, 950]), "0x32"]),
            era(LIVE, json!([calls(&[900, 950]), pinned(50)])),
        ),
        (
            "eth_simulateV1",
            json!([calls(&[50]), "0x96"]),
            era(1, json!([calls(&[50]), pinned(150)])),
        ),
        (
            "tempo_simulateV1",
            json!({"payload": calls(&[]), "block": "0x96"}),
            era(1, json!({"payload": calls(&[]), "block": pinned(150)})),
        ),
        (
            "mev_simBundle",
            json!([bundle, {"parentBlock": "0x32"}]),
            era(0, json!([bundle, {"parentBlock": pinned(50)}])),
        ),
        (
            "mev_simBundle",
            json!([bundle, {"parentBlock": "0x32", "timestamp": 150}]),
            era(
                1,
                json!([bundle, {"parentBlock": pinned(50), "timestamp": 150}]),
            ),
        ),
        (
            "mev_simBundle",
            json!({"bundle": bundle}),
            era(
                LIVE,
                json!({"bundle": bundle, "sim_overrides": {"parentBlock": pinned(1000)}}),
            ),
        ),
        (
            "reth_getBlockExecutionOutcome",
            json!(["0x32", "0x2"]),
            era(0, json!([pinned(50), "0x2"])),
        ),
        (
            "trace_filter",
            json!([{"fromBlock": "0x1", "toBlock": "0x2", "after": 1}]),
            era(
                0,
                json!([{"fromBlock": "0x1", "toBlock": "0x2", "after": 1}]),
            ),
        ),
        ("debug_traceBlock", json!(["0x96"]), era(1, json!(["0x96"]))),
        (
            "debug_subscribe",
            segment.clone(),
            Route::Relay {
                segments: vec![RelaySegment {
                    era: 0,
                    params: RpcParams(segment),
                    last_block: 20,
                    is_last: true,
                }],
            },
        ),
    ] {
        assert_eq!(
            route(&router().0, method, params).await,
            expected,
            "{method}"
        );
    }
}

#[tokio::test]
async fn live_requests_run_natively() {
    let bundle = json!({"bundle": []});
    for (method, params, resolves) in [
        ("eth_estimateGas", json!([TX]), false),
        (
            "eth_call",
            json!({"request": TX, "blockNumber": "pending"}),
            false,
        ),
        ("eth_feeHistory", json!(["0x0", "0x32"]), false),
        ("eth_feeHistory", json!(["bogus", "0x32"]), false),
        (
            "eth_feeHistory",
            json!(["0x4", {"blockHash": hash(50)}]),
            false,
        ),
        ("eth_feeHistory", json!(["0x4"]), false),
        ("eth_callMany", json!([[]]), false),
        (
            "eth_callMany",
            json!([[], {"blockNumber": "pending"}]),
            false,
        ),
        ("eth_callMany", json!([[], {"transactionIndex": 1}]), false),
        (
            "tempo_simulateV1",
            json!({"payload": calls(&[]), "block": "pending"}),
            false,
        ),
        ("tempo_simulateV1", json!({"payload": calls(&[])}), false),
        (
            "mev_simBundle",
            json!([bundle, {"parentBlock": "pending"}]),
            false,
        ),
        (
            "reth_getBlockExecutionOutcome",
            json!(["pending", 3]),
            false,
        ),
        ("reth_getBlockExecutionOutcome", json!(["0x0"]), true),
        (
            "debug_subscribe",
            json!(["traceChain", "0x3e0", "0x3e8"]),
            true,
        ),
        (
            "debug_subscribe",
            json!(["traceChain", "0x6e", "0x5a"]),
            true,
        ),
        (
            "debug_subscribe",
            json!(["traceChain", "0x5a", "0x5a"]),
            true,
        ),
        ("debug_subscribe", json!(["newHeads"]), false),
    ] {
        let (router, backend) = router();
        assert_eq!(
            route(&router, method, params.clone()).await,
            era(LIVE, params),
            "{method}"
        );
        assert_eq!(backend.resolutions() > 0, resolves, "{method}");
    }
}

#[tokio::test]
async fn invalid_requests_fail_with_exact_errors() {
    let (router, _) = router();
    for (method, params, code, message) in [
        (
            "eth_call",
            json!("0x1"),
            -32602,
            "params must be an array or an object",
        ),
        (
            "debug_traceTransaction",
            json!([]),
            -32602,
            "missing transaction hash",
        ),
        (
            "eth_simulateV1",
            json!([calls(&[50, 150]), "0x32"]),
            -32004,
            "simulated blocks span multiple eras",
        ),
        (
            "reth_getBlockExecutionOutcome",
            json!(["0x1", 0]),
            -32602,
            "block count must be between 1 and 128",
        ),
        (
            "reth_getBlockExecutionOutcome",
            json!(["0x1", "0x81"]),
            -32602,
            "block count must be between 1 and 128",
        ),
        (
            "trace_filter",
            json!([{"fromBlock": "0x6e", "toBlock": "0x5a"}]),
            -32602,
            "invalid parameters: fromBlock cannot be greater than toBlock",
        ),
        (
            "trace_filter",
            json!([{"fromBlock": "0x0", "toBlock": "0x65"}]),
            -32602,
            "Block range too large; currently limited to 100 blocks",
        ),
        (
            "testing_buildBlockV1",
            json!([]),
            -32004,
            "testing_buildBlockV1 has no era routing policy",
        ),
        (
            "foo_bar",
            json!([]),
            -32004,
            "foo_bar has no era routing policy",
        ),
    ] {
        let err = router.route(method, RpcParams(params)).await.unwrap_err();
        assert_eq!((err.code(), err.message()), (code, message), "{method}");
    }
}

#[tokio::test]
async fn transactions_route_by_their_block() {
    let historical = hash(9000);
    let backend = FakeBackend {
        transactions: [(historical, 150)].into(),
        ..Default::default()
    };
    let (router, _) = router_with(vec![100, 200], backend);
    for method in [
        "debug_traceTransaction",
        "trace_transaction",
        "trace_get",
        "trace_replayTransaction",
        "trace_transactionOpcodeGas",
        "ots_getInternalOperations",
        "ots_getTransactionError",
        "ots_traceTransaction",
    ] {
        let mut cases = vec![(json!([historical]), 1), (json!([hash(1)]), LIVE)];
        for name in ["tx_hash", "txHash", "hash", "transaction"] {
            cases.push((named(&[(name, json!(historical))]), 1));
        }
        for (params, expected) in cases {
            assert_eq!(
                route(&router, method, params.clone()).await,
                era(expected, params)
            );
        }
    }
}

#[tokio::test]
async fn canonical_ranges_split_at_boundaries() {
    let (router, backend) = router();
    let outcome = Merge::ExecutionOutcome;
    let expected = split(
        vec![
            (0, json!({"blockId": "0x5f", "count": "0x5"})),
            (1, json!({"blockId": "0x64", "count": "0x5"})),
        ],
        outcome,
    );
    assert_eq!(
        route(
            &router,
            "reth_getBlockExecutionOutcome",
            json!({"blockId": "0x5f", "count": 10})
        )
        .await,
        expected
    );
    // A hash re-resolves by canonical height.
    assert_eq!(
        route(
            &router,
            "reth_getBlockExecutionOutcome",
            json!([hash(95), "0xa"])
        )
        .await,
        route(
            &router,
            "reth_getBlockExecutionOutcome",
            json!(["0x5f", "0xa"])
        )
        .await,
    );
    // Clamped at the head.
    let (clamped, _) = router_with(vec![100, 995], FakeBackend::default());
    assert_eq!(
        route(
            &clamped,
            "reth_getBlockExecutionOutcome",
            json!(["0x3e0", "0x80"])
        )
        .await,
        split(
            vec![(1, json!(["0x3e0", "0x3"])), (2, json!(["0x3e3", "0x6"]))],
            outcome
        )
    );

    // Segments keep the caller's filter without pagination, which applies once to the merge.
    let filter = json!({"fromBlock": "0x5a", "toBlock": "0x6e", "mode": "union", "after": 2, "count": "0x3"});
    let segment =
        |from: u64, to: u64| json!([{"fromBlock": hex(from), "toBlock": hex(to), "mode": "union"}]);
    assert_eq!(
        route(&router, "trace_filter", json!([filter])).await,
        split(
            vec![(0, segment(90, 99)), (1, segment(100, 110))],
            Merge::TraceFilter {
                after: Some(2),
                count: Some(3)
            },
        )
    );
    let mut three_eras = filter;
    three_eras["fromBlock"] = hex(150);
    three_eras["toBlock"] = hex(210);
    let (three, _) = router_with(vec![100, 160, 200], FakeBackend::default());
    let Route::Split { segments, .. } = route(&three, "trace_filter", json!([three_eras])).await
    else {
        panic!("expected a split")
    };
    let segments: Vec<_> = segments
        .into_iter()
        .map(|(era, params)| (era, params.0))
        .collect();
    assert_eq!(
        segments,
        [
            (1, segment(150, 159)),
            (2, segment(160, 199)),
            (3, segment(200, 210))
        ]
    );
    // Equal bounds resolve once.
    let reads = backend.resolutions();
    assert_eq!(
        route(&router, "trace_filter", json!([{"toBlock": null}])).await,
        era(
            LIVE,
            json!([{"fromBlock": hex(1000), "toBlock": hex(1000)}])
        )
    );
    assert_eq!(backend.resolutions(), reads + 1);

    let relay = |era, start: u64, end: u64, is_last| RelaySegment {
        era,
        params: RpcParams(json!(["traceChain", hex(start), hex(end), {}])),
        last_block: end,
        is_last,
    };
    assert_eq!(
        route(
            &router,
            "debug_subscribe",
            json!(["traceChain", "0x5a", "0x6e", {}])
        )
        .await,
        Route::Relay {
            segments: vec![relay(0, 90, 99, false), relay(1, 99, 110, true)],
        }
    );
    let named =
        json!({"subscription": "traceChain", "startExclusive": "0x5a", "endInclusive": "0xc8"});
    assert!(matches!(
        route(&router, "debug_subscribe", named).await,
        Route::Relay { segments } if segments.len() == 3
    ));
}

#[tokio::test]
async fn split_points_follow_era_selection() {
    let bounds = |route: Route| {
        let Route::Split { segments, .. } = route else {
            panic!("expected a split")
        };
        let bound = |params: &RpcParams, name: &str| {
            u64::from_str_radix(&params.0[0][name].as_str().unwrap()[2..], 16).unwrap()
        };
        segments
            .iter()
            .map(|(era, params)| (*era, bound(params, "fromBlock"), bound(params, "toBlock")))
            .collect::<Vec<_>>()
    };
    let filter = |from: u64, to: u64| json!([{"fromBlock": hex(from), "toBlock": hex(to)}]);

    // With block `n` at `3n`, boundary 100 falls between blocks 33 and 34 and era 1 is empty.
    let backend = FakeBackend {
        timestamp: |number| 3 * number,
        ..Default::default()
    };
    let (sparse, _) = router_with(vec![100, 101], backend);
    let (router, _) = router();
    for (router, from, to, expected) in [
        (&sparse, 30, 40, vec![(0, 30, 33), (2, 34, 40)]),
        (&router, 99, 100, vec![(0, 99, 99), (1, 100, 100)]),
        (&router, 100, 200, vec![(1, 100, 199), (2, 200, 200)]),
    ] {
        assert_eq!(
            bounds(route(router, "trace_filter", filter(from, to)).await),
            expected
        );
    }

    // Logarithmic header reads.
    let backend = Arc::new(FakeBackend {
        head: 1 << 20,
        ..Default::default()
    });
    let router = Router::new(vec![1 << 19], u64::MAX, backend.clone());
    route(&router, "trace_filter", filter(0, 1 << 20)).await;
    assert!(backend.resolutions() <= 2 + 21, "{}", backend.resolutions());
}

#[tokio::test]
async fn first_block_at_is_a_binary_search() {
    let timestamp = async |number: u64| Ok::<_, &str>(number * 10);
    for (low, boundary, expected) in [(0, 0, 0), (0, 41, 5), (0, 50, 5), (3, 0, 3), (0, 1000, 10)] {
        assert_eq!(
            first_block_at(low, 10, boundary, timestamp).await,
            Ok(expected)
        );
    }
    let missing = async |number: u64| {
        if number < 3 {
            Ok(number)
        } else {
            Err("missing")
        }
    };
    assert_eq!(first_block_at(0, 5, 4, missing).await, Err("missing"));
}
