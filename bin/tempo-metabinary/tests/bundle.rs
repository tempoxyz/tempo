//! Native Flashbots bundle semantics select configuration from stateBlockNumber and then
//! advance or override the timestamp. Both contexts must stay inside one executable's era.
use std::{collections::HashSet, sync::Arc};

use futures::future::BoxFuture;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use serde_json::{Value, json};
use tempo_metabinary::{
    catalog::{ChainEras, ReleaseEra},
    routing::{Backend, Route, Router, RpcParams, is_execution_method},
};

struct Blocks;

impl Backend for Blocks {
    fn request<'a>(
        &'a self,
        era: usize,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Value>> {
        Box::pin(async move {
            assert_eq!(era, 1, "resolve through the live node");
            if method == "eth_getTransactionByHash" {
                return Ok(
                    json!({"blockHash":format!("0x{:064x}", if params.0[0] == "old" {1} else {3})}),
                );
            }
            if method == "eth_getBlockByHash" {
                let hash = params.0[0].as_str().unwrap();
                let number = u64::from_str_radix(&hash[2..], 16).unwrap();
                let (number, timestamp) = match number {
                    1 => (1, 50),
                    3 => (3, 110),
                    // Side-chain header has a different timestamp, but Reth replay uses height 2.
                    5 => (2, 150),
                    _ => panic!("unexpected hash {hash}"),
                };
                return Ok(
                    json!({"number":format!("0x{number:x}"), "hash":hash, "timestamp":format!("0x{timestamp:x}")}),
                );
            }
            assert_eq!(method, "eth_getBlockByNumber");
            let (number, timestamp) = match params.0[0].as_str().unwrap() {
                "0x0" => (0, 0),
                "safe" | "0x1" => (1, 50),
                "0x2" => (2, 99),
                "latest" | "0x3" => (3, 110),
                "0x4" => (4, u64::MAX),
                selector => panic!("unexpected selector {selector}"),
            };
            Ok(json!({
                "number": format!("0x{number:x}"),
                "hash": format!("0x{number:064x}"),
                "timestamp": format!("0x{timestamp:x}"),
            }))
        })
    }
}

fn router() -> Router {
    Router::with_backend(
        ChainEras {
            chain_id: "0x1".into(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            eras: vec![
                ReleaseEra {
                    name: "old".into(),
                    start_timestamp: 0,
                    binary: Some("/unused/frozen".into()),
                },
                ReleaseEra {
                    name: "live".into(),
                    start_timestamp: 100,
                    binary: None,
                },
            ],
        },
        Arc::new(Blocks),
        HashSet::new(),
    )
    .unwrap()
}

async fn route_ok(router: &Router, method: &str, params: Value) -> Route {
    router.route(method, RpcParams(params)).await.unwrap()
}

async fn route_err(router: &Router, method: &str, params: Value) -> ErrorObjectOwned {
    router.route(method, RpcParams(params)).await.err().unwrap()
}

fn request(selector: Value) -> Value {
    json!({"txs": ["0x02"], "blockNumber": "0xffff", "stateBlockNumber": selector})
}

#[tokio::test]
async fn bundle_routes_configuration_and_pins_the_numeric_state_selector() {
    let router = router();
    let bundle = request(json!("safe"));
    let route = route_ok(&router, "eth_callBundle", json!([bundle])).await;
    assert_eq!(route.era, 0);
    assert_eq!(route.params.0, json!([request(json!("0x1"))]));

    let mut bundle = request(json!("0x2"));
    bundle["timestamp"] = json!("0x62");
    let route = route_ok(&router, "eth_callBundle", json!({"request": bundle})).await;
    assert_eq!(route.era, 0);
    assert_eq!(route.params.0, json!({"request": bundle}));

    let route = route_ok(&router, "eth_callBundle", json!([request(json!("latest"))])).await;
    assert_eq!(route.era, 1);
    assert_eq!(route.params.0[0]["stateBlockNumber"], "0x3");

    let params = json!([request(json!("pending"))]);
    let route = route_ok(&router, "eth_callBundle", params.clone()).await;
    assert_eq!(route.era, 1);
    assert_eq!(route.params.0, params);
}

#[tokio::test]
async fn bundle_rejects_generated_and_explicit_timestamp_crossings() {
    let router = router();
    for (selector, timestamp) in [
        ("0x2", None),
        ("0x1", Some("0x64")),
        ("latest", Some("0x63")),
        ("pending", Some("0x63")),
    ] {
        let mut bundle = request(json!(selector));
        if let Some(timestamp) = timestamp {
            bundle["timestamp"] = json!(timestamp);
        }
        let error = route_err(&router, "eth_callBundle", json!([bundle])).await;
        assert_eq!(error.code(), -32004);
    }
}

#[tokio::test]
async fn bundle_rejects_block_id_objects_and_timestamp_overflow() {
    let router = router();
    for selector in [
        json!({"blockNumber":"0x1"}),
        json!({"blockHash":format!("0x{}", "11".repeat(32))}),
        Value::Null,
        json!("0x4"),
    ] {
        assert_eq!(
            route_err(&router, "eth_callBundle", json!([request(selector)]))
                .await
                .code(),
            -32602
        );
    }
}

#[tokio::test]
async fn optional_execution_methods_cannot_bypass_era_policy() {
    let router = router();
    for method in [
        "eth_futureExecution",
        "tempo_futureExecution",
        "ots_getContractCreator",
    ] {
        assert!(is_execution_method(method), "{method}");
        assert_eq!(route_err(&router, method, json!([])).await.code(), -32004);
    }
    for method in [
        "mev_simBundle",
        "reth_getBlockExecutionOutcome",
        "ots_getInternalOperations",
        "ots_getTransactionError",
        "ots_traceTransaction",
    ] {
        assert!(is_execution_method(method), "{method}");
    }
    for method in [
        "debug_chainConfig",
        "debug_dbGet",
        "debug_storageRangeAt",
        "reth_getBalanceChangesInBlock",
        "ots_hasCode",
        "ots_getBlockDetails",
        "tempo_executionInfo",
        "eth_sendRawTransactionConditional",
    ] {
        assert!(!is_execution_method(method), "{method}");
    }
}

#[tokio::test]
async fn ots_transaction_methods_resolve_the_replayed_transaction() {
    let router = router();
    for method in [
        "ots_getInternalOperations",
        "ots_getTransactionError",
        "ots_traceTransaction",
    ] {
        let old = route_ok(&router, method, json!({"tx_hash":"old"})).await;
        assert_eq!(old.era, 0);
        assert_eq!(old.params.0["tx_hash"], "old");
        let live = route_ok(&router, method, json!(["live"])).await;
        assert_eq!(live.era, 1);
    }
}

#[tokio::test]
async fn reth_execution_ranges_use_canonical_heights_and_stop_at_the_head() {
    let router = router();
    let old = route_ok(
        &router,
        "reth_getBlockExecutionOutcome",
        json!(["0x1", "0x2"]),
    )
    .await;
    assert_eq!(old.era, 0);
    let error = route_err(
        &router,
        "reth_getBlockExecutionOutcome",
        json!(["0x1", "0x3"]),
    )
    .await;
    assert_eq!(error.code(), -32004);
    let live = route_ok(
        &router,
        "reth_getBlockExecutionOutcome",
        json!({"blockId":"latest", "count":"0x80"}),
    )
    .await;
    assert_eq!(live.era, 1);
    assert_eq!(live.params.0["count"], "0x80");
    let side_hash = json!({"blockHash":format!("0x{:064x}", 5), "requireCanonical":true});
    let side = route_ok(
        &router,
        "reth_getBlockExecutionOutcome",
        json!([side_hash.clone()]),
    )
    .await;
    assert_eq!(side.era, 0);
    assert_eq!(side.params.0[0], side_hash);
    for count in ["0x0", "0x81"] {
        assert_eq!(
            route_err(
                &router,
                "reth_getBlockExecutionOutcome",
                json!(["0x1", count])
            )
            .await
            .code(),
            -32602
        );
    }
    for selector in ["0x0", "pending"] {
        assert_eq!(
            route_ok(
                &router,
                "reth_getBlockExecutionOutcome",
                json!([selector, "0x80"])
            )
            .await
            .era,
            1
        );
    }
}

#[tokio::test]
async fn mev_bundle_checks_generated_and_flattened_override_timestamps() {
    let router = router();
    let request = json!([{}, {"parentBlock":"safe", "time":"0x62"}]);
    let old = route_ok(&router, "mev_simBundle", request).await;
    assert_eq!(old.era, 0);
    assert_eq!(
        old.params.0[1]["parentBlock"]["blockHash"],
        format!("0x{:064x}", 1)
    );
    let live = route_ok(
        &router,
        "mev_simBundle",
        json!({"bundle":{}, "sim_overrides":{}}),
    )
    .await;
    assert_eq!(live.era, 1);
    for overrides in [
        json!({"parentBlock":"0x2"}),
        json!({"parentBlock":"0x2", "time":"0x62"}),
        json!({"parentBlock":"0x1", "timestamp":"0x64"}),
        json!({"parentBlock":"pending", "time":"0x63"}),
    ] {
        assert_eq!(
            route_err(&router, "mev_simBundle", json!([{}, overrides]))
                .await
                .code(),
            -32004
        );
    }
    let pending = json!([{}, {"parentBlock":"pending"}]);
    let live = route_ok(&router, "mev_simBundle", pending.clone()).await;
    assert_eq!(live.era, 1);
    assert_eq!(live.params.0, pending);
}
