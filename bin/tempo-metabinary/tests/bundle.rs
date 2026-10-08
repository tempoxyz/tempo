//! Bundle configuration and generated/overridden timestamps must stay in one executable's era.
use std::{collections::HashSet, sync::Arc};

use futures::future::BoxFuture;
use jsonrpsee::core::RpcResult;
use serde_json::{Value, json};
use tempo_metabinary::{
    handshake::EXECUTION_INFO_METHOD,
    routing::{Backend, Router, RpcParams, is_execution_method},
};

fn hash(number: u64) -> String {
    format!("0x{number:064x}")
}

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
            let selector = params.0[0].as_str().unwrap();
            let (number, timestamp) = match (method, selector) {
                ("eth_getTransactionByHash", _) => {
                    return Ok(json!({"blockHash":hash(if selector == "old" {1} else {3})}));
                }
                ("eth_getHeaderByHash", _) => {
                    match u64::from_str_radix(&selector[2..], 16).unwrap() {
                        1 => (1, 50),
                        3 => (3, 110),
                        // The side-chain timestamp differs, but Reth replays canonical height 2.
                        5 => (2, 150),
                        _ => panic!("unexpected hash {selector}"),
                    }
                }
                ("eth_getHeaderByNumber", "0x0") => (0, 0),
                ("eth_getHeaderByNumber", "safe" | "0x1") => (1, 50),
                ("eth_getHeaderByNumber", "0x2") => (2, 99),
                ("eth_getHeaderByNumber", "latest" | "0x3") => (3, 110),
                ("eth_getHeaderByNumber", "0x4") => (4, u64::MAX),
                _ => panic!("unexpected {method} {selector}"),
            };
            let hash = if method == "eth_getHeaderByHash" {
                selector.to_owned()
            } else {
                hash(number)
            };
            Ok(
                json!({"number":format!("0x{number:x}"), "hash":hash, "timestamp":format!("0x{timestamp:x}")}),
            )
        })
    }
}

fn router() -> Router {
    Router::with_backend(
        serde_json::from_value(json!({"chain_id":"0x1", "genesis_hash":hash(0), "eras":[
            {"name":"old", "start_timestamp":0, "binary":"/unused/frozen"},
            {"name":"live", "start_timestamp":100}
        ]}))
        .unwrap(),
        Arc::new(Blocks),
        HashSet::new(),
    )
    .unwrap()
}

async fn routed(router: &Router, method: &str, params: Value, era: usize) -> Value {
    assert!(is_execution_method(method), "{method}");
    let route = router.route(method, RpcParams(params)).await.unwrap();
    assert_eq!(route.era, era, "{method}");
    route.params.0
}

async fn reject(router: &Router, method: &str, params: Value, code: i32) {
    let error = router.route(method, RpcParams(params)).await.err().unwrap();
    assert_eq!(error.code(), code, "{method}");
}

fn request(selector: &str) -> Value {
    json!({"txs":["0x02"], "blockNumber":"0xffff", "stateBlockNumber":selector})
}

#[tokio::test]
async fn bundle_pins_numeric_state_and_rejects_invalid_or_crossing_timestamps() {
    let router = router();
    for (selector, pinned, era) in [
        ("safe", "0x1", 0),
        ("latest", "0x3", 1),
        ("pending", "pending", 1),
    ] {
        assert_eq!(
            routed(&router, "eth_callBundle", json!([request(selector)]), era).await,
            json!([request(pinned)])
        );
    }
    let mut bundle = request("0x2");
    bundle["timestamp"] = json!("0x62");
    let named = json!({"request":bundle});
    assert_eq!(
        routed(&router, "eth_callBundle", named.clone(), 0).await,
        named
    );

    for (selector, timestamp, code) in [
        (json!("0x2"), None, -32004),
        (json!("0x1"), Some("0x64"), -32004),
        (json!("latest"), Some("0x63"), -32004),
        (json!("pending"), Some("0x63"), -32004),
        (json!({"blockNumber":"0x1"}), None, -32602),
        (json!({"blockHash":hash(1)}), None, -32602),
        (Value::Null, None, -32602),
        (json!("0x4"), None, -32602),
    ] {
        let mut bundle = request("latest");
        bundle["stateBlockNumber"] = selector;
        if let Some(timestamp) = timestamp {
            bundle["timestamp"] = json!(timestamp);
        }
        reject(&router, "eth_callBundle", json!([bundle]), code).await;
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
        reject(&router, method, json!([]), -32004).await;
    }
    for method in [
        "debug_chainConfig",
        "debug_dbGet",
        "debug_storageRangeAt",
        "reth_getBalanceChangesInBlock",
        "ots_hasCode",
        "ots_getBlockDetails",
        EXECUTION_INFO_METHOD,
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
        for (params, era) in [(json!({"tx_hash":"old"}), 0), (json!(["live"]), 1)] {
            assert_eq!(routed(&router, method, params.clone(), era).await, params);
        }
    }
}

#[tokio::test]
async fn execution_ranges_use_canonical_heights_and_stop_at_the_head() {
    let router = router();
    let side_hash = json!({"blockHash":hash(5), "requireCanonical":true});
    for (params, era, pinned) in [
        (
            json!(["0x1", "0x2"]),
            0,
            json!([{ "blockHash":hash(1)}, "0x2"]),
        ),
        (
            json!({"blockId":"latest", "count":"0x80"}),
            1,
            json!({"blockId":{"blockHash":hash(3)}, "count":"0x80"}),
        ),
        (json!([side_hash]), 0, json!([side_hash])),
        (json!(["0x0", "0x80"]), 1, json!(["0x0", "0x80"])),
        (json!(["pending", "0x80"]), 1, json!(["pending", "0x80"])),
    ] {
        assert_eq!(
            routed(&router, "reth_getBlockExecutionOutcome", params, era).await,
            pinned
        );
    }
    for (count, code) in [("0x3", -32004), ("0x0", -32602), ("0x81", -32602)] {
        reject(
            &router,
            "reth_getBlockExecutionOutcome",
            json!(["0x1", count]),
            code,
        )
        .await;
    }
}

#[tokio::test]
async fn mev_bundle_checks_generated_and_flattened_override_timestamps() {
    let router = router();
    for (params, era, pinned) in [
        (
            json!([{}, {"parentBlock":"safe", "time":"0x62"}]),
            0,
            json!([{}, {"parentBlock":{"blockHash":hash(1)}, "time":"0x62"}]),
        ),
        (
            json!({"bundle":{}, "sim_overrides":{}}),
            1,
            json!({"bundle":{}, "sim_overrides":{"parentBlock":{"blockHash":hash(3)}}}),
        ),
        (
            json!([{}, {"parentBlock":"pending"}]),
            1,
            json!([{}, {"parentBlock":"pending"}]),
        ),
    ] {
        assert_eq!(routed(&router, "mev_simBundle", params, era).await, pinned);
    }
    for overrides in [
        json!({"parentBlock":"0x2"}),
        json!({"parentBlock":"0x2", "time":"0x62"}),
        json!({"parentBlock":"0x1", "timestamp":"0x64"}),
        json!({"parentBlock":"pending", "time":"0x63"}),
    ] {
        reject(&router, "mev_simBundle", json!([{}, overrides]), -32004).await;
    }
}
