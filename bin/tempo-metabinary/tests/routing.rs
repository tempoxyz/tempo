//! Routing policy and selector rewriting, using one execution-independent metadata fixture.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

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

struct Blocks {
    live: usize,
    resolutions: AtomicUsize,
}

impl Backend for Blocks {
    fn resolve<'a>(
        &'a self,
        method: &'a str,
        params: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Value>> {
        Box::pin(async move {
            let selector = params.0[0].as_str().unwrap();
            let value = if method == "eth_getTransactionByHash" {
                json!({"blockHash":hash(if selector == "live" {3} else {1})})
            } else {
                self.resolutions.fetch_add(1, Ordering::Relaxed);
                let number = match selector {
                    "earliest" => 0,
                    "safe" | "finalized" => 1,
                    "latest" => {
                        if self.live == 1 {
                            3
                        } else {
                            7
                        }
                    }
                    other => u64::from_str_radix(&other[2..], 16).unwrap(),
                };
                // Reth replay by hash uses canonical height, even if the side-chain timestamp differs.
                let (height, timestamp) = if method == "eth_getBlockByHash" && number == 5 {
                    (2, 150)
                } else {
                    (
                        number,
                        [0, 50, 99, 110, u64::MAX, 150, 200, 210][number as usize],
                    )
                };
                json!({"number":format!("0x{height:x}"), "hash":hash(number), "timestamp":format!("0x{timestamp:x}")})
            };
            Ok(value)
        })
    }
}

struct Fixture {
    router: Router,
    backend: Arc<Blocks>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_eras(2)
    }

    fn with_eras(count: usize) -> Self {
        let backend = Arc::new(Blocks {
            live: count - 1,
            resolutions: AtomicUsize::new(0),
        });
        let eras: Vec<_> = (0..count)
            .map(|index| {
                json!({
                    "name":format!("era{index}"), "start_timestamp":index * 100,
                    "binary":if index + 1 == count { None } else { Some("/unused/frozen") }
                })
            })
            .collect();
        let router = Router::new(
            serde_json::from_value(json!({"chain_id":"0x1", "genesis_hash":hash(0), "eras":eras}))
                .unwrap(),
            backend.clone(),
        )
        .unwrap();
        Self { router, backend }
    }

    async fn era(&self, method: &str, params: Value) -> usize {
        self.router
            .route(method, RpcParams(params))
            .await
            .unwrap()
            .era
    }

    async fn check(&self, method: &str, params: Value, era: usize, expected: Value) {
        assert_eq!(
            routed(&self.router, method, params, era).await,
            expected,
            "{method}"
        );
    }
}

fn router() -> Router {
    Fixture::new().router
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
#[tokio::test]
async fn debug_subscriptions_guard_the_included_range() {
    let f = Fixture::new();
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
    let f = Fixture::new();
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
        assert_eq!(f.era(method, params).await, era, "{method}");
    }
}

#[tokio::test]
async fn simulations_ranges_and_overrides_stay_in_one_era() {
    let f = Fixture::new();
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
    f.backend.resolutions.store(0, Ordering::Relaxed);
    f.check(
        "trace_filter",
        json!([{}]),
        1,
        json!([{"fromBlock":"0x3", "toBlock":"0x3"}]),
    )
    .await;
    assert_eq!(f.backend.resolutions.load(Ordering::Relaxed), 1);
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
        assert_eq!(f.era(method, params).await, era, "{method}");
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
        reject(&f.router, method, params, -32004).await;
    }
}

#[tokio::test]
async fn supports_three_eras() {
    let f = Fixture::with_eras(3);
    for (number, era) in [(1, 0), (3, 1), (6, 2)] {
        assert_eq!(
            f.era("eth_call", json!([{}, format!("0x{number:x}")]))
                .await,
            era
        );
    }
}
