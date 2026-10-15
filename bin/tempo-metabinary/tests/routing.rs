//! Routing policy and selector rewriting, using one execution-independent metadata fixture.
use futures::future::BoxFuture;
use jsonrpsee::core::RpcResult;
use serde_json::{Value, json, value::RawValue};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tempo_metabinary::routing::{Backend, BlockMetadata, Router, RpcParams, is_execution_method};

struct Fixture {
    router: Router,
    backend: Arc<Blocks>,
}

impl Fixture {
    fn new(count: usize) -> Self {
        let backend = Arc::new(Blocks {
            live: count - 1,
            resolutions: AtomicUsize::new(0),
        });
        let boundaries = (1..count as u64).map(|era| era * 100).collect();
        let router = Router::new(boundaries, backend.clone());
        Self { router, backend }
    }

    async fn era(&self, method: &str, params: Value) -> Result<usize, i32> {
        self.router
            .route(method, RpcParams(params))
            .await
            .map(|(era, _)| era)
            .map_err(|error| error.code())
    }

    async fn check(&self, method: &str, params: Value, era: usize, expected: Value) {
        assert!(is_execution_method(method), "{method}");
        let (actual, params) = self.router.route(method, RpcParams(params)).await.unwrap();
        assert_eq!(actual, era, "{method}");
        assert_eq!(params.0, expected, "{method}");
    }

    async fn reject(&self, method: &str, params: Value, code: i32) {
        assert_eq!(self.era(method, params).await, Err(code), "{method}");
    }
}

struct Blocks {
    live: usize,
    resolutions: AtomicUsize,
}

impl Backend for Blocks {
    fn block<'a>(&'a self, selector: &'a Value) -> BoxFuture<'a, RpcResult<BlockMetadata>> {
        Box::pin(async move {
            let selector = selector
                .get("blockHash")
                .or_else(|| selector.get("blockNumber"))
                .unwrap_or(selector)
                .as_str()
                .unwrap();
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
            let (height, timestamp) = if selector.len() == 66 && number == 5 {
                (2, 150)
            } else {
                (
                    number,
                    [0, 50, 99, 110, u64::MAX, 150, 200, 210][number as usize],
                )
            };
            Ok(BlockMetadata {
                number: height,
                hash: hash(number).parse().unwrap(),
                timestamp,
            })
        })
    }

    fn transaction_timestamp<'a>(
        &'a self,
        hash: &'a Value,
    ) -> BoxFuture<'a, RpcResult<Option<u64>>> {
        Box::pin(async move {
            Ok(match hash.as_str().unwrap() {
                "missing" | "pending" => None,
                "live" => Some(110),
                _ => Some(50),
            })
        })
    }

    fn raw_block_timestamp(&self, _: &RpcParams) -> RpcResult<u64> {
        unreachable!("routing tests use no raw blocks")
    }

    fn forward<'a>(
        &'a self,
        _: usize,
        _: &'a str,
        _: RpcParams,
    ) -> BoxFuture<'a, RpcResult<Box<RawValue>>> {
        unreachable!("routing does not forward")
    }
}

fn hash(number: u64) -> String {
    format!("0x{number:064x}")
}

#[tokio::test]
async fn simulations_and_bundles_require_a_live_base() {
    let f = Fixture::new(2);
    let bundle = |extra: Value| {
        let mut request = json!({"txs":["0x02"], "blockNumber":"0xffff"});
        request
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!([request])
    };
    let call_many = |context: Value, time: Value| json!([[{"transactions":[{}], "blockOverride":{"time":time}}], context]);
    let mut live = vec![
        (
            "eth_callBundle",
            bundle(json!({"stateBlockNumber":"latest"})),
        ),
        (
            "eth_callBundle",
            bundle(json!({"stateBlockNumber":"0x3", "timestamp":"0x6e"})),
        ),
        (
            "eth_callBundle",
            bundle(json!({"stateBlockNumber":"pending"})),
        ),
        ("eth_callBundle", bundle(json!({}))),
        ("mev_simBundle", json!({"bundle":{}, "sim_overrides":{}})),
        ("mev_simBundle", json!([{}, {"parentBlock":"pending"}])),
        (
            "mev_simBundle",
            json!([{}, {"parentBlock":"latest", "timestamp":"0x64"}]),
        ),
    ];
    let mut historical = vec![
        ("eth_callBundle", bundle(json!({"stateBlockNumber":"safe"}))),
        // The generated child would be live, but its base state is historical.
        (
            "eth_callBundle",
            bundle(json!({"stateBlockNumber":"0x2", "timestamp":"0x64"})),
        ),
        (
            "eth_callBundle",
            bundle(json!({"stateBlockNumber":"latest", "timestamp":"0x63"})),
        ),
        (
            "eth_callBundle",
            bundle(json!({"stateBlockNumber":"pending", "timestamp":"0x63"})),
        ),
        ("mev_simBundle", json!([{}, {"parentBlock":"0x2"}])),
        (
            "mev_simBundle",
            json!([{}, {"parentBlock":"pending", "time":"0x63"}]),
        ),
    ];
    for method in ["eth_callMany", "debug_traceCallMany"] {
        live.push((method, call_many(json!({"blockNumber":null}), Value::Null)));
        live.push((
            method,
            call_many(json!({"blockNumber":"pending"}), json!("0x64")),
        ));
        historical.push((method, call_many(json!({"blockNumber":"0x2"}), Value::Null)));
        historical.push((
            method,
            call_many(json!({"blockNumber":"latest"}), json!("0x63")),
        ));
    }
    for (method, payload, block) in [
        ("eth_simulateV1", "opts", "blockNumber"),
        ("tempo_simulateV1", "payload", "block"),
    ] {
        let simulation = |base: &str, time: &str| json!({payload:{"blockStateCalls":[{"blockOverrides":{"time":time},"calls":[{}]}]}, block:base});
        live.push((method, simulation("latest", "0x64")));
        live.push((method, simulation("pending", "0x6e")));
        historical.push((method, simulation("0x2", "0x64")));
        historical.push((method, simulation("latest", "0x63")));
    }
    for (method, params) in live {
        f.check(method, params.clone(), 1, params).await;
    }
    for (method, params) in historical {
        f.reject(method, params, -32004).await;
    }
}

#[tokio::test]
async fn optional_execution_methods_cannot_bypass_era_policy() {
    let f = Fixture::new(2);
    for method in [
        "eth_futureExecution",
        "tempo_futureExecution",
        "ots_getContractCreator",
        "ots_futureExecution",
        "reth_futureExecution",
        "testing_buildBlockV1",
        "flashbots_validateBuilderSubmissionV3",
    ] {
        assert!(is_execution_method(method), "{method}");
        f.reject(method, json!([]), -32004).await;
    }
    for method in [
        "debug_chainConfig",
        "debug_dbGet",
        "debug_storageRangeAt",
        "reth_getBalanceChangesInBlock",
        "ots_hasCode",
        "ots_getBlockDetails",
        "erigon_getHeaderByNumber",
        "eth_sendRawTransactionConditional",
        "token_getTokens",
        "miner_setExtra",
        "debug_subscribe",
    ] {
        assert!(!is_execution_method(method), "{method}");
    }
}

#[tokio::test]
async fn ots_transaction_methods_resolve_the_replayed_transaction() {
    let f = Fixture::new(2);
    for method in [
        "ots_getInternalOperations",
        "ots_getTransactionError",
        "ots_traceTransaction",
    ] {
        for (params, era) in [
            (json!({"tx_hash":"old"}), 0),
            (json!(["live"]), 1),
            (json!(["pending"]), 1),
            (json!(["missing"]), 1),
        ] {
            f.check(method, params.clone(), era, params).await;
        }
    }
}

#[tokio::test]
async fn execution_ranges_use_canonical_heights_and_stop_at_the_head() {
    let f = Fixture::new(2);
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
        f.check("reth_getBlockExecutionOutcome", params, era, pinned)
            .await;
    }
    for (count, code) in [("0x3", -32004), ("0x0", -32602), ("0x81", -32602)] {
        f.reject("reth_getBlockExecutionOutcome", json!(["0x1", count]), code)
            .await;
    }
}

#[tokio::test]
async fn debug_subscriptions_guard_the_included_range() {
    let f = Fixture::new(2);
    for (params, expected) in [
        // The exclusive start belongs to the predecessor; all included blocks are live.
        (json!(["traceChain", "0x2", "0x4"]), Ok(1)),
        (
            json!({"subscription":"traceChain", "startExclusive":"0x0", "endInclusive":"0x4"}),
            Err(-32004),
        ),
        (json!(["native-invalid-subscription"]), Ok(1)),
    ] {
        assert_eq!(f.era("debug_subscribe", params).await, expected);
    }
}

#[tokio::test]
async fn execution_routes_and_preserves_native_block_selectors() {
    let f = Fixture::new(2);
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
        assert_eq!(f.era(method, params).await, Ok(era), "{method}");
    }
}

#[tokio::test]
async fn ranges_and_overrides_stay_in_one_era() {
    let f = Fixture::new(2);
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
        assert_eq!(f.era(method, params).await, Ok(era), "{method}");
    }
    for (method, params) in [
        ("eth_call", json!([{}, "0x1", null, {"time":"0x64"}])),
        ("eth_call", json!([{}, "0x1", null, {"timestamp":"0x64"}])),
        ("trace_filter", json!([{"fromBlock":"0x1"}])),
    ] {
        f.reject(method, params, -32004).await;
    }
}

#[tokio::test]
async fn supports_three_eras() {
    let f = Fixture::new(3);
    for (number, era) in [(1, 0), (3, 1), (6, 2)] {
        assert_eq!(
            f.era("eth_call", json!([{}, format!("0x{number:x}")]))
                .await,
            Ok(era)
        );
    }
}
