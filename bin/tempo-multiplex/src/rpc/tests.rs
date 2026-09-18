use super::*;
use axum::{Router, routing::post};
use std::sync::Mutex;

#[derive(Clone)]
struct Mock {
    name: &'static str,
    calls: Arc<Mutex<Vec<Value>>>,
}

async fn mock(State(mock): State<Mock>, Json(request): Json<Value>) -> Json<Value> {
    mock.calls.lock().unwrap().push(request.clone());
    let params = &request["params"];
    let result = match request["method"].as_str().unwrap() {
        "eth_chainId" => json!("0x539"),
        "tempo_executionRules" => json!({"fixed":true,"protocol":"T11"}),
        "eth_getBlockByNumber" => {
            let number = match params[0].as_str().unwrap() {
                "latest" => 20,
                "safe" | "finalized" => 8,
                "earliest" => 0,
                _ => quantity(&params[0]).unwrap(),
            };
            json!({"number":format!("0x{number:x}"),"hash":format!("0x{number:064x}"),"backend":mock.name})
        }
        "eth_getBlockByHash" => {
            let n = u64::from_str_radix(&params[0].as_str().unwrap()[2..], 16).unwrap();
            json!({"number":format!("0x{n:x}"), "hash":params[0], "backend":mock.name})
        }
        "eth_getTransactionReceipt" => {
            let number = match params[0].as_str().unwrap().chars().last().unwrap() {
                '1' => 9,
                '2' => 10,
                _ => return Json(json!({"jsonrpc":"2.0","id":1,"result":null})),
            };
            json!({"blockNumber":format!("0x{number:x}"),"backend":mock.name})
        }
        "eth_getLogs" => {
            if params[0].get("blockHash").is_some() {
                json!([{"backend":mock.name}])
            } else {
                let from = quantity(&params[0]["fromBlock"]).unwrap();
                let to = quantity(&params[0]["toBlock"]).unwrap();
                json!(
                    (from..=to)
                        .map(|n| json!({"blockNumber":format!("0x{n:x}"),"backend":mock.name}))
                        .collect::<Vec<_>>()
                )
            }
        }
        "eth_feeHistory" => {
            let count = quantity(&params[0]).unwrap();
            let newest = quantity(&params[1]).unwrap();
            let oldest = newest - count + 1;
            json!({
                "oldestBlock":format!("0x{oldest:x}"),
                "baseFeePerGas":(oldest..=newest+1).map(|n| format!("0x{n:x}")).collect::<Vec<_>>(),
                "gasUsedRatio":vec![0.5; count as usize],
                "reward":vec![vec!["0x1"]; count as usize],
            })
        }
        "eth_call" if params[0].get("revert").is_some() => {
            return Json(
                json!({"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":"0xdead"}}),
            );
        }
        _ => json!({"backend":mock.name,"params":params}),
    };
    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
}

async fn setup() -> (Rpc, Vec<tokio::task::JoinHandle<()>>, [Mock; 2]) {
    let mut urls = Vec::new();
    let mut tasks = Vec::new();
    let mocks = [
        Mock {
            name: "v1",
            calls: Default::default(),
        },
        Mock {
            name: "v2",
            calls: Default::default(),
        },
    ];
    for mock in &mocks {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        urls.push(format!("http://{}", listener.local_addr().unwrap()));
        let app = Router::new()
            .route("/", post(self::mock))
            .with_state(mock.clone());
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
    }
    let rpc = Rpc {
        client: reqwest::Client::new(),
        urls: urls.try_into().unwrap(),
        cutover: 10,
        parent_hash: format!("0x{:064x}", 9),
        inflight: Arc::new(Semaphore::new(64)),
    };
    (rpc, tasks, mocks)
}

#[tokio::test]
async fn routes_boundary_tags_hashes_and_transactions() {
    let (rpc, tasks, _) = setup().await;
    for (selector, expected) in [
        (json!("0x9"), "v1"),
        (json!("0xa"), "v2"),
        (json!("earliest"), "v1"),
        (json!("latest"), "v2"),
        (json!("pending"), "v2"),
        (json!("safe"), "v1"),
        (json!({"blockNumber":"0x9"}), "v1"),
        (
            json!({"blockHash":format!("0x{:064x}", 9),"requireCanonical":true}),
            "v1",
        ),
    ] {
        let result = rpc.route("eth_call", &[json!({}), selector]).await.unwrap();
        assert_eq!(result["backend"], expected);
    }
    for (number, expected) in [(9, "v1"), (10, "v2")] {
        let result = rpc
            .route(
                "debug_traceBlockByHash",
                &[json!(format!("0x{number:064x}"))],
            )
            .await
            .unwrap();
        assert_eq!(result["backend"], expected);
    }
    for (tx, expected) in [(1, "v1"), (2, "v2"), (3, "v2")] {
        let result = rpc
            .route("debug_traceTransaction", &[json!(format!("0x{tx:064x}"))])
            .await
            .unwrap();
        assert_eq!(result["backend"], expected);
    }
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn splits_ranges_without_duplicates_and_merges_fee_history() {
    let (rpc, tasks, _) = setup().await;
    let logs = rpc
        .route(
            "eth_getLogs",
            &[json!({"fromBlock":"0x8","toBlock":"0xb","topics":[]})],
        )
        .await
        .unwrap();
    assert_eq!(logs.as_array().unwrap().len(), 4);
    assert_eq!(logs[1]["blockNumber"], "0x9");
    assert_eq!(logs[1]["backend"], "v1");
    assert_eq!(logs[2]["blockNumber"], "0xa");
    assert_eq!(logs[2]["backend"], "v2");
    let fees = rpc
        .route("eth_feeHistory", &[json!("0x4"), json!("0xb"), json!([50])])
        .await
        .unwrap();
    assert_eq!(fees["oldestBlock"], "0x8");
    assert_eq!(
        fees["baseFeePerGas"],
        json!(["0x8", "0x9", "0xa", "0xb", "0xc"])
    );
    assert_eq!(fees["gasUsedRatio"].as_array().unwrap().len(), 4);
    assert_eq!(fees["reward"].as_array().unwrap().len(), 4);
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn preserves_ids_revert_data_notifications_and_write_destination() {
    let (rpc, tasks, mocks) = setup().await;
    let response = rpc.request(json!({"jsonrpc":"2.0","id":"my-id","method":"eth_call","params":[{"revert":true},"0x9"]})).await.unwrap();
    assert_eq!(response["id"], "my-id");
    assert_eq!(
        response["error"],
        json!({"code":3,"message":"execution reverted","data":"0xdead"})
    );
    assert!(
        rpc.request(json!({"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x1234"]}))
            .await
            .is_none()
    );
    let v1_writes = mocks[0]
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c["method"] == "eth_sendRawTransaction")
        .count();
    let v2_writes = mocks[1]
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c["method"] == "eth_sendRawTransaction")
        .count();
    assert_eq!((v1_writes, v2_writes), (0, 1));
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn refuses_mismatched_checkpoint_and_unsupported_methods() {
    let (mut rpc, tasks, _) = setup().await;
    rpc.wait_ready().await.unwrap();
    rpc.parent_hash = format!("0x{:064x}", 8);
    assert!(rpc.wait_ready().await.is_err());
    assert_eq!(
        rpc.route("debug_setHead", &[json!("0x0")])
            .await
            .unwrap_err()["code"],
        -32601
    );
    assert!(
        rpc.route(
            "eth_getLogs",
            &[json!({"blockHash":format!("0x{:064x}",9),"fromBlock":"0x0"})]
        )
        .await
        .is_err()
    );
    for task in tasks {
        task.abort();
    }
}

#[tokio::test]
async fn serves_mixed_http_batches_and_parse_errors() {
    let (rpc, tasks, _) = setup().await;
    let body = json!([
        {"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{},"0x9"]},
        {"jsonrpc":"2.0","id":2,"method":"eth_call","params":[{},"0xa"]},
        {"jsonrpc":"2.0","method":"eth_chainId"},
        17
    ]);
    let response = handle(State(rpc.clone()), Bytes::from(body.to_string())).await;
    let bytes = axum::body::to_bytes(response.into_body(), 10000)
        .await
        .unwrap();
    let batch: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(batch.as_array().unwrap().len(), 3);
    assert_eq!(batch[0]["result"]["backend"], "v1");
    assert_eq!(batch[1]["result"]["backend"], "v2");
    assert_eq!(batch[2]["error"]["code"], -32600);
    let response = handle(State(rpc), Bytes::from_static(b"{")).await;
    let bytes = axum::body::to_bytes(response.into_body(), 10000)
        .await
        .unwrap();
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["error"]["code"], -32700);
    for task in tasks {
        task.abort();
    }
}

#[test]
fn rejects_malformed_quantities() {
    for bad in [
        json!("1"),
        json!("0x"),
        json!("0x00"),
        json!("0x10000000000000000"),
        json!(-1),
    ] {
        assert!(quantity(&bad).is_err());
    }
}
