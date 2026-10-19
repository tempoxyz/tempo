//! `tempo rpc-only` serving a datadir that a running dev node keeps writing.

use jsonrpsee::{
    core::client::{ClientT as _, SubscriptionClientT as _},
    http_client::HttpClientBuilder,
    rpc_params,
    ws_client::WsClientBuilder,
};
use serde_json::Value;
use std::{
    net::{Ipv4Addr, TcpListener},
    process::Stdio,
    time::Duration,
};
use tokio::process::{Child, Command};

const WAIT: Duration = Duration::from_secs(120);

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn tempo(args: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_tempo"))
        .args(args.split_whitespace())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

/// Waits until the server on `port` reports at least `number` blocks.
async fn wait_for_block(port: u16, number: u64) {
    let client = HttpClientBuilder::default()
        .build(format!("http://127.0.0.1:{port}"))
        .unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            let head = client
                .request::<String, _>("eth_blockNumber", rpc_params![])
                .await;
            if head.is_ok_and(|head| u64::from_str_radix(&head[2..], 16).unwrap() >= number) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("port {port} never reached block {number}"));
}

#[tokio::test(flavor = "multi_thread")]
async fn trace_chain_streams_stored_blocks_over_ws() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path().to_str().unwrap();
    let (node_port, worker_port) = (free_port(), free_port());
    let _node = tempo(&format!(
        "node --dev --dev.block-time 100ms --datadir {datadir} --tempo.bootnodes-endpoint none \
         --disable-discovery --no-persist-peers --ipcdisable --port 0 --authrpc.port 0 --http \
         --http.port {node_port} --engine.persistence-threshold 0 \
         --engine.memory-block-buffer-target 0"
    ));
    wait_for_block(node_port, 5).await;
    let _worker = tempo(&format!(
        "rpc-only --chain dev --datadir {datadir} --port {worker_port}"
    ));
    wait_for_block(worker_port, 3).await;

    let ws = WsClientBuilder::default()
        .build(format!("ws://127.0.0.1:{worker_port}"))
        .await
        .unwrap();
    let params = rpc_params!["traceChain", "0x1", "0x3"];
    let mut subscription = ws
        .subscribe::<Value, _>("debug_subscribe", params, "debug_unsubscribe")
        .await
        .unwrap();
    // Blocks without traces are skipped, except the end block.
    let mut blocks = Vec::new();
    while blocks.last() != Some(&Value::from("0x3")) {
        let item = tokio::time::timeout(WAIT, subscription.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        blocks.push(item["block"].clone());
        assert!(blocks.len() <= 2, "{blocks:?}");
    }
    let next = tokio::time::timeout(Duration::from_millis(500), subscription.next());
    assert!(next.await.is_err(), "the stream ends after the end block");
}
