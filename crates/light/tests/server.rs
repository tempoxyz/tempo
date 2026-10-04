#![cfg(feature = "rpc-server")]

mod common;
use serde_json::{Value, json};
use tempo_light::{client::Client, config::Limits, server};

#[tokio::test]
async fn local_service_is_read_only_latest_only_and_loopback_default() {
    let directory = tempfile::tempdir().unwrap();
    let client = Client::open(
        common::checkpoint().network,
        vec!["http://127.0.0.1:1".parse().unwrap()],
        directory.path(),
        Limits::default(),
    )
    .unwrap();
    assert!(matches!(
        server::serve(client.clone(), "0.0.0.0:0".parse().unwrap(), false).await,
        Err(server::Error::RemoteAccess)
    ));
    let (handle, address) = server::serve(client, "127.0.0.1:0".parse().unwrap(), false)
        .await
        .unwrap();
    let http = reqwest::Client::new();
    let url = format!("http://{address}");
    let cases = [
        ("eth_sendRawTransaction", json!(["0x"]), -32601),
        ("eth_call", json!([]), -32601),
        ("light_status", json!(["latest"]), -32602),
        (
            "light_readVerified",
            json!([[{"kind":"balance", "token":"0x20c0000000000000000000000000000000000001", "holder":"0x0000000000000000000000000000000000000000", "blockHash":"0x00"}]]),
            -32602,
        ),
        ("light_readVerified", json!([[]]), -32602),
        (
            "light_readVerified",
            json!([[{"kind":"balance", "token":"0x20c0000000000000000000000000000000000001", "holder":"0x0000000000000000000000000000000000000000"}]]),
            -32012,
        ),
    ];
    for (method, params, code) in cases {
        let response: Value = http
            .post(&url)
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response["error"]["code"], code, "{response}");
        assert!(response.get("result").is_none());
    }
    let status: Value = http
        .post(&url)
        .json(&json!({"jsonrpc":"2.0", "id":1, "method":"light_status", "params":[]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["result"]["durable"], false);
    assert_eq!(status["result"]["head"], Value::Null);
    handle.stop().unwrap();
    handle.stopped().await;
}
