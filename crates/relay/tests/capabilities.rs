use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy_sol_types::SolValue;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tempo_relay::{
    Backend, Next, Plugin, Relay, Request, RpcError, errors,
    external::{ExternalFeePayers, normalize},
    simulation::{FeeTokens, Simulate, format_units},
};

const TOKEN: Address = address!("20c0000000000000000000000000000000000000");
const OTHER: Address = address!("20c0000000000000000000000000000000000001");
const SENDER: Address = Address::repeat_byte(0x11);
const RECIPIENT: Address = Address::repeat_byte(0x22);
const VIRTUAL: Address = address!("aabbccddfdfdfdfdfdfdfdfdfdfd112233445566");

#[derive(Default)]
struct Node {
    requests: Mutex<Vec<Request>>,
    logs: Mutex<Vec<Value>>,
    preferred_funded: AtomicBool,
    simulation_failed: AtomicBool,
    fill_failed: AtomicBool,
}

#[async_trait]
impl Backend for Node {
    async fn request(&self, request: Request) -> Result<Value, RpcError> {
        self.requests.lock().unwrap().push(request.clone());
        match request.method.as_str() {
            "eth_fillTransaction" => {
                if self.fill_failed.load(Ordering::SeqCst) {
                    return Err(RpcError {
                        code: 3,
                        message: "execution reverted".into(),
                        data: Some(json!(Bytes::copy_from_slice(
                            &keccak256("UnauthorizedCaller()")[..4]
                        ))),
                    });
                }
                let mut transaction = request.params[0].clone();
                transaction["gas"] = json!("0x186a0");
                transaction["maxFeePerGas"] = json!("0x5");
                transaction["nonce"] = json!("0x0");
                transaction["chainId"] = json!("0x539");
                Ok(json!({"tx": transaction}))
            }
            "eth_call" => {
                let data: Bytes =
                    serde_json::from_value(request.params[0]["data"].clone()).unwrap();
                if request.params[0].get("to").is_none() {
                    let code: Bytes = include_str!("../src/preflight.hex").trim().parse().unwrap();
                    let (_, _, tokens, _, masters) =
                        <(
                            Address,
                            Address,
                            Vec<Address>,
                            Address,
                            Vec<alloy_primitives::FixedBytes<4>>,
                        )>::abi_decode_params(&data[code.len()..])
                        .unwrap();
                    let balances = tokens
                        .iter()
                        .map(|token| {
                            if *token == OTHER {
                                U256::from(10)
                            } else {
                                U256::from(1)
                            }
                        })
                        .collect::<Vec<_>>();
                    return Ok(json!(Bytes::from(
                        (
                            TOKEN,
                            U256::from(u8::from(self.preferred_funded.load(Ordering::SeqCst))),
                            balances,
                            true,
                            vec![RECIPIENT; masters.len()]
                        )
                            .abi_encode_params()
                    )));
                }
                let encoded = if data == keccak256("name()")[..4] {
                    "Path USD".to_string().abi_encode()
                } else if data == keccak256("symbol()")[..4] {
                    "USD".to_string().abi_encode()
                } else {
                    U256::from(6).abi_encode()
                };
                Ok(json!(Bytes::from(encoded)))
            }
            "tempo_simulateV1" => {
                if self.simulation_failed.load(Ordering::SeqCst) {
                    return Err(RpcError::new(-32000, "Unavailable"));
                }
                Ok(
                    json!({"blocks": [{"calls": [{"logs": self.logs.lock().unwrap().clone()}]}], "tokenMetadata": {format!("{TOKEN:#x}"): {"name": "Path USD", "symbol": "USD"}}}),
                )
            }
            _ => Ok(Value::Null),
        }
    }
}

fn fill(token: bool, target: Address) -> Request {
    let mut transaction =
        json!({"from": SENDER, "calls": [{"to": target, "data": "0x"}], "feePayer": false});
    if token {
        transaction["feeToken"] = json!(TOKEN);
    }
    Request::new("eth_fillTransaction", vec![transaction])
}

fn event(name: &str, from: Address, to: Address, amount: u64) -> Value {
    json!({"address": TOKEN, "topics": [keccak256(name), B256::from(from.into_word()), B256::from(to.into_word())], "data": Bytes::from(U256::from(amount).to_be_bytes::<32>().to_vec())})
}

#[tokio::test]
async fn fee_selection_prefers_funded_preference_then_liquid_balance_and_resolves_virtual_targets()
{
    let node = Arc::new(Node::default());
    let relay = Relay::new(node.clone())
        .with_plugin(FeeTokens::new(node.clone(), vec![TOKEN, OTHER]).unwrap())
        .with_plugin(Simulate::new(1337, None));
    let result = relay.handle(fill(false, VIRTUAL)).await.unwrap();
    assert_eq!(result["tx"]["feeToken"], json!(OTHER));
    assert_eq!(
        result["capabilities"]["virtualAddresses"][format!("{VIRTUAL:#x}")],
        json!(RECIPIENT)
    );
    node.preferred_funded.store(true, Ordering::SeqCst);
    let result = relay.handle(fill(false, RECIPIENT)).await.unwrap();
    assert_eq!(result["tx"]["feeToken"], json!(TOKEN));
    assert_eq!(result["capabilities"]["sponsored"], false);
}

#[tokio::test]
async fn simulation_nets_transfers_and_keeps_final_allowance_exposure() {
    let node = Arc::new(Node::default());
    *node.logs.lock().unwrap() = vec![
        event(
            "Transfer(address,address,uint256)",
            SENDER,
            RECIPIENT,
            2_000_000,
        ),
        event(
            "Transfer(address,address,uint256)",
            RECIPIENT,
            SENDER,
            500_000,
        ),
        event(
            "Approval(address,address,uint256)",
            SENDER,
            RECIPIENT,
            9_000_000,
        ),
        event(
            "Approval(address,address,uint256)",
            SENDER,
            RECIPIENT,
            1_000_000,
        ),
    ];
    let relay = Relay::new(node.clone()).with_plugin(Simulate::new(1337, None));
    let result = relay.handle(fill(true, TOKEN)).await.unwrap();
    assert_eq!(
        result["capabilities"]["balanceDiffs"],
        json!({format!("{SENDER:#x}"): [{"address": TOKEN, "decimals": 6, "name": "Path USD", "symbol": "USD", "direction": "outgoing", "formatted": "2.5", "recipients": [RECIPIENT], "value": "0x2625a0"}]})
    );
    assert_eq!(
        result["capabilities"]["fee"],
        json!({"amount": "0x1", "decimals": 6, "formatted": "0.000001", "symbol": "USD"})
    );
    node.simulation_failed.store(true, Ordering::SeqCst);
    let fallback = relay.handle(fill(true, TOKEN)).await.unwrap();
    assert!(fallback["capabilities"].get("balanceDiffs").is_none());
    assert_eq!(
        fallback["capabilities"]["fee"],
        result["capabilities"]["fee"]
    );
    assert_eq!(format_units(U256::from(1_010_000), 6), "1.01");
}

#[tokio::test]
async fn execution_previews_are_opt_in_and_do_not_hide_transport_errors() {
    let node = Arc::new(Node::default());
    node.fill_failed.store(true, Ordering::SeqCst);
    let relay = Relay::new(node).with_plugin(Simulate::new(1337, None));
    assert_eq!(relay.handle(fill(true, TOKEN)).await.unwrap_err().code, 3);
    let mut request = fill(true, TOKEN);
    request.params[0]["capabilities"] = json!({"errors": true});
    let result = relay.handle(request).await.unwrap();
    assert_eq!(
        result["capabilities"]["error"]["errorName"],
        "UnauthorizedCaller"
    );
    assert_eq!(result["tx"]["gas"], "0x0");
    assert_eq!(result["capabilities"]["sponsored"], false);
    assert!(!errors::is_execution(&RpcError::new(
        -32603,
        "Connection refused"
    )));
}

#[tokio::test]
async fn external_fee_payers_are_allowlisted_and_skip_local_forwarding() {
    let upstream = Arc::new(Node::default());
    let remote = Arc::new(Node::default());
    let relay = Relay::new(upstream.clone()).with_plugin(
        ExternalFeePayers::new(false)
            .allow("https://sponsor.example/rpc", remote.clone())
            .unwrap(),
    );
    let mut request = fill(true, TOKEN);
    request.params[0]["feePayer"] = json!("https://sponsor.example/rpc#ignored");
    relay.handle(request.clone()).await.unwrap();
    assert!(upstream.requests.lock().unwrap().is_empty());
    assert_eq!(
        remote.requests.lock().unwrap()[0].params[0]["feePayer"],
        true
    );
    request.params[0]["feePayer"] = json!("https://unlisted.example/");
    assert_eq!(relay.handle(request).await.unwrap_err().code, -32602);
    for url in [
        "http://public.example",
        "https://localhost",
        "https://10.0.0.1",
        "https://[::1]",
        "https://[::ffff:127.0.0.1]",
        "file:///tmp/test",
    ] {
        assert!(normalize(url, false).is_err(), "{url}");
    }
    assert_eq!(
        normalize(
            "https://user:password@Sponsor.example:443/rpc#fragment",
            false
        )
        .unwrap(),
        "https://sponsor.example/rpc"
    );
}

struct Slow;
#[async_trait]
impl Plugin for Slow {
    async fn handle(&self, request: Request, next: Next<'_>) -> Result<Value, RpcError> {
        tokio::time::sleep(Duration::from_secs(1)).await;
        next.run(request).await
    }
}

#[tokio::test]
async fn complete_fill_deadline_bounds_plugin_work() {
    let relay = Relay::new(Arc::new(Node::default()))
        .with_plugin(Slow)
        .with_fill_timeout(Duration::from_millis(10));
    assert_eq!(
        relay.handle(fill(true, TOKEN)).await.unwrap_err().message,
        "Relay fill deadline exceeded"
    );
}

#[tokio::test]
async fn chain_router_rejects_conflicting_and_unconfigured_chains() {
    let node = Arc::new(Node::default());
    let router = tempo_relay::chains::ChainRouter::default()
        .with_chain(1337, Relay::new(node))
        .unwrap()
        .with_default(1337)
        .unwrap();
    let mut request = fill(true, TOKEN);
    request.params[0]["chainId"] = json!("0x539");
    assert!(router.handle(request.clone(), None).await.is_ok());
    assert_eq!(
        router
            .handle(request.clone(), Some(42431))
            .await
            .unwrap_err()
            .message,
        "Conflicting chain IDs"
    );
    request.params[0]["chainId"] = json!("0xa5bf");
    assert_eq!(
        router.handle(request, None).await.unwrap_err().message,
        "Chain is not configured"
    );
}

#[cfg(feature = "http")]
#[tokio::test]
async fn external_transport_does_not_follow_redirects() {
    use axum::{Router, http::StatusCode, response::Redirect, routing::post};
    use std::sync::atomic::AtomicUsize;
    let followed = Arc::new(AtomicUsize::new(0));
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_url = format!("http://{}", target.local_addr().unwrap());
    let counter = followed.clone();
    let target_server = tokio::spawn(async move {
        axum::serve(
            target,
            Router::new().route(
                "/",
                post(move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let redirect = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_url = format!("http://{}", redirect.local_addr().unwrap());
    let redirect_server = tokio::spawn(async move {
        axum::serve(
            redirect,
            Router::new().route(
                "/",
                post(move || {
                    let url = target_url.clone();
                    async move { Redirect::temporary(&url) }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let backend = tempo_relay::http::HttpBackend::new(&redirect_url).unwrap();
    assert!(
        backend
            .request(Request::new("eth_chainId", vec![]))
            .await
            .is_err()
    );
    assert_eq!(followed.load(Ordering::SeqCst), 0);
    redirect_server.abort();
    target_server.abort();
}

#[test]
fn error_capabilities_decode_arguments_builtins_and_human_readable_names() {
    let data = Bytes::from(
        [
            &keccak256("InsufficientBalance(uint256,uint256,address)")[..4],
            &(U256::from(1), U256::from(10), TOKEN).abi_encode_params(),
        ]
        .concat(),
    );
    let error = errors::decode(&RpcError {
        code: 3,
        message: "execution reverted".into(),
        data: Some(json!({"error": {"data": data}})),
    });
    assert_eq!(error.rpc["errorName"], "InsufficientBalance");
    assert_eq!(
        error.rpc["message"],
        "Insufficient balance. Required: 10, available: 1."
    );
    let data = Bytes::from(
        [
            &keccak256("Error(string)")[..4],
            &"failed".to_string().abi_encode(),
        ]
        .concat(),
    );
    let error = errors::decode(&RpcError {
        code: 3,
        message: "EXECUTION REVERTED: failed".into(),
        data: Some(json!(data)),
    });
    assert_eq!(error.rpc["errorName"], "Error");
    assert_eq!(error.rpc["message"], "failed");
    let error = errors::decode(&RpcError::new(
        3,
        "execution reverted: UnauthorizedCaller()",
    ));
    assert_eq!(
        error.rpc,
        json!({"errorName": "unknown", "message": "Unauthorized caller."})
    );
}
