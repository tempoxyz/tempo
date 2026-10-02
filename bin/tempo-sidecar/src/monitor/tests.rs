use super::*;
use alloy::{primitives::Bytes, sol_types::SolValue, transports::mock::Asserter};
use metrics_exporter_prometheus::PrometheusBuilder;

fn fixture() -> Monitor {
    let a = Address::with_last_byte(1);
    let b = Address::with_last_byte(2);
    Monitor {
        rpc_url: "http://127.0.0.1:1".parse().unwrap(),
        poll_interval: 5,
        tokens: [
            (
                a,
                TIP20Token {
                    decimals: 6,
                    name: "A".into(),
                },
            ),
            (
                b,
                TIP20Token {
                    decimals: 0,
                    name: "B".into(),
                },
            ),
        ]
        .into_iter()
        .collect(),
        pools: Default::default(),
        successful_pairs: Default::default(),
        known_pairs: [(a, b)].into_iter().collect(),
        last_processed_block: 10,
    }
}

fn response(asserter: &Asserter, user: u128, validator: u128) {
    asserter.push_success(&Bytes::from(
        Pool {
            reserveUserToken: user,
            reserveValidatorToken: validator,
        }
        .abi_encode(),
    ));
}

fn exported(handle: &PrometheusHandle, metric: &str) -> Vec<f64> {
    handle
        .render()
        .lines()
        .filter(|line| line.starts_with(&format!("{metric}{{")))
        .map(|line| line.rsplit_once(' ').unwrap().1.parse().unwrap())
        .collect()
}

fn run(test: impl FnOnce(PrometheusHandle)) {
    let recorder = PrometheusBuilder::new()
        .add_global_label("chain_id", "4242")
        .build_recorder();
    let handle = recorder.handle();
    metrics::with_local_recorder(&recorder, || test(handle));
}

#[test]
fn zero_replaces_positive() {
    run(|handle| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut monitor = fixture();
                let mock = Asserter::new();
                let provider = ProviderBuilder::new().connect_mocked_client(mock.clone());
                response(&mock, 2_000_000, 3);
                monitor.update_pools_with_provider(&provider).await.unwrap();
                monitor.update_metrics();
                assert_eq!(
                    exported(&handle, "tempo_fee_amm_user_token_reserves"),
                    vec![2.0]
                );
                response(&mock, 0, 0);
                monitor.update_pools_with_provider(&provider).await.unwrap();
                monitor.update_metrics();
                assert_eq!(
                    exported(&handle, "tempo_fee_amm_user_token_reserves"),
                    vec![0.0]
                );
                assert_eq!(
                    exported(&handle, "tempo_fee_amm_validator_token_reserves"),
                    vec![0.0]
                );
            });
    });
}

#[test]
fn fractional_reserves_are_exported() {
    run(|handle| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut monitor = fixture();
                let mock = Asserter::new();
                let provider = ProviderBuilder::new().connect_mocked_client(mock.clone());
                response(&mock, 1_500_001, 7);
                monitor.update_pools_with_provider(&provider).await.unwrap();
                monitor.update_metrics();
                assert_eq!(
                    exported(&handle, "tempo_fee_amm_user_token_reserves"),
                    vec![1.500001]
                );
                assert_eq!(
                    exported(&handle, "tempo_fee_amm_validator_token_reserves"),
                    vec![7.0]
                );
            });
    });
}

#[test]
fn failure_does_not_prevent_later_pool_observations() {
    run(|handle| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut monitor = fixture();
                let a = Address::with_last_byte(1);
                let b = Address::with_last_byte(2);
                monitor.known_pairs.insert((b, a));
                let mock = Asserter::new();
                let provider = ProviderBuilder::new().connect_mocked_client(mock.clone());
                mock.push_failure_msg("first pool unavailable");
                response(&mock, 2_000_000, 3_000_000);
                let _ = monitor.update_pools_with_provider(&provider).await;
                monitor.update_metrics();
                let values = exported(&handle, "tempo_fee_amm_user_token_reserves");
                assert_eq!(values.len(), 1, "later successful pool must be exported");
                assert!(values[0] == 2.0 || values[0] == 2_000_000.0);
            });
    });
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_secs(seconds)
}

#[test]
fn numeric_boundaries_use_each_tokens_decimals() {
    run(|handle| {
        runtime().block_on(async {
            let mut monitor = fixture();
            let mock = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(mock.clone());
            // Decimal string parsing provides an oracle independent of binary exponentiation.
            for (reserve, decimals) in [
                (0, 255),
                (1, 6),
                (1_500_001, 6),
                (17, 0),
                (u128::MAX, 0),
                (u128::MAX, 38),
                (u128::MAX, 39),
                (u128::MAX, 255),
                (1, 38),
                (1, 39),
                (1, 255),
            ] {
                monitor
                    .tokens
                    .get_mut(&Address::with_last_byte(1))
                    .unwrap()
                    .decimals = decimals;
                response(&mock, reserve, 7);
                monitor.update_pools_with_provider(&provider).await.unwrap();
                monitor.update_metrics();
                let actual = exported(&handle, "tempo_fee_amm_user_token_reserves")[0];
                let expected: f64 = format!("{reserve}e-{decimals}").parse().unwrap();
                if reserve == 0 {
                    assert_eq!(actual, 0.0);
                } else {
                    assert!(
                        actual.is_finite() && actual > 0.0,
                        "{reserve}/{decimals}: {actual}"
                    );
                    assert!(
                        ((actual - expected) / expected).abs() <= 1e-12,
                        "{reserve}/{decimals}: {actual} != {expected}"
                    );
                }
                assert_eq!(
                    exported(&handle, "tempo_fee_amm_validator_token_reserves"),
                    vec![7.0]
                );
            }
        })
    });
}

#[test]
fn freshness_tracks_observations_failures_and_recovery() {
    run(|handle| {
        runtime().block_on(async {
            let mut monitor = fixture();
            let mock = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(mock.clone());
            let stamp = "tempo_fee_amm_last_successful_update_timestamp_seconds";
            let success = "tempo_fee_amm_update_success";
            let user = "tempo_fee_amm_user_token_reserves";
            let validator = "tempo_fee_amm_validator_token_reserves";
            monitor.update_metrics();
            assert_eq!(exported(&handle, stamp), vec![0.0]);
            assert_eq!(exported(&handle, success), vec![0.0]);
            assert!(exported(&handle, user).is_empty());
            assert!(exported(&handle, validator).is_empty());
            response(&mock, 1_500_001, 7);
            monitor
                .update_pools_with_clock(&provider, || time(100))
                .await
                .unwrap();
            monitor.update_metrics();
            assert_eq!(exported(&handle, stamp), vec![100.0]);
            assert_eq!(exported(&handle, success), vec![1.0]);
            assert_eq!(exported(&handle, user), vec![1.500001]);
            for abi_error in [false, true] {
                if abi_error {
                    mock.push_success(&Bytes::from(vec![1]));
                } else {
                    mock.push_failure_msg("unavailable");
                }
                assert!(
                    monitor
                        .update_pools_with_clock(&provider, || panic!(
                            "failed response must not read clock"
                        ))
                        .await
                        .is_err()
                );
                monitor.update_metrics();
                assert_eq!(exported(&handle, stamp), vec![100.0]);
                assert_eq!(exported(&handle, success), vec![0.0]);
                assert_eq!(exported(&handle, user), vec![1.500001]);
                assert_eq!(exported(&handle, validator), vec![7.0]);
            }
            response(&mock, 0, 9);
            monitor
                .update_pools_with_clock(&provider, || time(200))
                .await
                .unwrap();
            monitor.update_metrics();
            assert_eq!(exported(&handle, stamp), vec![200.0]);
            assert_eq!(exported(&handle, success), vec![1.0]);
            assert_eq!(exported(&handle, user), vec![0.0]);
            assert_eq!(exported(&handle, validator), vec![9.0]);
            // Re-emitting and scraping without another observation cannot alter completion time.
            monitor.update_metrics();
            assert_eq!(exported(&handle, stamp), vec![200.0]);
            response(&mock, 1, 1);
            monitor
                .update_pools_with_clock(&provider, || {
                    UNIX_EPOCH - std::time::Duration::from_secs(1)
                })
                .await
                .unwrap();
            monitor.update_metrics();
            assert_eq!(exported(&handle, stamp), vec![0.0]);
            assert_eq!(exported(&handle, success), vec![1.0]);
            assert_eq!(exported(&handle, user), vec![0.000001]);
        })
    });
}

#[test]
fn registration_and_exposition_preserve_metric_contract() {
    run(|handle| {
        runtime().block_on(async {
            register_metrics();
            let mut monitor = fixture();
            monitor
                .tokens
                .get_mut(&Address::with_last_byte(1))
                .unwrap()
                .name = "A\"\\Z\n".into();
            let mock = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(mock.clone());
            response(&mock, 1, 7);
            monitor
                .update_pools_with_clock(&provider, || time(123))
                .await
                .unwrap();
            monitor.update_metrics();
            let text = handle.render();
            println!("Prometheus exposition:\n{text}");
            for metric in [
                "tempo_fee_amm_user_token_reserves",
                "tempo_fee_amm_validator_token_reserves",
                "tempo_fee_amm_last_successful_update_timestamp_seconds",
                "tempo_fee_amm_update_success",
            ] {
                assert!(text.contains(&format!("# HELP {metric} ")), "{text}");
                assert!(text.contains(&format!("# TYPE {metric} gauge")), "{text}");
                let line = text
                    .lines()
                    .find(|line| line.starts_with(&format!("{metric}{{")))
                    .unwrap();
                for label in [
                    "chain_id=\"4242\"".to_string(),
                    format!("token_a=\"{}\"", Address::with_last_byte(1)),
                    format!("token_b=\"{}\"", Address::with_last_byte(2)),
                    "token_a_name=\"A\\\"\\\\Z\\n\"".into(),
                    "token_b_name=\"B\"".into(),
                ] {
                    assert!(line.contains(&label), "missing {label}: {line}");
                }
            }
            assert_eq!(
                exported(&handle, "tempo_fee_amm_user_token_reserves"),
                vec![0.000001]
            );
            assert_eq!(
                exported(&handle, "tempo_fee_amm_validator_token_reserves"),
                vec![7.0]
            );
            assert!(!text.contains("# HELP tempo_fee_amm_user_reserves "));
        })
    });
}

type Pair = (Address, Address);
#[derive(Default)]
struct RpcState {
    replies: HashMap<Pair, Option<(u128, u128)>>,
    malformed: HashSet<Pair>,
    requests: Vec<Pair>,
}

async fn local_rpc(state: Arc<std::sync::Mutex<RpcState>>) -> (Url, tokio::task::JoinHandle<()>) {
    use alloy::sol_types::SolCall;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = poem::endpoint::make(move |mut request: poem::Request| {
        let state = state.clone();
        async move {
            let request: serde_json::Value = request.take_body().into_json().await.unwrap();
            let mut reply = serde_json::json!({"jsonrpc": "2.0", "id": request["id"]});
            if request["method"] == "eth_call" {
                let tx = &request["params"][0];
                assert_eq!(
                    tx["to"].as_str().unwrap().parse::<Address>().unwrap(),
                    TIP_FEE_MANAGER_ADDRESS
                );
                let input = tx
                    .get("input")
                    .or_else(|| tx.get("data"))
                    .unwrap()
                    .as_str()
                    .unwrap();
                let call = ITIPFeeAMM::getPoolCall::abi_decode(
                    &hex::decode(input.trim_start_matches("0x")).unwrap(),
                )
                .unwrap();
                let pair = (call.userToken, call.validatorToken);
                let mut state = state.lock().unwrap();
                state.requests.push(pair);
                if state.malformed.contains(&pair) {
                    reply["result"] = serde_json::json!("0x01");
                } else if let Some(Some((user, validator))) = state.replies.get(&pair) {
                    reply["result"] = serde_json::json!(format!(
                        "0x{}",
                        hex::encode(
                            Pool {
                                reserveUserToken: *user,
                                reserveValidatorToken: *validator
                            }
                            .abi_encode()
                        )
                    ));
                } else {
                    reply["error"] =
                        serde_json::json!({"code": -32603, "message": "pool unavailable"});
                }
            } else {
                assert_eq!(request["method"], "eth_blockNumber");
                reply["error"] =
                    serde_json::json!({"code": -32603, "message": "discovery unavailable"});
            }
            Response::builder()
                .header("content-type", "application/json")
                .body(reply.to_string())
        }
    });
    let server = tokio::spawn(async move {
        poem::Server::new_with_acceptor(poem::listener::TcpAcceptor::from_tokio(listener).unwrap())
            .run(endpoint)
            .await
            .unwrap();
    });
    (format!("http://{address}").parse().unwrap(), server)
}

fn pool_value(handle: &PrometheusHandle, metric: &str, pair: Pair) -> Option<f64> {
    handle
        .render()
        .lines()
        .find(|line| {
            line.starts_with(&format!("{metric}{{"))
                && line.contains(&format!("token_a=\"{}\"", pair.0))
                && line.contains(&format!("token_b=\"{}\"", pair.1))
        })
        .map(|line| line.rsplit_once(' ').unwrap().1.parse().unwrap())
}

#[test]
fn directional_pools_are_isolated_and_runtime_survives_discovery_failure() {
    run(|handle| {
        runtime().block_on(async {
            let mut monitor = fixture();
            let a = Address::with_last_byte(1);
            let b = Address::with_last_byte(2);
            let c = Address::with_last_byte(3);
            monitor.tokens.insert(
                c,
                TIP20Token {
                    decimals: 0,
                    name: "C".into(),
                },
            );
            monitor.known_pairs = [(a, b), (b, a), (a, c)].into_iter().collect();
            // Choose the first actual polling pair to make the failure-before-success case deterministic.
            let order: Vec<_> = monitor.known_pairs.iter().copied().collect();
            let state = Arc::new(std::sync::Mutex::new(RpcState::default()));
            for (i, pair) in order.iter().enumerate() {
                state
                    .lock()
                    .unwrap()
                    .replies
                    .insert(*pair, Some(((i as u128 + 1) * 1_000_000, i as u128 + 11)));
            }
            let (url, server) = local_rpc(state.clone()).await;
            monitor.rpc_url = url.clone();
            let provider = ProviderBuilder::new().connect(url.as_str()).await.unwrap();
            monitor
                .update_pools_with_clock(&provider, || time(100))
                .await
                .unwrap();
            monitor.update_metrics();
            assert_eq!(state.lock().unwrap().requests, order);
            let previous: Vec<_> = order
                .iter()
                .map(|pair| {
                    pool_value(&handle, "tempo_fee_amm_user_token_reserves", *pair).unwrap()
                })
                .collect();
            {
                let mut state = state.lock().unwrap();
                state.requests.clear();
                state.replies.insert(order[0], None);
                state.malformed.insert(order[1]);
                state.replies.insert(order[2], Some((9_000_000, 99)));
            }
            assert!(
                monitor
                    .update_pools_with_clock(&provider, || time(200))
                    .await
                    .is_err()
            );
            monitor.update_metrics();
            assert_eq!(state.lock().unwrap().requests, order);
            for (i, pair) in order.iter().enumerate() {
                assert_eq!(
                    pool_value(&handle, "tempo_fee_amm_update_success", *pair),
                    Some(if i == 2 { 1.0 } else { 0.0 })
                );
                assert_eq!(
                    pool_value(
                        &handle,
                        "tempo_fee_amm_last_successful_update_timestamp_seconds",
                        *pair
                    ),
                    Some(if i == 2 { 200.0 } else { 100.0 })
                );
                let expected = if i == 2 {
                    if pair.0 == a { 9.0 } else { 9_000_000.0 }
                } else {
                    previous[i]
                };
                assert_eq!(
                    pool_value(&handle, "tempo_fee_amm_user_token_reserves", *pair),
                    Some(expected)
                );
                let validator = if i == 2 {
                    if pair.1 == a { 0.000099 } else { 99.0 }
                } else {
                    if pair.1 == a {
                        (i as f64 + 11.0) / 1_000_000.0
                    } else {
                        i as f64 + 11.0
                    }
                };
                assert_eq!(
                    pool_value(&handle, "tempo_fee_amm_validator_token_reserves", *pair),
                    Some(validator)
                );
            }
            {
                let mut state = state.lock().unwrap();
                state.requests.clear();
                state.malformed.clear();
                for pair in &order {
                    state.replies.insert(*pair, None);
                }
            }
            assert!(
                monitor
                    .update_pools_with_clock(&provider, || panic!("no successful response"))
                    .await
                    .is_err()
            );
            monitor.update_metrics();
            assert_eq!(state.lock().unwrap().requests, order);
            assert_eq!(
                exported(&handle, "tempo_fee_amm_update_success"),
                vec![0.0; 3]
            );
            // The production single-poll path attempts known pools after discovery fails.
            {
                let mut state = state.lock().unwrap();
                state.requests.clear();
                for pair in &order {
                    state.replies.insert(*pair, Some((0, 17)));
                }
            }
            monitor.poll_once().await;
            assert_eq!(state.lock().unwrap().requests, order);
            assert_eq!(monitor.last_processed_block, 10);
            assert_eq!(
                exported(&handle, "tempo_fee_amm_update_success"),
                vec![1.0; 3]
            );
            assert_eq!(
                exported(&handle, "tempo_fee_amm_user_token_reserves"),
                vec![0.0; 3]
            );
            let mut before = exported(
                &handle,
                "tempo_fee_amm_last_successful_update_timestamp_seconds",
            );
            assert!(before.iter().all(|value| *value > 200.0));
            before.sort_by(f64::total_cmp);
            // Unsupported transport fails provider setup immediately and invalidates all pairs.
            monitor.rpc_url = "unsupported://fixture".parse().unwrap();
            assert!(monitor.update_tip20_pools().await.is_err());
            monitor.update_metrics();
            assert_eq!(
                exported(&handle, "tempo_fee_amm_update_success"),
                vec![0.0; 3]
            );
            let mut after = exported(
                &handle,
                "tempo_fee_amm_last_successful_update_timestamp_seconds",
            );
            after.sort_by(f64::total_cmp);
            assert_eq!(after, before);
            assert_eq!(
                exported(&handle, "tempo_fee_amm_user_token_reserves"),
                vec![0.0; 3]
            );
            let text = handle.render();
            let errors = text
                .lines()
                .find(|line| line.starts_with("tempo_fee_amm_errors{"))
                .unwrap();
            assert_eq!(
                errors.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap(),
                6
            );
            server.abort();
        })
    });
}
