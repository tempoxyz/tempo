// TODO: desired tests
// round trips for all custom serde impls
//
// Possibly also snapshot tests

#[test]
fn example_input_is_parsed() {
    const INPUT: &str = r#"
signer = "0x81d35644dd13b5d712215023ab16615d9f8852c5a2fdfbd72dee06f538894b58"
share = "0x002ca4985d4850d2836b02a9597170ae3e122d4f858a11ed6d6447d1ca3ec3380d"
polynomial = "0x85a21686d219ba66f65165c17cb9b8f02a827b473b54f734e8f00d5705b7ceb12537de49c1c06fdad1df74cbfb7cd7d104eb6ab9330edf7854b2180ff1594034115fa80dbc865aca54f8813f41ef0e34518f972adad793e9d9302114f941db0183a5ec4224f3df5471a3927e2d8968e2a7948322f204b228a131c5931df4eb5e903d1a1e4cf31f2fbda357191e33b0810a0e97b748b7ab8142fdb946c457b1b3d29b60469c488306381285e794a377e9d3cf049eb850507a04f8775b2dcb0788"
listen_addr = "0.0.0.0:8000"
metrics_port = 8001
storage_directory = "/Users/janis/dev/tempo/tempo-commonware/test_deployment/945fadcd1ea3bac97c86c2acbc539fce43219552d24aaa3188c3afc1df4d50a7/storage"
worker_threads = 3
message_backlog = 16384
mailbox_size = 16384
deque_size = 10
fee_recipient = "0x0000000000000000000000000000000000000000"
epoch_length = 1000

[p2p]
max_message_size_bytes = 1_048_576

[timeouts]
time_for_peer_response = "2s"
time_to_collect_notarizations = "2s"
time_to_propose = "2s"
time_to_retry_nullify_broadcast = "10s"
views_to_track = 256
views_until_leader_skip = 32
new_payload_wait_time = "500ms"
    
[peers]
0x945fadcd1ea3bac97c86c2acbc539fce43219552d24aaa3188c3afc1df4d50a7 = "127.0.0.1:8000"
0xbaad106129bc215c1cca3760644914ed37ea91f1f1319999ce91ef2eaf51c827 = "127.0.0.1:8002"
"#;

    toml::from_str::<crate::Config>(INPUT).expect("the example config should be parse-able");
}
