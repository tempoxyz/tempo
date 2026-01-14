//! Integration tests for the bootnode server.

use reqwest::Client;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tempo_bootnode::{BootnodeConfig, BootnodeServer, PeerInfo, generate_secret_key};

/// Find an available port for testing.
fn find_available_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Create a test bootnode config with random ports.
fn test_config() -> BootnodeConfig {
    let discovery_port = find_available_port();
    let http_port = find_available_port();

    BootnodeConfig::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), discovery_port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), http_port),
    )
    .with_lookup_interval_secs(60)
}

#[tokio::test]
async fn test_bootnode_health_endpoint() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();
    let resp = client
        .get(format!("{}/health", handle.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_bootnode_info_endpoint() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let expected_enode = server.local_enr().to_string();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();
    let resp = client
        .get(format!("{}/", handle.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let info: Value = resp.json().await.unwrap();
    assert_eq!(info["enode"], expected_enode);
    assert_eq!(info["registered_peers"], 0);
    assert_eq!(info["discovered_peers"], 0);
}

#[tokio::test]
async fn test_register_peer() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();

    let peer_key = generate_secret_key();
    let secret_hex = const_hex::encode(peer_key.secret_bytes());

    let resp = client
        .post(format!("{}/peers", handle.base_url()))
        .json(&serde_json::json!({
            "secret_key": secret_hex,
            "ip": "10.0.0.5",
            "tcp_port": 30303
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);

    let peer: PeerInfo = resp.json().await.unwrap();
    assert_eq!(peer.ip, "10.0.0.5");
    assert_eq!(peer.tcp_port, 30303);
    assert!(peer.enode.starts_with("enode://"));

    let info_resp = client
        .get(format!("{}/", handle.base_url()))
        .send()
        .await
        .unwrap();
    let info: Value = info_resp.json().await.unwrap();
    assert_eq!(info["registered_peers"], 1);
}

#[tokio::test]
async fn test_list_peers_empty() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();
    let resp = client
        .get(format!("{}/peers", handle.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let peers: Vec<PeerInfo> = resp.json().await.unwrap();
    assert!(peers.is_empty());
}

#[tokio::test]
async fn test_register_and_list_peers() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();

    for i in 1..=3 {
        let peer_key = generate_secret_key();
        let secret_hex = const_hex::encode(peer_key.secret_bytes());

        let resp = client
            .post(format!("{}/peers", handle.base_url()))
            .json(&serde_json::json!({
                "secret_key": secret_hex,
                "ip": format!("10.0.0.{}", i),
                "tcp_port": 30303 + i
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 201);
    }

    let resp = client
        .get(format!("{}/peers", handle.base_url()))
        .send()
        .await
        .unwrap();

    let peers: Vec<PeerInfo> = resp.json().await.unwrap();
    assert_eq!(peers.len(), 3);
}

#[tokio::test]
async fn test_deregister_peer() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();

    let peer_key = generate_secret_key();
    let secret_hex = const_hex::encode(peer_key.secret_bytes());

    let resp = client
        .post(format!("{}/peers", handle.base_url()))
        .json(&serde_json::json!({
            "secret_key": secret_hex,
            "ip": "10.0.0.10",
            "tcp_port": 30303
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let peer: PeerInfo = resp.json().await.unwrap();

    let peer_id = peer.id.trim_start_matches("0x");

    let delete_resp = client
        .delete(format!("{}/peers/{}", handle.base_url(), peer_id))
        .send()
        .await
        .unwrap();

    assert_eq!(delete_resp.status(), 200);
    let result: Value = delete_resp.json().await.unwrap();
    assert_eq!(result["removed"], true);

    let list_resp = client
        .get(format!("{}/peers", handle.base_url()))
        .send()
        .await
        .unwrap();
    let peers: Vec<PeerInfo> = list_resp.json().await.unwrap();
    assert!(peers.is_empty());
}

#[tokio::test]
async fn test_deregister_nonexistent_peer() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();

    let fake_peer_id = "a".repeat(128);

    let resp = client
        .delete(format!("{}/peers/{}", handle.base_url(), fake_peer_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_register_invalid_secret_key() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();

    let resp = client
        .post(format!("{}/peers", handle.base_url()))
        .json(&serde_json::json!({
            "secret_key": "invalid_hex",
            "ip": "10.0.0.1",
            "tcp_port": 30303
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let error: Value = resp.json().await.unwrap();
    assert!(error["error"].as_str().unwrap().contains("Invalid"));
}

#[tokio::test]
async fn test_register_with_custom_udp_port() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();

    let peer_key = generate_secret_key();
    let secret_hex = const_hex::encode(peer_key.secret_bytes());

    let resp = client
        .post(format!("{}/peers", handle.base_url()))
        .json(&serde_json::json!({
            "secret_key": secret_hex,
            "ip": "10.0.0.20",
            "tcp_port": 30303,
            "udp_port": 30304
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);

    let peer: PeerInfo = resp.json().await.unwrap();
    assert_eq!(peer.tcp_port, 30303);
    assert_eq!(peer.udp_port, 30304);
}

#[tokio::test]
async fn test_get_peer_by_id() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();

    let peer_key = generate_secret_key();
    let secret_hex = const_hex::encode(peer_key.secret_bytes());

    let resp = client
        .post(format!("{}/peers", handle.base_url()))
        .json(&serde_json::json!({
            "secret_key": secret_hex,
            "ip": "10.0.0.30",
            "tcp_port": 30303
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let peer: PeerInfo = resp.json().await.unwrap();
    let peer_id = peer.id.trim_start_matches("0x");

    let get_resp = client
        .get(format!("{}/peers/{}", handle.base_url(), peer_id))
        .send()
        .await
        .unwrap();

    assert_eq!(get_resp.status(), 200);
    let fetched_peer: PeerInfo = get_resp.json().await.unwrap();
    assert_eq!(fetched_peer.ip, "10.0.0.30");
}

#[tokio::test]
async fn test_get_nonexistent_peer() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();

    let fake_peer_id = "b".repeat(128);

    let resp = client
        .get(format!("{}/peers/{}", handle.base_url(), fake_peer_id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_discovered_peers_endpoint() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = Client::new();
    let resp = client
        .get(format!("{}/discovered", handle.base_url()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let peers: Vec<PeerInfo> = resp.json().await.unwrap();
    assert!(peers.is_empty());
}

#[tokio::test]
async fn test_state_direct_access() {
    let config = test_config();
    let server = BootnodeServer::new(config).await.unwrap();
    let handle = server.start().await.unwrap();

    assert!(handle.state().list_registered().is_empty());
    assert!(handle.state().list_discovered().is_empty());

    let info = handle.state().info();
    assert_eq!(info.registered_peers, 0);
    assert_eq!(info.discovered_peers, 0);
}
