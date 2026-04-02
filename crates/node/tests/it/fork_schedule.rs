use crate::utils::TestNodeBuilder;
use alloy::providers::{Provider, ProviderBuilder};
use tempo_node::rpc::fork_schedule::ForkSchedule;

#[tokio::test(flavor = "multi_thread")]
async fn test_fork_schedule_returns_only_tempo_forks() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url);

    let schedule: ForkSchedule = provider
        .raw_request("tempo_forkSchedule".into(), ())
        .await?;

    // Must not contain Ethereum hardforks or Genesis.
    let eth_forks = [
        "Frontier",
        "Homestead",
        "Byzantium",
        "Constantinople",
        "Petersburg",
        "Istanbul",
        "Berlin",
        "London",
        "Paris",
        "Shanghai",
        "Cancun",
        "Prague",
        "Osaka",
    ];
    for fork in &schedule.schedule {
        assert!(
            !eth_forks.contains(&fork.name.as_str()),
            "Ethereum fork '{}' should not appear in tempo_forkSchedule",
            fork.name
        );
        assert_ne!(
            fork.name, "Genesis",
            "Genesis should not appear in tempo_forkSchedule"
        );
    }

    // Must contain known Tempo forks.
    let names: Vec<&str> = schedule.schedule.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"T0"), "T0 missing from schedule");
    assert!(names.contains(&"T1"), "T1 missing from schedule");
    assert!(names.contains(&"T2"), "T2 missing from schedule");

    // All forks should be active on devnet (all timestamps = 0).
    for fork in &schedule.schedule {
        if fork.activation_time == 0 {
            assert!(fork.active, "fork '{}' at t=0 should be active", fork.name);
        }
    }

    // Active fork must be one of the schedule entries.
    assert!(
        names.contains(&schedule.active.as_str()),
        "active fork '{}' not in schedule",
        schedule.active
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fork_schedule_fork_id_matches_eth_config() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url);

    let schedule: serde_json::Value = provider
        .raw_request("tempo_forkSchedule".into(), ())
        .await?;

    let eth_config: serde_json::Value = provider
        .raw_request("eth_config".into(), ())
        .await?;

    let eth_config_fork_id = eth_config["current"]["forkId"]
        .as_str()
        .expect("eth_config must have current.forkId");

    // ForkHash serializes as a byte array [u8; 4], convert to hex for comparison.
    let hash_bytes: Vec<u8> = schedule["forkId"]["hash"]
        .as_array()
        .expect("forkId.hash must be an array")
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    let schedule_fork_id = format!(
        "0x{}",
        hash_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    assert_eq!(
        schedule_fork_id, eth_config_fork_id,
        "tempo_forkSchedule.forkId.hash must match eth_config.current.forkId"
    );

    Ok(())
}
