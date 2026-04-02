use crate::utils::TestNodeBuilder;
use alloy::providers::{Provider, ProviderBuilder};
use reth_chainspec::Hardfork;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_node::rpc::fork_schedule::ForkSchedule;

#[tokio::test(flavor = "multi_thread")]
async fn test_fork_schedule() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let provider = ProviderBuilder::new().connect_http(setup.http_url);

    let schedule: ForkSchedule = provider
        .raw_request("tempo_forkSchedule".into(), ())
        .await?;

    // Every TempoHardfork variant except Genesis must appear.
    let names: Vec<&str> = schedule.schedule.iter().map(|f| f.name.as_str()).collect();
    for fork in TempoHardfork::VARIANTS.iter().filter(|f| f.name() != "Genesis") {
        assert!(
            names.contains(&fork.name()),
            "missing fork '{}' in schedule",
            fork.name()
        );
    }
    // No extra entries beyond the expected Tempo forks.
    assert_eq!(names.len(), TempoHardfork::VARIANTS.len() - 1); // minus Genesis

    // Active fork must be in the schedule.
    assert!(names.contains(&schedule.active.as_str()));

    // fork_id.hash must match eth_config.
    let eth_config: serde_json::Value = provider
        .raw_request("eth_config".into(), ())
        .await?;
    let hash_hex = format!(
        "0x{}",
        schedule
            .fork_id
            .hash
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert_eq!(hash_hex, eth_config["current"]["forkId"].as_str().unwrap());

    Ok(())
}
