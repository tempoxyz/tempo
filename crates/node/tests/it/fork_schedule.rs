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
    for fork in TempoHardfork::VARIANTS
        .iter()
        .filter(|f| f.name() != "Genesis")
    {
        assert!(
            names.contains(&fork.name()),
            "missing fork '{}' in schedule",
            fork.name()
        );
    }
    assert_eq!(names.len(), TempoHardfork::VARIANTS.len() - 1);

    // Active fork must be in the schedule.
    assert!(names.contains(&schedule.active.as_str()));

    // Active forks must have a fork_id; inactive forks must not.
    for entry in &schedule.schedule {
        assert_eq!(
            entry.active,
            entry.fork_id.is_some(),
            "fork '{}': active={} but fork_id={}",
            entry.name,
            entry.active,
            if entry.fork_id.is_some() {
                "Some"
            } else {
                "None"
            }
        );
    }

    // The active fork's fork_id must match eth_config.
    let active_entry = schedule
        .schedule
        .iter()
        .find(|f| f.name == schedule.active)
        .expect("active fork must be in schedule");
    let eth_config: serde_json::Value = provider.raw_request("eth_config".into(), ()).await?;
    assert_eq!(
        active_entry.fork_id.as_deref().unwrap(),
        eth_config["current"]["forkId"].as_str().unwrap()
    );

    Ok(())
}
