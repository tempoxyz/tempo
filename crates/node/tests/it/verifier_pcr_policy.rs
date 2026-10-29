use crate::utils::{ForkSchedule, TestNodeBuilder};
use alloy::{
    consensus::BlockHeader as _,
    providers::{Provider, ProviderBuilder},
};
use alloy_primitives::FixedBytes;
use tempo_alloy::{TempoNetwork, provider::TempoProviderExt, rpc::VerifierPcrPolicy};
use tempo_chainspec::TempoHardfork;
use tempo_precompiles::zone_verifier::APPROVED_PCRS;

#[tokio::test(flavor = "multi_thread")]
async fn verifier_pcr_policy_reports_expected_values_before_any_batch() -> eyre::Result<()> {
    let setup = TestNodeBuilder::new()
        .with_schedule(ForkSchedule::DevnetAt(TempoHardfork::T14))
        .with_instant_mining()
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(setup.http_url);
    let policy = provider.get_verifier_pcr_policy(None).await?;
    let omitted: VerifierPcrPolicy = provider
        .raw_request("tempo_getVerifierPcrPolicy".into(), [] as [String; 0])
        .await?;
    assert_eq!(omitted, policy);
    let header = provider
        .get_block_by_number(policy.block_number.into())
        .await?
        .unwrap()
        .header;
    assert_eq!(policy.block_number, 0);
    assert_eq!(policy.block_hash, header.hash);
    assert_eq!(policy.block_timestamp, header.timestamp());
    assert_eq!(policy.chain_id, provider.get_chain_id().await?);
    assert_eq!(
        policy.active_hardfork,
        provider.get_active_hardfork().await?.to_string()
    );
    assert_eq!(policy.selected.hardfork, policy.active_hardfork);
    assert_eq!(
        policy.selected.pcrs,
        APPROVED_PCRS
            .at(TempoHardfork::T14)
            .map(|pcrs| pcrs.map(FixedBytes::from))
    );
    assert_eq!(policy.history.last(), Some(&policy.selected));

    let historical = provider.get_verifier_pcr_policy(Some("T13")).await?;
    assert_eq!(historical.selected.hardfork, "T13");
    assert_eq!(
        historical.selected.pcrs,
        APPROVED_PCRS
            .at(TempoHardfork::T13)
            .map(|pcrs| pcrs.map(FixedBytes::from))
    );
    assert_eq!(historical.history.last(), Some(&historical.selected));
    assert!(
        historical
            .history
            .iter()
            .all(|entry| entry.hardfork != "T14")
    );
    let before = provider.get_verifier_pcr_policy(Some("T12")).await?;
    assert_eq!(before.selected.pcrs, None);
    assert!(before.history.iter().all(|entry| entry.pcrs.is_none()));
    assert_eq!(
        serde_json::to_value(&before)?["selected"]["pcrs"],
        serde_json::Value::Null
    );
    let genesis = provider.get_verifier_pcr_policy(Some("Genesis")).await?;
    assert_eq!(genesis.history, [genesis.selected.clone()]);
    assert_eq!(genesis.selected.activation_time, None);
    assert_eq!(genesis.selected.pcrs, None);

    let error = provider
        .get_verifier_pcr_policy(Some("T999"))
        .await
        .unwrap_err();
    assert_eq!(error.as_error_resp().unwrap().code, -32602);
    assert_eq!(
        error.as_error_resp().unwrap().message,
        "unknown Tempo hardfork: T999"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn verifier_pcr_policy_rejects_future_and_unconfigured_forks() -> eyre::Result<()> {
    let mut genesis: serde_json::Value =
        serde_json::from_str(include_str!("../assets/test-genesis.json"))?;
    genesis["config"].as_object_mut().unwrap().remove("t14Time");
    let setup = TestNodeBuilder::new()
        .with_genesis(genesis.to_string())
        .with_schedule(ForkSchedule::DevnetAt(TempoHardfork::T12))
        .with_instant_mining()
        .build_http_only()
        .await?;
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(setup.http_url);
    let policy = provider.get_verifier_pcr_policy(None).await?;
    assert_eq!(policy.selected.hardfork, "T12");
    assert_eq!(policy.selected.pcrs, None);
    for fork in ["T13", "T14"] {
        let error = provider
            .get_verifier_pcr_policy(Some(fork))
            .await
            .unwrap_err();
        assert_eq!(error.as_error_resp().unwrap().code, -32602);
        assert_eq!(
            error.as_error_resp().unwrap().message,
            format!("hardfork {fork} is not activated on this chain")
        );
    }
    Ok(())
}
