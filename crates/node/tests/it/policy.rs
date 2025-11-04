use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use std::env;
use tempo_contracts::precompiles::ITIP403Registry;
use tempo_precompiles::TIP403_REGISTRY_ADDRESS;

/// Test that pagination respects the limit parameter
///
/// Scenario: Add 5 addresses, request with limit=2
/// Expected: Should return only 2 addresses and provide a nextCursor
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_get_addresses_pagination_limit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider.clone());

    // Create a whitelist policy
    let admin = caller;
    let policy_type = ITIP403Registry::PolicyType::WHITELIST;
    let tx = registry.createPolicy(admin, policy_type).send().await?;
    let receipt = tx.get_receipt().await?;
    let policy_id = receipt.logs()[0]
        .log_decode::<ITIP403Registry::PolicyCreated>()?
        .inner
        .data
        .policyId;

    // Add 5 addresses
    for i in 1..=5 {
        let addr = Address::from([i; 20]);
        registry
            .modifyPolicyWhitelist(policy_id, addr, true)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    // Request with limit=2
    let result: serde_json::Value = provider
        .raw_request(
            "policy_getAddresses".into(),
            vec![serde_json::json!({
                "policyId": policy_id,
                "limit": 2,
            })],
        )
        .await?;

    let addresses = result["addresses"]
        .as_array()
        .expect("addresses should be an array");

    // Should return exactly 2 addresses (respecting limit)
    assert_eq!(
        addresses.len(),
        2,
        "Should return only 2 addresses when limit=2. Got: {}",
        addresses.len()
    );

    // Should have a nextCursor since there are more results
    let next_cursor = result.get("nextCursor");
    assert!(
        next_cursor.is_some() && !next_cursor.unwrap().is_null(),
        "Should return a nextCursor when more results are available. Got: {next_cursor:?}"
    );

    Ok(())
}

/// Test that cursor allows navigating to the next page
///
/// Scenario: Add 5 addresses, get first page (limit=2), use cursor to get next page
/// Expected: Second page should return different addresses (the next 2)
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_get_addresses_cursor_navigation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider.clone());

    // Create a whitelist policy
    let admin = caller;
    let policy_type = ITIP403Registry::PolicyType::WHITELIST;
    let tx = registry.createPolicy(admin, policy_type).send().await?;
    let receipt = tx.get_receipt().await?;
    let policy_id = receipt.logs()[0]
        .log_decode::<ITIP403Registry::PolicyCreated>()?
        .inner
        .data
        .policyId;

    // Add 5 addresses
    for i in 1..=5 {
        let addr = Address::from([i; 20]);
        registry
            .modifyPolicyWhitelist(policy_id, addr, true)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    // First page: limit=2
    let page1: serde_json::Value = provider
        .raw_request(
            "policy_getAddresses".into(),
            vec![serde_json::json!({
                "policyId": policy_id,
                "limit": 2,
            })],
        )
        .await?;

    let page1_addresses = page1["addresses"]
        .as_array()
        .expect("addresses should be an array");
    assert_eq!(
        page1_addresses.len(),
        2,
        "First page should have 2 addresses"
    );

    let cursor = page1["nextCursor"]
        .as_str()
        .expect("nextCursor should be present");

    // Second page: use cursor
    let page2: serde_json::Value = provider
        .raw_request(
            "policy_getAddresses".into(),
            vec![serde_json::json!({
                "policyId": policy_id,
                "cursor": cursor,
                "limit": 2,
            })],
        )
        .await?;

    let page2_addresses = page2["addresses"]
        .as_array()
        .expect("addresses should be an array");
    assert_eq!(
        page2_addresses.len(),
        2,
        "Second page should have 2 addresses"
    );

    // Pages should have different addresses
    let page1_addr0 = page1_addresses[0]["address"].as_str().unwrap();
    let page2_addr0 = page2_addresses[0]["address"].as_str().unwrap();
    assert_ne!(
        page1_addr0, page2_addr0,
        "Second page should have different addresses than first page. Page1: {page1_addr0}, Page2: {page2_addr0}"
    );

    // Third page: should have 1 address
    let cursor2 = page2["nextCursor"]
        .as_str()
        .expect("nextCursor should be present");
    let page3: serde_json::Value = provider
        .raw_request(
            "policy_getAddresses".into(),
            vec![serde_json::json!({
                "policyId": policy_id,
                "cursor": cursor2,
                "limit": 2,
            })],
        )
        .await?;

    let page3_addresses = page3["addresses"]
        .as_array()
        .expect("addresses should be an array");
    assert_eq!(
        page3_addresses.len(),
        1,
        "Third page should have 1 address (last one)"
    );

    // Should be no more results
    assert!(
        page3["nextCursor"].is_null(),
        "nextCursor should be null on last page"
    );

    Ok(())
}

/// Test that addresses can be sorted ascending and descending
///
/// Scenario: Add 3 addresses in random order
/// Expected: Can retrieve them sorted asc or desc by address
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_get_addresses_sorting() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(http_url.clone());

    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider.clone());

    // Create a whitelist policy
    let admin = caller;
    let policy_type = ITIP403Registry::PolicyType::WHITELIST;
    let tx = registry.createPolicy(admin, policy_type).send().await?;
    let receipt = tx.get_receipt().await?;
    let policy_id = receipt.logs()[0]
        .log_decode::<ITIP403Registry::PolicyCreated>()?
        .inner
        .data
        .policyId;

    // Add addresses in non-sorted order (using sequential values like pagination test)
    for i in [3u8, 1, 4, 2] {
        let addr = Address::from([i; 20]);
        registry
            .modifyPolicyWhitelist(policy_id, addr, true)
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    // Get addresses sorted ascending
    let result_asc: serde_json::Value = provider
        .raw_request(
            "policy_getAddresses".into(),
            vec![serde_json::json!({
                "policyId": policy_id,
                "sort": {
                    "on": "address",
                    "order": "asc"
                }
            })],
        )
        .await?;

    let addresses_asc = result_asc["addresses"]
        .as_array()
        .expect("addresses should be an array");

    // We expect at least 2 addresses to test sorting
    assert!(
        addresses_asc.len() >= 2,
        "Need at least 2 addresses to test sorting, got {}",
        addresses_asc.len()
    );

    // Verify ascending order (check all consecutive pairs)
    for i in 0..addresses_asc.len() - 1 {
        let addr_i = addresses_asc[i]["address"].as_str().unwrap();
        let addr_next = addresses_asc[i + 1]["address"].as_str().unwrap();
        assert!(
            addr_i < addr_next,
            "Addresses should be sorted ascending: addr[{}]={} >= addr[{}]={}",
            i,
            addr_i,
            i + 1,
            addr_next
        );
    }

    // Get addresses sorted descending
    let result_desc: serde_json::Value = provider
        .raw_request(
            "policy_getAddresses".into(),
            vec![serde_json::json!({
                "policyId": policy_id,
                "sort": {
                    "on": "address",
                    "order": "desc"
                }
            })],
        )
        .await?;

    let addresses_desc = result_desc["addresses"]
        .as_array()
        .expect("addresses should be an array");
    assert_eq!(
        addresses_desc.len(),
        addresses_asc.len(),
        "Desc and asc should return same number of addresses"
    );

    // Verify descending order (check all consecutive pairs)
    for i in 0..addresses_desc.len() - 1 {
        let addr_i = addresses_desc[i]["address"].as_str().unwrap();
        let addr_next = addresses_desc[i + 1]["address"].as_str().unwrap();
        assert!(
            addr_i > addr_next,
            "Addresses should be sorted descending: addr[{}]={} <= addr[{}]={}",
            i,
            addr_i,
            i + 1,
            addr_next
        );
    }

    // First in desc should equal last in asc, and vice versa
    let addr_first_asc = addresses_asc[0]["address"].as_str().unwrap();
    let addr_last_asc = addresses_asc[addresses_asc.len() - 1]["address"]
        .as_str()
        .unwrap();
    let addr_first_desc = addresses_desc[0]["address"].as_str().unwrap();
    let addr_last_desc = addresses_desc[addresses_desc.len() - 1]["address"]
        .as_str()
        .unwrap();

    assert_eq!(
        addr_first_desc, addr_last_asc,
        "First in desc should be last in asc"
    );
    assert_eq!(
        addr_last_desc, addr_first_asc,
        "Last in desc should be first in asc"
    );

    Ok(())
}
