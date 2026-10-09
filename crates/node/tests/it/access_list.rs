use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
};
use reth_e2e_test_utils::wallet::test_signer;
use serde_json::json;
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_node::rpc::TempoAccessListResponse;
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, tip20::TIP20Token};

use crate::utils::{TestNodeBuilder, setup_test_token};

#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_access_list_tip20_simulation_and_mined_replay() -> eyre::Result<()> {
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = test_signer(0);
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);
    let token = setup_test_token(provider.clone(), caller).await?;
    let address = *token.address();
    let recipient = Address::repeat_byte(0x77);
    let amount = U256::from(1_000_000);
    token
        .mint(caller, amount)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    let call = token.transfer(recipient, U256::from(10));
    let tx = json!({ "from": caller, "to": address, "input": call.calldata(), "gas": "0xf4240" });
    let response: TempoAccessListResponse = provider
        .raw_request("tempo_createAccessList".into(), (tx.clone(), "latest"))
        .await?;
    assert_disjoint(&response);
    assert!(response.success, "{:?}", response.error);
    let storage = TIP20Token::from_address_unchecked(address);
    let sender_slot = B256::from(storage.balances[caller].slot());
    let recipient_slot = B256::from(storage.balances[recipient].slot());
    let entry = response
        .access_list
        .iter()
        .find(|item| item.address == address)
        .unwrap();
    assert!(!entry.read_storage_keys.contains(&sender_slot));
    assert!(!entry.read_storage_keys.contains(&recipient_slot));
    assert!(entry.write_storage_keys.contains(&sender_slot));
    assert!(entry.write_storage_keys.contains(&recipient_slot));
    assert_eq!(token.balanceOf(caller).call().await?, amount);
    assert_eq!(token.balanceOf(recipient).call().await?, U256::ZERO);

    let mut lane_tx = tx;
    lane_tx["nonceKey"] = json!("0x7");
    let lane: TempoAccessListResponse = provider
        .raw_request("tempo_createAccessList".into(), (lane_tx,))
        .await?;
    assert_disjoint(&lane);
    assert!(lane.success, "{:?}", lane.error);
    let nonce = lane
        .access_list
        .iter()
        .find(|item| item.address == NONCE_PRECOMPILE_ADDRESS)
        .unwrap();
    assert!(!nonce.write_storage_keys.is_empty());

    let receipt = call
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    let replay: Option<TempoAccessListResponse> = provider
        .raw_request(
            "tempo_getTransactionAccessList".into(),
            (receipt.transaction_hash,),
        )
        .await?;
    let replay = replay.expect("mined transaction must be traceable");
    assert_disjoint(&replay);
    assert!(replay.success, "{:?}", replay.error);
    assert_eq!(replay.gas_used, receipt.gas_used);
    let entry = replay
        .access_list
        .iter()
        .find(|item| item.address == address)
        .unwrap();
    assert!(entry.write_storage_keys.contains(&sender_slot));
    assert!(entry.write_storage_keys.contains(&recipient_slot));
    assert_eq!(token.balanceOf(recipient).call().await?, U256::from(10));

    let unknown: Option<TempoAccessListResponse> = provider
        .raw_request(
            "tempo_getTransactionAccessList".into(),
            (B256::repeat_byte(0xfe),),
        )
        .await?;
    assert!(unknown.is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_access_list_reports_precompile_reverts() -> eyre::Result<()> {
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = test_signer(0);
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);
    let token = setup_test_token(provider.clone(), caller).await?;
    let tx = json!({ "from": caller, "to": token.address(), "gas": "0xf4240",
        "input": token.transfer(Address::repeat_byte(0x77), U256::MAX).calldata() });
    // The transaction is executable but its transfer reverts: return the accesses and error,
    // rather than discarding them in a JSON-RPC execution error.
    let response: TempoAccessListResponse = provider
        .raw_request("tempo_createAccessList".into(), (tx,))
        .await?;
    assert_disjoint(&response);
    assert!(!response.success);
    assert_eq!(response.error.as_deref(), Some("execution reverted"));
    assert!(!response.return_data.is_empty());
    let entry = response
        .access_list
        .iter()
        .find(|item| item.address == *token.address())
        .unwrap();
    assert!(!entry.read_storage_keys.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tempo_access_list_retains_reverted_aa_precompile_writes() -> eyre::Result<()> {
    let setup = TestNodeBuilder::new().build_http_only().await?;
    let wallet = test_signer(0);
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(setup.http_url);
    let token = setup_test_token(provider.clone(), caller).await?;
    token
        .mint(caller, U256::from(1_000))
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    let recipient = Address::repeat_byte(0x77);
    let tx = json!({ "from": caller, "gas": "0xf4240", "calls": [
        { "to": token.address(), "value": "0x0", "input": token.transfer(recipient, U256::from(10)).calldata() },
        { "to": token.address(), "value": "0x0", "input": token.transfer(recipient, U256::MAX).calldata() }
    ] });
    let response: TempoAccessListResponse = provider
        .raw_request("tempo_createAccessList".into(), (tx,))
        .await?;
    assert_disjoint(&response);
    assert!(!response.success);
    let storage = TIP20Token::from_address_unchecked(*token.address());
    let recipient_slot = B256::from(storage.balances[recipient].slot());
    let entry = response
        .access_list
        .iter()
        .find(|item| item.address == *token.address())
        .unwrap();
    assert!(entry.write_storage_keys.contains(&recipient_slot));
    assert_eq!(token.balanceOf(recipient).call().await?, U256::ZERO);
    assert_eq!(token.balanceOf(caller).call().await?, U256::from(1_000));
    Ok(())
}

fn assert_disjoint(response: &TempoAccessListResponse) {
    for entry in &response.access_list {
        assert!(
            entry
                .read_storage_keys
                .iter()
                .all(|key| !entry.write_storage_keys.contains(key)),
            "read and write keys overlap at {}",
            entry.address
        );
    }
}
