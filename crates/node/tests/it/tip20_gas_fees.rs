use alloy::{
    network::ReceiptResponse,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use alloy_rpc_types_eth::TransactionRequest;
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{IFeeManager, ITIP20},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_fee_in_stable() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        crate::utils::NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        crate::utils::NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _local_node) = crate::utils::setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    // Ensure the native account balance is 0
    assert_eq!(provider.get_balance(caller).await?, U256::ZERO);

    let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let fee_token_address = fee_manager.userTokens(caller).call().await?;

    // Get the balance of the fee token before the tx
    let fee_token = ITIP20::new(fee_token_address, provider.clone());
    let initial_balance = fee_token.balanceOf(caller).call().await?;

    let tx = TransactionRequest::default()
        .from(caller)
        .to(caller)
        .gas_price(TEMPO_BASE_FEE as u128)
        .gas_limit(300000);

    let pending_tx = provider.send_transaction(tx).await?;
    let receipt = pending_tx.get_receipt().await?;

    // Assert that the fee token balance has decreased by gas spent
    let balance_after = fee_token.balanceOf(caller).call().await?;

    let cost = receipt.effective_gas_price() * receipt.gas_used as u128;
    assert_eq!(balance_after, initial_balance - U256::from(cost));

    Ok(())
}
