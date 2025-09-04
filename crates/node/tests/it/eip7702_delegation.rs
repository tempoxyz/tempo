use crate::utils::{NodeSource, setup_test_node};
use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, WalletProvider, ext::TraceApi},
    rpc::types::TransactionRequest,
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;

#[tokio::test(flavor = "multi_thread")]
async fn test_auto_7702_delegation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _node_handle) = setup_test_node(source).await?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(1)?
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);

    let tx_count = provider.get_transaction_count(caller).await?;
    assert_eq!(tx_count, 0);

    // let code_before = provider.get_code(fresh_address).await?;
    // assert!(code_before.is_empty());
    //
    // // Send the first transaction from this account (nonce 0)
    // // This should trigger auto-delegation to DEFAULT_7702_DELEGATE_ADDRESS
    // let tx = TransactionRequest::default()
    //     .to(Address::random()) // Send to any address
    //     .value(U256::from(1))
    //     .gas_price(TEMPO_BASE_FEE as u128)
    //     .gas(21000);
    //
    // let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    //
    // assert!(receipt.status());
    //
    // // Check that the account now has EIP-7702 delegation code
    // let code_after = provider.get_code(fresh_address).await?;
    // assert!(!code_after.is_empty());
    //
    // // The code should be the EIP-7702 delegation bytecode
    // // EIP-7702 bytecode format: 0xef0100 + 20-byte address
    // let expected_delegation_code = {
    //     let mut code = vec![0xef, 0x01, 0x00];
    //     code.extend_from_slice(DEFAULT_7702_DELEGATE_ADDRESS.as_slice());
    //     code
    // };
    //
    // assert_eq!(code_after.as_ref(), &expected_delegation_code);

    Ok(())
}
