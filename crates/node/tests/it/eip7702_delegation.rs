use crate::utils::{NodeSource, setup_test_node, setup_test_token};
use alloy::{
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol,
    sol_types::SolValue,
};
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use rand::random;
use std::env;
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::{DEFAULT_7702_DELEGATE_ADDRESS, IthacaAccount};
use tempo_precompiles::contracts::ITIP20::{self, ITIP20Calls};

sol! {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_auto_7702_delegation() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _node_handle) = setup_test_node(source).await?;

    // TODO: use a different account to mint so we can assert nonce = 1 after
    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(1)?
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);
    assert_eq!(provider.get_transaction_count(caller).await?, 0);
    // TODO: assert 0 code

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;

    let sender_balance = token.balanceOf(caller).call().await?;
    let recipient = Address::random();
    let recipient_balance = token.balanceOf(recipient).call().await?;

    let delegate_calldata = token
        .transfer(recipient, sender_balance)
        .calldata()
        .to_owned();
    let delegate_account = IthacaAccount::new(caller, provider.clone());
    let calls = vec![Call {
        to: *token.address(),
        value: alloy::primitives::U256::from(0),
        data: delegate_calldata,
    }];

    let execute_call = delegate_account.execute(B256::ZERO, calls.abi_encode().into());
    let _receipt = execute_call.send().await?.get_receipt().await?;

    // Assert state changes after delegation execution
    let sender_balance_after = token.balanceOf(caller).call().await?;
    let recipient_balance_after = token.balanceOf(recipient).call().await?;

    // Verify the transfer was successful
    assert_eq!(sender_balance_after, U256::ZERO,);
    assert_eq!(recipient_balance_after, sender_balance);
    // assert_eq!(provider.get_transaction_count(caller).await?, tx_count + 1);

    // TODO: assert that code is as expected

    Ok(())
}
