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

    let wallet = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(1)?
        .build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(http_url);
    let tx_count = provider.get_transaction_count(caller).await?;
    assert_eq!(tx_count, 0);

    // Setup test token
    let token = setup_test_token(provider.clone(), caller).await?;

    let sender_balance = token.balanceOf(caller).call().await?;
    let recipient = Address::random();
    let recipient_balance = token.balanceOf(recipient).call().await?;

    let delegate_calldata = token
        .transfer(recipient, sender_balance)
        .calldata()
        .to_owned();
    let delegate_account = IthacaAccount::new(DEFAULT_7702_DELEGATE_ADDRESS, provider.clone());
    let calls = vec![Call {
        to: *token.address(),
        value: alloy::primitives::U256::from(0),
        data: delegate_calldata,
    }];

    let tx = TransactionRequest::default()
        .from(caller)
        .to(caller)
        .input(TransactionInput::new(calls.abi_encode().into()))
        .gas_price(TEMPO_BASE_FEE as u128);

    let execute_call = delegate_account.execute(B256::ZERO, calls.abi_encode().into());
    let receipt = execute_call.send().await?.get_receipt().await?;

    // TODO: assert state changes

    Ok(())
}
