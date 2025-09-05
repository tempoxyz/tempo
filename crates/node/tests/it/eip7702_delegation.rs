use crate::utils::{NodeSource, setup_test_node, setup_test_token};
use alloy::{
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::local::{MnemonicBuilder, coins_bip39::English},
    sol,
    sol_types::SolValue,
};
use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use rand::random;
use reth_evm::revm::state::Bytecode;
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

    // Create a wallet to deploy the test token
    let wallet_0 = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let provider = ProviderBuilder::new()
        .wallet(wallet_0)
        .connect_http(http_url.clone());
    let signer = provider.default_signer_address();

    // Setup test token
    let token = setup_test_token(provider.clone(), signer).await?;

    // Create a new wallet to test auto delegation and ensure nonce = 0
    let wallet_1 = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(1)?
        .build()?;
    let caller = wallet_1.address();

    // Mint test token to the caller
    let amount = U256::random();
    token
        .mint(caller, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Assert that the caller has 0 nonce and empty code before auto delegation
    let tx_count = provider.get_transaction_count(caller).await?;
    let code_before = provider.get_code_at(caller).await?;
    assert_eq!(tx_count, 0);
    assert!(code_before.is_empty());

    // Cache pre execution balances
    let sender_balance = token.balanceOf(caller).call().await?;
    assert_eq!(sender_balance, amount);
    let recipient = Address::random();
    let recipient_balance = token.balanceOf(recipient).call().await?;
    assert_eq!(recipient_balance, U256::ZERO);

    // Create the calldata to transfer test token
    let delegate_calldata = token
        .transfer(recipient, sender_balance)
        .calldata()
        .to_owned();

    // Create new provider with wallet_1 as signer
    let provider = ProviderBuilder::new()
        .wallet(wallet_1)
        .connect_http(http_url);

    let delegate_account = IthacaAccount::new(caller, provider.clone());
    let calls = vec![Call {
        to: *token.address(),
        value: alloy::primitives::U256::from(0),
        data: delegate_calldata,
    }];

    // Send the tx to the caller account with empty code
    let execute_call = delegate_account.execute(B256::ZERO, calls.abi_encode().into());
    let receipt = execute_call.send().await?.get_receipt().await?;
    assert!(receipt.status());

    // Assert state changes after delegation execution
    let sender_balance_after = token.balanceOf(caller).call().await?;
    let recipient_balance_after = token.balanceOf(recipient).call().await?;
    assert_eq!(sender_balance_after, U256::ZERO);
    assert_eq!(recipient_balance_after, amount);

    // Assert nonce incremented and code is updated to auto delegate account
    assert_eq!(provider.get_transaction_count(caller).await?, 1);
    let code_after = provider.get_code_at(caller).await?;
    assert_eq!(
        code_after,
        *Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS).bytecode()
    );

    Ok(())
}
