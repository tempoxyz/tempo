use crate::utils::{NodeSource, setup_test_node};
use alloy::{
    providers::{Provider, ProviderBuilder},
    signers::{
        SignerSync,
        local::{MnemonicBuilder, coins_bip39::English},
    },
    sol,
    sol_types::SolValue,
};
use alloy_primitives::{Address, B256, U256, b256, keccak256};
use reth_evm::revm::state::Bytecode;
use std::{env, str::FromStr};
use tempo_contracts::{DEFAULT_7702_DELEGATE_ADDRESS, IthacaAccount};
use tempo_precompiles::{
    TIP_ACCOUNT_REGISTRAR,
    contracts::{token_id_to_address, types::{ITIP20, ITipAccountRegistrar}},
};

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

    let alice = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let provider = ProviderBuilder::new()
        .wallet(alice)
        .connect_http(http_url.clone());

    // Use the pre-deployed token from genesis (token 0)
    let token_addr = token_id_to_address(0);
    let token = ITIP20::new(token_addr, provider.clone());

    // Init a fresh wallet with nonce 0
    let bob = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(1)?
        .build()?;
    let bob_addr = bob.address();

    // Transfer some tokens from alice to bob (enough for gas and transfers)
    let amount = U256::from(1_000_000u64);
    token
        .transfer(bob_addr, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    assert_eq!(provider.get_transaction_count(bob_addr).await?, 0);
    let code_before = provider.get_code_at(bob_addr).await?;
    assert!(code_before.is_empty(),);

    let bob_bal_before = token.balanceOf(bob_addr).call().await?;
    assert_eq!(bob_bal_before, amount);
    let recipient = Address::random();
    let recip_bal_before = token.balanceOf(recipient).call().await?;
    assert_eq!(recip_bal_before, U256::ZERO);

    let delegate_calldata = token
        .transfer(recipient, bob_bal_before)
        .calldata()
        .to_owned();

    let calls = vec![Call {
        to: *token.address(),
        value: U256::from(0),
        data: delegate_calldata,
    }];

    let bob_provider = ProviderBuilder::new().wallet(bob).connect_http(http_url);
    let delegate_account = IthacaAccount::new(bob_addr, bob_provider.clone());
    let execution_mode =
        B256::from_str("0x0100000000007821000100000000000000000000000000000000000000000000")
            .unwrap();

    println!("Executing 7702 delegate call from bob_addr: {}", bob_addr);
    let execute_call = delegate_account.execute(execution_mode, calls.abi_encode().into());
    println!("Sending transaction...");
    let pending = execute_call.send().await?;
    println!("Transaction sent, waiting for receipt...");
    let receipt = pending.get_receipt().await?;
    println!("Got receipt: {:?}", receipt.status());

    assert!(receipt.status(), "7702 delegate execution tx failed");
    assert_eq!(bob_provider.get_transaction_count(bob_addr).await?, 1);
    let code_after = bob_provider.get_code_at(bob_addr).await?;
    assert_eq!(
        code_after,
        *Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS).bytecode(),
    );

    // Assert state changes
    let bob_bal_after = token.balanceOf(bob_addr).call().await?;
    let recip_bal_after = token.balanceOf(recipient).call().await?;
    assert_eq!(bob_bal_after, U256::ZERO);
    assert_eq!(recip_bal_after, amount);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ensure_7702_delegation_on_revert() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _node_handle) = setup_test_node(source).await?;

    let alice = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let provider = ProviderBuilder::new()
        .wallet(alice)
        .connect_http(http_url.clone());

    // Init a new wallet with nonce 0
    let bob = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(1)?
        .build()?;
    let bob_addr = bob.address();

    assert_eq!(provider.get_transaction_count(bob_addr).await?, 0);
    let code_before = provider.get_code_at(bob_addr).await?;
    assert!(code_before.is_empty());

    let invalid_call = Call {
        to: Address::random(),
        value: U256::from(1),
        data: b"invalid_method()".to_vec().into(),
    };

    let bob_provider = ProviderBuilder::new().wallet(bob).connect_http(http_url);
    let delegate_account = IthacaAccount::new(bob_addr, bob_provider.clone());
    let execution_mode =
        B256::from_str("0x0100000000007821000100000000000000000000000000000000000000000000")
            .unwrap();

    let execute_call =
        delegate_account.execute(execution_mode, vec![invalid_call].abi_encode().into());

    let receipt = execute_call
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    assert!(!receipt.inner.is_success());

    let code_after = bob_provider.get_code_at(bob_addr).await?;
    assert_eq!(
        code_after,
        *Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS).bytecode(),
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_default_account_registrar() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let source = if let Ok(rpc_url) = env::var("RPC_URL") {
        NodeSource::ExternalRpc(rpc_url.parse()?)
    } else {
        NodeSource::LocalNode(include_str!("../assets/test-genesis.json").to_string())
    };
    let (http_url, _node_handle) = setup_test_node(source).await?;

    let alice = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;
    let provider = ProviderBuilder::new()
        .wallet(alice)
        .connect_http(http_url.clone());
    // Use the pre-deployed token from genesis (token 0)
    let token_addr = token_id_to_address(0);
    let token = ITIP20::new(token_addr, provider.clone());

    let bob = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .index(1)?
        .build()?;
    let bob_addr = bob.address();

    // Transfer some tokens from alice to bob (enough for gas and transfers)
    let amount = U256::from(1_000_000u64);
    token
        .transfer(bob_addr, amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    // Assert account has nonce 0 and empty code
    assert_eq!(provider.get_transaction_count(bob_addr).await?, 0);
    let code_before = provider.get_code_at(bob_addr).await?;
    assert!(code_before.is_empty());

    let hash = keccak256(b"test");
    let signature = bob.sign_hash_sync(&hash)?;

    // Create a new tx to delegate to the default 7702 impl
    let registrar = ITipAccountRegistrar::new(TIP_ACCOUNT_REGISTRAR, provider.clone());
    let registrar_call = registrar.delegateToDefault(hash, signature.as_bytes().into());
    let addr = registrar_call.call().await?;
    assert_eq!(addr, bob_addr);
    let receipt = registrar_call.send().await?.get_receipt().await?;
    assert!(receipt.status(), "TipAccountRegistrar call failed");

    let code_after = provider.get_code_at(bob_addr).await?;
    assert_eq!(
        code_after,
        *Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS).bytecode(),
    );

    // Ensure that the account can execute 7702 txs
    let recipient = Address::random();
    let bob_bal_before = token.balanceOf(bob_addr).call().await?;
    let recip_bal_before = token.balanceOf(recipient).call().await?;
    assert_eq!(bob_bal_before, amount);
    assert_eq!(recip_bal_before, U256::ZERO);

    let delegate_calldata = token
        .transfer(recipient, bob_bal_before)
        .calldata()
        .to_owned();

    let calls = vec![Call {
        to: *token.address(),
        value: U256::from(0),
        data: delegate_calldata,
    }];

    let bob_provider = ProviderBuilder::new().wallet(bob).connect_http(http_url);
    let delegate_account = IthacaAccount::new(bob_addr, bob_provider.clone());
    let execution_mode =
        b256!("0x0100000000007821000100000000000000000000000000000000000000000000");

    let execute_call = delegate_account.execute(execution_mode, calls.abi_encode().into());
    let receipt = execute_call.send().await?.get_receipt().await?;

    assert!(receipt.status(), "7702 delegate execution tx failed");
    assert_eq!(bob_provider.get_transaction_count(bob_addr).await?, 1);

    let bob_bal_after = token.balanceOf(bob_addr).call().await?;
    let recip_bal_after = token.balanceOf(recipient).call().await?;
    assert_eq!(bob_bal_after, U256::ZERO);
    assert_eq!(recip_bal_after, amount);

    Ok(())
}
