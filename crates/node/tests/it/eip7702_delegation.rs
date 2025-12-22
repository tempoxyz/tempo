use crate::utils::{TestNodeBuilder, setup_test_token};
use alloy::{
    providers::{Provider, ProviderBuilder, WalletProvider},
    signers::local::MnemonicBuilder,
    sol,
    sol_types::SolValue,
};
use alloy_primitives::{Address, B256, U256};
use reth_evm::revm::state::Bytecode;
use std::str::FromStr;
use tempo_contracts::{DEFAULT_7702_DELEGATE_ADDRESS, IthacaAccount};

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

    let setup = TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let alice = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new()
        .wallet(alice)
        .connect_http(http_url.clone());

    let deployer = provider.default_signer_address();
    let token = setup_test_token(provider.clone(), deployer).await?;

    // Init a fresh wallet with nonce 0
    let bob = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let bob_addr = bob.address();

    let transfer_amount = U256::from(1000);
    let mint_amount = transfer_amount * U256::from(3);
    token
        .mint(bob_addr, mint_amount)
        .send()
        .await?
        .get_receipt()
        .await?;

    assert_eq!(provider.get_transaction_count(bob_addr).await?, 0);
    let code_before = provider.get_code_at(bob_addr).await?;
    assert!(code_before.is_empty(),);

    let bob_bal_before = token.balanceOf(bob_addr).call().await?;
    assert_eq!(bob_bal_before, mint_amount);

    // Create three random recipients
    let recipient_0 = Address::random();
    let recipient_1 = Address::random();
    let recipient_2 = Address::random();

    // Verify initial balances
    let recip_0_bal_before = token.balanceOf(recipient_0).call().await?;
    let recip_1_bal_before = token.balanceOf(recipient_1).call().await?;
    let recip_2_bal_before = token.balanceOf(recipient_2).call().await?;
    assert_eq!(recip_0_bal_before, U256::ZERO);
    assert_eq!(recip_1_bal_before, U256::ZERO);
    assert_eq!(recip_2_bal_before, U256::ZERO);

    // Create batch transfer calldata
    let transfer_0_calldata = token
        .transfer(recipient_0, transfer_amount)
        .calldata()
        .to_owned();
    let transfer_1_calldata = token
        .transfer(recipient_1, transfer_amount)
        .calldata()
        .to_owned();
    let transfer_2_calldata = token
        .transfer(recipient_2, transfer_amount)
        .calldata()
        .to_owned();

    let calls = vec![
        Call {
            to: *token.address(),
            value: U256::from(0),
            data: transfer_0_calldata,
        },
        Call {
            to: *token.address(),
            value: U256::from(0),
            data: transfer_1_calldata,
        },
        Call {
            to: *token.address(),
            value: U256::from(0),
            data: transfer_2_calldata,
        },
    ];

    let bob_provider = ProviderBuilder::new().wallet(bob).connect_http(http_url);
    let delegate_account = IthacaAccount::new(bob_addr, bob_provider.clone());
    let execution_mode =
        B256::from_str("0x0100000000007821000100000000000000000000000000000000000000000000")
            .unwrap();

    let execute_call = delegate_account.execute(execution_mode, calls.abi_encode().into());
    let receipt = execute_call.send().await?.get_receipt().await?;

    assert!(receipt.status(), "7702 delegate execution tx failed");
    assert_eq!(bob_provider.get_transaction_count(bob_addr).await?, 1);
    let code_after = bob_provider.get_code_at(bob_addr).await?;
    assert_eq!(
        code_after,
        *Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS).bytecode(),
    );

    // Assert state changes
    let bob_bal_after = token.balanceOf(bob_addr).call().await?;
    let recip_0_bal_after = token.balanceOf(recipient_0).call().await?;
    let recip_1_bal_after = token.balanceOf(recipient_1).call().await?;
    let recip_2_bal_after = token.balanceOf(recipient_2).call().await?;

    // Bob should have spent 3 * transfer_amount
    assert_eq!(
        bob_bal_after,
        bob_bal_before - (transfer_amount * U256::from(3))
    );
    // Each recipient should have received transfer_amount
    assert_eq!(recip_0_bal_after, transfer_amount);
    assert_eq!(recip_1_bal_after, transfer_amount);
    assert_eq!(recip_2_bal_after, transfer_amount);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ensure_7702_delegation_on_revert() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new()
        .allegretto_activated()
        .build_http_only()
        .await?;
    let http_url = setup.http_url;

    let alice = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC).build()?;
    let provider = ProviderBuilder::new()
        .wallet(alice)
        .connect_http(http_url.clone());

    // Init a new wallet with nonce 0
    let bob = MnemonicBuilder::from_phrase(crate::utils::TEST_MNEMONIC)
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
