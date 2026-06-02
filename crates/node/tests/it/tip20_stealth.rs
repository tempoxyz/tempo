use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
    sol_types::SolEvent,
};
use tempo_chainspec::spec::TEMPO_T1_BASE_FEE;
use tempo_contracts::precompiles::{ITIP20, ITIP20Stealth, TIP20Error, TIP20StealthError};
use tempo_precompiles::TIP20_STEALTH_ADDRESS;

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, setup_test_token};

fn metadata(scheme: u8) -> Bytes {
    let mut metadata = vec![0u8; 35];
    metadata[0] = scheme;
    metadata[1] = 0x02;
    metadata[34] = 0xa7;
    metadata.into()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_stealth_transfer_e2e() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let admin = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let sender = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(1)?
        .build()?;
    let admin_provider = ProviderBuilder::new()
        .wallet(admin.clone())
        .connect_http(http_url.clone());
    let sender_provider = ProviderBuilder::new()
        .wallet(sender.clone())
        .connect_http(http_url);

    let token = setup_test_token(admin_provider.clone(), admin.address()).await?;
    let sender_token = ITIP20::new(*token.address(), sender_provider.clone());
    let stealth = ITIP20Stealth::new(TIP20_STEALTH_ADDRESS, sender_provider.clone());

    let initial_balance = U256::from(1_000);
    token
        .mint(sender.address(), initial_balance)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let code = sender_provider.get_code_at(TIP20_STEALTH_ADDRESS).await?;
    assert_eq!(code.as_ref(), &[0xef], "TIP20Stealth marker code missing");

    let stealth_address = Address::repeat_byte(0x42);
    let amount = U256::from(250);
    let metadata = metadata(0x01);
    let memo = Bytes::from_static(b"encrypted memo");

    assert_eq!(
        sender_token
            .allowance(sender.address(), TIP20_STEALTH_ADDRESS)
            .call()
            .await?,
        U256::ZERO
    );
    assert!(
        stealth
            .transfer(
                *token.address(),
                stealth_address,
                amount,
                metadata.clone(),
                memo.clone()
            )
            .call()
            .await?
    );

    let receipt = stealth
        .transfer(
            *token.address(),
            stealth_address,
            amount,
            metadata.clone(),
            memo.clone(),
        )
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "stealth transfer tx failed");

    assert_eq!(
        sender_token.balanceOf(sender.address()).call().await?,
        initial_balance - amount
    );
    assert_eq!(
        sender_token.balanceOf(stealth_address).call().await?,
        amount
    );
    assert_eq!(
        sender_token.balanceOf(TIP20_STEALTH_ADDRESS).call().await?,
        U256::ZERO
    );
    assert_eq!(
        sender_token
            .allowance(sender.address(), TIP20_STEALTH_ADDRESS)
            .call()
            .await?,
        U256::ZERO
    );

    let transfer = receipt
        .logs()
        .iter()
        .filter(|log| log.inner.address == *token.address())
        .find_map(|log| ITIP20::Transfer::decode_log(&log.inner).ok())
        .expect("TIP-20 Transfer event missing");
    assert_eq!(transfer.from, sender.address());
    assert_eq!(transfer.to, stealth_address);
    assert_eq!(transfer.amount, amount);

    let announce = receipt
        .logs()
        .iter()
        .filter(|log| log.inner.address == TIP20_STEALTH_ADDRESS)
        .find_map(|log| ITIP20Stealth::Announce::decode_log(&log.inner).ok())
        .expect("Announce event missing");
    assert_eq!(announce.token, *token.address());
    assert_eq!(announce.stealthAddress, stealth_address);
    assert_eq!(announce.metadata, metadata);
    assert_eq!(announce.memo, memo);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tip20_stealth_reverts_do_not_move_funds_e2e() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let admin = MnemonicBuilder::from_phrase(TEST_MNEMONIC).build()?;
    let sender = MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(2)?
        .build()?;
    let admin_provider = ProviderBuilder::new()
        .wallet(admin.clone())
        .connect_http(http_url.clone());
    let sender_provider = ProviderBuilder::new()
        .wallet(sender.clone())
        .connect_http(http_url);

    let token = setup_test_token(admin_provider.clone(), admin.address()).await?;
    let sender_token = ITIP20::new(*token.address(), sender_provider.clone());
    let stealth = ITIP20Stealth::new(TIP20_STEALTH_ADDRESS, sender_provider);

    let initial_balance = U256::from(1_000);
    token
        .mint(sender.address(), initial_balance)
        .gas_price(TEMPO_T1_BASE_FEE as u128)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;

    let stealth_address = Address::repeat_byte(0x77);
    let amount = U256::from(250);
    let err = stealth
        .transfer(
            *token.address(),
            stealth_address,
            amount,
            Bytes::new(),
            Bytes::new(),
        )
        .call()
        .await
        .expect_err("empty metadata must revert");
    assert_eq!(
        err.as_decoded_interface_error::<TIP20StealthError>(),
        Some(TIP20StealthError::invalid_metadata())
    );
    assert_eq!(
        sender_token.balanceOf(sender.address()).call().await?,
        initial_balance
    );
    assert_eq!(
        sender_token.balanceOf(stealth_address).call().await?,
        U256::ZERO
    );

    let err = sender_token
        .transferAsSystem(sender.address(), stealth_address, U256::ONE)
        .call()
        .await
        .expect_err("direct transferAsSystem must revert");
    assert_eq!(
        err.as_decoded_interface_error::<TIP20Error>(),
        Some(TIP20Error::unauthorized())
    );

    let err = sender_token
        .transfer(TIP20_STEALTH_ADDRESS, U256::ONE)
        .call()
        .await
        .expect_err("TIP20Stealth must not be a token recipient");
    assert_eq!(
        err.as_decoded_interface_error::<TIP20Error>(),
        Some(TIP20Error::invalid_recipient())
    );
    assert_eq!(
        sender_token.balanceOf(TIP20_STEALTH_ADDRESS).call().await?,
        U256::ZERO
    );

    Ok(())
}
