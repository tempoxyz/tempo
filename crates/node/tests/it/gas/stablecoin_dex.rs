use std::collections::BTreeMap;

use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::{MnemonicBuilder, PrivateKeySigner},
    sol_types::SolEvent,
};
use tempo_contracts::precompiles::{
    IRolesAuth, IStablecoinDEX,
    ITIP20::{self, ITIP20Instance},
    ITIP20Factory,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, STABLECOIN_DEX_ADDRESS, TIP20_FACTORY_ADDRESS,
    stablecoin_dex::MIN_ORDER_AMOUNT, tip20::ISSUER_ROLE,
};

use crate::utils::{TEST_MNEMONIC, TestNodeBuilder, await_receipts};

fn signer(index: u32) -> eyre::Result<PrivateKeySigner> {
    Ok(MnemonicBuilder::from_phrase(TEST_MNEMONIC)
        .index(index)?
        .build()?)
}

async fn approve<P: Provider + Clone>(
    provider: P,
    token: Address,
    spender: Address,
) -> eyre::Result<()> {
    let receipt = ITIP20::new(token, provider)
        .approve(spender, U256::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "approve failed");
    Ok(())
}

async fn setup_deterministic_test_token<P>(
    provider: P,
    caller: Address,
) -> eyre::Result<ITIP20Instance<impl Clone + Provider>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken_0(
            "Test".to_string(),
            "TEST".to_string(),
            "USD".to_string(),
            PATH_USD_ADDRESS,
            caller,
            B256::with_last_byte(0x62),
        )
        .gas(5_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "token creation failed");

    let event = receipt
        .logs()
        .iter()
        .find_map(|log| ITIP20Factory::TokenCreated::decode_log(&log.inner).ok())
        .ok_or_else(|| eyre::eyre!("TokenCreated event not found"))?;
    let token = ITIP20::new(event.token, provider.clone());

    let roles = IRolesAuth::new(*token.address(), provider);
    let receipt = roles
        .grantRole(*ISSUER_ROLE, caller)
        .gas(1_000_000)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "grant issuer role failed");

    Ok(token)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_stablecoin_dex_order_gas_snapshots() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let setup = TestNodeBuilder::new().build_http_only().await?;
    let http_url = setup.http_url;

    let admin = signer(0)?;
    let alice = signer(1)?;
    let bob = signer(2)?;
    let carol = signer(3)?;
    let dave = signer(4)?;

    let admin_provider = ProviderBuilder::new()
        .wallet(admin.clone())
        .connect_http(http_url.clone());
    let alice_provider = ProviderBuilder::new()
        .wallet(alice.clone())
        .connect_http(http_url.clone());
    let bob_provider = ProviderBuilder::new()
        .wallet(bob.clone())
        .connect_http(http_url.clone());
    let carol_provider = ProviderBuilder::new()
        .wallet(carol.clone())
        .connect_http(http_url.clone());
    let dave_provider = ProviderBuilder::new()
        .wallet(dave.clone())
        .connect_http(http_url);

    let base = setup_deterministic_test_token(admin_provider.clone(), admin.address()).await?;
    let quote = ITIP20Instance::new(PATH_USD_ADDRESS, admin_provider.clone());
    let base_addr = *base.address();
    let quote_addr = *quote.address();

    let mint_amount = U256::from(10_000_000_000u128);
    let mut pending = vec![];
    for account in [
        alice.address(),
        bob.address(),
        carol.address(),
        dave.address(),
    ] {
        pending.push(base.mint(account, mint_amount).send().await?);
        pending.push(quote.mint(account, mint_amount).send().await?);
    }
    await_receipts(&mut pending).await?;

    for provider in [
        alice_provider.clone(),
        bob_provider.clone(),
        carol_provider.clone(),
        dave_provider.clone(),
    ] {
        approve(provider.clone(), base_addr, STABLECOIN_DEX_ADDRESS).await?;
        approve(provider, quote_addr, STABLECOIN_DEX_ADDRESS).await?;
    }

    let admin_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, admin_provider);
    let receipt = admin_exchange
        .createPair(base_addr)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "createPair failed");

    let alice_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, alice_provider);
    let bob_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, bob_provider);
    let carol_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, carol_provider);
    let dave_exchange = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, dave_provider);

    let amount = MIN_ORDER_AMOUNT * 4;
    let mut gas = BTreeMap::new();

    let receipt = alice_exchange
        .place(base_addr, amount, true, 0)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "place bid failed");
    gas.insert("place_bid_empty_level", receipt.gas_used);

    let receipt = bob_exchange
        .place(base_addr, amount, true, 0)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "place bid tail failed");
    gas.insert("place_bid_append_same_level", receipt.gas_used);

    let receipt = alice_exchange
        .placeFlip(base_addr, amount, false, 10, 0)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "place flip ask failed");
    gas.insert("place_flip_ask_empty_level", receipt.gas_used);

    let receipt = bob_exchange.cancel(2).send().await?.get_receipt().await?;
    assert!(receipt.status(), "cancel failed");
    gas.insert("cancel_tail_bid_order", receipt.gas_used);

    let partial_fill = amount / 2;
    let quote_out = alice_exchange
        .quoteSwapExactAmountIn(base_addr, quote_addr, partial_fill)
        .call()
        .await?;
    assert!(quote_out > 0);
    let receipt = carol_exchange
        .swapExactAmountIn(base_addr, quote_addr, partial_fill, 0)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "partial swapExactAmountIn failed");
    gas.insert("swap_exact_in_partial_bid_fill", receipt.gas_used);

    let receipt = dave_exchange
        .swapExactAmountOut(quote_addr, base_addr, amount, u128::MAX)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(receipt.status(), "full flip swapExactAmountOut failed");
    gas.insert("swap_exact_out_full_flip_ask_fill", receipt.gas_used);

    eprintln!("\nStablecoinDEX order gas snapshot:");
    for (name, gas_used) in &gas {
        eprintln!("{name}: {gas_used}");
    }

    insta::assert_yaml_snapshot!(gas);

    Ok(())
}
