use crate::cmd::max_tps::tip20::TIP20Instance;

use super::*;
use alloy::providers::DynProvider;
use std::pin::Pin;
use tempo_contracts::precompiles::{IStablecoinExchange, PATH_USD_ADDRESS};
use tempo_precompiles::stablecoin_exchange::{MAX_TICK, MIN_TICK};

type StablecoinExchangeInstance =
    IStablecoinExchangeInstance<DynProvider<TempoNetwork>, TempoNetwork>;

const GAS_LIMIT: u64 = 500_000;

/// This method performs a one-time setup for sending a lot of transactions:
/// * Adds a quote token and a couple of user tokens paired with the quote token.
/// * Mints some large amount for all `signers` and approves unlimited spending for stablecoin
///   exchange contract.
/// * Seeds initial liquidity by placing flip orders
pub(super) async fn setup(
    url: Url,
    mnemonic: &str,
    signers: Vec<PrivateKeySigner>,
    user_tokens: usize,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<(StablecoinExchangeInstance, Address, Vec<TIP20Instance>)> {
    let tx_count = ProgressBar::new(0);

    // Setup HTTP provider with a test wallet
    let wallet = MnemonicBuilder::from_phrase(mnemonic).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(wallet.clone())
        .with_cached_nonce_management()
        .connect_http(url.clone())
        .erased();

    tx_count.inc_length(user_tokens as u64);
    let user_tokens = stream::iter(0..user_tokens)
        .then(|_| setup_test_token(provider.clone(), caller, &tx_count))
        .try_collect::<Vec<_>>()
        .await?;

    let mint_amount = U256::from(1000000000000000u128);
    let first_order_amount = 1000000000000u128;

    let mut futures = Vec::new();

    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());

    for token in &user_tokens {
        let tx = create_pair(exchange.clone(), wallet.clone(), *token.address()).await?;

        let provider = provider.clone();
        futures.push(Box::pin(async move {
            alloy::contract::Result::Ok(provider.send_raw_transaction(&tx).await?)
        }) as Pin<Box<dyn Future<Output = _>>>);
    }

    for signer in &signers {
        for token in &user_tokens {
            let tx = mint(token, wallet.clone(), signer.address(), mint_amount).await?;

            let provider = provider.clone();
            futures.push(Box::pin(async move {
                alloy::contract::Result::Ok(provider.send_raw_transaction(&tx).await?)
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    let quote = ITIP20::new(PATH_USD_ADDRESS, provider.clone());
    for signer in &signers {
        let tokens = user_tokens.iter().chain(std::iter::once(&quote));
        for token in tokens {
            let tx = approve(token, signer.clone()).await?;

            let provider = provider.clone();
            futures.push(Box::pin(async move {
                alloy::contract::Result::Ok(provider.send_raw_transaction(&tx).await?)
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    tx_count.inc_length(futures.len() as u64);
    join_all(
        futures.drain(..),
        &tx_count,
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    let tick_over = exchange.priceToTick(100010).call().await?;
    let tick_under = exchange.priceToTick(99990).call().await?;

    for signer in signers {
        for token in &user_tokens {
            let tx = place_flip(
                exchange.clone(),
                signer.clone(),
                *token.address(),
                first_order_amount,
                tick_under,
                tick_over,
            )
            .await?;

            let provider = provider.clone();
            futures.push(Box::pin(async move {
                alloy::contract::Result::Ok(provider.send_raw_transaction(&tx).await?)
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    tx_count.inc_length(futures.len() as u64);
    join_all(
        futures,
        &tx_count,
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());

    Ok((exchange, PATH_USD_ADDRESS, user_tokens))
}

pub(super) async fn approve(
    token: &TIP20Instance,
    signer: PrivateKeySigner,
) -> eyre::Result<Vec<u8>> {
    Ok(token
        .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn mint(
    token: &TIP20Instance,
    signer: PrivateKeySigner,
    recipient: Address,
    mint_amount: U256,
) -> eyre::Result<Vec<u8>> {
    Ok(token
        .mint(recipient, mint_amount)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn place_flip(
    exchange: StablecoinExchangeInstance,
    signer: PrivateKeySigner,
    token: Address,
    amount: u128,
    tick_under: i16,
    tick_over: i16,
) -> eyre::Result<Vec<u8>> {
    Ok(exchange
        .placeFlip(token, amount, true, tick_under, tick_over)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn create_pair(
    exchange: StablecoinExchangeInstance,
    signer: PrivateKeySigner,
    token_address: Address,
) -> eyre::Result<Vec<u8>> {
    Ok(exchange
        .createPair(token_address)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn place(
    exchange: StablecoinExchangeInstance,
    signer: PrivateKeySigner,
    token_address: Address,
) -> eyre::Result<Vec<u8>> {
    let tick = (random::<u16>() % (MAX_TICK - MIN_TICK) as u16) as i16 + MIN_TICK;

    // Place an order at exactly the dust limit (should succeed)
    Ok(exchange
        .place(token_address, MIN_ORDER_AMOUNT, true, tick)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn swap_in(
    exchange: StablecoinExchangeInstance,
    signer: PrivateKeySigner,
    token_in: Address,
    token_out: Address,
) -> eyre::Result<Vec<u8>> {
    // Place an order at exactly the dust limit (should succeed)
    Ok(exchange
        .swapExactAmountIn(token_in, token_out, MIN_ORDER_AMOUNT, 0)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .build_raw_transaction(signer)
        .await?)
}

/// Creates a test TIP20 token with issuer role granted to the caller
async fn setup_test_token(
    provider: DynProvider<TempoNetwork>,
    caller: Address,
    tx_count: &ProgressBar,
) -> eyre::Result<TIP20Instance>
where
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken_0(
            "Test".to_owned(),
            "TEST".to_owned(),
            "USD".to_owned(),
            PATH_USD_ADDRESS,
            caller,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    tx_count.inc(1);
    let event = ITIP20Factory::TokenCreated_0::decode_log(&receipt.logs()[0].inner)?;

    let token_addr = token_id_to_address(event.tokenId.to());
    let token = ITIP20::new(token_addr, provider.clone());
    let roles = IRolesAuth::new(*token.address(), provider);

    roles
        .grantRole(*ISSUER_ROLE, caller)
        .send()
        .await?
        .get_receipt()
        .await?;
    tx_count.inc(1);

    Ok(token)
}
