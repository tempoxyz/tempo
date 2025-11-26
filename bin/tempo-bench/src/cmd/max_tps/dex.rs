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
    chain_id: ChainId,
    mnemonic: &str,
    signers: Vec<PrivateKeySigner>,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<(StablecoinExchangeInstance, Address, Vec<TIP20Instance>)> {
    println!("Sending DEX setup transactions...");

    let user_tokens_count = 2;
    let tokens_count = user_tokens_count + 1;
    let signers_count = signers.len() as u64;
    let setup_test_token_tx_count = 2;
    let tx_count = ProgressBar::new(
        setup_test_token_tx_count * user_tokens_count
            + user_tokens_count
            + 2 * tokens_count * signers_count
            + user_tokens_count * signers_count,
    );
    tx_count.tick();

    // Setup HTTP provider with a test wallet
    let wallet = MnemonicBuilder::from_phrase(mnemonic).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(wallet.clone())
        .connect_http(url.clone())
        .erased();

    let base1 = setup_test_token(provider.clone(), caller, &tx_count).await?;
    let base2 = setup_test_token(provider.clone(), caller, &tx_count).await?;
    let user_tokens = [*base1.address(), *base2.address()];
    let base = vec![base1.clone(), base2.clone()];

    let quote_address = token_id_to_address(0);

    let mint_amount = U256::from(1000000000000000u128);
    let first_order_amount = 1000000000000u128;

    let tokens = [&base1, &base2];
    let mut futures = Vec::new();
    let nonce = provider.get_transaction_count(caller).await?;

    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());

    for (i, &token) in user_tokens.iter().enumerate() {
        let provider = provider.clone();
        let tx = create_pair(&exchange, wallet.clone(), nonce + i as u64, chain_id, token).await?;

        futures.push(Box::pin(async move {
            alloy::contract::Result::Ok(provider.send_raw_transaction(tx.as_slice()).await?)
        }) as Pin<Box<dyn Future<Output = _>>>);
    }

    let nonce = nonce + base.len() as u64;

    for (i, signer) in signers.iter().enumerate() {
        for (j, token) in tokens.iter().enumerate() {
            let provider = provider.clone();
            let recipient = signer.address();
            let tx = mint(
                token,
                wallet.clone(),
                nonce + (i as u64 * tokens.len() as u64) + j as u64,
                chain_id,
                recipient,
                mint_amount,
            )
            .await?;
            futures.push(Box::pin(async move {
                alloy::contract::Result::Ok(provider.send_raw_transaction(tx.as_slice()).await?)
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    join_all(
        futures,
        &tx_count,
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    let mut futures = Vec::new();
    let mut signers_with_nonce = Vec::with_capacity(signers_count as usize);

    for signer in signers {
        let nonce = provider.get_transaction_count(signer.address()).await?;
        let quote = ITIP20::new(quote_address, provider.clone());
        let tokens = base.clone().into_iter().chain(std::iter::once(quote));
        let tokens_count = base.len() as u64 + 1;

        for (i, token) in tokens.enumerate() {
            let provider = provider.clone();
            let tx = approve(&token, signer.clone(), nonce + i as u64, chain_id).await?;
            futures.push(Box::pin(async move {
                alloy::contract::Result::Ok(provider.send_raw_transaction(tx.as_slice()).await?)
            }) as Pin<Box<dyn Future<Output = _>>>);
        }

        signers_with_nonce.push((signer, nonce + tokens_count));
    }

    join_all(
        futures,
        &tx_count,
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    let tick_over = exchange.priceToTick(100010).call().await?;
    let tick_under = exchange.priceToTick(99990).call().await?;

    let mut futures = Vec::new();

    for (signer, nonce) in signers_with_nonce.into_iter() {
        for (i, &token) in user_tokens.iter().enumerate() {
            let provider = provider.clone();
            let tx = place_flip(
                &exchange,
                signer.clone(),
                nonce + i as u64,
                chain_id,
                token,
                first_order_amount,
                tick_under,
                tick_over,
            )
            .await?;

            futures.push(Box::pin(async move {
                alloy::contract::Result::Ok(provider.send_raw_transaction(tx.as_slice()).await?)
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    join_all(
        futures,
        &tx_count,
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone().erased());

    Ok((exchange, quote_address, base))
}

pub(super) async fn approve(
    token: &TIP20Instance,
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
) -> eyre::Result<Vec<u8>> {
    Ok(token
        .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .chain_id(chain_id)
        .nonce(nonce)
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn mint(
    token: &TIP20Instance,
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    recipient: Address,
    mint_amount: U256,
) -> eyre::Result<Vec<u8>> {
    Ok(token
        .mint(recipient, mint_amount)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .chain_id(chain_id)
        .nonce(nonce)
        .build_raw_transaction(signer)
        .await?)
}

#[expect(clippy::too_many_arguments)]
pub(super) async fn place_flip(
    exchange: &StablecoinExchangeInstance,
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    token: Address,
    amount: u128,
    tick_under: i16,
    tick_over: i16,
) -> eyre::Result<Vec<u8>> {
    Ok(exchange
        .placeFlip(token, amount, true, tick_under, tick_over)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .chain_id(chain_id)
        .nonce(nonce)
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn create_pair(
    exchange: &StablecoinExchangeInstance,
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    token_address: Address,
) -> eyre::Result<Vec<u8>> {
    Ok(exchange
        .createPair(token_address)
        .map(|request| {
            request
                .with_gas_limit(GAS_LIMIT)
                .with_gas_price(TEMPO_BASE_FEE as u128)
                .with_chain_id(chain_id)
                .with_nonce(nonce)
        })
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn place(
    exchange: &StablecoinExchangeInstance,
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    token_address: Address,
) -> eyre::Result<Vec<u8>> {
    let tick = (random::<u16>() % (MAX_TICK - MIN_TICK) as u16) as i16 + MIN_TICK;

    // Place an order at exactly the dust limit (should succeed)
    Ok(exchange
        .place(token_address, MIN_ORDER_AMOUNT, true, tick)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .chain_id(chain_id)
        .nonce(nonce)
        .build_raw_transaction(signer)
        .await?)
}

pub(super) async fn swap_in(
    exchange: &StablecoinExchangeInstance,
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    token_in: Address,
    token_out: Address,
) -> eyre::Result<Vec<u8>> {
    // Place an order at exactly the dust limit (should succeed)
    Ok(exchange
        .swapExactAmountIn(token_in, token_out, MIN_ORDER_AMOUNT, 0)
        .gas(GAS_LIMIT)
        .gas_price(TEMPO_BASE_FEE as u128)
        .chain_id(chain_id)
        .nonce(nonce)
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
