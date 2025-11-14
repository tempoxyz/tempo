use super::*;
use alloy::providers::DynProvider;
use alloy_consensus::TxLegacy;
use std::pin::Pin;
use tempo_contracts::precompiles::{
    IStablecoinExchange,
    IStablecoinExchange::{createPairCall, placeFlipCall},
};
use tempo_precompiles::stablecoin_exchange::{MAX_TICK, MIN_TICK, price_to_tick};

const GAS_LIMIT: u64 = 500_000;

async fn fetch_nonces(
    provider: impl Provider,
    max_concurrent_requests: usize,
    signers: impl IntoIterator<Item = PrivateKeySigner>,
) -> eyre::Result<Vec<(PrivateKeySigner, u64)>> {
    let mut futures = Vec::new();
    let mut signers_with_nonces = Vec::new();
    for signer in signers {
        let address = signer.address();
        let current_nonce = provider.get_transaction_count(address);
        futures.push(async move { (signer, current_nonce.await) });
    }

    let mut iter = stream::iter(futures).buffer_unordered(max_concurrent_requests);
    while let Some((signer, nonce)) = iter.next().await {
        let nonce = nonce.context("Failed to get transaction count")?;
        signers_with_nonces.push((signer.clone(), nonce));
    }
    Ok(signers_with_nonces)
}

/// This method performs a one-time setup for sending a lot of transactions:
/// * Adds a quote token and a couple of user tokens paired with the quote token.
/// * Mints some large amount for all `signers` and approves unlimited spending for stablecoin
///   exchange contract.
/// * Seeds initial liquidity by placing flip orders
pub(super) async fn setup(
    url: Url,
    mnemonic: &str,
    signers: Vec<PrivateKeySigner>,
    max_concurrent_requests: usize,
    chain_id: u64,
) -> eyre::Result<(
    IStablecoinExchangeInstance<DynProvider>,
    Address,
    Address,
    Address,
)> {
    println!("Sending DEX setup transactions...");

    let accounts = signers.len();

    let user_tokens_count = 2;
    let tokens_count = user_tokens_count + 1;
    let setup_test_token_tx_count = 2;
    let tx_count = ProgressBar::new(
        setup_test_token_tx_count * user_tokens_count
            + user_tokens_count
            + 2 * tokens_count * accounts as u64
            + user_tokens_count * accounts as u64,
    );
    tx_count.tick();

    // Setup HTTP provider with a test wallet
    let wallet = MnemonicBuilder::from_phrase(mnemonic).build()?;
    let caller = wallet.address();
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(url.clone());

    let base1 = setup_test_token(provider.clone(), caller, &tx_count).await?;
    let base2 = setup_test_token(provider.clone(), caller, &tx_count).await?;

    let quote = ITIP20Instance::new(token_id_to_address(0), provider.clone());

    let mint_amount = U256::from(1000000000000000u128);
    let first_order_amount = 1000000000000u128;

    let provider = ProviderBuilder::new().connect_http(url.clone());
    let mut nonce = provider.get_transaction_count(caller).await?;
    let user_tokens = [*base1.address(), *base2.address()];
    let tokens = [&base1, &base2, &quote];
    let mut futures = Vec::new();

    for token in user_tokens {
        let provider = provider.clone();
        let signer = wallet.clone();

        futures.push(Box::pin(async move {
            let tx = TxLegacy {
                chain_id: Some(chain_id),
                nonce,
                gas_limit: GAS_LIMIT,
                gas_price: TEMPO_BASE_FEE as u128,
                to: TxKind::Call(STABLECOIN_EXCHANGE_ADDRESS),
                value: U256::ZERO,
                input: createPairCall { base: token }.abi_encode().into(),
            };

            let tx = into_signed_encoded(tx, signer).expect("Signer should be valid");

            provider.send_raw_transaction(tx.as_slice()).await
        }) as Pin<Box<dyn Future<Output = _>>>);

        nonce += 1;
    }

    for signer in signers.iter() {
        for token in tokens {
            let recipient = signer.address();
            let signer = wallet.clone();
            let provider = provider.clone();

            futures.push(Box::pin(async move {
                {
                    let tx = TxLegacy {
                        chain_id: Some(chain_id),
                        nonce,
                        gas_price: TEMPO_BASE_FEE as u128,
                        gas_limit: GAS_LIMIT,
                        to: TxKind::Call(*token.address()),
                        value: U256::ZERO,
                        input: ITIP20::mintCall {
                            to: recipient,
                            amount: mint_amount,
                        }
                        .abi_encode()
                        .into(),
                    };

                    let tx = into_signed_encoded(tx, signer).expect("Signer should be valid");

                    provider.send_raw_transaction(tx.as_slice()).await
                }
            }) as Pin<Box<dyn Future<Output = _>>>);

            nonce += 1;
        }
    }

    join_all(futures, &tx_count, max_concurrent_requests)
        .await
        .wrap_err("Failed to join all 1")?;

    let mut futures = Vec::new();

    let signers_with_nonces: Vec<_> = fetch_nonces(&provider, max_concurrent_requests, signers)
        .await?
        .into_iter()
        .map(|(signer, nonce)| {
            let tokens = [*base1.address(), *base2.address(), *quote.address()];
            let length = tokens.len();

            for (i, token) in tokens.into_iter().enumerate() {
                let provider = provider.clone();
                let signer = signer.clone();

                futures.push(Box::pin(async move {
                    let tx = TxLegacy {
                        chain_id: Some(chain_id),
                        nonce: nonce + i as u64,
                        gas_price: TEMPO_BASE_FEE as u128,
                        gas_limit: 50_000,
                        to: TxKind::Call(token),
                        value: U256::ZERO,
                        input: ITIP20::approveCall {
                            spender: STABLECOIN_EXCHANGE_ADDRESS,
                            amount: U256::MAX,
                        }
                        .abi_encode()
                        .into(),
                    };

                    let tx = into_signed_encoded(tx, signer).expect("Signer should be valid");

                    provider.send_raw_transaction(tx.as_slice()).await
                }) as Pin<Box<dyn Future<Output = _>>>);
            }

            eyre::Ok((signer, nonce + length as u64))
        })
        .collect::<eyre::Result<_, _>>()?;

    join_all(futures, &tx_count, max_concurrent_requests)
        .await
        .wrap_err("Failed to join all 2")?;

    let tick_over = price_to_tick(100010);
    let tick_under = price_to_tick(99990);

    let mut futures = Vec::new();

    for (signer, nonce) in signers_with_nonces.into_iter() {
        for (i, token) in user_tokens.into_iter().enumerate() {
            let provider = provider.clone();
            let signer = signer.clone();

            futures.push(Box::pin(async move {
                let tx = TxLegacy {
                    chain_id: Some(chain_id),
                    nonce: nonce + i as u64,
                    gas_price: TEMPO_BASE_FEE as u128,
                    gas_limit: 1_000_000,
                    to: TxKind::Call(STABLECOIN_EXCHANGE_ADDRESS),
                    value: U256::ZERO,
                    input: placeFlipCall {
                        token,
                        amount: first_order_amount,
                        isBid: true,
                        tick: tick_under,
                        flipTick: tick_over,
                    }
                    .abi_encode()
                    .into(),
                };

                let tx = into_signed_encoded(tx, signer).expect("Signer should be valid");

                provider.send_raw_transaction(tx.as_slice()).await
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    join_all(futures, &tx_count, max_concurrent_requests)
        .await
        .wrap_err("Failed to join all 3")?;

    tokio::time::sleep(Duration::from_secs(10)).await;

    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone().erased());

    Ok((
        exchange,
        *quote.address(),
        *base1.address(),
        *base2.address(),
    ))
}

pub(super) fn place<P, N>(
    exchange: &IStablecoinExchangeInstance<P, N>,
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    token_address: Address,
) -> eyre::Result<Vec<u8>>
where
    N: Network<UnsignedTx: SignableTransaction<alloy::signers::Signature> + RlpEcdsaEncodableTx>,
    P: Provider<N>,
{
    let min_order_amount = MIN_ORDER_AMOUNT;
    let tick = (random::<u16>() % (MAX_TICK - MIN_TICK) as u16) as i16 + MIN_TICK;

    // Place an order at exactly the dust limit (should succeed)
    let tx = exchange
        .place(token_address, min_order_amount, true, tick)
        .into_transaction_request()
        .with_gas_limit(GAS_LIMIT)
        .with_gas_price(TEMPO_BASE_FEE as u128)
        .with_chain_id(chain_id)
        .with_nonce(nonce)
        .build_unsigned()?;

    into_signed_encoded(tx, signer)
}

pub(super) fn swap_in<P, N>(
    exchange: &IStablecoinExchangeInstance<P, N>,
    signer: PrivateKeySigner,
    nonce: u64,
    chain_id: ChainId,
    token_in: Address,
    token_out: Address,
) -> eyre::Result<Vec<u8>>
where
    N: Network<UnsignedTx: SignableTransaction<alloy::signers::Signature> + RlpEcdsaEncodableTx>,
    P: Provider<N>,
{
    let min_amount_out = 0;
    let min_order_amount = MIN_ORDER_AMOUNT;

    // Place an order at exactly the dust limit (should succeed)
    let tx = exchange
        .swapExactAmountIn(token_in, token_out, min_order_amount, min_amount_out)
        .into_transaction_request()
        .with_gas_limit(GAS_LIMIT)
        .with_gas_price(TEMPO_BASE_FEE as u128)
        .with_chain_id(chain_id)
        .with_nonce(nonce)
        .build_unsigned()?;

    into_signed_encoded(tx, signer)
}

/// Creates a test TIP20 token with issuer role granted to the caller
async fn setup_test_token<P>(
    provider: P,
    caller: Address,
    tx_count: &ProgressBar,
) -> eyre::Result<ITIP20Instance<P>>
where
    P: Provider + Clone,
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken(
            "Test".to_owned(),
            "TEST".to_owned(),
            "USD".to_owned(),
            LINKING_USD_ADDRESS,
            caller,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    tx_count.inc(1);
    let event = ITIP20Factory::TokenCreated::decode_log(&receipt.logs()[0].inner)?;

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
