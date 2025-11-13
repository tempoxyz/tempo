use super::*;
use std::pin::Pin;
use tempo_contracts::precompiles::IStablecoinExchange;
use tempo_precompiles::stablecoin_exchange::{MAX_TICK, MIN_TICK, price_to_tick};

const GAS_LIMIT: u64 = 500_000;

type DexProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

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
) -> eyre::Result<(
    IStablecoinExchangeInstance<DexProvider>,
    Address,
    Address,
    Address,
)> {
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
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(url.clone());

    let base1 = setup_test_token(provider.clone(), caller, &tx_count).await?;
    let base2 = setup_test_token(provider.clone(), caller, &tx_count).await?;

    let quote = ITIP20Instance::new(token_id_to_address(0), provider.clone());

    let mint_amount = U256::from(1000000000000000u128);
    let first_order_amount = 1000000000000u128;

    let user_tokens = [*base1.address(), *base2.address()];
    let mut receipts = Vec::new();
    let tokens = [&base1, &base2, &quote];
    let mut futures = Vec::new();

    for token in user_tokens {
        let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());

        futures.push(
            Box::pin(async move { exchange.createPair(token).send().await })
                as Pin<Box<dyn Future<Output = _>>>,
        );
    }

    for signer in signers.iter() {
        for token in &tokens {
            let recipient = signer.address();
            futures.push(
                Box::pin(async move { token.mint(recipient, mint_amount).send().await })
                    as Pin<Box<dyn Future<Output = _>>>,
            );
        }
    }

    join_all(futures, &mut receipts, &tx_count, max_concurrent_requests).await?;

    let mut futures = Vec::new();

    let signers: Vec<_> = signers
        .into_iter()
        .map(|signer| {
            ProviderBuilder::new()
                .wallet(signer.clone())
                .connect_http(url.clone())
        })
        .collect();
    for account_provider in signers.iter() {
        let base1 = ITIP20::new(*base1.address(), account_provider.clone());
        let base2 = ITIP20::new(*base2.address(), account_provider.clone());
        let quote = ITIP20::new(*quote.address(), account_provider.clone());
        let tokens = [base1, base2, quote];

        for token in tokens {
            futures.push(Box::pin(async move {
                token
                    .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
                    .send()
                    .await
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    join_all(futures, &mut receipts, &tx_count, max_concurrent_requests).await?;

    let tick_over = price_to_tick(100010);
    let tick_under = price_to_tick(99990);

    let mut futures = Vec::new();

    for account_provider in signers.into_iter() {
        for token in user_tokens {
            let exchange =
                IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, account_provider.clone());

            futures.push(Box::pin(async move {
                exchange
                    .placeFlip(token, first_order_amount, true, tick_under, tick_over)
                    .send()
                    .await
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    join_all(futures, &mut receipts, &tx_count, max_concurrent_requests).await?;

    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());

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
