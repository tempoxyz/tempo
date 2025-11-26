use super::*;
use alloy::providers::DynProvider;
use indicatif::ProgressIterator;
use tempo_contracts::precompiles::{IStablecoinExchange, PATH_USD_ADDRESS};
use tempo_precompiles::tip20::U128_MAX;

/// This method performs a one-time setup for sending a lot of transactions:
/// * Deploys the specified number of user tokens.
/// * Creates DEX pairs of user tokens with the quote token.
/// * Mints user tokens for all signers and approves unlimited spending for DEX.
/// * Seeds initial liquidity by placing DEX flip orders.
pub(super) async fn setup(
    signer_providers: &[(PrivateKeySigner, DynProvider<TempoNetwork>)],
    fee_token: Address,
    user_tokens: usize,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<(Address, Vec<Address>)> {
    info!(
        signers = signer_providers.len(),
        %fee_token, user_tokens, "Setting up DEX"
    );

    // Grab first signer provider
    let (signer, provider) = signer_providers.first().unwrap();
    let caller = signer.address();

    let quote_token =
        setup_test_token(provider.clone(), fee_token, caller, PATH_USD_ADDRESS).await?;

    // Create `user_tokens` tokens
    info!("Creating tokens");
    let user_tokens = stream::iter((0..user_tokens).progress())
        .then(|_| setup_test_token(provider.clone(), fee_token, caller, *quote_token.address()))
        .try_collect::<Vec<_>>()
        .await?;
    let user_token_addresses = user_tokens
        .iter()
        .map(|token| *token.address())
        .collect::<Vec<_>>();

    let all_tokens = user_tokens
        .iter()
        .cloned()
        .chain(std::iter::once(quote_token.clone()))
        .collect::<Vec<_>>();
    let all_token_addresses = all_tokens
        .iter()
        .map(|token| *token.address())
        .collect::<Vec<_>>();

    // Create exchange pairs for each user token
    info!("Creating exchange pairs");
    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
    join_all(
        user_token_addresses.iter().copied().map(|token| {
            let exchange = exchange.clone();
            Box::pin(async move {
                let tx = exchange
                    .createPair(token)
                    .map(|request| request.with_fee_token(fee_token));
                tx.send().await
            }) as BoxFuture<'static, _>
        }),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    // Mint user tokens to each signer
    let mint_amount = U128_MAX / U256::from(signer_providers.len());
    info!(%mint_amount, "Minting tokens");
    join_all(
        signer_providers
            .iter()
            .map(|(signer, _)| signer.address())
            .flat_map(|signer| {
                #[expect(clippy::redundant_iter_cloned)] // False positive
                all_tokens.iter().cloned().map(move |token| {
                    Box::pin(async move {
                        let tx = token
                            .mint(signer, mint_amount)
                            .map(|request| request.with_fee_token(fee_token));
                        tx.send().await
                    }) as BoxFuture<'static, _>
                })
            })
            .progress_count((signer_providers.len() + all_tokens.len()) as u64),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    // Approve for each signer quote token and each user token to spend by exchange
    info!("Approving tokens");
    join_all(
        signer_providers
            .iter()
            .flat_map(|(_, provider)| {
                all_token_addresses.iter().copied().map(move |token| {
                    let token = ITIP20Instance::new(token, provider.clone());
                    Box::pin(async move {
                        let tx = token
                            .approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX)
                            .map(|request| request.with_fee_token(fee_token));
                        tx.send().await
                    }) as BoxFuture<'static, _>
                })
            })
            .progress_count((signer_providers.len() * all_tokens.len()) as u64),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    // Place flip orders of `order_amount` with tick `tick_over` and flip tick `tick_under` for each signer and each token
    let order_amount = 1000000000000u128;
    let tick_over = exchange.priceToTick(100010).call().await?;
    let tick_under = exchange.priceToTick(99990).call().await?;
    info!(order_amount, tick_over, tick_under, "Placing flip orders");
    join_all(
        signer_providers
            .iter()
            .flat_map(|(_, provider)| {
                user_token_addresses.iter().copied().map(move |token| {
                    let exchange = IStablecoinExchangeInstance::new(
                        STABLECOIN_EXCHANGE_ADDRESS,
                        provider.clone(),
                    );
                    Box::pin(async move {
                        let tx = exchange
                            .placeFlip(token, order_amount, true, tick_under, tick_over)
                            .map(|request| request.with_fee_token(fee_token));
                        tx.send().await
                    }) as BoxFuture<'static, _>
                })
            })
            .progress_count((signer_providers.len() * user_tokens.len()) as u64),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    Ok((*quote_token.address(), user_token_addresses))
}

/// Creates a test TIP20 token with issuer role granted to the provided address.
async fn setup_test_token(
    provider: DynProvider<TempoNetwork>,
    fee_token: Address,
    admin: Address,
    quote_token: Address,
) -> eyre::Result<ITIP20Instance<DynProvider<TempoNetwork>, TempoNetwork>>
where
{
    let factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
    let receipt = factory
        .createToken(
            "Test".to_owned(),
            "TEST".to_owned(),
            "USD".to_owned(),
            quote_token,
            admin,
        )
        .map(|request| request.with_fee_token(fee_token))
        .send()
        .await?
        .get_receipt()
        .await?;
    let event = receipt.logs()[0].log_decode::<ITIP20Factory::TokenCreated>()?;

    let token_addr = token_id_to_address(event.data().tokenId.to());
    let token = ITIP20::new(token_addr, provider.clone());
    let roles = IRolesAuth::new(*token.address(), provider);

    roles
        .grantRole(*ISSUER_ROLE, admin)
        .map(|request| request.with_fee_token(fee_token))
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(token)
}
