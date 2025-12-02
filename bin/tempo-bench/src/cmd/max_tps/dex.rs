use crate::cmd::signer_providers::BenchProvider;

use super::*;
use indicatif::ProgressIterator;
use tempo_contracts::precompiles::{IStablecoinExchange, PATH_USD_ADDRESS};
use tempo_precompiles::tip20::U128_MAX;

/// This method performs a one-time setup for sending a lot of transactions:
/// * Deploys the specified number of user tokens.
/// * Creates DEX pairs of user tokens with the quote token.
/// * Mints user tokens for all signers and approves unlimited spending for DEX.
/// * Seeds initial liquidity by placing DEX flip orders.
pub(super) async fn setup(
    signer_providers: &[(PrivateKeySigner, BenchProvider)],
    user_tokens: usize,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<(Address, Vec<Address>)> {
    // Grab first signer provider
    let (signer, provider) = signer_providers
        .first()
        .ok_or_eyre("No signer providers found")?;
    let caller = signer.address();

    info!("Creating tokens");
    let progress = ProgressBar::new(user_tokens as u64 + 1);
    // Create quote token
    let quote_token = setup_test_token(provider.clone(), caller, PATH_USD_ADDRESS).await?;
    progress.inc(1);
    // Create `user_tokens` tokens
    let user_tokens = stream::iter((0..user_tokens).progress_with(progress))
        .map(|_| setup_test_token(provider.clone(), caller, *quote_token.address()))
        .buffered(max_concurrent_requests)
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
        user_token_addresses
            .iter()
            .copied()
            .map(|token| {
                let exchange = exchange.clone();
                Box::pin(async move {
                    let tx = exchange.createPair(token);
                    tx.send().await
                }) as BoxFuture<'static, _>
            })
            .progress(),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await
    .context("Failed to create exchange pairs")?;

    // Mint user tokens to each signer
    let mint_amount = U128_MAX / U256::from(signer_providers.len());
    info!(%mint_amount, "Minting tokens");
    join_all(
        signer_providers
            .iter()
            .map(|(signer, _)| signer.address())
            .flat_map(|signer| {
                all_tokens.iter().map(move |token| {
                    let token = token.clone();
                    Box::pin(async move {
                        let tx = token.mint(signer, mint_amount);
                        tx.send().await
                    }) as BoxFuture<'static, _>
                })
            })
            .progress_count((signer_providers.len() * all_tokens.len()) as u64),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await
    .context("Failed to mint tokens")?;

    // Approve for each signer quote token and each user token to spend by exchange
    info!("Approving tokens");
    join_all(
        signer_providers
            .iter()
            .flat_map(|(_, provider)| {
                all_token_addresses.iter().copied().map(move |token| {
                    let token = ITIP20Instance::new(token, provider.clone());
                    Box::pin(async move {
                        let tx = token.approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX);
                        tx.send().await
                    }) as BoxFuture<'static, _>
                })
            })
            .progress_count((signer_providers.len() * all_tokens.len()) as u64),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await
    .context("Failed to approve tokens")?;

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
                        let tx =
                            exchange.placeFlip(token, order_amount, true, tick_under, tick_over);
                        tx.send().await
                    }) as BoxFuture<'static, _>
                })
            })
            .progress_count((signer_providers.len() * user_tokens.len()) as u64),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await
    .context("Failed to place flip orders")?;

    Ok((*quote_token.address(), user_token_addresses))
}

/// Creates a test TIP20 token with issuer role granted to the provided address.
async fn setup_test_token(
    provider: BenchProvider,
    admin: Address,
    quote_token: Address,
) -> eyre::Result<ITIP20Instance<BenchProvider, TempoNetwork>>
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
        .send()
        .await?
        .get_receipt()
        .await?;
    let event = receipt
        .decoded_log::<ITIP20Factory::TokenCreated>()
        .ok_or_eyre("Token creation event not found")?;
    assert_receipt(receipt)
        .await
        .context("Failed to create token")?;

    let token_addr = token_id_to_address(event.tokenId.to());
    let token = ITIP20::new(token_addr, provider.clone());
    let roles = IRolesAuth::new(*token.address(), provider);
    let grant_role_receipt = roles
        .grantRole(*ISSUER_ROLE, admin)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert_receipt(grant_role_receipt)
        .await
        .context("Failed to grant issuer role")?;

    Ok(token)
}
