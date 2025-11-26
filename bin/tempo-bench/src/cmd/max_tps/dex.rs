use super::*;
use alloy::providers::DynProvider;
use std::pin::Pin;
use tempo_contracts::precompiles::{IStablecoinExchange, PATH_USD_ADDRESS};

pub(crate) type TIP20Instance = ITIP20Instance<DynProvider<TempoNetwork>, TempoNetwork>;
type StablecoinExchangeInstance =
    IStablecoinExchangeInstance<DynProvider<TempoNetwork>, TempoNetwork>;

/// This method performs a one-time setup for sending a lot of transactions:
/// * Adds a quote token and a couple of user tokens paired with the quote token.
/// * Mints some large amount for all `signers` and approves unlimited spending for stablecoin
///   exchange contract.
/// * Seeds initial liquidity by placing flip orders
pub(super) async fn setup(
    signer_providers: &[(PrivateKeySigner, DynProvider<TempoNetwork>)],
    user_tokens: usize,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<(Address, Vec<Address>)> {
    info!(user_tokens, "Setting up DEX");

    let tx_count = ProgressBar::new(0);

    // Grab first signer provider
    let (signer, provider) = signer_providers.first().unwrap();
    let caller = signer.address();

    tx_count.inc_length(user_tokens as u64 * 2);
    let user_tokens = stream::iter(0..user_tokens)
        .then(|_| setup_test_token(provider.clone(), caller, &tx_count))
        .try_collect::<Vec<_>>()
        .await?;
    let user_token_addresses = user_tokens
        .iter()
        .map(|token| *token.address())
        .collect::<Vec<_>>();

    let mut futures = Vec::new();

    let exchange = IStablecoinExchange::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
    for token in &user_tokens {
        let exchange = exchange.clone();
        futures.push(Box::pin(async move {
            let tx = exchange.createPair(*token.address());
            tx.send().await
        }) as Pin<Box<dyn Future<Output = _>>>);
    }

    let mint_amount = U256::from(1000000000000000u128);
    for (signer, _) in signer_providers {
        for token in &user_tokens {
            let token = token.clone();
            futures.push(Box::pin(async move {
                let tx = token.mint(signer.address(), mint_amount);
                tx.send().await
            }) as Pin<Box<dyn Future<Output = _>>>);
        }
    }

    let tokens = user_token_addresses
        .iter()
        .copied()
        .chain(std::iter::once(PATH_USD_ADDRESS))
        .collect::<Vec<_>>();
    for (_, provider) in signer_providers {
        for token in &tokens {
            let token = ITIP20Instance::new(*token, provider.clone());
            futures.push(Box::pin(async move {
                let tx = token.approve(STABLECOIN_EXCHANGE_ADDRESS, U256::MAX);
                tx.send().await
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

    let first_order_amount = 1000000000000u128;
    let tick_over = exchange.priceToTick(100010).call().await?;
    let tick_under = exchange.priceToTick(99990).call().await?;
    for (_, provider) in signer_providers {
        for token in &user_token_addresses {
            let exchange =
                StablecoinExchangeInstance::new(STABLECOIN_EXCHANGE_ADDRESS, provider.clone());
            futures.push(Box::pin(async move {
                let tx =
                    exchange.placeFlip(*token, first_order_amount, true, tick_under, tick_over);
                tx.send().await
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

    Ok((PATH_USD_ADDRESS, user_token_addresses))
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
