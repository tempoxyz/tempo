use super::*;
use alloy::sol;

// Generate bindings from artifact
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    MockERC20,
    "artifacts/MockERC20.json"
}

/// Setup ERC-20 tokens for benchmarking:
/// - Deploy N ERC-20 tokens
/// - Mint equal amounts to all signers
pub(super) async fn setup(
    signer_providers: &[(PrivateKeySigner, DynProvider<TempoNetwork>)],
    num_tokens: usize,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<Vec<Address>> {
    let (_signer, provider) = signer_providers
        .first()
        .ok_or_eyre("No signer providers found")?;

    info!("Deploying ERC-20 tokens");
    let progress = ProgressBar::new(num_tokens as u64);

    // Deploy tokens
    let tokens = stream::iter((0..num_tokens).progress_with(progress))
        .map(|i| {
            let name = format!("BenchToken{}", i);
            let symbol = format!("BENCH{}", i);
            deploy_erc20(provider.clone(), name, symbol)
        })
        .buffered(max_concurrent_requests)
        .try_collect::<Vec<_>>()
        .await?;

    let token_addresses: Vec<Address> = tokens
        .iter()
        .map(|token| *token.address())
        .collect();

    // Mint tokens to all signers
    let mint_amount = U256::from(u128::MAX) / U256::from(signer_providers.len());
    info!(%mint_amount, "Minting ERC-20 tokens");

    join_all(
        signer_providers
            .iter()
            .flat_map(|(signer, _)| {
                tokens.iter().map(move |token| {
                    let token = token.clone();
                    let to = signer.address();
                    Box::pin(async move {
                        let tx = token.mint(to, mint_amount);
                        tx.send().await
                    }) as BoxFuture<'static, _>
                })
            })
            .progress_count((signer_providers.len() * tokens.len()) as u64),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await
    .context("Failed to mint ERC-20 tokens")?;

    Ok(token_addresses)
}

async fn deploy_erc20(
    provider: DynProvider<TempoNetwork>,
    name: String,
    symbol: String,
) -> eyre::Result<MockERC20::MockERC20Instance<DynProvider<TempoNetwork>, TempoNetwork>> {
    // Deploy with 18 decimals (standard for ERC-20)
    let contract = MockERC20::deploy(provider, name, symbol, 18u8).await?;
    Ok(contract)
}
