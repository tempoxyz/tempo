use super::*;
use alloy::sol;

sol! {
    #[sol(rpc)]
    #[allow(clippy::too_many_arguments)]
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

    info!(num_tokens, "Deploying ERC-20 tokens");
    let progress = ProgressBar::new(num_tokens as u64);

    // Deploy tokens
    let tokens = stream::iter((0..num_tokens).progress_with(progress))
        .map(|i| {
            MockERC20::deploy(
                provider.clone(),
                format!("BenchToken{}", i),
                format!("BENCH{}", i),
                18,
            )
        })
        .buffered(max_concurrent_requests)
        .try_collect::<Vec<_>>()
        .await?;

    let token_addresses: Vec<Address> = tokens.iter().map(|token| *token.address()).collect();

    // Mint tokens to all signers
    let mint_amount = U256::MAX / U256::from(signer_providers.len());
    info!(%mint_amount, "Minting ERC-20 tokens");

    join_all(
        signer_providers
            .iter()
            .map(|(signer, _)| signer.address())
            .flat_map(|to| {
                tokens.iter().cloned().map(move |token| {
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
