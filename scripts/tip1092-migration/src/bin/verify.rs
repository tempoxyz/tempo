use alloy::providers::ProviderBuilder;
use clap::Parser;
use eyre::{Context, Result, bail};
use futures::{StreamExt, stream};
use std::{fs::File, io::Write, path::PathBuf};
use tempo_alloy::{
    TempoNetwork,
    chainspec::hardfork::TempoHardfork,
    contracts::precompiles::{ITIP403Registry, TIP403_REGISTRY_ADDRESS},
    provider::ext::TempoProviderExt,
};
use tempo_tip1092_migration::{
    DEFAULT_RPC_RETRIES, DEFAULT_SCAN_BLOCKS, Network, ScanConfig, ensure_chain, next_token_chunk,
};

#[derive(Debug, Parser)]
#[command(about = "Verify that every TIP-20 has a TIP-403 transfer-policy binding")]
struct Args {
    /// Target chain. Required to guard against checking the wrong network.
    #[arg(long, value_enum)]
    network: Network,

    /// Override the selected network's public RPC endpoint.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Initial block span for TokenCreated log queries. Failed queries are bisected.
    #[arg(long, default_value_t = DEFAULT_SCAN_BLOCKS)]
    scan_blocks: u64,

    /// Maximum concurrent TIP-403 lookup calls.
    #[arg(long, default_value_t = 64)]
    concurrency: usize,

    /// Number of retries for RPC log reads.
    #[arg(long, default_value_t = DEFAULT_RPC_RETRIES)]
    max_retries: u32,

    /// Write every missing or failed token lookup as newline-delimited JSON.
    #[arg(long)]
    report: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.scan_blocks == 0 || args.concurrency == 0 {
        bail!("--scan-blocks and --concurrency must be greater than zero");
    }

    let rpc_url = args
        .rpc_url
        .clone()
        .unwrap_or_else(|| args.network.rpc_url().to_owned());
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&rpc_url)
        .await
        .with_context(|| format!("failed to connect to {rpc_url}"))?;
    ensure_chain(&provider, args.network).await?;
    if !provider.is_hardfork_active(TempoHardfork::T9).await? {
        bail!("T9 is not active on the selected chain; TIP-1092 bindings are unavailable");
    }

    let head = alloy::providers::Provider::get_block_number(&provider)
        .await
        .context("failed to read latest block")?;
    let scan = ScanConfig {
        block_span: args.scan_blocks,
        max_retries: args.max_retries,
    };
    let mut report = args.report.as_ref().map(File::create).transpose()?;
    let mut checked = 0_u64;
    let mut missing = 0_u64;
    let mut failed = 0_u64;

    let genesis = verify_tokens(&provider, args.network.genesis_tokens(), args.concurrency).await;
    record_results(
        &genesis,
        &mut report,
        &mut checked,
        &mut missing,
        &mut failed,
    )?;

    let mut next_block = 0_u64;
    while next_block <= head {
        let chunk = next_token_chunk(&provider, next_block, head, &scan).await?;
        let results = verify_tokens(&provider, &chunk.tokens, args.concurrency).await;
        record_results(
            &results,
            &mut report,
            &mut checked,
            &mut missing,
            &mut failed,
        )?;
        println!(
            "verified blocks {}..={}: {} tokens (missing: {missing}, RPC failures: {failed})",
            chunk.from_block,
            chunk.to_block,
            chunk.tokens.len()
        );
        next_block = chunk.to_block.saturating_add(1);
    }

    println!(
        "verification complete at block {head}: {checked} tokens checked, {missing} missing bindings, {failed} RPC failures"
    );
    if missing != 0 || failed != 0 {
        bail!("TIP-1092 verification failed");
    }
    Ok(())
}

#[derive(Debug)]
enum Verification {
    Bound,
    Missing(alloy::primitives::Address, u64),
    Failed(alloy::primitives::Address, String),
}

async fn verify_tokens<P>(
    provider: &P,
    tokens: &[alloy::primitives::Address],
    concurrency: usize,
) -> Vec<Verification>
where
    P: alloy::providers::Provider<TempoNetwork>,
{
    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider);
    stream::iter(tokens.iter().copied())
        .map(|token| {
            let registry = &registry;
            async move {
                match registry.tokenTransferPolicyId(token).call().await {
                    Ok(result) if result.isSet => Verification::Bound,
                    Ok(result) => Verification::Missing(token, result.policyId),
                    Err(error) => Verification::Failed(token, error.to_string()),
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await
}

fn record_results(
    results: &[Verification],
    report: &mut Option<File>,
    checked: &mut u64,
    missing: &mut u64,
    failed: &mut u64,
) -> Result<()> {
    for result in results {
        *checked += 1;
        let line = match result {
            Verification::Bound => None,
            Verification::Missing(token, policy_id) => {
                *missing += 1;
                Some(serde_json::json!({
                    "token": token,
                    "status": "missing",
                    "fallbackPolicyId": policy_id,
                }))
            }
            Verification::Failed(token, error) => {
                *failed += 1;
                Some(serde_json::json!({
                    "token": token,
                    "status": "rpc_error",
                    "error": error,
                }))
            }
        };

        if let (Some(file), Some(line)) = (report.as_mut(), line) {
            writeln!(file, "{line}")?;
        }
    }
    Ok(())
}
