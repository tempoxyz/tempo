use alloy::{
    network::{EthereumWallet, ReceiptResponse},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use eyre::{Context, Result, bail};
use futures::{StreamExt, stream};
use std::{path::PathBuf, str::FromStr};
use tempo_alloy::{
    TempoNetwork,
    chainspec::hardfork::TempoHardfork,
    contracts::precompiles::{ITIP403Registry, TIP403_REGISTRY_ADDRESS},
    provider::ext::{TempoProviderBuilderExt, TempoProviderExt},
};
use tempo_tip1092_migration::{
    DEFAULT_RPC_RETRIES, DEFAULT_SCAN_BLOCKS, Network, Progress, ScanConfig, ensure_chain,
    load_state, next_token_chunk, retry_delay, save_state,
};

#[derive(Debug, Parser)]
#[command(about = "Migrate every existing TIP-20 transfer-policy binding into TIP-403")]
struct Args {
    /// Target chain. Required to guard against sending to the wrong network.
    #[arg(long, value_enum)]
    network: Network,

    /// Transaction signer. Prefer TEMPO_PRIVATE_KEY so the key is not recorded in shell history.
    #[arg(long, env = "TEMPO_PRIVATE_KEY", hide_env_values = true)]
    private_key: String,

    /// Override the selected network's public RPC endpoint.
    #[arg(long)]
    rpc_url: Option<String>,

    /// Number of token addresses included in each TIP-403 transaction.
    #[arg(long, default_value_t = 128)]
    batch_size: usize,

    /// Maximum concurrent transactions. Expiring nonces make these independent.
    #[arg(long, default_value_t = 4)]
    max_in_flight: usize,

    /// Initial block span for TokenCreated log queries. Failed queries are bisected.
    #[arg(long, default_value_t = DEFAULT_SCAN_BLOCKS)]
    scan_blocks: u64,

    /// Number of retries for RPC reads and transactions.
    #[arg(long, default_value_t = DEFAULT_RPC_RETRIES)]
    max_retries: u32,

    /// Durable progress file. A confirmed block range is never resent after restart.
    #[arg(long)]
    state_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.batch_size == 0 || args.max_in_flight == 0 || args.scan_blocks == 0 {
        bail!("--batch-size, --max-in-flight, and --scan-blocks must be greater than zero");
    }

    let rpc_url = args
        .rpc_url
        .clone()
        .unwrap_or_else(|| args.network.rpc_url().to_owned());
    let state_file = args.state_file.clone().unwrap_or_else(|| {
        PathBuf::from(format!(
            ".tip1092-migration-{}.json",
            args.network.chain_id()
        ))
    });

    let signer = PrivateKeySigner::from_str(&args.private_key)
        .context("failed to parse --private-key/TEMPO_PRIVATE_KEY")?;
    let signer_address = signer.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .with_expiring_nonces()
        .wallet(EthereumWallet::from(signer))
        .connect(&rpc_url)
        .await
        .with_context(|| format!("failed to connect to {rpc_url}"))?;

    ensure_chain(&provider, args.network).await?;
    if !provider.is_hardfork_active(TempoHardfork::T9).await? {
        bail!("T9 is not active on the selected chain; refusing to submit migration calls");
    }

    let mut progress =
        load_state::<Progress>(&state_file)?.unwrap_or_else(|| Progress::new(args.network));
    progress.validate(args.network)?;

    println!("network chain ID: {}", args.network.chain_id());
    println!("signer: {signer_address}");
    println!("state file: {}", state_file.display());
    println!(
        "using expiring nonces with up to {} transactions in flight",
        args.max_in_flight
    );

    if !progress.genesis_done {
        let tokens = args.network.genesis_tokens().to_vec();
        let confirmed = migrate_tokens(
            &provider,
            &tokens,
            args.batch_size,
            args.max_in_flight,
            args.max_retries,
        )
        .await?;
        progress.genesis_done = true;
        progress.tokens_seen += tokens.len() as u64;
        progress.transactions_confirmed += confirmed;
        save_state(&state_file, &progress)?;
        println!("confirmed migration of genesis TIP-20 batch");
    }

    let scan = ScanConfig {
        block_span: args.scan_blocks,
        max_retries: args.max_retries,
    };

    loop {
        let head = alloy::providers::Provider::get_block_number(&provider)
            .await
            .context("failed to read latest block")?;
        if progress.next_block > head {
            break;
        }

        let chunk = next_token_chunk(&provider, progress.next_block, head, &scan).await?;
        let confirmed = migrate_tokens(
            &provider,
            &chunk.tokens,
            args.batch_size,
            args.max_in_flight,
            args.max_retries,
        )
        .await?;

        progress.next_block = chunk.to_block.saturating_add(1);
        progress.tokens_seen += chunk.tokens.len() as u64;
        progress.transactions_confirmed += confirmed;
        save_state(&state_file, &progress)?;
        println!(
            "blocks {}..={}: {} tokens, {} confirmed transactions",
            chunk.from_block,
            chunk.to_block,
            chunk.tokens.len(),
            confirmed
        );
    }

    println!(
        "migration complete through block {}: {} tokens scanned, {} transactions confirmed",
        progress.next_block.saturating_sub(1),
        progress.tokens_seen,
        progress.transactions_confirmed
    );
    println!(
        "run scripts/tip1092-verify.sh --network {}",
        args.network.as_str()
    );
    Ok(())
}

async fn migrate_tokens<P>(
    provider: &P,
    tokens: &[alloy::primitives::Address],
    batch_size: usize,
    max_in_flight: usize,
    max_retries: u32,
) -> Result<u64>
where
    P: alloy::providers::Provider<TempoNetwork>,
{
    let batches = tokens
        .chunks(batch_size)
        .map(<[_]>::to_vec)
        .collect::<Vec<_>>();

    let results = stream::iter(batches)
        .map(|batch| migrate_batch(provider, batch, max_retries))
        .buffer_unordered(max_in_flight)
        .collect::<Vec<_>>()
        .await;

    for result in &results {
        result
            .as_ref()
            .map_err(|error| eyre::eyre!(error.to_string()))?;
    }
    Ok(results.len() as u64)
}

async fn migrate_batch<P>(
    provider: &P,
    tokens: Vec<alloy::primitives::Address>,
    max_retries: u32,
) -> Result<()>
where
    P: alloy::providers::Provider<TempoNetwork>,
{
    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider);
    let mut last_error = None;

    for attempt in 0..=max_retries {
        let result = async {
            let pending = registry
                .migrateTransferPolicyIds(tokens.clone())
                .send()
                .await?;
            let tx_hash = *pending.tx_hash();
            let receipt = pending.get_receipt().await?;
            if !receipt.status() {
                bail!("migration transaction {tx_hash} reverted");
            }
            println!("confirmed {tx_hash} ({} tokens)", tokens.len());
            Ok::<_, eyre::Report>(())
        }
        .await;

        match result {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt < max_retries {
                    eprintln!(
                        "batch of {} tokens failed (attempt {}); retrying with a fresh expiring nonce",
                        tokens.len(),
                        attempt + 1
                    );
                    tokio::time::sleep(retry_delay(attempt)).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| eyre::eyre!("migration batch failed")))
}
