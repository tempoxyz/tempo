//! Standalone development relay. Signing is opt-in and restricted to loopback.

use alloy_primitives::Address;
use alloy_signer_local::MnemonicBuilder;
use clap::Parser;
use std::{net::SocketAddr, sync::Arc};
use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;
use tempo_relay::{
    Backend, Relay, Request,
    external::ExternalFeePayers,
    http::{HttpBackend, serve},
    plugins::{FeeToken, Preflight},
    simulation::{FeeTokens, Simulate},
    sponsor::Sponsor,
    store::{
        Store,
        sql::{PostgresStore, SqliteStore},
    },
};

#[derive(Parser)]
#[command(name = "tempo-relay", about = "Tempo development JSON-RPC relay")]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    upstream: String,
    #[arg(long, default_value = "127.0.0.1:8547")]
    listen: SocketAddr,
    #[arg(long)]
    dev: bool,
    #[arg(
        long,
        requires = "dev",
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,
    #[arg(long, default_value_t = DEFAULT_FEE_TOKEN)]
    fee_token: Address,
    #[arg(long, default_value_t = 30_000_000)]
    max_gas: u64,
    #[arg(long, default_value_t = 100_000_000_000_u128)]
    max_fee_per_gas: u128,
    #[arg(long)]
    preflight: bool,
    /// SQLite or Postgres connection URL. Use the environment for credentials.
    #[arg(
        long,
        env = "TEMPO_RELAY_STORE",
        default_value = "sqlite://tempo-relay.sqlite"
    )]
    store: String,
    /// Additional liquid fee-token candidates for unsponsored fills.
    #[arg(long)]
    fee_token_candidate: Vec<Address>,
    /// HTTPS fee-payer endpoints explicitly permitted for forwarding.
    #[arg(long)]
    allow_fee_payer: Vec<String>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let args = Args::parse();
    if !args.listen.ip().is_loopback() {
        eyre::bail!(
            "Development relay must bind a loopback address; embed the crate for authenticated deployments"
        );
    }
    let backend = Arc::new(HttpBackend::new(&args.upstream)?);
    let chain_id = backend.request(Request::new("eth_chainId", vec![])).await?;
    let chain_id = u64::from_str_radix(
        chain_id
            .as_str()
            .and_then(|value| value.strip_prefix("0x"))
            .ok_or_else(|| eyre::eyre!("Invalid chain ID"))?,
        16,
    )?;
    if chain_id == 0 {
        eyre::bail!("Chain ID must be positive");
    }
    let store: Arc<dyn Store> = if args.store.starts_with("sqlite:") {
        Arc::new(SqliteStore::connect(&args.store).await?)
    } else if args.store.starts_with("postgres:") || args.store.starts_with("postgresql:") {
        Arc::new(PostgresStore::connect(&args.store).await?)
    } else {
        eyre::bail!("Store must be a SQLite or Postgres URL");
    };
    let mut external = ExternalFeePayers::new(false);
    for url in &args.allow_fee_payer {
        let url = tempo_relay::external::normalize(url, false)?;
        external = external.allow(&url, Arc::new(HttpBackend::new(&url)?))?;
    }
    let mut tokens = vec![args.fee_token];
    tokens.extend(
        args.fee_token_candidate
            .iter()
            .copied()
            .filter(|token| *token != args.fee_token),
    );
    let mut relay = Relay::new(backend.clone())
        .with_multisig(store.clone(), chain_id)
        .with_plugin(external)
        .with_plugin(FeeTokens::new(backend.clone(), tokens)?)
        .with_plugin(FeeToken(args.fee_token))
        .with_plugin(Simulate::new(chain_id, Some(store)));
    if args.preflight {
        relay = relay.with_plugin(Preflight);
    }
    if args.dev {
        if chain_id != 1337 {
            eyre::bail!("--dev sponsorship requires the Tempo development chain (1337)");
        }
        let signer = MnemonicBuilder::try_from_phrase_first(&args.mnemonic)?;
        eprintln!(
            "Development fee payer: {}; do not use this mnemonic for real funds",
            signer.address()
        );
        relay = relay.with_sponsor(Sponsor::new(
            Arc::new(signer),
            chain_id,
            args.fee_token,
            args.max_gas,
            args.max_fee_per_gas,
        )?)?;
    }
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!("Tempo relay listening on {}", listener.local_addr()?);
    serve(listener, relay, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
