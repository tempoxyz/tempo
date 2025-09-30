use crate::synthetic_load::SyntheticLoadGenerator;
use alloy::primitives::{Address, address};
use clap::Parser;
use reqwest::Url;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
pub struct SyntheticLoadArgs {
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    #[arg(short, long, required = true)]
    rpc_url: Url,

    #[arg(long, default_value_t = 10)]
    wallet_count: usize,

    #[arg(long, default_value_t = 10)]
    average_tps: usize,

    #[arg(long, default_values_t = vec![address!("0x20C0000000000000000000000000000000000000")])]
    fee_token_addresses: Vec<Address>,

    #[arg(long)]
    seed: Option<u64>,
}

impl SyntheticLoadArgs {
    pub async fn run(&self) -> eyre::Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .init();

        let generator = SyntheticLoadGenerator::new(
            self.mnemonic.clone(),
            self.rpc_url.clone(),
            self.wallet_count,
            self.average_tps,
            self.fee_token_addresses.clone(),
            self.seed,
        );

        generator.worker().await?;

        Ok(())
    }
}
