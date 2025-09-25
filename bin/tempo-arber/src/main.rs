//! Tempo Arbitrage Bot
//! This binary launches an arb bot responsible for reblancing pools on the TIPFeeAMM

use std::time::Duration;

use alloy::{
    network::{EthereumWallet, TxSigner},
    providers::ProviderBuilder,
};
use clap::Parser;
use foundry_wallets::WalletOpts;
use futures::StreamExt;
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, contracts::ITIPFeeAMM};

const RPC: &str = "https://eng:zealous-mayer@rpc-adagietto.tempoxyz.dev ";

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long, default_value = RPC)]
    rpc_url: String,

    #[command(flatten)]
    pub wallet: WalletOpts,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let signer = EthereumWallet::new(args.wallet.signer().await?);
    let address = signer.default_signer().address();
    let provider = ProviderBuilder::new().wallet(signer).connect(RPC).await?;

    // Configure the Fee AMM contract ABI @ the Fee Manager address.
    let amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    // TODO: Convert to WSS subscription to avoid overriding the polling time.
    let mut logs = amm.FeeSwap_filter().watch().await?;
    logs.poller.set_poll_interval(Duration::from_millis(200));
    let mut logs = logs.into_stream();

    while let Some(log) = logs.next().await {
        let (log, metadata) = log?;
        tracing::info!(?log, ?metadata.block_number);
        let amm = amm.clone();
        tokio::spawn(async move {
            let tx = amm
                .rebalanceSwap(log.userToken, log.validatorToken, log.amountIn, address)
                .send()
                .await?;
            let receipt = tx.get_receipt().await?;
            tracing::info!(?receipt);
            Ok::<_, eyre::Error>(())
        });
    }

    // let blk = provider.get_block_number().await?;
    // dbg!(blk);

    Ok(())
}
