//! Tempo Arbitrage Bot
//! This binary launches an arb bot responsible for reblancing pools on the TIPFeeAMM

use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::{Address, U256},
    providers::ProviderBuilder,
    rpc::types::TransactionReceipt,
};
use clap::Parser;
use dashmap::DashMap;
use eyre::{Context, eyre};
use foundry_wallets::WalletOpts;
use futures::StreamExt;
use itertools::Itertools;
use std::{
    collections::HashSet,
    ops::{Div, Mul},
    sync::Arc,
    time::Duration,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    contracts::{
        ITIP20Factory, ITIPFeeAMM,
        ITIPFeeAMM::{Pool, RebalanceSwap},
        tip_fee_manager::amm::{N, SCALE},
        token_id_to_address,
    },
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument};
use tracing_subscriber::EnvFilter;

const RPC: &str = "http://100.110.210.109:8545";

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long, default_value = RPC)]
    rpc_url: String,

    #[command(flatten)]
    pub wallet: WalletOpts,
}

pub struct Bot {
    signer: Arc<EthereumWallet>,
    tokens: RwLock<HashSet<Address>>,
    pools: Arc<DashMap<(Address, Address), Pool>>,
}

impl Bot {
    pub fn new(signer: EthereumWallet) -> Self {
        Self {
            signer: Arc::new(signer),
            tokens: RwLock::new(HashSet::new()),
            pools: Arc::new(DashMap::new()),
        }
    }

    #[instrument(skip(self))]
    pub async fn fetch_tokens(&self) -> eyre::Result<HashSet<Address>> {
        let provider = ProviderBuilder::new()
            .wallet(self.signer.clone())
            .connect(RPC)
            .await?;
        let tip20_factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
        let last_token_id = tip20_factory.tokenIdCounter().call().await?.to::<u64>();
        let tokens = (0..last_token_id)
            .map(token_id_to_address)
            .collect::<HashSet<_>>();

        Ok(tokens)
    }

    pub async fn token_worker(&self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(self.signer.clone())
            .connect(RPC)
            .await?;
        let tip20_factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());
        let mut filter = tip20_factory.TokenCreated_filter().watch().await?;
        filter.poller.set_poll_interval(Duration::from_millis(200));
        let mut filter = filter.into_stream();

        while let Some(log) = filter.next().await {
            let (log, _) = log?;
            self.tokens.write().await.insert(log.token);
        }

        Ok(())
    }

    pub async fn update_pools(&self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new()
            .wallet(self.signer.clone())
            .connect(RPC)
            .await?;
        let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

        let tokens = self.tokens.read().await.clone();

        for token in tokens.iter().permutations(2) {
            let (&token_a, &token_b) = (token[0], token[1]);

            if self.pools.contains_key(&(token_a, token_b)) {
                continue;
            }

            let pool: eyre::Result<Pool, _> = fee_amm.getPool(token_a, token_b).call().await;
            match pool {
                Ok(pool) => {
                    self.pools.insert((token_a, token_b), pool);
                }
                Err(e) => {
                    // skip if pool is non existent
                    if e.as_revert_data().is_some() {
                        continue;
                    };

                    return Err(eyre!(
                        "failed to fetch pool {} -> {}: {}",
                        token_a,
                        token_b,
                        e
                    ));
                }
            }
        }

        Ok(())
    }

    pub async fn pool_worker(&self) -> eyre::Result<()> {
        loop {
            self.update_pools().await?;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn calculate_ratio(pool: &Pool) -> f64 {
        pool.reserveUserToken
            .mul(1000)
            .div(pool.reserveValidatorToken) as f64
            / 1000.0
    }

    #[instrument(skip(self, pool))]
    async fn rebalance_pool(
        &self,
        token_a: Address,
        token_b: Address,
        pool: &Pool,
    ) -> eyre::Result<()> {
        let signer = self.signer.clone();
        let provider = ProviderBuilder::new()
            .wallet(signer.clone())
            .connect(RPC)
            .await?;
        let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);

        let amount_in = U256::from(
            pool.reserveUserToken
                .checked_sub(pool.reserveValidatorToken)
                .unwrap()
                .div(2),
        );
        let amount_out = (amount_in - U256::ONE) * SCALE / N;

        let pools = self.pools.clone();
        tokio::spawn(async move {
            info!(%token_a, %token_b, %amount_out, "rebalancing pool");
            let tx = match fee_amm
                .rebalanceSwap(
                    token_a,
                    token_b,
                    amount_out,
                    signer.clone().default_signer().address(),
                )
                .send()
                .await
            {
                Ok(tx) => tx,
                Err(e) => {
                    error!(err=e.to_string(), %token_a, %token_b, %amount_out, "failed to rebalance pool");
                    return;
                }
            };

            let receipt: TransactionReceipt = match tx.get_receipt().await {
                Ok(receipt) => receipt,
                Err(e) => {
                    error!(err=e.to_string(), %token_a, %token_b, %amount_out, "failed to get rebalance pool receipt");
                    return;
                }
            };

            let log = match receipt.decoded_log::<RebalanceSwap>() {
                Some(log) => log,
                None => {
                    error!(%token_a, %token_b, %amount_out, "could not find rebalance pool log");
                    return;
                }
            };

            Self::update_pool(
                pools,
                log.userToken,
                log.validatorToken,
                log.amountIn,
                log.amountOut,
            );
        });
        Ok(())
    }

    pub fn update_pool(
        pools: Arc<DashMap<(Address, Address), Pool>>,
        token_a: Address,
        token_b: Address,
        amount_in: U256,
        amount_out: U256,
    ) {
        pools.entry((token_a, token_b)).and_modify(|pool| {
            pool.reserveUserToken = pool
                .reserveUserToken
                .checked_add(amount_in.to::<u128>())
                .expect("this should never overflow");
            pool.reserveValidatorToken = pool
                .reserveValidatorToken
                .checked_sub(amount_out.to::<u128>())
                .expect("this should never overflow");
        });
    }

    pub async fn worker(self) -> eyre::Result<()> {
        info!("starting worker");
        *self.tokens.write().await = self.fetch_tokens().await?;
        self.update_pools().await?;

        for entry in self.pools.iter() {
            let &(token_a, token_b) = entry.key();
            if Self::calculate_ratio(entry.value()) <= 1.15 {
                continue;
            }

            self.rebalance_pool(token_a, token_b, entry.value()).await?;
        }

        let provider = ProviderBuilder::new().connect(RPC).await?;
        let amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

        let mut logs = amm.FeeSwap_filter().watch().await?;
        logs.poller.set_poll_interval(Duration::from_millis(200));
        let mut logs = logs.into_stream();

        while let Some(log) = logs.next().await {
            let (log, metadata) = log?;
            info!(?log, ?metadata.block_number);
            Self::update_pool(
                self.pools.clone(),
                log.userToken,
                log.validatorToken,
                log.amountIn,
                log.amountOut,
            );

            let ratio = Self::calculate_ratio(
                &self
                    .pools
                    .get(&(log.userToken, log.validatorToken))
                    .unwrap(),
            );
            debug!(%ratio, "pool ratio");

            if ratio > 1.15 {
                self.rebalance_pool(
                    log.userToken,
                    log.validatorToken,
                    self.pools
                        .get(&(log.userToken, log.validatorToken))
                        .unwrap()
                        .value(),
                )
                .await
                .expect("failed");
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let bot = Bot::new(EthereumWallet::new(args.wallet.signer().await?));

    bot.worker().await.context("error in bot worker")?;

    Ok(())
}
