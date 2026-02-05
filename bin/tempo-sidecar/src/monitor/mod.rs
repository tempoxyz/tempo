use alloy::{
    primitives::{
        Address,
        map::{AddressMap, AddressSet, HashMap, HashSet},
    },
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use eyre::{Result, eyre};
use futures::future::{join_all, try_join_all};
use itertools::Itertools;
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusHandle;
use poem::{Response, handler};
use rand_distr::num_traits::Zero;
use reqwest::Url;
use std::sync::Arc;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    tip_fee_manager::IFeeAMM::{self, IFeeAMMInstance, Mint, Pool},
    tip20::ITIP20,
};
use tracing::{debug, error, info, instrument};

pub struct TIP20Token {
    decimals: u8,
    name: String,
}

/// Configuration for the monitor.
struct MonitorConfig {
    rpc_url: Url,
    poll_interval: u64,
    target_tokens: AddressSet,
}

/// Initialized monitor with fetched token metadata.
pub struct Monitor {
    rpc_url: Url,
    poll_interval: u64,
    tokens: AddressMap<TIP20Token>,
    pools: HashMap<(Address, Address), Pool>,
    known_pairs: HashSet<(Address, Address)>,
    last_processed_block: u64,
}

trait FilterExt {
    fn with_minted_tokens<'a>(self, tokens: impl Iterator<Item = &'a Address>) -> Self;
}

impl FilterExt for Filter {
    /// Restricts the filter to events where both, topic 2 and topic 3, are among the input tokens.
    ///
    /// WARNING: Caller must ensure that the filter targets fee AMM mint events:
    /// - `Mint(address indexed sender, address indexed userToken, address indexed validatorToken, ..)`
    fn with_minted_tokens<'a>(mut self, tokens: impl Iterator<Item = &'a Address>) -> Self {
        for addr in tokens {
            let b256 = addr.into_word();
            self.topics[2].insert(b256);
            self.topics[3].insert(b256);
        }
        self
    }
}

impl MonitorConfig {
    pub fn new(rpc_url: Url, poll_interval: u64, target_tokens: AddressSet) -> Self {
        Self {
            rpc_url,
            poll_interval,
            target_tokens,
        }
    }

    /// Fetches token metadata, discovers existing pools, and returns an initialized `Monitor`.
    #[instrument(name = "monitor::init", skip(self))]
    pub async fn init(self) -> Result<Monitor> {
        let provider = Arc::new(
            ProviderBuilder::new()
                .connect(self.rpc_url.as_str())
                .await?,
        );

        // Fetch metadata for all whitelisted tokens
        let tokens = self.fetch_token_metadata(&provider).await?;

        // Discover existing pools by querying all token permutations
        let last_processed_block = provider.get_block_number().await?;
        let known_pairs = self.discover_pools(&provider).await?;

        info!(
            pools_discovered = known_pairs.len(),
            last_block = last_processed_block,
            "pool discovery complete"
        );

        Ok(Monitor {
            rpc_url: self.rpc_url,
            poll_interval: self.poll_interval,
            tokens,
            pools: Default::default(),
            known_pairs,
            last_processed_block,
        })
    }

    /// Fetches metadata for all whitelisted tokens.
    async fn fetch_token_metadata<P: Provider + Clone>(
        &self,
        provider: &Arc<P>,
    ) -> Result<AddressMap<TIP20Token>> {
        let get_token_metadata: Vec<_> = self
            .target_tokens
            .iter()
            .map(|addr| {
                debug!(%addr, "fetching token metadata");
                let token = ITIP20::new(*addr, provider.clone());
                async move {
                    let decimals = token.decimals().call().await.map_err(|e| {
                        counter!("tempo_fee_amm_errors", "request" => "decimals").increment(1);
                        eyre!("failed to fetch token decimals for {}: {}", addr, e)
                    })?;
                    let name = token.name().call().await.map_err(|e| {
                        counter!("tempo_fee_amm_errors", "request" => "name").increment(1);
                        eyre!("failed to fetch token name for {}: {}", addr, e)
                    })?;
                    Ok::<_, eyre::Error>((*addr, TIP20Token { decimals, name }))
                }
            })
            .collect();

        try_join_all(get_token_metadata)
            .await
            .map(|v| v.into_iter().collect())
    }

    /// Discovers existing pools by querying all token permutations in parallel.
    async fn discover_pools<P: Provider + Clone>(
        &self,
        provider: &Arc<P>,
    ) -> Result<HashSet<(Address, Address)>> {
        let check_pool_futures: Vec<_> = self
            .target_tokens
            .iter()
            .permutations(2)
            .map(|pair| {
                let (token_a, token_b) = (*pair[0], *pair[1]);
                let fee_amm = IFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
                async move {
                    match fee_amm.getPool(token_a, token_b).call().await {
                        Ok(pool) => {
                            // Skip if pool isn't initialized.
                            if pool.reserve_user_token.is_zero() {
                                None
                            } else {
                                debug!(%token_a, %token_b, "discovered pool");
                                Some((token_a, token_b))
                            }
                        }
                        Err(e) => {
                            counter!("tempo_fee_amm_errors", "request" => "pool").increment(1);
                            error!(%token_a, %token_b, "failed to fetch pool: {}", e);
                            None
                        }
                    }
                }
            })
            .collect();

        let results = join_all(check_pool_futures).await;
        Ok(results.into_iter().flatten().collect())
    }
}

impl Monitor {
    /// Creates a new `Monitor` by fetching token metadata and discovering historical pools.
    pub async fn new(rpc_url: Url, poll_interval: u64, target_tokens: AddressSet) -> Result<Self> {
        MonitorConfig::new(rpc_url, poll_interval, target_tokens)
            .init()
            .await
    }

    /// Checks for new pools by querying `Mint` events since last processed block.
    #[instrument(name = "monitor::check_for_new_pools", skip(self))]
    async fn check_for_new_pools(&mut self) -> Result<()> {
        let provider = ProviderBuilder::new()
            .connect(self.rpc_url.as_str())
            .await?;

        let current_block = provider.get_block_number().await?;

        if current_block <= self.last_processed_block {
            return Ok(());
        }

        let filter = Filter::new()
            .address(TIP_FEE_MANAGER_ADDRESS)
            .event_signature(Mint::SIGNATURE_HASH)
            .from_block(self.last_processed_block + 1)
            .to_block(current_block)
            .with_minted_tokens(self.tokens.keys());

        let logs = provider.get_logs(&filter).await?;

        let mut new_pools = 0;
        for log in logs {
            let (user_token, validator_token) = parse_mint_tokens(&log);
            if self.known_pairs.insert((user_token, validator_token)) {
                new_pools += 1;
            }
        }

        self.last_processed_block = current_block;
        if new_pools > 0 {
            info!(new_pools, "discovered new pools");
        }

        Ok(())
    }

    #[instrument(name = "monitor::update_tip20_pools", skip(self))]
    async fn update_tip20_pools(&mut self) -> Result<()> {
        let provider = ProviderBuilder::new()
            .connect(self.rpc_url.as_str())
            .await?;

        let fee_amm: IFeeAMMInstance<_, _> = IFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);

        for &(token_a, token_b) in &self.known_pairs {
            debug!(%token_a, %token_b, "fetching pool");

            let pool: Result<Pool, _> = fee_amm.getPool(token_a, token_b).call().await;
            match pool {
                Ok(pool) => {
                    // Skip if pool isn't initialized.
                    if pool.reserve_user_token.is_zero() {
                        continue;
                    }

                    self.pools.insert((token_a, token_b), pool);
                }
                Err(e) => {
                    counter!("tempo_fee_amm_errors", "request" => "pool").increment(1);

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

    #[instrument(name = "monitor::update_metrics", skip(self))]
    fn update_metrics(&self) {
        for ((token_a_address, token_b_address), pool) in self.pools.iter() {
            let (token_a_balance, token_b_balance) =
                (pool.reserve_user_token, pool.reserve_validator_token);

            let token_a = match self.tokens.get(token_a_address) {
                Some(token) => token,
                None => continue,
            };

            let token_b = match self.tokens.get(token_b_address) {
                Some(token) => token,
                None => continue,
            };

            gauge!(
                "tempo_fee_amm_user_token_reserves",
                "token_a" => token_a_address.to_string(),
                "token_b" => token_b_address.to_string(),
                "token_a_name" => token_a.name.to_string(),
                "token_b_name" => token_b.name.to_string()
            )
            .set((token_a_balance / 10u128.pow(token_a.decimals as u32)) as f64);

            gauge!(
                "tempo_fee_amm_validator_token_reserves",
                "token_a" => token_a_address.to_string(),
                "token_b" => token_b_address.to_string(),
                "token_a_name" => token_a.name.to_string(),
                "token_b_name" => token_b.name.to_string()
            )
            .set((token_b_balance / 10u128.pow(token_b.decimals as u32)) as f64);
        }
    }

    #[instrument(name = "monitor::worker", skip(self))]
    pub async fn worker(&mut self) {
        loop {
            info!("updating pools");
            if let Err(e) = self.check_for_new_pools().await {
                error!("failed to check for new pools: {}", e);
            }
            if let Err(e) = self.update_tip20_pools().await {
                error!("failed to update pools: {}", e);
            }
            self.update_metrics();
            tokio::time::sleep(std::time::Duration::from_secs(self.poll_interval)).await;
        }
    }
}

#[handler]
pub async fn prometheus_metrics(handle: poem::web::Data<&PrometheusHandle>) -> Response {
    let metrics = handle.render();
    Response::builder()
        .header("content-type", "text/plain")
        .body(metrics)
}

/// Parses user and validator token addresses from a `FeeAMM::Mint` event log.
///
/// WARNING: Caller is responsible for ensuring the input is a `FeeAMM::Mint` event.
fn parse_mint_tokens(log: &Log) -> (Address, Address) {
    (
        Address::from_word(log.topics()[2]),
        Address::from_word(log.topics()[3]),
    )
}
