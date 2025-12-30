use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use eyre::{Result, eyre};
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusHandle;
use poem::{Response, handler};
use reqwest::Url;
use std::collections::{HashMap, HashSet};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    tip_fee_manager::ITIPFeeAMM::{self, ITIPFeeAMMInstance, Mint, Pool},
    tip20::{ITIP20, token_id_to_address},
    tip20_factory::ITIP20Factory,
};
use tracing::{debug, error, info, instrument};

pub struct TIP20Token {
    decimals: u8,
    name: String,
}

pub struct Monitor {
    rpc_url: Url,
    poll_interval: u64,
    tokens: HashMap<Address, TIP20Token>,
    pools: HashMap<(Address, Address), Pool>,
    known_pool_pairs: HashSet<(Address, Address)>,
    last_processed_block: u64,
}

impl Monitor {
    pub fn new(rpc_url: Url, poll_interval: u64) -> Self {
        Self {
            rpc_url,
            poll_interval,
            tokens: HashMap::new(),
            pools: HashMap::new(),
            known_pool_pairs: HashSet::new(),
            last_processed_block: 0,
        }
    }

    #[instrument(name = "monitor::update_tip20_tokens", skip(self))]
    async fn update_tip20_tokens(&mut self) -> Result<()> {
        let provider = ProviderBuilder::new()
            .connect(self.rpc_url.as_str())
            .await?;
        let tip20_factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider.clone());

        let last_token_id = tip20_factory
            .tokenIdCounter()
            .call()
            .await
            .map_err(|e| eyre!("{}", e))?
            .to::<u64>();

        info!(count = last_token_id + 1, "fetching tokens");

        for token_address in (0..last_token_id).map(token_id_to_address) {
            debug!("fetching token at address {}", token_address);
            if self.tokens.contains_key(&token_address) {
                debug!("token already exists, skipping");
                continue;
            }

            let token = ITIP20::new(token_address, provider.clone());
            let decimals = token.decimals().call().await.map_err(|e| {
                counter!("tempo_fee_amm_errors", "request" => "decimals").increment(1);
                eyre!(
                    "failed to fetch token decimals for {}: {}",
                    token_address,
                    e
                )
            })?;

            let name = token.name().call().await.map_err(|e| {
                counter!("tempo_fee_amm_errors", "request" => "decimals").increment(1);
                eyre!("failed to fetch token name for {}: {}", token_address, e)
            })?;

            self.tokens
                .insert(token_address, TIP20Token { decimals, name });
        }

        Ok(())
    }

    /// Discovers all pool pairs from historical Mint events (block 0 to current).
    /// Called once on startup.
    #[instrument(name = "monitor::discover_historical_pools", skip(self))]
    async fn discover_historical_pools(&mut self) -> Result<()> {
        let provider = ProviderBuilder::new()
            .connect(self.rpc_url.as_str())
            .await?;

        let current_block = provider.get_block_number().await?;

        let filter = Filter::new()
            .address(TIP_FEE_MANAGER_ADDRESS)
            .event_signature(Mint::SIGNATURE_HASH)
            .from_block(0)
            .to_block(current_block);

        let logs = provider.get_logs(&filter).await?;

        for log in logs {
            // Mint event: topic[1]=sender, topic[2]=userToken, topic[3]=validatorToken
            if log.topics().len() >= 4 {
                let user_token = Address::from_word(log.topics()[2]);
                let validator_token = Address::from_word(log.topics()[3]);
                self.known_pool_pairs.insert((user_token, validator_token));
            }
        }

        self.last_processed_block = current_block;
        info!(
            pools_discovered = self.known_pool_pairs.len(),
            last_block = current_block,
            "historical pool discovery complete"
        );

        Ok(())
    }

    /// Checks for new pools by querying Mint events since last processed block.
    /// Called each poll cycle.
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
            .to_block(current_block);

        let logs = provider.get_logs(&filter).await?;

        let mut new_pools = 0;
        for log in logs {
            if log.topics().len() >= 4 {
                let user_token = Address::from_word(log.topics()[2]);
                let validator_token = Address::from_word(log.topics()[3]);
                if self.known_pool_pairs.insert((user_token, validator_token)) {
                    new_pools += 1;
                }
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

        let fee_amm: ITIPFeeAMMInstance<_, _> = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);

        for &(token_a, token_b) in &self.known_pool_pairs {
            debug!(%token_a, %token_b, "fetching pool");

            let pool: Result<Pool, _> = fee_amm.getPool(token_a, token_b).call().await;
            match pool {
                Ok(pool) => {
                    self.pools.insert((token_a, token_b), pool);
                }
                Err(e) => {
                    // skip if pool is non existent
                    if e.as_revert_data().is_some() {
                        continue;
                    };

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
    async fn update_metrics(&self) {
        for ((token_a_address, token_b_address), pool) in self.pools.iter() {
            let (token_a_balance, token_b_balance) =
                (pool.reserveUserToken, pool.reserveValidatorToken);

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
        // Initial historical discovery
        if let Err(e) = self.discover_historical_pools().await {
            error!("failed to discover historical pools: {}", e);
        }

        loop {
            info!("updating pools and tokens");
            if let Err(e) = self.update_tip20_tokens().await {
                error!("failed to update tokens: {}", e);
            }
            if let Err(e) = self.check_for_new_pools().await {
                error!("failed to check for new pools: {}", e);
            }
            if let Err(e) = self.update_tip20_pools().await {
                error!("failed to update pools: {}", e);
            }
            self.update_metrics().await;
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
