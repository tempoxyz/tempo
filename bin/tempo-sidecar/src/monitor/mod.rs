use alloy::{primitives::Address, providers::ProviderBuilder};
use eyre::{Result, eyre};
use itertools::Itertools;
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusHandle;
use poem::{Response, handler};
use reqwest::Url;
use std::collections::HashMap;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    tip_fee_manager::ITIPFeeAMM::{self, ITIPFeeAMMInstance, Pool},
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
}

impl Monitor {
    pub fn new(rpc_url: Url, poll_interval: u64) -> Self {
        Self {
            rpc_url,
            poll_interval,
            tokens: HashMap::new(),
            pools: HashMap::new(),
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

    #[instrument(name = "monitor::update_tip20_pools", skip(self))]
    async fn update_tip20_pools(&mut self) -> Result<()> {
        let provider = ProviderBuilder::new()
            .connect(self.rpc_url.as_str())
            .await?;

        let fee_amm: ITIPFeeAMMInstance<_, _> = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);

        for pool_addresses in self.tokens.keys().permutations(2) {
            let (&token_a, &token_b) = (pool_addresses[0], pool_addresses[1]);
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
        loop {
            info!("updating pools and tokens");
            if let Err(e) = self.update_tip20_tokens().await {
                error!("failed to update pools: {}", e);
            };
            if let Err(e) = self.update_tip20_pools().await {
                error!("failed to update pools: {}", e);
            };
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
