use alloy::{
    primitives::{
        Address, B256,
        private::rand::{Rng, SeedableRng, rngs::StdRng},
    },
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use eyre::Result;
use futures::future::join_all;
use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusHandle;
use poem::{Response, handler};
use reqwest::Url;
use tempo_precompiles::{
    STABLECOIN_DEX_ADDRESS,
    stablecoin_dex::IStablecoinDEX::{self, PairCreated},
    tip20::ITIP20,
};
use tracing::{debug, error, info, instrument};

struct PairInfo {
    base: Address,
    quote: Address,
    base_name: String,
    quote_name: String,
    book_key: B256,
}

const MAX_BLOCK_RANGE: u64 = 100_000;

pub struct DexMonitor {
    poll_interval: u64,
    provider: Option<DynProvider>,
    known_pairs: Vec<PairInfo>,
    last_processed_block: u64,
    demo_profiles: Vec<(f64, f64, f64, f64)>,
}

impl DexMonitor {
    /// Creates a new monitor, connects to the node, and discovers existing trading pairs.
    #[instrument(name = "dex_monitor::new", skip_all)]
    pub async fn new(rpc_url: Url, poll_interval: u64) -> Result<Self> {
        let provider: DynProvider = ProviderBuilder::new()
            .connect(rpc_url.as_str())
            .await?
            .erased();

        let current_block = provider.get_block_number().await?;

        // Discover pairs by scanning PairCreated events in batches.
        let mut raw_pairs: Vec<(B256, Address, Address)> = Vec::new();
        let mut from_block = current_block.saturating_sub(MAX_BLOCK_RANGE);

        loop {
            let to_block = (from_block + MAX_BLOCK_RANGE).min(current_block);

            let filter = Filter::new()
                .address(STABLECOIN_DEX_ADDRESS)
                .event_signature(PairCreated::SIGNATURE_HASH)
                .from_block(from_block)
                .to_block(to_block);

            let logs = provider.get_logs(&filter).await?;

            for log in logs {
                if log.topics().len() < 4 {
                    continue;
                }
                let book_key = log.topics()[1];
                let base = Address::from_word(log.topics()[2]);
                let quote = Address::from_word(log.topics()[3]);

                if !raw_pairs.iter().any(|(k, ..)| *k == book_key) {
                    raw_pairs.push((book_key, base, quote));
                }
            }

            if to_block >= current_block {
                break;
            }
            from_block = to_block + 1;
        }

        // Second pass: fetch token names in parallel batches of 20.
        let provider_ref = &provider;
        let mut known_pairs = Vec::with_capacity(raw_pairs.len());
        for chunk in raw_pairs.chunks(20) {
            let addrs: Vec<Address> = chunk
                .iter()
                .flat_map(|(_, base, quote)| [*base, *quote])
                .collect();

            let futs: Vec<_> = addrs
                .iter()
                .map(|addr| {
                    let addr = *addr;
                    async move {
                        ITIP20::new(addr, provider_ref)
                            .name()
                            .call()
                            .await
                            .map(|n| n.to_string())
                            .unwrap_or_else(|_| format!("{:.8}", addr))
                    }
                })
                .collect();

            let names = join_all(futs).await;

            for (i, (book_key, base, quote)) in chunk.iter().enumerate() {
                let base_name = names[i * 2].clone();
                let quote_name = names[i * 2 + 1].clone();

                info!(
                    %base, %quote,
                    base_name, quote_name,
                    "discovered pair"
                );

                known_pairs.push(PairInfo {
                    base: *base,
                    quote: *quote,
                    base_name,
                    quote_name,
                    book_key: *book_key,
                });
            }
        }

        info!(
            pairs_discovered = known_pairs.len(),
            last_block = current_block,
            "pair discovery complete"
        );

        Ok(Self {
            poll_interval,
            provider: Some(provider),
            known_pairs,
            last_processed_block: current_block,
            demo_profiles: Vec::new(),
        })
    }

    /// Checks for new PairCreated events since last processed block.
    #[instrument(name = "dex_monitor::discover_new_pairs", skip(self))]
    async fn discover_new_pairs(&mut self) -> Result<()> {
        let provider = self
            .provider
            .as_ref()
            .expect("provider required for live mode");

        let current_block = provider.get_block_number().await?;
        if current_block <= self.last_processed_block {
            return Ok(());
        }

        let filter = Filter::new()
            .address(STABLECOIN_DEX_ADDRESS)
            .event_signature(PairCreated::SIGNATURE_HASH)
            .from_block(self.last_processed_block + 1)
            .to_block(current_block);

        let logs = provider.get_logs(&filter).await?;
        let mut new_pairs = 0;

        for log in logs {
            if log.topics().len() < 4 {
                continue;
            }
            let book_key = log.topics()[1];
            let base = Address::from_word(log.topics()[2]);
            let quote = Address::from_word(log.topics()[3]);

            if self.known_pairs.iter().any(|p| p.book_key == book_key) {
                continue;
            }

            let base_token = ITIP20::new(base, &provider);
            let quote_token = ITIP20::new(quote, &provider);

            let base_name = base_token
                .name()
                .call()
                .await
                .map(|n| n.to_string())
                .unwrap_or_else(|_| format!("{:.8}", base));
            let quote_name = quote_token
                .name()
                .call()
                .await
                .map(|n| n.to_string())
                .unwrap_or_else(|_| format!("{:.8}", quote));

            info!(%base, %quote, base_name, quote_name, "discovered new pair");

            self.known_pairs.push(PairInfo {
                base,
                quote,
                base_name,
                quote_name,
                book_key,
            });
            new_pairs += 1;
        }

        self.last_processed_block = current_block;
        if new_pairs > 0 {
            info!(new_pairs, "new pairs discovered");
        }

        Ok(())
    }

    /// Polls orderbook state for each known pair and updates Prometheus metrics.
    #[instrument(name = "dex_monitor::update_orderbook_metrics", skip(self))]
    async fn update_orderbook_metrics(&self) -> Result<()> {
        let provider = self
            .provider
            .as_ref()
            .expect("provider required for live mode");

        let dex = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider);

        match dex.nextOrderId().call().await {
            Ok(id) => {
                gauge!("tempo_dex_total_orders").set(id as f64);
            }
            Err(e) => {
                counter!("tempo_dex_monitor_errors", "request" => "next_order_id").increment(1);
                error!("failed to fetch nextOrderId: {e}");
            }
        }

        for pair in &self.known_pairs {
            // 1. Get orderbook state => spread
            let book = match dex.books(pair.book_key).call().await {
                Ok(b) => b,
                Err(e) => {
                    counter!("tempo_dex_monitor_errors", "request" => "books").increment(1);
                    error!(base = %pair.base, "failed to fetch books: {e}");
                    continue;
                }
            };

            let best_bid = book.bestBidTick;
            let best_ask = book.bestAskTick;

            if best_bid != i16::MIN && best_ask != i16::MAX {
                let spread = (best_ask - best_bid) as f64;
                gauge!("tempo_dex_spread_ticks",
                    "base_name" => pair.base_name.clone(),
                    "quote_name" => pair.quote_name.clone()
                )
                .set(spread);
            }

            // 2. Bid liquidity at best price
            if best_bid != i16::MIN {
                match dex.getTickLevel(pair.base, best_bid, true).call().await {
                    Ok(level) => {
                        gauge!("tempo_dex_best_bid_liquidity",
                            "base_name" => pair.base_name.clone(),
                            "quote_name" => pair.quote_name.clone()
                        )
                        .set(level.totalLiquidity as f64);
                    }
                    Err(e) => {
                        counter!("tempo_dex_monitor_errors", "request" => "tick_level_bid")
                            .increment(1);
                        debug!(base = %pair.base, "failed to fetch bid tick level: {e}");
                    }
                }
            }

            // 3. Ask liquidity at best price
            if best_ask != i16::MAX {
                match dex.getTickLevel(pair.base, best_ask, false).call().await {
                    Ok(level) => {
                        gauge!("tempo_dex_best_ask_liquidity",
                            "base_name" => pair.base_name.clone(),
                            "quote_name" => pair.quote_name.clone()
                        )
                        .set(level.totalLiquidity as f64);
                    }
                    Err(e) => {
                        counter!("tempo_dex_monitor_errors", "request" => "tick_level_ask")
                            .increment(1);
                        debug!(base = %pair.base, "failed to fetch ask tick level: {e}");
                    }
                }
            }

            // 4. Slippage estimation
            match dex
                .quoteSwapExactAmountIn(pair.base, pair.quote, 1_000_000_000u128)
                .call()
                .await
            {
                Ok(amount_out) => {
                    let slippage_bps = if amount_out > 0 {
                        ((1_000_000_000_f64 - amount_out as f64) / 1_000_000_000_f64 * 10_000_f64)
                            .abs()
                    } else {
                        0.0
                    };
                    gauge!("tempo_dex_slippage_bps",
                        "base_name" => pair.base_name.clone(),
                        "quote_name" => pair.quote_name.clone()
                    )
                    .set(slippage_bps);
                }
                Err(_) => {
                }
            }
        }

        Ok(())
    }

    #[instrument(name = "dex_monitor::worker", skip(self))]
    pub async fn worker(&mut self) {
        loop {
            info!("polling orderbooks");

            if let Err(e) = self.discover_new_pairs().await {
                error!("failed to discover new pairs: {e}");
            }

            if let Err(e) = self.update_orderbook_metrics().await {
                error!("failed to update orderbook metrics: {e}");
            }

            tokio::time::sleep(std::time::Duration::from_secs(self.poll_interval)).await;
        }
    }

    /// Monitor with simulated pairs for dashboard demonstration
    pub fn new_demo(poll_interval: u64) -> Self {
        let demo_pairs: Vec<(&str, f64, f64, f64, f64)> = vec![
            ("USDC", 5.0, 500_000_000.0, 450_000_000.0, 3.0),
            ("USDT", 8.0, 300_000_000.0, 280_000_000.0, 8.0),
            ("DAI", 15.0, 100_000_000.0, 90_000_000.0, 25.0),
            ("EURC", 25.0, 50_000_000.0, 45_000_000.0, 65.0),
            ("wBTC", 40.0, 20_000_000.0, 18_000_000.0, 150.0),
        ];

        let known_pairs = demo_pairs
            .iter()
            .enumerate()
            .map(|(i, (name, ..))| PairInfo {
                base: Address::ZERO,
                quote: Address::ZERO,
                base_name: name.to_string(),
                quote_name: "PathUSD".to_string(),
                book_key: B256::from([i as u8; 32]),
            })
            .collect();

        let demo_profiles = demo_pairs
            .iter()
            .map(|(_, spread, bid, ask, slip)| (*spread, *bid, *ask, *slip))
            .collect();

        info!(pairs = demo_pairs.len(), "demo mode initialized");

        Self {
            poll_interval,
            provider: None,
            known_pairs,
            last_processed_block: 0,
            demo_profiles,
        }
    }

    /// Polling loop with simulated data.
    pub async fn demo_worker(&mut self) {
        let mut rng = StdRng::from_os_rng();
        let mut total_orders: f64 = 1_250_000.0;

        loop {
            info!("demo: updating simulated metrics");

            // Total orders grows gradually
            total_orders += rng.random_range(50.0..500.0);
            gauge!("tempo_dex_total_orders").set(total_orders);

            for (pair, (spread_base, bid_base, ask_base, slip_base)) in
                self.known_pairs.iter().zip(self.demo_profiles.iter())
            {
                let mut jitter = || 1.0 + rng.random_range(-0.15..0.15);

                let spread = (spread_base * jitter()).max(1.0);
                let bid_liq = bid_base * jitter();
                let ask_liq = ask_base * jitter();
                let slippage = (slip_base * jitter()).max(0.0);

                gauge!("tempo_dex_spread_ticks",
                    "base_name" => pair.base_name.clone(),
                    "quote_name" => pair.quote_name.clone()
                )
                .set(spread);

                gauge!("tempo_dex_best_bid_liquidity",
                    "base_name" => pair.base_name.clone(),
                    "quote_name" => pair.quote_name.clone()
                )
                .set(bid_liq);

                gauge!("tempo_dex_best_ask_liquidity",
                    "base_name" => pair.base_name.clone(),
                    "quote_name" => pair.quote_name.clone()
                )
                .set(ask_liq);

                gauge!("tempo_dex_slippage_bps",
                    "base_name" => pair.base_name.clone(),
                    "quote_name" => pair.quote_name.clone()
                )
                .set(slippage);
            }

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
