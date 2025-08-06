use std::{path::PathBuf, sync::OnceLock};

use serde::{Deserialize, Serialize};

use crate::utils::merge_toml_values;

/// Global configuration instance for the application.
static CONFIG_INSTANCE: OnceLock<Config> = OnceLock::new();

/// Initialize the global configuration instance.
pub fn init(config: Config) {
    CONFIG_INSTANCE.set(config).unwrap();
}

/// Gets the global configuration instance's value,
/// blocking until initialized if necessary.
pub fn get() -> &'static Config {
    CONFIG_INSTANCE.wait()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub tx_gen_worker: TxGenWorkerConfig,
    pub network_worker: NetworkWorkerConfig,
    pub rate_limiting: RateLimitingConfig,

    pub workers: WorkersConfig,
    pub reporters: ReportersConfig,
}

impl Config {
    pub fn from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let config_str = std::fs::read_to_string(path)?;
        let mut config_value: toml::Value = toml::from_str(&config_str)?;

        // Check if this config inherits from another.
        if let Some(inherits) = config_value.get("inherits").and_then(|v| v.as_str()) {
            // Load the inherited config recursively.
            let inherited_config = Self::from_file(&{
                if let Some(parent) = path.parent() {
                    parent.join(inherits)
                } else {
                    PathBuf::from(inherits)
                }
            })?;

            // Merge the current config over the inherited one.
            config_value =
                merge_toml_values(toml::Value::try_from(inherited_config)?, config_value);
        }

        // Remove the inherits field before deserializing.
        if let Some(table) = config_value.as_table_mut() {
            table.remove("inherits");
        }

        Ok(config_value.try_into()?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkWorkerConfig {
    pub target_urls: Vec<String>,
    pub total_connections: u64,

    pub batch_factor: usize,

    pub error_sleep_ms: u64,
    pub tx_queue_empty_sleep_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxGenWorkerConfig {
    pub chain_id: u64,

    pub mnemonic: String,
    pub num_accounts: u32,

    pub gas_price: u64,
    pub gas_limit: u64,

    pub token_contract_address: String,
    pub recipient_distribution_factor: u32,
    pub max_transfer_amount: u64,

    pub batch_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    pub initial_ratelimit: u64,
    pub ratelimit_thresholds: Vec<(u32, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkersConfig {
    pub thread_pinning: bool,
    pub tx_gen_worker_percentage: f64,
    pub network_worker_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportersConfig {
    pub tx_queue_report_interval_secs: u64,
    pub network_stats_report_interval_secs: u64,
}
