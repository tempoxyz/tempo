//! Shared endpoint and checkpoint configuration with command-specific settings.

use crate::{
    source::{TempoProvider, connect},
    state::ReplayIdentity,
};
use alloy::primitives::B256;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

/// Shared configuration loaded by all `tempo-replay` commands.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub chain_id: u64,
    pub source: Endpoint,
    pub target: Option<Endpoint>,
    pub checkpoint: Option<Checkpoint>,
    pub run: Option<Run>,
    pub audit: Option<Audit>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(
            &std::fs::read_to_string(path)
                .with_context(|| format!("read config {}", path.display()))?,
        )
        .with_context(|| format!("parse config {}", path.display()))?;
        ensure!(config.chain_id > 0, "chain id must be positive");
        Ok(config)
    }

    pub fn run(&self) -> Result<(&Endpoint, &Checkpoint, &Run)> {
        let (target, checkpoint) = self.target_checkpoint("run")?;
        let run = self.run.as_ref().context("run requires [run]")?;
        ensure!(run.concurrency() > 0, "run concurrency must be positive");
        ensure!(
            run.store.max_bytes() > 0,
            "run database limit must be positive"
        );
        ensure!(
            checkpoint.source_hash != checkpoint.target_hash,
            "source and patched target checkpoint hashes must differ"
        );
        Ok((target, checkpoint, run))
    }

    pub fn audit(&self) -> Result<(&Endpoint, &Checkpoint, &Audit)> {
        let (target, checkpoint) = self.target_checkpoint("audit")?;
        let audit = self.audit.as_ref().context("audit requires [audit]")?;
        ensure!(
            audit.missing_after_blocks() > 0 || !audit.missing_after().is_zero(),
            "audit missing horizon must be positive"
        );
        ensure!(
            audit.store.max_bytes() > 0,
            "audit database limit must be positive"
        );
        ensure!(
            checkpoint.source_hash != checkpoint.target_hash,
            "source and patched target checkpoint hashes must differ"
        );
        Ok((target, checkpoint, audit))
    }

    fn target_checkpoint(&self, command: &str) -> Result<(&Endpoint, &Checkpoint)> {
        Ok((
            self.target
                .as_ref()
                .with_context(|| format!("{command} requires [target]"))?,
            self.checkpoint
                .as_ref()
                .with_context(|| format!("{command} requires [checkpoint]"))?,
        ))
    }
}

/// RPC endpoint with optional bearer-token and private-CA configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub url: String,
    pub credential_env: Option<String>,
    pub ca_file: Option<PathBuf>,
}

impl Endpoint {
    pub fn connect(&self) -> Result<TempoProvider> {
        let url = reqwest::Url::parse(&self.url).context("invalid RPC URL")?;
        ensure!(url.scheme() == "https", "RPC endpoints must use HTTPS");
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "RPC URL cannot embed credentials, query parameters, or fragments"
        );
        let credential = self
            .credential_env
            .as_ref()
            .map(|name| std::env::var(name).with_context(|| format!("read credential from {name}")))
            .transpose()?;
        let ca = self
            .ca_file
            .as_ref()
            .map(|path| std::fs::read(path).with_context(|| format!("read CA {}", path.display())))
            .transpose()?;
        connect(&self.url, credential.as_deref(), ca.as_deref())
    }
}

/// Source snapshot boundary and its patched shadow-fork counterpart.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub height: u64,
    pub source_hash: B256,
    pub target_hash: B256,
}

impl Checkpoint {
    pub fn identity(&self, chain_id: u64) -> ReplayIdentity {
        ReplayIdentity {
            chain_id,
            checkpoint_height: self.height,
            source_hash: self.source_hash,
            target_hash: self.target_hash,
        }
    }
}

/// Mirror persistence, concurrency, and retry settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    #[serde(flatten)]
    pub store: StoreConfig,
    pub metrics: Option<SocketAddr>,
    concurrency: Option<usize>,
    retries: Option<u32>,
    retry_delay_ms: Option<u64>,
    retain_completed_blocks: Option<u64>,
}

impl Run {
    pub fn concurrency(&self) -> usize {
        self.concurrency.unwrap_or(DEFAULT_CONCURRENCY)
    }

    pub fn retries(&self) -> u32 {
        self.retries.unwrap_or(DEFAULT_RETRIES)
    }

    pub fn retry_delay_ms(&self) -> u64 {
        self.retry_delay_ms.unwrap_or(DEFAULT_RETRY_DELAY_MS)
    }

    pub fn retain_completed_blocks(&self) -> u64 {
        self.retain_completed_blocks
            .unwrap_or(DEFAULT_RETAIN_COMPLETED_BLOCKS)
    }
}

/// Auditor persistence, missing horizon, and retention settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    #[serde(flatten)]
    pub store: StoreConfig,
    pub metrics: Option<SocketAddr>,
    missing_after_blocks: Option<u64>,
    missing_after_seconds: Option<u64>,
    retain_included_blocks: Option<u64>,
    finality_stall_seconds: Option<u64>,
}

impl Audit {
    pub fn missing_after_blocks(&self) -> u64 {
        self.missing_after_blocks
            .unwrap_or(DEFAULT_MISSING_AFTER_BLOCKS)
    }

    pub fn missing_after(&self) -> Duration {
        Duration::from_secs(
            self.missing_after_seconds
                .unwrap_or(DEFAULT_MISSING_AFTER_SECONDS),
        )
    }

    pub fn retain_included_blocks(&self) -> u64 {
        self.retain_included_blocks
            .unwrap_or(DEFAULT_RETAIN_INCLUDED_BLOCKS)
    }

    pub fn finality_stall(&self) -> Duration {
        Duration::from_secs(
            self.finality_stall_seconds
                .unwrap_or(DEFAULT_FINALITY_STALL_SECONDS),
        )
    }
}

/// RocksDB path and disk bounds shared by long-running commands.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    pub state: PathBuf,
    max_bytes: Option<u64>,
    min_free_bytes: Option<u64>,
}

impl StoreConfig {
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes.unwrap_or(DEFAULT_MAX_BYTES)
    }

    pub fn min_free_bytes(&self) -> u64 {
        self.min_free_bytes.unwrap_or(DEFAULT_MIN_FREE_BYTES)
    }
}

const DEFAULT_CONCURRENCY: usize = 64;
const DEFAULT_RETRIES: u32 = 2;
const DEFAULT_RETRY_DELAY_MS: u64 = 250;
const DEFAULT_RETAIN_COMPLETED_BLOCKS: u64 = 10_000;
const DEFAULT_MISSING_AFTER_BLOCKS: u64 = 64;
const DEFAULT_MISSING_AFTER_SECONDS: u64 = 120;
const DEFAULT_RETAIN_INCLUDED_BLOCKS: u64 = 10_000;
const DEFAULT_FINALITY_STALL_SECONDS: u64 = 30;
const DEFAULT_MAX_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const DEFAULT_MIN_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses_and_has_independent_state() {
        let config: Config = toml::from_str(include_str!("../tempo-replay.example.toml")).unwrap();
        let (_, _, run) = config.run().unwrap();
        let (_, _, audit) = config.audit().unwrap();
        assert_ne!(run.store.state, audit.store.state);
        assert_eq!(run.concurrency(), 64);
        assert_eq!(audit.missing_after_blocks(), 64);
    }

    #[test]
    fn omitted_tuning_uses_named_defaults() {
        let run: Run = toml::from_str("state = 'mirror'").unwrap();
        assert_eq!(run.concurrency(), DEFAULT_CONCURRENCY);
        assert_eq!(run.retries(), DEFAULT_RETRIES);
        assert_eq!(run.retry_delay_ms(), DEFAULT_RETRY_DELAY_MS);

        let audit: Audit = toml::from_str("state = 'audit'").unwrap();
        assert_eq!(audit.missing_after_blocks(), DEFAULT_MISSING_AFTER_BLOCKS);
        assert_eq!(
            audit.missing_after(),
            Duration::from_secs(DEFAULT_MISSING_AFTER_SECONDS)
        );
        assert_eq!(
            audit.retain_included_blocks(),
            DEFAULT_RETAIN_INCLUDED_BLOCKS
        );
    }

    #[test]
    fn endpoint_rejects_insecure_or_embedded_credentials() {
        let endpoint = |url: &str| Endpoint {
            url: url.into(),
            credential_env: None,
            ca_file: None,
        };
        assert!(endpoint("http://source.example").connect().is_err());
        assert!(endpoint("https://user@source.example").connect().is_err());
        assert!(
            endpoint("https://source.example?token=secret")
                .connect()
                .is_err()
        );
    }

    #[test]
    fn profile_only_config_does_not_require_a_target() {
        let config: Config = toml::from_str(
            r#"
chain_id = 4217
[source]
url = "https://source.example"
"#,
        )
        .unwrap();
        assert!(config.run().is_err());
        assert!(config.audit().is_err());
    }
}
