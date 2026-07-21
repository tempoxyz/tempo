use alloy::{
    primitives::{Address, address},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use clap::ValueEnum;
use eyre::{Context, Result, bail, eyre};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempo_alloy::{
    TempoNetwork,
    contracts::precompiles::{ITIP20Factory, TIP20_FACTORY_ADDRESS},
};

pub const DEFAULT_SCAN_BLOCKS: u64 = 50_000;
pub const DEFAULT_RPC_RETRIES: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet,
    Nextfork,
}

impl Network {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Nextfork => "nextfork",
        }
    }

    pub const fn chain_id(self) -> u64 {
        match self {
            Self::Mainnet => 4_217,
            Self::Testnet => 42_431,
            Self::Nextfork => 31_318,
        }
    }

    pub const fn default_rpc_url(self) -> Option<&'static str> {
        match self {
            Self::Mainnet => Some("https://rpc.tempo.xyz"),
            Self::Testnet => Some("https://rpc.moderato.tempo.xyz"),
            Self::Nextfork => None,
        }
    }

    /// Genesis TIP-20s do not have `TokenCreated` logs and must be seeded explicitly.
    pub fn genesis_tokens(self) -> &'static [Address] {
        const MAINNET: &[Address] = &[
            address!("0x20C0000000000000000000000000000000000000"),
            address!("0x20C00000000000000000000016C6514B53947FDC"),
        ];
        const TESTNET: &[Address] = &[
            address!("0x20C0000000000000000000000000000000000000"),
            address!("0x20C0000000000000000000000000000000000001"),
            address!("0x20C0000000000000000000000000000000000002"),
            address!("0x20C0000000000000000000000000000000000003"),
        ];

        match self {
            Self::Mainnet => MAINNET,
            Self::Testnet | Self::Nextfork => TESTNET,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub block_span: u64,
    pub max_retries: u32,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            block_span: DEFAULT_SCAN_BLOCKS,
            max_retries: DEFAULT_RPC_RETRIES,
        }
    }
}

#[derive(Debug)]
pub struct TokenChunk {
    pub from_block: u64,
    pub to_block: u64,
    pub tokens: Vec<Address>,
}

pub async fn ensure_chain<P>(provider: &P, network: Network) -> Result<()>
where
    P: Provider<TempoNetwork>,
{
    let actual = provider
        .get_chain_id()
        .await
        .context("failed to read chain ID")?;
    let expected = network.chain_id();
    if actual != expected {
        bail!("RPC chain ID mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

/// Fetch the next factory-log range. RPCs commonly cap log ranges or result counts, so a failed
/// range is retried and then bisected until it succeeds.
pub async fn next_token_chunk<P>(
    provider: &P,
    from_block: u64,
    upper_bound: u64,
    config: &ScanConfig,
) -> Result<TokenChunk>
where
    P: Provider<TempoNetwork>,
{
    let mut span = config.block_span.max(1);

    loop {
        let to_block = upper_bound.min(from_block.saturating_add(span - 1));
        let filter = Filter::new()
            .address(TIP20_FACTORY_ADDRESS)
            .event_signature(ITIP20Factory::TokenCreated::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block);

        let mut last_error = None;
        for attempt in 0..=config.max_retries {
            match provider.get_logs(&filter).await {
                Ok(logs) => {
                    let tokens = logs
                        .iter()
                        .map(|log| {
                            log.log_decode::<ITIP20Factory::TokenCreated>()
                                .map(|event| event.inner.token)
                                .map_err(|error| eyre!(error))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    return Ok(TokenChunk {
                        from_block,
                        to_block,
                        tokens,
                    });
                }
                Err(error) => {
                    last_error = Some(error.to_string());
                    if attempt < config.max_retries {
                        tokio::time::sleep(retry_delay(attempt)).await;
                    }
                }
            }
        }

        if span == 1 {
            return Err(eyre!(
                "failed to fetch TokenCreated logs for block {from_block}: {}",
                last_error.unwrap_or_else(|| "unknown RPC error".to_owned())
            ));
        }

        span = (span / 2).max(1);
        eprintln!(
            "log query failed after retries; reducing range at block {from_block} to {span} blocks"
        );
    }
}

pub const fn retry_delay(attempt: u32) -> Duration {
    let exponent = if attempt > 5 { 5 } else { attempt };
    Duration::from_secs(1_u64 << exponent)
}

pub fn load_state<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse state file {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read state file {}", path.display()))
        }
    }
}

pub fn save_state<T: Serialize>(path: &Path, state: &T) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create state directory {}", parent.display()))?;

    let mut temporary = PathBuf::from(path);
    temporary.set_extension("tmp");
    let bytes = serde_json::to_vec_pretty(state)?;
    fs::write(&temporary, bytes)
        .with_context(|| format!("failed to write state file {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("failed to install state file {}", path.display()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Progress {
    pub chain_id: u64,
    pub genesis_done: bool,
    pub next_block: u64,
    pub tokens_seen: u64,
    pub transactions_confirmed: u64,
}

impl Progress {
    pub fn new(network: Network) -> Self {
        Self {
            chain_id: network.chain_id(),
            genesis_done: false,
            next_block: 0,
            tokens_seen: 0,
            transactions_confirmed: 0,
        }
    }

    pub fn validate(&self, network: Network) -> Result<()> {
        if self.chain_id != network.chain_id() {
            bail!(
                "state file is for chain {}, but --network selects {}",
                self.chain_id,
                network.chain_id()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_constants_match_chainspec() {
        assert_eq!(Network::Mainnet.chain_id(), 4_217);
        assert_eq!(Network::Testnet.chain_id(), 42_431);
        assert_eq!(Network::Nextfork.chain_id(), 31_318);
        assert_eq!(
            Network::Mainnet.default_rpc_url(),
            Some("https://rpc.tempo.xyz")
        );
        assert_eq!(
            Network::Testnet.default_rpc_url(),
            Some("https://rpc.moderato.tempo.xyz")
        );
        assert_eq!(Network::Nextfork.default_rpc_url(), None);
        assert_eq!(Network::Mainnet.genesis_tokens().len(), 2);
        assert_eq!(Network::Testnet.genesis_tokens().len(), 4);
        assert_eq!(Network::Nextfork.genesis_tokens().len(), 4);
    }

    #[test]
    fn retry_delay_is_bounded() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(99), Duration::from_secs(32));
    }
}
