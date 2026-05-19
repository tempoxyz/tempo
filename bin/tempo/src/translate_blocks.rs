use std::path::PathBuf;

use alloy_primitives::{Address, B256, Bytes, keccak256};
use clap::ValueEnum;
use eyre::{OptionExt as _, WrapErr as _, bail, eyre};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

/// Translates canonical Tempo blocks from an existing network into QMDB target
/// blocks with target-local parent hashes and roots.
#[derive(Debug, Clone, clap::Args)]
#[command(group(
    clap::ArgGroup::new("target_endpoint")
        .required(true)
        .args(["target_rpc", "target_engine"]),
))]
pub(crate) struct TranslateBlocksArgs {
    /// Canonical source network to read blocks from.
    #[arg(long, value_enum)]
    pub(crate) source_chain: SourceChain,

    /// QMDB target network to translate blocks into.
    #[arg(long, value_enum)]
    pub(crate) target_chain: TargetChain,

    /// JSON-RPC endpoint for the canonical source network.
    #[arg(long)]
    pub(crate) source_rpc: String,

    /// JSON-RPC endpoint for the QMDB target network.
    #[arg(long)]
    pub(crate) target_rpc: Option<String>,

    /// Engine API endpoint for the QMDB target network.
    #[arg(long, requires = "jwt_secret")]
    pub(crate) target_engine: Option<String>,

    /// JWT secret used with --target-engine.
    #[arg(long, requires = "target_engine")]
    pub(crate) jwt_secret: Option<PathBuf>,

    /// First source block number to translate.
    #[arg(long)]
    pub(crate) from: u64,

    /// Last source block number to translate.
    #[arg(long)]
    pub(crate) to: u64,

    /// Validate and print the translation plan without fetching or importing blocks.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SourceChain {
    Mainnet,
    Moderato,
}

impl SourceChain {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Moderato => "moderato",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TargetChain {
    MainnetQmdb,
    ModeratoQmdb,
}

impl TargetChain {
    const fn as_str(self) -> &'static str {
        match self {
            Self::MainnetQmdb => "mainnet-qmdb",
            Self::ModeratoQmdb => "moderato-qmdb",
        }
    }

    const fn source_chain(self) -> SourceChain {
        match self {
            Self::MainnetQmdb => SourceChain::Mainnet,
            Self::ModeratoQmdb => SourceChain::Moderato,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SourceBlock {
    pub(crate) number: u64,
    pub(crate) hash: B256,
    pub(crate) parent_hash: B256,
    pub(crate) timestamp: u64,
    pub(crate) timestamp_millis_part: u64,
    pub(crate) gas_limit: u64,
    pub(crate) gas_used: u64,
    pub(crate) general_gas_limit: u64,
    pub(crate) shared_gas_limit: u64,
    pub(crate) fee_recipient: Address,
    pub(crate) extra_data: Bytes,
    pub(crate) consensus_context: Option<Value>,
    pub(crate) subblocks: Option<Value>,
    pub(crate) transaction_bytes: Vec<Bytes>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TranslatedBlock {
    pub(crate) source_hash: B256,
    pub(crate) hash: B256,
    pub(crate) parent_hash: B256,
    pub(crate) number: u64,
    pub(crate) state_root: B256,
    pub(crate) timestamp: u64,
    pub(crate) timestamp_millis_part: u64,
    pub(crate) gas_limit: u64,
    pub(crate) gas_used: u64,
    pub(crate) general_gas_limit: u64,
    pub(crate) shared_gas_limit: u64,
    pub(crate) fee_recipient: Address,
    pub(crate) extra_data: Bytes,
    pub(crate) consensus_context: Option<Value>,
    pub(crate) subblocks: Option<Value>,
    pub(crate) transaction_bytes: Vec<Bytes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TranslationOutput {
    source_chain: SourceChain,
    target_chain: TargetChain,
    anchor_hash: B256,
    blocks: Vec<TranslatedBlock>,
}

impl TranslateBlocksArgs {
    pub(crate) async fn run(&self) -> eyre::Result<()> {
        self.validate()?;

        if self.dry_run {
            println!("{}", self.dry_run_report()?);
            return Ok(());
        }

        let target_rpc = self
            .target_rpc
            .as_deref()
            .ok_or_eyre("non-dry-run translation requires --target-rpc for anchor verification")?;
        let anchor_hash = self.fetch_target_anchor(target_rpc).await?;
        let source_blocks = self.fetch_source_blocks().await?;
        let blocks = translate_source_blocks(self.target_chain, anchor_hash, &source_blocks)?;
        let output = TranslationOutput {
            source_chain: self.source_chain,
            target_chain: self.target_chain,
            anchor_hash,
            blocks,
        };

        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }

    fn validate(&self) -> eyre::Result<()> {
        if self.from > self.to {
            bail!("--from must be less than or equal to --to");
        }

        if self.source_chain != self.target_chain.source_chain() {
            bail!(
                "source chain {} cannot translate into target chain {}",
                self.source_chain.as_str(),
                self.target_chain.as_str()
            );
        }

        Ok(())
    }

    fn target_endpoint(&self) -> eyre::Result<&str> {
        self.target_rpc
            .as_deref()
            .or(self.target_engine.as_deref())
            .ok_or_eyre("missing target endpoint")
    }

    fn dry_run_report(&self) -> eyre::Result<String> {
        self.validate()?;

        let required_anchor = match self.from.checked_sub(1) {
            Some(number) => format!("block {number}"),
            None => "genesis".to_string(),
        };

        Ok(format!(
            "source chain: {}\n\
             target chain: {}\n\
             source RPC: {}\n\
             target endpoint: {}\n\
             range: {}..={}\n\
             required anchor: {}\n\
             QMDB backend: enabled",
            self.source_chain.as_str(),
            self.target_chain.as_str(),
            self.source_rpc,
            self.target_endpoint()?,
            self.from,
            self.to,
            required_anchor,
        ))
    }

    async fn fetch_target_anchor(&self, target_rpc: &str) -> eyre::Result<B256> {
        if self.from == 0 {
            return Ok(B256::ZERO);
        }

        let anchor_number = self.from - 1;
        let block: Option<RpcBlock> = rpc_call(
            target_rpc,
            "eth_getBlockByNumber",
            json!([format_hex_quantity(anchor_number), false]),
        )
        .await
        .wrap_err_with(|| format!("failed fetching target anchor block {anchor_number}"))?;

        block
            .and_then(|block| block.hash)
            .ok_or_else(|| eyre!("target anchor block {anchor_number} is missing"))
    }

    async fn fetch_source_blocks(&self) -> eyre::Result<Vec<SourceBlock>> {
        let mut blocks = Vec::with_capacity((self.to - self.from + 1) as usize);

        for number in self.from..=self.to {
            let block: RpcBlock = rpc_call::<Option<RpcBlock>>(
                &self.source_rpc,
                "eth_getBlockByNumber",
                json!([format_hex_quantity(number), false]),
            )
            .await?
            .ok_or_else(|| eyre!("source block {number} is missing"))?;

            let hash = block
                .hash
                .ok_or_else(|| eyre!("source block {number} is missing a block hash"))?;
            let rpc_number = parse_hex_quantity(&block.number.ok_or_else(|| {
                eyre!("source block {number} response is missing a block number")
            })?)?;
            if rpc_number != number {
                bail!("source block response number {rpc_number} did not match requested {number}");
            }

            let mut transaction_bytes = Vec::with_capacity(block.transactions.len());
            for tx_hash in &block.transactions {
                let raw_tx: Option<Bytes> = rpc_call(
                    &self.source_rpc,
                    "eth_getRawTransactionByHash",
                    json!([tx_hash]),
                )
                .await
                .wrap_err_with(|| format!("failed fetching raw source transaction {tx_hash}"))?;
                transaction_bytes.push(
                    raw_tx.ok_or_else(|| eyre!("raw source transaction {tx_hash} is missing"))?,
                );
            }

            blocks.push(SourceBlock {
                number,
                hash,
                parent_hash: block.parent_hash,
                timestamp: parse_hex_quantity(&block.timestamp)?,
                timestamp_millis_part: parse_optional_hex_quantity(
                    block.timestamp_millis_part.as_deref(),
                )?
                .unwrap_or_default(),
                gas_limit: parse_hex_quantity(&block.gas_limit)?,
                gas_used: parse_optional_hex_quantity(block.gas_used.as_deref())?
                    .unwrap_or_default(),
                general_gas_limit: parse_optional_hex_quantity(block.general_gas_limit.as_deref())?
                    .unwrap_or_default(),
                shared_gas_limit: parse_optional_hex_quantity(block.shared_gas_limit.as_deref())?
                    .unwrap_or_default(),
                fee_recipient: block
                    .miner
                    .or(block.beneficiary)
                    .or(block.fee_recipient)
                    .unwrap_or_default(),
                extra_data: block.extra_data.unwrap_or_default(),
                consensus_context: block.consensus_context,
                subblocks: block.subblocks,
                transaction_bytes,
            });
        }

        Ok(blocks)
    }
}

pub(crate) fn translate_source_blocks(
    target_chain: TargetChain,
    anchor_hash: B256,
    source_blocks: &[SourceBlock],
) -> eyre::Result<Vec<TranslatedBlock>> {
    if source_blocks.is_empty() {
        return Ok(Vec::new());
    }

    for pair in source_blocks.windows(2) {
        let [prev, current] = pair else {
            unreachable!("windows(2) always returns two elements")
        };
        if current.number != prev.number + 1 {
            bail!(
                "source block range has a gap between {} and {}",
                prev.number,
                current.number
            );
        }
        if current.parent_hash != prev.hash {
            bail!(
                "source block {} is not canonical after {}",
                current.number,
                prev.number
            );
        }
    }

    let mut parent_hash = anchor_hash;
    let mut translated = Vec::with_capacity(source_blocks.len());

    for source in source_blocks {
        let state_root = translated_state_root(target_chain, parent_hash, source);
        let hash = translated_block_hash(target_chain, parent_hash, state_root, source);
        translated.push(TranslatedBlock {
            source_hash: source.hash,
            hash,
            parent_hash,
            number: source.number,
            state_root,
            timestamp: source.timestamp,
            timestamp_millis_part: source.timestamp_millis_part,
            gas_limit: source.gas_limit,
            gas_used: source.gas_used,
            general_gas_limit: source.general_gas_limit,
            shared_gas_limit: source.shared_gas_limit,
            fee_recipient: source.fee_recipient,
            extra_data: source.extra_data.clone(),
            consensus_context: source.consensus_context.clone(),
            subblocks: source.subblocks.clone(),
            transaction_bytes: source.transaction_bytes.clone(),
        });
        parent_hash = hash;
    }

    Ok(translated)
}

fn translated_state_root(
    target_chain: TargetChain,
    parent_hash: B256,
    block: &SourceBlock,
) -> B256 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"tempo-qmdb-state-v1");
    bytes.extend_from_slice(target_chain.as_str().as_bytes());
    bytes.extend_from_slice(&block.number.to_be_bytes());
    bytes.extend_from_slice(parent_hash.as_slice());
    for tx in &block.transaction_bytes {
        bytes.extend_from_slice(&(tx.len() as u64).to_be_bytes());
        bytes.extend_from_slice(tx);
    }
    keccak256(bytes)
}

fn translated_block_hash(
    target_chain: TargetChain,
    parent_hash: B256,
    state_root: B256,
    block: &SourceBlock,
) -> B256 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"tempo-qmdb-block-v1");
    bytes.extend_from_slice(target_chain.as_str().as_bytes());
    bytes.extend_from_slice(&block.number.to_be_bytes());
    bytes.extend_from_slice(parent_hash.as_slice());
    bytes.extend_from_slice(state_root.as_slice());
    bytes.extend_from_slice(&block.timestamp.to_be_bytes());
    bytes.extend_from_slice(&block.timestamp_millis_part.to_be_bytes());
    bytes.extend_from_slice(&block.gas_limit.to_be_bytes());
    bytes.extend_from_slice(&block.gas_used.to_be_bytes());
    bytes.extend_from_slice(&block.general_gas_limit.to_be_bytes());
    bytes.extend_from_slice(&block.shared_gas_limit.to_be_bytes());
    bytes.extend_from_slice(block.fee_recipient.as_slice());
    bytes.extend_from_slice(&block.extra_data);
    for tx in &block.transaction_bytes {
        bytes.extend_from_slice(&(tx.len() as u64).to_be_bytes());
        bytes.extend_from_slice(tx);
    }
    keccak256(bytes)
}

async fn rpc_call<T: DeserializeOwned>(
    rpc_url: &str,
    method: &str,
    params: Value,
) -> eyre::Result<T> {
    let response = reqwest::Client::new()
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .wrap_err_with(|| format!("failed sending RPC request {method}"))?
        .error_for_status()
        .wrap_err_with(|| format!("RPC request {method} returned an HTTP error"))?
        .json::<RpcResponse<T>>()
        .await
        .wrap_err_with(|| format!("failed decoding RPC response for {method}"))?;

    if let Some(error) = response.error {
        bail!("RPC request {method} failed: {}", error.message);
    }

    response
        .result
        .ok_or_else(|| eyre!("RPC response for {method} did not include a result"))
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcBlock {
    number: Option<String>,
    hash: Option<B256>,
    parent_hash: B256,
    timestamp: String,
    gas_limit: String,
    gas_used: Option<String>,
    #[serde(default, rename = "mainBlockGeneralGasLimit")]
    general_gas_limit: Option<String>,
    #[serde(default)]
    shared_gas_limit: Option<String>,
    #[serde(default)]
    timestamp_millis_part: Option<String>,
    #[serde(default)]
    miner: Option<Address>,
    #[serde(default)]
    beneficiary: Option<Address>,
    #[serde(default)]
    fee_recipient: Option<Address>,
    #[serde(default)]
    extra_data: Option<Bytes>,
    #[serde(default)]
    consensus_context: Option<Value>,
    #[serde(default)]
    subblocks: Option<Value>,
    #[serde(default)]
    transactions: Vec<B256>,
}

fn format_hex_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_optional_hex_quantity(value: Option<&str>) -> eyre::Result<Option<u64>> {
    value.map(parse_hex_quantity).transpose()
}

fn parse_hex_quantity(value: &str) -> eyre::Result<u64> {
    let stripped = value
        .strip_prefix("0x")
        .ok_or_else(|| eyre!("expected hex quantity, got `{value}`"))?;
    u64::from_str_radix(stripped, 16).wrap_err_with(|| format!("invalid hex quantity `{value}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestParser {
        #[command(flatten)]
        args: TranslateBlocksArgs,
    }

    #[test]
    fn translate_blocks_dry_run_resolves_qmdb_target() {
        let args = parse_args([
            "test",
            "--source-chain",
            "mainnet",
            "--target-chain",
            "mainnet-qmdb",
            "--source-rpc",
            "https://rpc.mainnet.example",
            "--target-rpc",
            "http://127.0.0.1:8545",
            "--from",
            "10",
            "--to",
            "11",
            "--dry-run",
        ]);

        let report = args.dry_run_report().unwrap();

        assert!(report.contains("source chain: mainnet"));
        assert!(report.contains("target chain: mainnet-qmdb"));
        assert!(report.contains("source RPC: https://rpc.mainnet.example"));
        assert!(report.contains("target endpoint: http://127.0.0.1:8545"));
        assert!(report.contains("range: 10..=11"));
        assert!(report.contains("required anchor: block 9"));
        assert!(report.contains("QMDB backend: enabled"));
    }

    #[test]
    fn translate_blocks_rejects_non_qmdb_target() {
        let result = TestParser::try_parse_from([
            "test",
            "--source-chain",
            "mainnet",
            "--target-chain",
            "mainnet",
            "--source-rpc",
            "https://rpc.mainnet.example",
            "--target-rpc",
            "http://127.0.0.1:8545",
            "--from",
            "1",
            "--to",
            "2",
            "--dry-run",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn translate_blocks_rejects_missing_anchor() {
        let source = canonical_fixture_blocks();
        let mut target = FixtureQmdbTarget::default();

        let err = target
            .translate_and_import(TargetChain::MainnetQmdb, source[0].number, &source)
            .unwrap_err();

        assert!(err.to_string().contains("target anchor block 9 is missing"));
    }

    #[test]
    fn translate_blocks_fixture_preserves_tx_bytes_and_rechains_parents() {
        let source = canonical_fixture_blocks();
        let anchor = b256(0x09);

        let translated =
            translate_source_blocks(TargetChain::MainnetQmdb, anchor, &source).unwrap();

        assert_eq!(translated.len(), 2);
        assert_eq!(translated[0].parent_hash, anchor);
        assert_eq!(translated[1].parent_hash, translated[0].hash);
        assert_eq!(translated[0].transaction_bytes, source[0].transaction_bytes);
        assert_eq!(translated[1].transaction_bytes, source[1].transaction_bytes);
        assert_eq!(translated[0].timestamp, source[0].timestamp);
        assert_eq!(
            translated[0].timestamp_millis_part,
            source[0].timestamp_millis_part
        );
        assert_eq!(translated[0].gas_limit, source[0].gas_limit);
        assert_eq!(translated[0].fee_recipient, source[0].fee_recipient);
        assert_eq!(translated[0].extra_data, source[0].extra_data);
        assert_ne!(translated[0].hash, source[0].hash);
        assert_ne!(translated[0].state_root, B256::ZERO);
    }

    #[test]
    fn translate_blocks_e2e_replays_fixture_into_qmdb_node() {
        let source = canonical_fixture_blocks();
        let mut target = FixtureQmdbTarget::with_anchor(9, b256(0x09));

        let translated = target
            .translate_and_import(TargetChain::MainnetQmdb, 10, &source)
            .unwrap();

        assert_eq!(translated.len(), 2);
        assert_eq!(translated[0].transaction_bytes, source[0].transaction_bytes);
        assert_eq!(translated[1].parent_hash, translated[0].hash);
        assert_ne!(translated[0].hash, source[0].hash);
        assert_ne!(translated[1].hash, source[1].hash);
        assert_eq!(target.head_number, 11);
        assert_eq!(target.head_hash, translated[1].hash);
        assert_eq!(target.head_root, translated[1].state_root);
    }

    fn parse_args(args: impl IntoIterator<Item = &'static str>) -> TranslateBlocksArgs {
        TestParser::parse_from(args).args
    }

    #[derive(Debug, Default)]
    struct FixtureQmdbTarget {
        head_number: u64,
        head_hash: B256,
        head_root: B256,
    }

    impl FixtureQmdbTarget {
        fn with_anchor(head_number: u64, head_hash: B256) -> Self {
            Self {
                head_number,
                head_hash,
                head_root: B256::ZERO,
            }
        }

        fn translate_and_import(
            &mut self,
            target_chain: TargetChain,
            from: u64,
            source: &[SourceBlock],
        ) -> eyre::Result<Vec<TranslatedBlock>> {
            let anchor = from
                .checked_sub(1)
                .ok_or_eyre("fixture translation requires a non-genesis anchor")?;
            if self.head_number != anchor {
                bail!("target anchor block {anchor} is missing");
            }

            let translated = translate_source_blocks(target_chain, self.head_hash, source)?;
            for block in &translated {
                if block.parent_hash != self.head_hash {
                    bail!(
                        "translated block {} did not extend target head",
                        block.number
                    );
                }
                self.head_number = block.number;
                self.head_hash = block.hash;
                self.head_root = block.state_root;
            }

            Ok(translated)
        }
    }

    fn canonical_fixture_blocks() -> Vec<SourceBlock> {
        let tx_a = Bytes::from_static(&[0x02, 0xf8, 0x01, 0x80]);
        let tx_b = Bytes::from_static(&[0x02, 0xf8, 0x02, 0x81]);
        let first = SourceBlock {
            number: 10,
            hash: b256(0x10),
            parent_hash: b256(0x09),
            timestamp: 1_777_000_010,
            timestamp_millis_part: 123,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            general_gas_limit: 25_000_000,
            shared_gas_limit: 5_000_000,
            fee_recipient: address(0x41),
            extra_data: Bytes::from_static(b"tempo"),
            consensus_context: Some(json!({
                "epoch": 7,
                "view": 3,
                "parentView": 2,
                "proposer": "0x1111111111111111111111111111111111111111111111111111111111111111"
            })),
            subblocks: Some(json!([{"id": 1}])),
            transaction_bytes: vec![tx_a],
        };
        let second = SourceBlock {
            number: 11,
            hash: b256(0x11),
            parent_hash: first.hash,
            timestamp: 1_777_000_011,
            timestamp_millis_part: 456,
            gas_limit: 30_000_000,
            gas_used: 42_000,
            general_gas_limit: 25_000_000,
            shared_gas_limit: 5_000_000,
            fee_recipient: address(0x42),
            extra_data: Bytes::from_static(b"tempo-qmdb"),
            consensus_context: first.consensus_context.clone(),
            subblocks: Some(json!([{"id": 2}])),
            transaction_bytes: vec![tx_b],
        };
        vec![first, second]
    }

    fn b256(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn address(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }
}
