//! Export a deterministic Tempo block range in Benchmarkoor's semantic suite format.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{BufRead as _, BufReader},
    path::{Path, PathBuf},
    str::FromStr as _,
};

use alloy::{
    consensus::{BlockBody, Header, Sealable as _, proofs::calculate_transaction_root},
    eips::{Decodable2718 as _, eip4895::Withdrawals, eip7685::Requests},
    genesis::Genesis,
    primitives::{Address, B256, Bloom, Bytes, U256},
    providers::{Provider, ProviderBuilder},
};
use eyre::{Context as _, ensure};
use reth_chainspec::EthChainSpec as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_primitives::{Block as TempoBlock, TempoHeader, TempoTxEnvelope};

const FORMAT: &str = "tempo-engine-suite/v1";

/// Export canonical Tempo blocks for deterministic execution benchmarking.
#[derive(Debug, clap::Args)]
pub(crate) struct GenerateBenchmarkSuite {
    /// HTTP JSON-RPC endpoint of the populated Tempo node.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,

    /// Genesis/chainspec used by the source node.
    #[arg(long)]
    genesis: PathBuf,

    /// Directory to create (manifest.json, genesis.json, and blocks/).
    #[arg(long)]
    out: PathBuf,

    /// Stable suite and measured test name.
    #[arg(long)]
    name: String,

    /// First block included in measurement. Blocks from 1 up to this block are setup.
    #[arg(long, default_value_t = 1)]
    from_block: u64,

    /// Last block included in measurement (inclusive).
    #[arg(long, required_unless_present = "capture_file")]
    to_block: Option<u64>,

    /// JSONL emitted by the Tempo EEST adapter. Each passing pytest case is
    /// exported as an independent Benchmarkoor test whose final transaction-
    /// bearing block is measured and whose preceding blocks are setup.
    #[arg(long, conflicts_with = "to_block")]
    capture_file: Option<PathBuf>,

    /// Human-readable description of the workload and intent.
    #[arg(long, default_value = "Tempo block execution replay")]
    description: String,

    /// Report category; repeat for multiple dimensions (for example aa, tip20, fees).
    #[arg(long = "tag")]
    tags: Vec<String>,

    /// Generator/workload seed recorded in suite provenance.
    #[arg(long, default_value = "0")]
    seed: String,

    /// Provenance kind for the workload before Tempo canonicalization.
    #[arg(long, default_value = "tempo-native")]
    origin_kind: String,

    /// Source repository for the workload definition.
    #[arg(long, default_value = "https://github.com/tempoxyz/tempo")]
    origin_repository: String,

    /// Generator pipeline recorded in suite provenance.
    #[arg(long, default_value = "tempo-xtask generate-benchmark-suite")]
    generator: String,

    /// Additional suite metadata as KEY=VALUE; repeat for multiple entries.
    #[arg(long = "metadata", value_name = "KEY=VALUE")]
    extra_metadata: Vec<String>,

    /// Source revision recorded in suite provenance.
    #[arg(long, default_value = "unknown")]
    revision: String,

    /// Active Tempo hardfork recorded in the suite.
    #[arg(long, default_value = "unknown")]
    hardfork: String,

    /// Source chain ID recorded in the suite.
    #[arg(long, default_value_t = 0)]
    chain_id: u64,

    /// Export debug_getRawBlockAccessList and replay it with every block.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    block_access_lists: bool,

    /// Let reth_newPayload wait for execution cache and sparse trie locks.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    wait_for_caches: bool,

    /// Overwrite a manifest previously generated in the output directory.
    #[arg(long, default_value_t = false)]
    force: bool,
}

impl GenerateBenchmarkSuite {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        ensure!(self.genesis.is_file(), "genesis file does not exist");
        if let Some(capture_file) = &self.capture_file {
            ensure!(capture_file.is_file(), "capture file does not exist");
        } else {
            ensure!(self.from_block > 0, "--from-block must be at least 1");
            ensure!(
                self.to_block
                    .is_some_and(|to_block| to_block >= self.from_block),
                "--to-block must be greater than or equal to --from-block"
            );
        }

        let manifest_path = self.out.join("manifest.json");
        ensure!(
            self.force || !manifest_path.exists(),
            "{} already exists; pass --force to replace generated files",
            manifest_path.display()
        );

        let blocks_dir = self.out.join("blocks");
        if self.force && blocks_dir.exists() {
            fs::remove_dir_all(&blocks_dir)
                .wrap_err("failed to clear existing suite block directory")?;
        }
        fs::create_dir_all(&blocks_dir).wrap_err("failed to create suite block directory")?;
        fs::copy(&self.genesis, self.out.join("genesis.json"))
            .wrap_err("failed to copy suite genesis")?;

        let rpc_url = self.rpc_url.parse().wrap_err("invalid --rpc-url")?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);

        let (tests, capture_metadata) = if let Some(capture_file) = &self.capture_file {
            export_captured_tests(
                &provider,
                &blocks_dir,
                capture_file,
                self.block_access_lists,
                self.wait_for_caches,
                &self.tags,
                &self.description,
            )
            .await?
        } else {
            let mut setup = Vec::new();
            let mut test = Vec::new();
            for number in 1..=self.to_block.expect("validated above") {
                let calls = export_block(
                    &provider,
                    &blocks_dir,
                    number,
                    self.block_access_lists,
                    self.wait_for_caches,
                )
                .await
                .wrap_err_with(|| format!("failed to export block {number}"))?;

                if number < self.from_block {
                    setup.extend(calls);
                } else {
                    test.extend(calls);
                }
            }
            (
                vec![SuiteTest {
                    name: self.name.clone(),
                    description: self.description.clone(),
                    tags: self.tags.clone(),
                    metadata: BTreeMap::new(),
                    setup,
                    test,
                    cleanup: Vec::new(),
                }],
                BTreeMap::new(),
            )
        };

        let mut metadata = BTreeMap::new();
        metadata.insert("measurement".to_string(), "server_execution_ns".to_string());
        metadata.insert("source_rpc".to_string(), self.rpc_url);
        metadata.extend(capture_metadata);
        for entry in self.extra_metadata {
            let (key, value) = entry
                .split_once('=')
                .ok_or_else(|| eyre::eyre!("invalid --metadata {entry:?}; expected KEY=VALUE"))?;
            ensure!(!key.is_empty(), "metadata key must not be empty");
            metadata.insert(key.to_string(), value.to_string());
        }

        let manifest = Manifest {
            format: FORMAT.to_string(),
            name: self.name.clone(),
            description: self.description.clone(),
            origin: Origin {
                kind: self.origin_kind,
                repository: self.origin_repository,
                revision: self.revision.clone(),
                generator: self.generator,
                seed: self.seed.clone(),
            },
            chain: Chain {
                name: "tempo".to_string(),
                chain_id: self.chain_id,
                hardfork: self.hardfork.clone(),
                genesis: "genesis.json".to_string(),
            },
            metadata,
            defaults: Defaults {
                wait_for_persistence: true,
                wait_for_caches: self.wait_for_caches,
                expected_status: "VALID".to_string(),
            },
            tests,
        };

        let encoded =
            serde_json::to_vec_pretty(&manifest).wrap_err("failed to serialize suite manifest")?;
        fs::write(&manifest_path, encoded).wrap_err("failed to write suite manifest")?;

        println!("wrote {}", manifest_path.display());
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct EestCaptureRecord {
    nodeid: String,
    before_block: u64,
    after_block: u64,
    outcome: String,
}

async fn export_captured_tests<P: Provider>(
    provider: &P,
    blocks_dir: &Path,
    capture_file: &Path,
    include_bal: bool,
    wait_for_caches: bool,
    tags: &[String],
    description: &str,
) -> eyre::Result<(Vec<SuiteTest>, BTreeMap<String, String>)> {
    let file = fs::File::open(capture_file)
        .wrap_err_with(|| format!("failed to open capture file {}", capture_file.display()))?;
    let mut records = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.wrap_err("failed to read EEST capture record")?;
        if line.trim().is_empty() {
            continue;
        }
        records.push(
            serde_json::from_str::<EestCaptureRecord>(&line).wrap_err_with(|| {
                format!(
                    "invalid EEST capture JSON at {}:{}",
                    capture_file.display(),
                    index + 1
                )
            })?,
        );
    }
    ensure!(!records.is_empty(), "EEST capture file contains no records");

    let passed_records = records
        .iter()
        .filter(|record| record.outcome == "passed")
        .count();
    let failed_records = records.len() - passed_records;
    let mut next_block = 1;
    let mut tests = Vec::new();
    let mut passed_without_transaction = 0;

    for record in &records {
        ensure!(
            record.after_block >= record.before_block,
            "capture interval moved backwards for {}",
            record.nodeid
        );
        if record.outcome != "passed" {
            continue;
        }

        let mut measured_block = None;
        for number in (record.before_block + 1)..=record.after_block {
            if block_transaction_count(provider, number).await? > 0 {
                measured_block = Some(number);
            }
        }
        let Some(measured_block) = measured_block else {
            passed_without_transaction += 1;
            continue;
        };
        ensure!(
            measured_block >= next_block,
            "captured measured block {measured_block} for {} was already exported",
            record.nodeid
        );

        let mut setup = Vec::new();
        let mut test = Vec::new();
        for number in next_block..=measured_block {
            let calls = export_block(provider, blocks_dir, number, include_bal, wait_for_caches)
                .await
                .wrap_err_with(|| {
                    format!("failed to export block {number} for {}", record.nodeid)
                })?;
            if number == measured_block {
                test.extend(calls);
            } else {
                setup.extend(calls);
            }
        }
        next_block = measured_block + 1;

        tests.push(SuiteTest {
            name: record.nodeid.clone(),
            description: description.to_string(),
            tags: tags.to_vec(),
            metadata: BTreeMap::from([
                (
                    "capture_before_block".to_string(),
                    record.before_block.to_string(),
                ),
                (
                    "capture_after_block".to_string(),
                    record.after_block.to_string(),
                ),
                ("measured_block".to_string(), measured_block.to_string()),
            ]),
            setup,
            test,
            cleanup: Vec::new(),
        });
    }
    ensure!(
        !tests.is_empty(),
        "capture contains no passing transaction-bearing tests"
    );

    let metadata = BTreeMap::from([
        (
            "capture_record_count".to_string(),
            records.len().to_string(),
        ),
        (
            "capture_passed_count".to_string(),
            passed_records.to_string(),
        ),
        (
            "capture_failed_count".to_string(),
            failed_records.to_string(),
        ),
        (
            "capture_exported_count".to_string(),
            tests.len().to_string(),
        ),
        (
            "capture_passed_without_transaction_count".to_string(),
            passed_without_transaction.to_string(),
        ),
    ]);
    Ok((tests, metadata))
}

async fn block_transaction_count<P: Provider>(provider: &P, number: u64) -> eyre::Result<u64> {
    let block_id = format!("0x{number:x}");
    let block: Value = provider
        .raw_request("eth_getBlockByNumber".into(), (&block_id, false))
        .await
        .wrap_err("eth_getBlockByNumber failed")?;
    ensure!(!block.is_null(), "source node has no block {number}");
    Ok(block
        .get("transactions")
        .and_then(Value::as_array)
        .map_or(0, Vec::len) as u64)
}

async fn export_block<P: Provider>(
    provider: &P,
    blocks_dir: &Path,
    number: u64,
    include_bal: bool,
    wait_for_caches: bool,
) -> eyre::Result<Vec<Call>> {
    let block_id = format!("0x{number:x}");
    let block: Value = provider
        .raw_request("eth_getBlockByNumber".into(), (&block_id, false))
        .await
        .wrap_err("eth_getBlockByNumber failed")?;
    ensure!(!block.is_null(), "source node has no block {number}");

    let hash = required_hex_string(&block, "hash")?;
    let gas_used = parse_quantity(required_hex_string(&block, "gasUsed")?)?;
    let transaction_count = block
        .get("transactions")
        .and_then(Value::as_array)
        .map_or(0, Vec::len) as u64;

    let raw: Bytes = provider
        .raw_request("debug_getRawBlock".into(), (&block_id,))
        .await
        .wrap_err("debug_getRawBlock failed")?;
    let rlp_name = format!("{number}.rlp");
    fs::write(blocks_dir.join(&rlp_name), format!("{raw}"))
        .wrap_err("failed to write block RLP")?;

    let bal_file = if include_bal {
        let bal: Bytes = provider
            .raw_request("debug_getRawBlockAccessList".into(), (&block_id,))
            .await
            .wrap_err("debug_getRawBlockAccessList failed")?;
        let name = format!("{number}.bal");
        fs::write(blocks_dir.join(&name), format!("{bal}"))
            .wrap_err("failed to write block access list")?;
        Some(format!("blocks/{name}"))
    } else {
        None
    };

    Ok(vec![
        Call {
            method: None,
            params: None,
            rlp_file: Some(format!("blocks/{rlp_name}")),
            bal_file,
            wait_for_caches: Some(wait_for_caches),
            block_number: Some(number),
            block_hash: Some(hash.to_string()),
            gas_used: Some(gas_used),
            transaction_count: Some(transaction_count),
            expected_status: Some("VALID".to_string()),
        },
        Call {
            method: Some("reth_forkchoiceUpdated".to_string()),
            params: Some(vec![json!({
                "headBlockHash": hash,
                "safeBlockHash": hash,
                "finalizedBlockHash": hash,
            })]),
            rlp_file: None,
            bal_file: None,
            wait_for_caches: None,
            block_number: Some(number),
            block_hash: Some(hash.to_string()),
            gas_used: None,
            transaction_count: None,
            expected_status: Some("VALID".to_string()),
        },
    ])
}

fn required_hex_string<'a>(value: &'a Value, field: &str) -> eyre::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| eyre::eyre!("block response has no {field}"))
}

fn parse_quantity(value: &str) -> eyre::Result<u64> {
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)
        .wrap_err_with(|| format!("invalid RPC quantity {value}"))
}

/// Convert Benchmarkoor's standard Engine API requests into Tempo block RLP.
///
/// This is the compatibility bridge: Benchmarkoor/EEST remains the source of
/// Ethereum test cases, while Tempo owns the explicit header adaptation needed
/// by its Reth Engine API. Unsupported features (currently blob transactions,
/// non-empty withdrawals, and non-linear request streams) fail loudly.
#[derive(Debug, clap::Args)]
pub(crate) struct ImportBenchmarkoorSuite {
    /// Benchmarkoor suite directory containing summary.json and test request files.
    #[arg(
        long,
        required_unless_present = "requests_dir",
        conflicts_with = "requests_dir"
    )]
    suite_dir: Option<PathBuf>,

    /// Raw Benchmarkoor request corpus. Accepts either the gas-benchmarks
    /// `eest_tests` directory or its parent repository directory.
    #[arg(
        long,
        required_unless_present = "suite_dir",
        conflicts_with = "suite_dir"
    )]
    requests_dir: Option<PathBuf>,

    /// Genesis used by the Benchmarkoor suite.
    #[arg(long)]
    genesis: PathBuf,

    /// Output directory for the Tempo semantic suite.
    #[arg(long)]
    out: PathBuf,

    /// Name of the converted suite.
    #[arg(long)]
    name: String,

    /// Only import Benchmarkoor test names containing this value.
    #[arg(long, default_value = "")]
    filter: String,

    /// Maximum number of tests to import (zero means all matches).
    #[arg(long, default_value_t = 0)]
    limit: usize,

    /// Keep converting after source-incompatible tests and record them in
    /// conversion-report.json. Without this flag, the first incompatibility fails.
    #[arg(long, default_value_t = false)]
    skip_incompatible: bool,

    /// Override the Tempo general-gas limit. By default it is derived from the
    /// imported genesis hardfork schedule and payload gas limit.
    #[arg(long)]
    general_gas_limit: Option<u64>,

    /// Override the Tempo shared-gas limit. By default it is derived from the
    /// imported genesis hardfork schedule and payload gas limit.
    #[arg(long)]
    shared_gas_limit: Option<u64>,

    /// Additional report tag; repeat for multiple tags.
    #[arg(long = "tag")]
    tags: Vec<String>,

    /// Benchmarkoor/EEST source revision recorded in provenance.
    #[arg(long, default_value = "unknown")]
    revision: String,

    /// Active Tempo hardfork recorded in the suite.
    #[arg(long, default_value = "ethereum-compat")]
    hardfork: String,

    /// Overwrite an existing generated manifest.
    #[arg(long, default_value_t = false)]
    force: bool,
}

impl ImportBenchmarkoorSuite {
    pub(crate) fn run(self) -> eyre::Result<()> {
        ensure!(self.genesis.is_file(), "genesis file does not exist");

        let input = match (&self.suite_dir, &self.requests_dir) {
            (Some(suite_dir), None) => load_benchmarkoor_suite(suite_dir)?,
            (None, Some(requests_dir)) => load_request_corpus(requests_dir)?,
            _ => eyre::bail!("exactly one of --suite-dir or --requests-dir is required"),
        };

        let manifest_path = self.out.join("manifest.json");
        ensure!(
            self.force || !manifest_path.exists(),
            "{} already exists; pass --force to replace generated files",
            manifest_path.display()
        );

        let genesis: Genesis =
            serde_json::from_slice(&fs::read(&self.genesis).wrap_err("failed to read genesis")?)
                .wrap_err("failed to parse genesis")?;
        let chain_id = genesis.config.chain_id;
        let ethereum_genesis_hash =
            reth_chainspec::ChainSpec::from_genesis(genesis.clone()).genesis_hash();
        let tempo_chain_spec = TempoChainSpec::from_genesis(genesis);
        let tempo_genesis_hash = tempo_chain_spec.genesis_hash();

        let blocks_dir = self.out.join("blocks");
        if self.force && blocks_dir.exists() {
            fs::remove_dir_all(&blocks_dir)
                .wrap_err("failed to clear existing output block directory")?;
        }
        fs::create_dir_all(&blocks_dir).wrap_err("failed to create output block directory")?;
        fs::copy(&self.genesis, self.out.join("genesis.json"))
            .wrap_err("failed to copy suite genesis")?;

        let source_test_count = input.tests.len();
        let mut tests = Vec::new();
        let mut issues = Vec::new();
        for source_test in input.tests {
            if !self.filter.is_empty() && !source_test.name.contains(&self.filter) {
                continue;
            }
            if self.limit > 0 && tests.len() >= self.limit {
                break;
            }
            let converted = (|| -> eyre::Result<_> {
                let mut hashes = HashMap::from([(ethereum_genesis_hash, tempo_genesis_hash)]);
                let setup = convert_benchmarkoor_step(
                    source_test.setup.as_deref(),
                    &blocks_dir,
                    &mut hashes,
                    &tempo_chain_spec,
                    self.general_gas_limit,
                    self.shared_gas_limit,
                )
                .wrap_err("converting setup step")?;
                let test = convert_benchmarkoor_step(
                    Some(&source_test.test),
                    &blocks_dir,
                    &mut hashes,
                    &tempo_chain_spec,
                    self.general_gas_limit,
                    self.shared_gas_limit,
                )
                .wrap_err("converting measured step")?;
                let cleanup = convert_benchmarkoor_step(
                    source_test.cleanup.as_deref(),
                    &blocks_dir,
                    &mut hashes,
                    &tempo_chain_spec,
                    self.general_gas_limit,
                    self.shared_gas_limit,
                )
                .wrap_err("converting cleanup step")?;
                Ok((setup, test, cleanup))
            })();
            let (setup, test, cleanup) = match converted {
                Ok(converted) => converted,
                Err(error) if self.skip_incompatible => {
                    issues.push(ConversionIssue {
                        test: source_test.name,
                        error: format!("{error:#}"),
                    });
                    continue;
                }
                Err(error) => {
                    return Err(error)
                        .wrap_err_with(|| format!("failed to convert test {}", source_test.name));
                }
            };

            if test.is_empty() {
                continue;
            }

            let mut tags = vec!["benchmarkoor".to_string(), "ethereum-compat".to_string()];
            tags.extend(self.tags.iter().cloned());
            tags.sort();
            tags.dedup();

            tests.push(SuiteTest {
                name: source_test.name,
                description: "Converted from Benchmarkoor standard Engine API payloads".to_string(),
                tags,
                metadata: BTreeMap::new(),
                setup,
                test,
                cleanup,
            });
        }
        ensure!(
            !tests.is_empty(),
            "no compatible Benchmarkoor tests were imported"
        );

        let mut metadata = BTreeMap::new();
        metadata.insert("benchmarkoor_suite_hash".to_string(), input.hash);
        metadata.insert(
            "adapter".to_string(),
            "ethereum-payload-to-tempo-block".to_string(),
        );
        metadata.insert("source_layout".to_string(), input.layout);
        metadata.insert(
            "source_test_count".to_string(),
            source_test_count.to_string(),
        );
        metadata.insert("converted_test_count".to_string(), tests.len().to_string());
        metadata.insert("skipped_test_count".to_string(), issues.len().to_string());

        let manifest = Manifest {
            format: FORMAT.to_string(),
            name: self.name,
            description: "Benchmarkoor/EEST compatibility cases adapted to Tempo headers"
                .to_string(),
            origin: Origin {
                kind: "benchmarkoor".to_string(),
                repository: input.repository,
                revision: self.revision,
                generator: "tempo-xtask import-benchmarkoor-suite".to_string(),
                seed: String::new(),
            },
            chain: Chain {
                name: "tempo".to_string(),
                chain_id,
                hardfork: self.hardfork,
                genesis: "genesis.json".to_string(),
            },
            metadata,
            defaults: Defaults {
                wait_for_persistence: true,
                wait_for_caches: true,
                expected_status: "VALID".to_string(),
            },
            tests,
        };

        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).wrap_err("failed to serialize manifest")?,
        )
        .wrap_err("failed to write manifest")?;
        let report = ConversionReport {
            source_tests: source_test_count,
            converted_tests: manifest.tests.len(),
            skipped_tests: issues.len(),
            issues,
        };
        fs::write(
            self.out.join("conversion-report.json"),
            serde_json::to_vec_pretty(&report).wrap_err("failed to serialize conversion report")?,
        )
        .wrap_err("failed to write conversion report")?;
        println!("wrote {}", manifest_path.display());
        println!(
            "converted {} of {} tests ({} skipped)",
            report.converted_tests, report.source_tests, report.skipped_tests
        );
        Ok(())
    }
}

/// Match Benchmarkoor's result-directory shortening for long test names.
/// Benchmarkoor permits `/` in names, so each path component is handled
/// independently and ordinary names keep their existing layout.
fn benchmarkoor_result_path(name: &str) -> PathBuf {
    const MAX_COMPONENT_BYTES: usize = 200;
    const HASH_SUFFIX_BYTES: usize = 17;

    name.split('/')
        .map(|component| {
            if component.len() <= MAX_COMPONENT_BYTES {
                return component.to_string();
            }

            let digest = Sha256::digest(component.as_bytes());
            let prefix_len = MAX_COMPONENT_BYTES - HASH_SUFFIX_BYTES;
            let prefix = component
                .get(..prefix_len)
                .expect("Benchmarkoor test path components must be ASCII when truncated");
            format!("{prefix}-{}", const_hex::encode(&digest[..8]))
        })
        .collect()
}

struct BenchmarkoorImportInput {
    hash: String,
    repository: String,
    layout: String,
    tests: Vec<BenchmarkoorImportTest>,
}

struct BenchmarkoorImportTest {
    name: String,
    setup: Option<PathBuf>,
    test: PathBuf,
    cleanup: Option<PathBuf>,
}

#[derive(Serialize)]
struct ConversionReport {
    source_tests: usize,
    converted_tests: usize,
    skipped_tests: usize,
    issues: Vec<ConversionIssue>,
}

#[derive(Serialize)]
struct ConversionIssue {
    test: String,
    error: String,
}

#[derive(Deserialize)]
struct BenchmarkoorSummary {
    hash: String,
    tests: Vec<BenchmarkoorTest>,
}

#[derive(Deserialize)]
struct BenchmarkoorTest {
    name: String,
}

fn load_benchmarkoor_suite(suite_dir: &Path) -> eyre::Result<BenchmarkoorImportInput> {
    ensure!(
        suite_dir.is_dir(),
        "Benchmarkoor suite directory does not exist"
    );
    let summary: BenchmarkoorSummary = serde_json::from_slice(
        &fs::read(suite_dir.join("summary.json"))
            .wrap_err("failed to read Benchmarkoor summary.json")?,
    )
    .wrap_err("failed to parse Benchmarkoor summary.json")?;

    let tests = summary
        .tests
        .into_iter()
        .map(|test| {
            let source_dir = suite_dir.join(benchmarkoor_result_path(&test.name));
            BenchmarkoorImportTest {
                name: test.name,
                setup: existing_file(source_dir.join("setup.request")),
                test: source_dir.join("test.request"),
                cleanup: existing_file(source_dir.join("cleanup.request")),
            }
        })
        .collect();

    Ok(BenchmarkoorImportInput {
        hash: summary.hash,
        repository: "https://github.com/ethpandaops/benchmarkoor".to_string(),
        layout: "benchmarkoor-suite-output".to_string(),
        tests,
    })
}

fn load_request_corpus(requests_dir: &Path) -> eyre::Result<BenchmarkoorImportInput> {
    ensure!(
        requests_dir.is_dir(),
        "request corpus directory does not exist"
    );

    let corpus_dir = if requests_dir.join("testing").is_dir() {
        requests_dir.to_path_buf()
    } else if requests_dir.join("eest_tests/testing").is_dir() {
        requests_dir.join("eest_tests")
    } else {
        eyre::bail!(
            "request corpus must contain testing/ or eest_tests/testing/: {}",
            requests_dir.display()
        );
    };
    let testing_dir = corpus_dir.join("testing");
    let setup_dir = corpus_dir.join("setup");
    let cleanup_dir = corpus_dir.join("cleanup");
    let mut measured = Vec::new();
    collect_request_files(&testing_dir, &mut measured)?;
    measured.sort();
    ensure!(
        !measured.is_empty(),
        "request corpus contains no measured tests"
    );

    let mut tests = Vec::with_capacity(measured.len());
    for test in measured {
        let relative = test
            .strip_prefix(&testing_dir)
            .wrap_err("failed to derive request corpus test name")?
            .to_path_buf();
        let name = relative.to_string_lossy().replace('\\', "/");
        tests.push(BenchmarkoorImportTest {
            name,
            setup: existing_file(setup_dir.join(&relative)),
            test,
            cleanup: existing_file(cleanup_dir.join(&relative)),
        });
    }

    let mut hasher = Sha256::new();
    for test in &tests {
        hasher.update(test.name.as_bytes());
        for (step, path) in [
            ("setup", test.setup.as_ref()),
            ("test", Some(&test.test)),
            ("cleanup", test.cleanup.as_ref()),
        ] {
            if let Some(path) = path {
                hasher.update(step.as_bytes());
                hasher.update(
                    fs::read(path).wrap_err_with(|| {
                        format!("failed to hash request file {}", path.display())
                    })?,
                );
            }
        }
    }
    let digest = hasher.finalize();

    Ok(BenchmarkoorImportInput {
        hash: const_hex::encode(&digest[..8]),
        repository: "https://github.com/NethermindEth/gas-benchmarks".to_string(),
        layout: "benchmarkoor-request-corpus".to_string(),
        tests,
    })
}

fn existing_file(path: PathBuf) -> Option<PathBuf> {
    path.is_file().then_some(path)
}

fn collect_request_files(dir: &Path, files: &mut Vec<PathBuf>) -> eyre::Result<()> {
    for entry in fs::read_dir(dir)
        .wrap_err_with(|| format!("failed to read request directory {}", dir.display()))?
    {
        let path = entry
            .wrap_err("failed to read request directory entry")?
            .path();
        if path.is_dir() {
            collect_request_files(&path, files)?;
        } else if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("txt" | "jsonl")
        ) {
            files.push(path);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EthereumExecutionPayload {
    parent_hash: B256,
    fee_recipient: Address,
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    prev_randao: B256,
    block_number: String,
    gas_limit: String,
    gas_used: String,
    timestamp: String,
    extra_data: Bytes,
    base_fee_per_gas: String,
    block_hash: B256,
    transactions: Vec<Bytes>,
    #[serde(default)]
    withdrawals: Option<Withdrawals>,
    #[serde(default)]
    blob_gas_used: Option<String>,
    #[serde(default)]
    excess_blob_gas: Option<String>,
}

fn convert_benchmarkoor_step(
    path: Option<&Path>,
    blocks_dir: &Path,
    hashes: &mut HashMap<B256, B256>,
    chain_spec: &TempoChainSpec,
    general_gas_limit: Option<u64>,
    shared_gas_limit: Option<u64>,
) -> eyre::Result<Vec<Call>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    ensure!(
        path.is_file(),
        "request step does not exist: {}",
        path.display()
    );

    let file =
        fs::File::open(path).wrap_err_with(|| format!("failed to open {}", path.display()))?;
    let mut calls = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.wrap_err("failed to read Benchmarkoor request")?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = serde_json::from_str(&line)
            .wrap_err_with(|| format!("invalid JSON-RPC at {}:{}", path.display(), index + 1))?;
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            continue;
        };
        if !method.starts_with("engine_newPayload") {
            continue;
        }

        let params = request
            .get("params")
            .and_then(Value::as_array)
            .ok_or_else(|| eyre::eyre!("newPayload request has no params"))?;
        let payload: EthereumExecutionPayload = serde_json::from_value(
            params
                .first()
                .cloned()
                .ok_or_else(|| eyre::eyre!("newPayload has no payload"))?,
        )
        .wrap_err("failed to decode execution payload")?;

        ensure!(
            payload.withdrawals.as_ref().is_none_or(|w| w.is_empty()),
            "Tempo compatibility adapter does not support non-empty withdrawals"
        );

        let parent_hash = hashes.get(&payload.parent_hash).copied().ok_or_else(|| {
            eyre::eyre!(
                "payload parent {} is not the genesis or a preceding payload; non-linear suites are not supported",
                payload.parent_hash
            )
        })?;

        let transactions = payload
            .transactions
            .iter()
            .map(|encoded| {
                TempoTxEnvelope::decode_2718_exact(encoded.as_ref())
                    .wrap_err("unsupported transaction in Ethereum compatibility suite")
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        let withdrawals_root = payload
            .withdrawals
            .as_ref()
            .map(|withdrawals| alloy::consensus::proofs::calculate_withdrawals_root(withdrawals));
        let parent_beacon_block_root = params
            .get(2)
            .filter(|value| !value.is_null())
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .wrap_err("invalid parent beacon block root")?;
        let requests_hash = params
            .get(3)
            .map(|value| serde_json::from_value::<Vec<Bytes>>(value.clone()))
            .transpose()
            .wrap_err("invalid execution requests")?
            .map(|requests| Requests::new(requests).requests_hash());

        let gas_limit = parse_quantity(&payload.gas_limit)?;
        let gas_used = parse_quantity(&payload.gas_used)?;
        let timestamp = parse_quantity(&payload.timestamp)?;
        let shared_gas_limit = shared_gas_limit
            .unwrap_or_else(|| chain_spec.shared_gas_limit_at(timestamp, gas_limit));
        let general_gas_limit = general_gas_limit.unwrap_or_else(|| {
            chain_spec.general_gas_limit_at(timestamp, gas_limit, shared_gas_limit)
        });
        let base_fee = U256::from_str(&payload.base_fee_per_gas)
            .wrap_err("invalid baseFeePerGas")?
            .try_into()
            .wrap_err("baseFeePerGas does not fit u64")?;
        let body = BlockBody {
            transactions,
            ommers: Vec::new(),
            withdrawals: payload.withdrawals,
        };
        let inner = Header {
            parent_hash,
            beneficiary: payload.fee_recipient,
            state_root: payload.state_root,
            transactions_root: calculate_transaction_root(&body.transactions),
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            difficulty: U256::ZERO,
            number: parse_quantity(&payload.block_number)?,
            gas_limit,
            gas_used,
            timestamp,
            extra_data: payload.extra_data,
            mix_hash: payload.prev_randao,
            base_fee_per_gas: Some(base_fee),
            withdrawals_root,
            blob_gas_used: payload
                .blob_gas_used
                .as_deref()
                .map(parse_quantity)
                .transpose()?,
            excess_blob_gas: payload
                .excess_blob_gas
                .as_deref()
                .map(parse_quantity)
                .transpose()?,
            parent_beacon_block_root,
            requests_hash,
            ..Default::default()
        };
        let header = TempoHeader {
            general_gas_limit,
            shared_gas_limit,
            timestamp_millis_part: 0,
            inner,
            consensus_context: None,
        };
        let tempo_hash = header.hash_slow();
        let block = TempoBlock { header, body };
        let encoded = alloy_rlp::encode(&block);
        let filename = format!("{}.rlp", tempo_hash.to_string().trim_start_matches("0x"));
        fs::write(
            blocks_dir.join(&filename),
            format!("0x{}", const_hex::encode(encoded)),
        )
        .wrap_err("failed to write adapted block")?;

        hashes.insert(payload.block_hash, tempo_hash);
        calls.push(Call {
            method: None,
            params: None,
            rlp_file: Some(format!("blocks/{filename}")),
            bal_file: None,
            wait_for_caches: Some(true),
            block_number: Some(parse_quantity(&payload.block_number)?),
            block_hash: Some(tempo_hash.to_string()),
            gas_used: Some(gas_used),
            transaction_count: Some(block.body.transactions.len() as u64),
            expected_status: Some("VALID".to_string()),
        });
        calls.push(Call {
            method: Some("reth_forkchoiceUpdated".to_string()),
            params: Some(vec![json!({
                "headBlockHash": tempo_hash,
                "safeBlockHash": B256::ZERO,
                "finalizedBlockHash": B256::ZERO,
            })]),
            rlp_file: None,
            bal_file: None,
            wait_for_caches: None,
            block_number: Some(parse_quantity(&payload.block_number)?),
            block_hash: Some(tempo_hash.to_string()),
            gas_used: None,
            transaction_count: None,
            expected_status: Some("VALID".to_string()),
        });
    }

    Ok(calls)
}

#[derive(Serialize)]
struct Manifest {
    format: String,
    name: String,
    description: String,
    origin: Origin,
    chain: Chain,
    metadata: BTreeMap<String, String>,
    defaults: Defaults,
    tests: Vec<SuiteTest>,
}

#[derive(Serialize)]
struct Origin {
    kind: String,
    repository: String,
    revision: String,
    generator: String,
    seed: String,
}

#[derive(Serialize)]
struct Chain {
    name: String,
    chain_id: u64,
    hardfork: String,
    genesis: String,
}

#[derive(Serialize)]
struct Defaults {
    wait_for_persistence: bool,
    wait_for_caches: bool,
    expected_status: String,
}

#[derive(Serialize)]
struct SuiteTest {
    name: String,
    description: String,
    tags: Vec<String>,
    metadata: BTreeMap<String, String>,
    setup: Vec<Call>,
    test: Vec<Call>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cleanup: Vec<Call>,
}

#[derive(Serialize)]
struct Call {
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rlp_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bal_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wait_for_caches: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_status: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, path::PathBuf};

    use alloy::{genesis::Genesis, primitives::B256};
    use serde_json::json;
    use tempfile::tempdir;

    use super::{
        ImportBenchmarkoorSuite, TempoChainSpec, benchmarkoor_result_path,
        convert_benchmarkoor_step, parse_quantity,
    };

    #[test]
    fn parses_rpc_quantities() {
        assert_eq!(parse_quantity("0x0").unwrap(), 0);
        assert_eq!(parse_quantity("0x2a").unwrap(), 42);
    }

    #[test]
    fn matches_benchmarkoor_long_result_paths() {
        let name = format!("eest/{}", "a".repeat(201));
        let path = benchmarkoor_result_path(&name);
        assert_eq!(
            path.to_string_lossy(),
            format!("eest/{}-{}", "a".repeat(183), "a92efd82109373e5")
        );
    }

    #[test]
    fn converts_standard_payload_to_tempo_rlp() {
        let dir = tempdir().unwrap();
        let blocks = dir.path().join("blocks");
        fs::create_dir(&blocks).unwrap();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "engine_newPayloadV3",
            "params": [{
                "parentHash": B256::ZERO,
                "feeRecipient": "0x0000000000000000000000000000000000000000",
                "stateRoot": B256::ZERO,
                "receiptsRoot": B256::ZERO,
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "prevRandao": B256::ZERO,
                "blockNumber": "0x1",
                "gasLimit": "0x1c9c380",
                "gasUsed": "0x0",
                "timestamp": "0x1",
                "extraData": "0x",
                "baseFeePerGas": "0x1",
                "blockHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "transactions": [],
                "withdrawals": [],
                "blobGasUsed": "0x0",
                "excessBlobGas": "0x0"
            }, [], B256::ZERO]
        });
        let requests = dir.path().join("test.request");
        fs::write(&requests, format!("{request}\n")).unwrap();

        let mut hashes = HashMap::from([(B256::ZERO, B256::ZERO)]);
        let chain_spec = TempoChainSpec::from_genesis(Genesis::default());
        let calls = convert_benchmarkoor_step(
            Some(&requests),
            &blocks,
            &mut hashes,
            &chain_spec,
            None,
            None,
        )
        .unwrap();

        assert_eq!(calls.len(), 2);
        assert!(
            blocks
                .join(
                    calls[0]
                        .rlp_file
                        .as_ref()
                        .unwrap()
                        .trim_start_matches("blocks/")
                )
                .is_file()
        );
        assert_eq!(calls[0].gas_used, Some(0));
        assert_eq!(calls[0].transaction_count, Some(0));
        assert_eq!(calls[1].method.as_deref(), Some("reth_forkchoiceUpdated"));
        assert_eq!(
            calls[1].params.as_ref().unwrap()[0]["safeBlockHash"],
            B256::ZERO.to_string()
        );
        assert_eq!(
            calls[1].params.as_ref().unwrap()[0]["finalizedBlockHash"],
            B256::ZERO.to_string()
        );
    }

    #[test]
    fn imports_benchmarkoor_suite_into_semantic_manifest() {
        let dir = tempdir().unwrap();
        let suite = dir.path().join("suite");
        let source_test = suite.join("compat/basic");
        fs::create_dir_all(&source_test).unwrap();

        let source_genesis = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/node/tests/assets/test-genesis.json");
        let genesis_path = dir.path().join("genesis.json");
        fs::copy(&source_genesis, &genesis_path).unwrap();
        let genesis: Genesis = serde_json::from_slice(&fs::read(&genesis_path).unwrap()).unwrap();
        let parent_hash = reth_chainspec::ChainSpec::from_genesis(genesis).genesis_hash();

        fs::write(
            suite.join("summary.json"),
            serde_json::to_vec(&json!({
                "hash": "benchmarkoor-suite-hash",
                "tests": [{"name": "compat/basic"}]
            }))
            .unwrap(),
        )
        .unwrap();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "engine_newPayloadV3",
            "params": [{
                "parentHash": parent_hash,
                "feeRecipient": "0x0000000000000000000000000000000000000000",
                "stateRoot": B256::ZERO,
                "receiptsRoot": B256::ZERO,
                "logsBloom": format!("0x{}", "00".repeat(256)),
                "prevRandao": B256::ZERO,
                "blockNumber": "0x1",
                "gasLimit": "0x1c9c380",
                "gasUsed": "0x0",
                "timestamp": "0x1",
                "extraData": "0x",
                "baseFeePerGas": "0x1",
                "blockHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "transactions": [],
                "withdrawals": [],
                "blobGasUsed": "0x0",
                "excessBlobGas": "0x0"
            }, [], B256::ZERO]
        });
        fs::write(source_test.join("test.request"), format!("{request}\n")).unwrap();

        let out = dir.path().join("out");
        ImportBenchmarkoorSuite {
            suite_dir: Some(suite),
            requests_dir: None,
            genesis: genesis_path,
            out: out.clone(),
            name: "compat".to_string(),
            filter: String::new(),
            limit: 0,
            skip_incompatible: false,
            general_gas_limit: None,
            shared_gas_limit: None,
            tags: vec!["eest".to_string()],
            revision: "test-revision".to_string(),
            hardfork: "ethereum-compat".to_string(),
            force: false,
        }
        .run()
        .unwrap();

        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["format"], "tempo-engine-suite/v1");
        assert_eq!(manifest["tests"][0]["name"], "compat/basic");
        assert_eq!(manifest["tests"][0]["test"].as_array().unwrap().len(), 2);
        let rlp_file = manifest["tests"][0]["test"][0]["rlp_file"]
            .as_str()
            .unwrap();
        assert!(out.join(rlp_file).is_file());
    }
}
