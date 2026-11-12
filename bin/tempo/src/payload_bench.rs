//! Standalone payload builder benchmark over an existing database.
//!
//! Opens a datadir read-only, builds the real Tempo transaction pool on top of it, fills the pool
//! with TIP-20 transfers (the derek bench `tip20` preset), and repeatedly builds a payload on the
//! database tip with [`TempoPayloadBuilder`]. Nothing is committed, so every build starts from the
//! same parent state and the same pool, which makes runs repeatable and easy to profile.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer::SignerSync as _;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use alloy_sol_types::SolCall as _;
use clap::Parser;
use eyre::{OptionExt as _, ensure};
use rand::RngExt as _;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, PayloadBuilder as _, PayloadConfig,
};
use reth_chainspec::{ChainSpecProvider as _, EthChainSpec as _};
use reth_cli_commands::common::{AccessRights, EnvironmentArgs};
use reth_ethereum::{
    pool::{
        PoolConfig, SubPoolLimit, TransactionOrigin, TransactionPool as _,
        TransactionValidationTaskExecutor,
    },
    tasks::Runtime,
};
use reth_execution_cache::{ExecutionCache, SavedCache};
use reth_node_builder::BuiltPayload as _;
use reth_payload_builder::PayloadId;
use reth_primitives_traits::{Recovered, SignerRecoverable as _};
use reth_provider::{BlockNumReader as _, HeaderProvider as _, providers::BlockchainProvider};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tempo_chainspec::spec::TempoChainSpecParser;
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::TempoEvmConfig;
use tempo_node::node::{TempoNode, TempoPoolBuilder};
use tempo_payload_builder::{TempoPayloadBuilder, TempoPayloadBuilderConfig};
use tempo_payload_types::{Estimator, EstimatorConfig, TempoPayloadAttributes};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    TempoAddressExt as _, TempoTxEnvelope,
    transaction::{TEMPO_EXPIRING_NONCE_KEY, TempoTransaction, tempo_transaction::Call},
};
use tempo_transaction_pool::transaction::TempoPooledTransaction;
use tracing::{info, warn};

/// Benchmark the payload builder alone against an existing database and a real transaction pool.
#[derive(Debug, Parser)]
pub struct PayloadBench {
    /// Chain and database environment to build on. The database is opened read-only.
    #[command(flatten)]
    env: EnvironmentArgs<TempoChainSpecParser>,

    /// Number of measured builds.
    #[arg(long, default_value_t = 10)]
    iterations: usize,

    /// Number of unmeasured builds run first.
    #[arg(long, default_value_t = 2)]
    warmup: usize,

    /// Number of generated TIP-20 transfers to put into the pool.
    #[arg(long, default_value_t = 40_000)]
    txs: usize,

    /// Number of mnemonic accounts that send and receive the transfers (derek bench `accounts`).
    #[arg(long, default_value_t = 1000)]
    accounts: u32,

    /// Number of TIP-20 tokens (ids `0..N`) the transfers pick from.
    #[arg(long, default_value_t = 4)]
    tokens: u64,

    /// Mnemonic of the funded accounts.
    #[arg(
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    /// Raw EIP-2718 transactions, one hex string per line, to use instead of generated transfers.
    #[arg(long)]
    txs_file: Option<PathBuf>,

    /// Disable prewarming of best transactions.
    #[arg(long)]
    disable_prewarming: bool,

    /// Enable speculative parallel payload-builder planning.
    #[arg(long)]
    parallel: bool,

    /// Skip state-root computation.
    #[arg(long)]
    skip_state_root: bool,

    /// Share an execution cache of this many MiB across builds, as the engine shares its cache
    /// with the builder. Builds after the first find the state they read already cached.
    /// 0 builds without one.
    #[arg(long, default_value_t = 0)]
    execution_cache_mib: usize,
}

impl PayloadBench {
    pub(crate) async fn execute(self, runtime: Runtime) -> eyre::Result<()> {
        let environment = self
            .env
            .init::<TempoNode>(AccessRights::RO, runtime.clone())?;
        let provider = BlockchainProvider::new(environment.provider_factory)?;
        let chain_spec = provider.chain_spec();
        let tip = provider.best_block_number()?;
        let parent = Arc::new(
            provider
                .sealed_header(tip)?
                .ok_or_eyre("database tip header not found")?,
        );
        info!(
            number = parent.number(),
            hash = ?parent.hash(),
            gas_limit = parent.gas_limit(),
            "Building on database tip"
        );

        let evm_config = TempoEvmConfig::new(chain_spec.clone());
        let unlimited = SubPoolLimit {
            max_txs: usize::MAX,
            max_size: usize::MAX,
        };
        let pool_config = PoolConfig {
            pending_limit: unlimited,
            basefee_limit: unlimited,
            queued_limit: unlimited,
            max_account_slots: usize::MAX,
            ..Default::default()
        };
        let pool = TempoPoolBuilder::default().build_with_validator(
            provider.clone(),
            TransactionValidationTaskExecutor::eth_builder(provider.clone(), evm_config.clone())
                .with_additional_tasks(std::thread::available_parallelism()?.get()),
            runtime.clone(),
            pool_config,
            true,
        )?;

        let started = Instant::now();
        let transactions = match &self.txs_file {
            Some(path) => read_transactions(path)?,
            None => {
                ensure!(
                    self.accounts > 0 && self.tokens > 0,
                    "--accounts and --tokens must be greater than zero"
                );
                self.generate_transfers(chain_spec.chain_id(), parent.timestamp())?
            }
        };
        info!(count = transactions.len(), elapsed = ?started.elapsed(), "Prepared transactions");

        let started = Instant::now();
        let mut rejected = 0usize;
        for chunk in transactions.chunks(4096) {
            for result in pool
                .add_transactions(TransactionOrigin::External, chunk.to_vec())
                .await
            {
                if let Err(err) = result {
                    if rejected == 0 {
                        warn!(%err, "Pool rejected a transaction");
                    }
                    rejected += 1;
                }
            }
        }
        let size = pool.pool_size();
        info!(
            accepted = transactions.len() - rejected,
            rejected,
            pending = size.pending,
            queued = size.queued,
            elapsed = ?started.elapsed(),
            "Filled transaction pool"
        );
        ensure!(size.pending > 0, "no pending transactions to build with");

        let builder = TempoPayloadBuilder::new(
            pool,
            provider,
            runtime,
            evm_config,
            TempoPayloadBuilderConfig {
                desired_gas_limit: None,
                is_dev: true,
                state_provider_metrics: false,
                enable_prewarming: !self.disable_prewarming,
                skip_state_root: self.skip_state_root,
                enable_parallel: self.parallel,
            },
            Estimator::new(EstimatorConfig::default()),
        );

        let execution_cache = (self.execution_cache_mib > 0)
            .then(|| ExecutionCache::new(self.execution_cache_mib * 1024 * 1024));
        let mut samples = Vec::with_capacity(self.iterations);
        for iteration in 0..self.warmup + self.iterations {
            let attributes = TempoPayloadAttributes::new(
                None,
                parent.timestamp() + 1,
                0,
                Default::default(),
                None,
            );
            let execution_cache = execution_cache
                .as_ref()
                .map(|cache: &ExecutionCache| SavedCache::new(parent.hash(), cache.clone()));
            let args = BuildArguments::new(
                Default::default(),
                execution_cache,
                None,
                PayloadConfig::new(parent.clone(), attributes, PayloadId::new([0; 8])),
                Default::default(),
                None,
            );

            let started = Instant::now();
            // The builder blocks on its roots task, so it must not run on an async worker thread.
            let outcome = tokio::task::block_in_place(|| builder.try_build(args))?;
            let elapsed = started.elapsed();
            let BuildOutcome::Freeze(payload) = outcome else {
                eyre::bail!("payload build did not finish: {outcome:?}");
            };
            let block = payload.block();
            let gas_used = block.gas_used();
            let transactions = block.body().transactions.len();
            let warmup = iteration < self.warmup;
            info!(
                iteration,
                warmup,
                ?elapsed,
                transactions,
                gas_used,
                mgas_per_second = gas_used as f64 / elapsed.as_secs_f64() / 1e6,
                "Payload build finished"
            );
            if !warmup {
                samples.push((elapsed, gas_used, transactions));
            }
        }

        report(&samples);
        Ok(())
    }

    /// Signs `self.txs` TIP-20 transfers shaped like the derek bench `tip20` preset: random sender
    /// and recipient among the accounts, a random token, an expiring nonce and pathUSD fees.
    fn generate_transfers(
        &self,
        chain_id: u64,
        parent_timestamp: u64,
    ) -> eyre::Result<Vec<TempoPooledTransaction>> {
        let signers = (0..self.accounts)
            .map(|index| MnemonicBuilder::from_phrase_nth(self.mnemonic.as_str(), index))
            .collect::<Vec<PrivateKeySigner>>();
        let mut rng = rand::rng();
        (0..self.txs)
            .map(|_| -> eyre::Result<TempoPooledTransaction> {
                let sender = &signers[rng.random_range(0..signers.len())];
                let recipient = signers[rng.random_range(0..signers.len())].address();
                let token = Address::new_tip20(rng.random_range(0..self.tokens));
                let tx = TempoTransaction {
                    chain_id,
                    max_priority_fee_per_gas: 100_000_000_000,
                    max_fee_per_gas: 100_000_000_000,
                    gas_limit: 300_000,
                    calls: vec![Call {
                        to: TxKind::Call(token),
                        value: U256::ZERO,
                        input: ITIP20::transferCall {
                            to: recipient,
                            amount: U256::from(1),
                        }
                        .abi_encode()
                        .into(),
                    }],
                    nonce_key: TEMPO_EXPIRING_NONCE_KEY,
                    nonce: rng.random(),
                    fee_token: Some(PATH_USD_ADDRESS),
                    fee_payer_signature: None,
                    valid_after: None,
                    valid_before: std::num::NonZeroU64::new(parent_timestamp + 10),
                    access_list: Default::default(),
                    tempo_authorization_list: Vec::new(),
                    key_authorization: None,
                };
                let signature = sender.sign_hash_sync(&tx.signature_hash())?;
                let envelope = TempoTxEnvelope::from(tx.into_signed(signature.into()));
                Ok(TempoPooledTransaction::new(Recovered::new_unchecked(
                    envelope,
                    sender.address(),
                )))
            })
            .collect()
    }
}

/// Reads raw EIP-2718 transactions, one hex string per line, and recovers their senders.
fn read_transactions(path: &Path) -> eyre::Result<Vec<TempoPooledTransaction>> {
    std::fs::read_to_string(path)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let bytes = alloy_primitives::hex::decode(line)?;
            let envelope =
                <TempoTxEnvelope as alloy_eips::eip2718::Decodable2718>::decode_2718_exact(&bytes)?;
            Ok(TempoPooledTransaction::new(envelope.try_into_recovered()?))
        })
        .collect()
}

/// Logs min, median and max build time and throughput over the measured builds.
fn report(samples: &[(Duration, u64, usize)]) {
    if samples.is_empty() {
        return;
    }
    let mut times = samples
        .iter()
        .map(|(elapsed, ..)| *elapsed)
        .collect::<Vec<_>>();
    times.sort();
    let gas = samples.iter().map(|(_, gas, _)| *gas).sum::<u64>() as f64 / samples.len() as f64;
    let txs = samples.iter().map(|(.., txs)| *txs).sum::<usize>() as f64 / samples.len() as f64;
    let median = times[times.len() / 2];
    info!(
        builds = samples.len(),
        min = ?times[0],
        median = ?median,
        max = ?times[times.len() - 1],
        avg_transactions = txs,
        avg_gas_used = gas,
        median_mgas_per_second = gas / median.as_secs_f64() / 1e6,
        "Payload builder benchmark"
    );
}
