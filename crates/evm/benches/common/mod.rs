//! Shared microbenchmark helpers for EVM execution benches.

use alloy_consensus::transaction::{Recovered, SignerRecoverable};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use evm2::evm::InMemoryDB;
use reth_evm::{BlockExecutor, BlockExecutorFactory};
use reth_evm_ethereum::EthBlockExecutionCtx;
use std::{
    num::NonZeroU64,
    time::{SystemTime, UNIX_EPOCH},
};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
    spec::TEMPO_T1_BASE_FEE,
};
use tempo_evm::{
    TempoBlockEnv, TempoBlockExecutionCtx, TempoEvm, TempoEvmConfig, TempoEvmEnv, TempoTxEnv,
    tempo_execution_config,
};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    AASigned, TempoBlockExt, TempoSignature, TempoTransaction, TempoTxEnvelope,
    transaction::{Call, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY},
};

pub(crate) const CHAIN_ID: u64 = 1337;
pub(crate) const TXGEN_MNEMONIC: &str =
    "test test test test test test test test test test test junk";
pub(crate) const DEFAULT_ACCOUNT_COUNT: usize = 1_024;
pub(crate) const DEFAULT_BLOCK_TIMESTAMP: u64 = 1_700_000_000;
pub(crate) const TXGEN_GAS_LIMIT: u64 = 2_000_000;
pub(crate) const TXGEN_FEE_PER_GAS: u128 = 100_000_000_000;

#[derive(Default)]
pub(crate) struct ExecutionStats {
    pub(crate) txs: u64,
    pub(crate) gas_used: u64,
}

#[derive(Clone)]
pub(crate) struct ExecutionFixture {
    db: InMemoryDB,
}

impl ExecutionFixture {
    pub(crate) fn state_db(&self) -> InMemoryDB {
        self.db.clone()
    }

    pub(crate) fn prewarm_state_db(&self) -> InMemoryDB {
        self.state_db()
    }
}

pub(crate) fn current_active_hardfork() -> TempoHardfork {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs();
    TempoChainSpec::mainnet().tempo_hardfork_at(now)
}
pub(crate) fn latest_known_hardfork() -> TempoHardfork {
    *TempoHardfork::VARIANTS
        .last()
        .expect("TempoHardfork has at least one variant")
}
pub(crate) fn hardfork_bench_cases() -> Vec<(&'static str, TempoHardfork)> {
    let current = current_active_hardfork();
    let latest = latest_known_hardfork();
    let mut cases = vec![("current", current)];
    if latest != current {
        cases.push(("latest", latest));
    }
    cases
}

pub(crate) fn bench_env(hardfork: TempoHardfork, block_timestamp: u64) -> TempoEvmEnv {
    let mut version = *tempo_execution_config(hardfork, CHAIN_ID).version();
    version.tx_gas_limit_cap = hardfork.tx_gas_limit_cap().unwrap_or(u64::MAX);
    TempoEvmEnv {
        tempo_spec: hardfork,
        version,
        block: TempoBlockEnv {
            number: U256::from(1),
            beneficiary: Address::repeat_byte(0x42),
            timestamp: U256::from(block_timestamp),
            basefee: U256::from(TEMPO_T1_BASE_FEE),
            gas_limit: U256::from(10_000_000_000u64),
            ext: TempoBlockExt::default(),
            ..Default::default()
        },
    }
}

pub(crate) fn bench_evm(
    db: InMemoryDB,
    hardfork: TempoHardfork,
    timestamp: u64,
) -> TempoEvm<'static> {
    BlockExecutorFactory::evm_with_env(
        &TempoEvmConfig::moderato(),
        db,
        bench_env(hardfork, timestamp),
    )
}

pub(crate) fn seeded_db(evm: &TempoEvm<'_>) -> InMemoryDB {
    let mut db = InMemoryDB::default();
    db.cache = evm.overlay_db().cache.clone();
    db
}

pub(crate) fn txgen_signers(account_count: usize) -> Vec<PrivateKeySigner> {
    (0..account_count)
        .map(|idx| {
            MnemonicBuilder::from_phrase(TXGEN_MNEMONIC)
                .index(idx as u32)
                .expect("valid txgen account index")
                .build()
                .expect("valid txgen mnemonic")
        })
        .collect()
}

pub(crate) fn sign_precompile_call(
    signer: &PrivateKeySigner,
    to: Address,
    input: Bytes,
) -> Recovered<TempoTxEnvelope> {
    let tx = TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: Some(PATH_USD_ADDRESS),
        max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
        max_fee_per_gas: TXGEN_FEE_PER_GAS,
        gas_limit: TXGEN_GAS_LIMIT,
        calls: vec![Call {
            to: TxKind::Call(to),
            value: U256::ZERO,
            input,
        }],
        access_list: Default::default(),
        nonce_key: TEMPO_EXPIRING_NONCE_KEY,
        nonce: 0,
        fee_payer_signature: None,
        valid_before: Some(NonZeroU64::new(DEFAULT_BLOCK_TIMESTAMP + 10).unwrap()),
        valid_after: None,
        key_authorization: None,
        tempo_authorization_list: Vec::new(),
    };
    let signature = signer
        .sign_hash_sync(&tx.signature_hash())
        .expect("failed to sign generated benchmark transaction");
    let signed = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );
    TempoTxEnvelope::from(signed)
        .try_into_recovered()
        .expect("generated benchmark transaction should recover")
}

pub(crate) fn fixture_from_seeded_db(db: InMemoryDB) -> ExecutionFixture {
    ExecutionFixture { db }
}

pub(crate) fn execute_txs<DB>(
    config: &TempoEvmConfig,
    db: DB,
    txs: &[Recovered<TempoTxEnvelope>],
    block_timestamp: u64,
    hardfork: TempoHardfork,
) -> ExecutionStats
where
    DB: evm2::evm::DynDatabase + 'static,
{
    let evm = BlockExecutorFactory::evm_with_env(config, db, bench_env(hardfork, block_timestamp));
    let ctx = TempoBlockExecutionCtx {
        inner: EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::ZERO),
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(txs.len()),
            slot_number: None,
        },
        general_gas_limit: 10_000_000_000,
        shared_gas_limit: 0,
        validator_set: None,
        consensus_context: None,
        subblock_fee_recipients: Default::default(),
    };
    let mut executor = config.create_executor(evm, ctx);
    executor
        .apply_pre_execution_changes()
        .expect("failed to apply pre-execution changes");
    let mut stats = ExecutionStats::default();
    for tx in txs {
        assert!(
            tx.inner().is_aa(),
            "execution bench expects Tempo AA transactions"
        );
        let signer = tx.signer();
        let output = executor
            .execute_transaction_without_commit((
                Recovered::new_unchecked(TempoTxEnv::from(tx.clone()), signer),
                tx.clone(),
            ))
            .expect("transaction execution failed");
        assert!(
            output.result().status,
            "transaction reverted: {:?}",
            output.result()
        );
        stats.gas_used = stats.gas_used.saturating_add(
            executor
                .commit_transaction(output)
                .expect("commit failed")
                .tx_gas_used(),
        );
        stats.txs += 1;
    }
    stats
}
