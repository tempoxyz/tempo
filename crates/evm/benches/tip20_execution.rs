//! Pure TIP20 execution benchmark.
//!
//! By default this generates txgen-style AA TIP20 transfers from the benchmark mnemonic. Set
//! `TEMPO_TIP20_EXEC_TXS` to a newline-delimited raw 2718 txgen output file to replay exact
//! txgen transactions against the in-memory execution path.

use alloy_consensus::transaction::{Recovered, SignerRecoverable};
use alloy_eips::Decodable2718;
use alloy_evm::{
    Evm, EvmEnv, EvmFactory,
    block::{BlockExecutor, BlockExecutorFactory, TxResult},
    eth::EthBlockExecutionCtx,
};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use alloy_sol_types::SolCall;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use revm::{
    DatabaseCommit,
    context::{BlockEnv, CfgEnv},
    database::{CacheDB, EmptyDB},
    inspector::JournalExt,
};
use std::{
    collections::BTreeSet,
    fs,
    hint::black_box,
    num::NonZeroU64,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE};
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::{
    TempoBlockEnv, TempoBlockExecutionCtx, TempoEvmConfig, TempoEvmFactory, evm::TempoEvm,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    error::TempoPrecompileError,
    nonce::NonceManager,
    storage::StorageCtx,
    tip_fee_manager::TipFeeManager,
    tip20::{ISSUER_ROLE, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{
    AASigned, TempoSignature, TempoTransaction, TempoTxEnvelope,
    transaction::{Call, PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY},
};
use tempo_revm::gas_params::tempo_gas_params_with_amsterdam;

const CHAIN_ID: u64 = 1337;
const TXGEN_MNEMONIC: &str = "test test test test test test test test test test test junk";
const DEFAULT_ACCOUNT_COUNT: usize = 1_024;
const DEFAULT_TX_COUNT: usize = 4_096;
const DEFAULT_BLOCK_TIMESTAMP: u64 = 1_700_000_000;
const TXGEN_GAS_LIMIT: u64 = 300_000;
const TXGEN_FEE_PER_GAS: u128 = 100_000_000_000;
const PARTICIPANT_MINT_AMOUNT: u128 = 1_000_000_000_000_000_000;

#[derive(Clone)]
struct Workload {
    transactions: Vec<Recovered<TempoTxEnvelope>>,
    participants: Vec<Address>,
    block_timestamp: u64,
}

#[derive(Default)]
struct ExecutionStats {
    txs: u64,
    gas_used: u64,
}

fn bench_env(block_timestamp: u64) -> EvmEnv<TempoHardfork, TempoBlockEnv> {
    let spec = TempoHardfork::T5;
    let amsterdam_eip8037_enabled = false;
    let mut cfg_env = CfgEnv::default();
    cfg_env.chain_id = CHAIN_ID;
    cfg_env.spec = spec;
    cfg_env.gas_params = tempo_gas_params_with_amsterdam(spec, amsterdam_eip8037_enabled);
    cfg_env.tx_gas_limit_cap = spec.tx_gas_limit_cap();

    EvmEnv {
        cfg_env,
        block_env: TempoBlockEnv {
            inner: BlockEnv {
                number: U256::from(1),
                beneficiary: Address::repeat_byte(0x42),
                timestamp: U256::from(block_timestamp),
                basefee: TEMPO_T1_BASE_FEE,
                gas_limit: 10_000_000_000,
                ..Default::default()
            },
            timestamp_millis_part: 0,
        },
    }
}

fn setup_in_memory_state(participants: &[Address], block_timestamp: u64) -> CacheDB<EmptyDB> {
    // The benchmark state is intentionally a revm memory overlay over an empty database.
    // Do not replace this with a provider backed by DB files or static files.
    let mut evm = TempoEvmFactory::default()
        .create_evm(CacheDB::new(EmptyDB::default()), bench_env(block_timestamp));
    let admin = participants
        .first()
        .copied()
        .unwrap_or_else(|| Address::repeat_byte(0x01));

    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        || {
            TIP403Registry::new().initialize()?;
            TIP20Factory::new().initialize()?;
            TIP20Factory::new().create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                Address::ZERO,
                admin,
            )?;

            let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            token.grant_role_internal(admin, *ISSUER_ROLE)?;
            for participant in participants {
                token.mint(
                    admin,
                    ITIP20::mintCall {
                        to: *participant,
                        amount: U256::from(PARTICIPANT_MINT_AMOUNT),
                    },
                )?;
            }

            TipFeeManager::new().initialize()?;
            NonceManager::new().initialize()?;
            Ok::<(), TempoPrecompileError>(())
        },
    )
    .expect("failed to seed TIP20 benchmark state");

    let evm_state = evm.ctx_mut().journaled_state.evm_state().clone();
    evm.db_mut().commit(evm_state);
    evm.finish().0
}

fn txgen_signers(account_count: usize) -> Vec<PrivateKeySigner> {
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

fn sign_tip20_transfer(
    signer: &PrivateKeySigner,
    recipient: Address,
    amount: U256,
) -> Recovered<TempoTxEnvelope> {
    let call = ITIP20::transferCall {
        to: recipient,
        amount,
    };
    let tx = TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: Some(PATH_USD_ADDRESS),
        max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
        max_fee_per_gas: TXGEN_FEE_PER_GAS,
        gas_limit: TXGEN_GAS_LIMIT,
        calls: vec![Call {
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: Bytes::from(call.abi_encode()),
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
        .expect("failed to sign generated TIP20 transaction");
    let signed = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );

    TempoTxEnvelope::from(signed)
        .try_into_recovered()
        .expect("generated TIP20 transaction should recover")
}

fn generated_workload() -> Workload {
    let signers = txgen_signers(DEFAULT_ACCOUNT_COUNT);
    let mut participants = Vec::with_capacity(signers.len());
    participants.extend(signers.iter().map(|signer| signer.address()));

    let transactions = (0..DEFAULT_TX_COUNT)
        .map(|idx| {
            let signer = &signers[idx % signers.len()];
            let recipient = participants[(idx.wrapping_mul(17) + 1) % participants.len()];
            sign_tip20_transfer(signer, recipient, U256::from(idx as u64 + 1))
        })
        .collect();

    Workload {
        transactions,
        participants,
        block_timestamp: DEFAULT_BLOCK_TIMESTAMP,
    }
}

fn decode_raw_tx_line(line: &str) -> Recovered<TempoTxEnvelope> {
    let raw = line
        .trim()
        .trim_matches('"')
        .strip_prefix("0x")
        .unwrap_or(line.trim());
    let bytes = alloy_primitives::hex::decode(raw).expect("invalid raw transaction hex");
    TempoTxEnvelope::decode_2718_exact(bytes.as_slice())
        .expect("invalid 2718 transaction")
        .try_into_recovered()
        .expect("raw transaction should recover signer")
}

fn load_txgen_workload(path: &Path) -> Workload {
    let raw = fs::read_to_string(path).expect("failed to read txgen transaction stream");
    let transactions: Vec<_> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(decode_raw_tx_line)
        .collect();
    assert!(
        !transactions.is_empty(),
        "txgen transaction stream was empty"
    );

    let mut participants = BTreeSet::new();
    let mut min_valid_before = None;
    let mut max_valid_after = None;
    for tx in &transactions {
        participants.insert(tx.signer());
        if let Some(aa) = tx.inner().as_aa() {
            let aa_tx = aa.tx();
            min_valid_before = aa_tx
                .valid_before
                .map(NonZeroU64::get)
                .into_iter()
                .chain(min_valid_before)
                .min();
            max_valid_after = aa_tx
                .valid_after
                .map(NonZeroU64::get)
                .into_iter()
                .chain(max_valid_after)
                .max();

            for call in &aa_tx.calls {
                if call.to.to() == Some(&PATH_USD_ADDRESS)
                    && let Ok(transfer) = ITIP20::transferCall::abi_decode(&call.input)
                {
                    participants.insert(transfer.to);
                }
            }
        }
    }

    let block_timestamp = min_valid_before
        .map(|ts| ts.saturating_sub(1))
        .unwrap_or(DEFAULT_BLOCK_TIMESTAMP)
        .max(max_valid_after.unwrap_or(0));

    Workload {
        transactions,
        participants: participants.into_iter().collect(),
        block_timestamp,
    }
}

fn workload() -> Workload {
    if let Ok(path) = std::env::var("TEMPO_TIP20_EXEC_TXS") {
        load_txgen_workload(Path::new(&path))
    } else {
        generated_workload()
    }
}

fn execute_txs(
    config: &TempoEvmConfig,
    db: CacheDB<EmptyDB>,
    txs: &[Recovered<TempoTxEnvelope>],
    block_timestamp: u64,
) -> ExecutionStats {
    let evm: TempoEvm<_, _> = TempoEvmFactory::default().create_evm(db, bench_env(block_timestamp));
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
            "tip20 execution bench expects Tempo AA transactions"
        );
        let output = executor
            .execute_transaction_without_commit(tx)
            .expect("TIP20 transaction execution failed");
        assert!(
            output.result().result.is_success(),
            "TIP20 transaction reverted: {:?}",
            output.result().result
        );
        stats.gas_used = stats
            .gas_used
            .saturating_add(executor.commit_transaction(output).tx_gas_used());
        stats.txs += 1;
    }
    stats
}

fn tip20_execution(c: &mut Criterion) {
    let workload = workload();
    let db = setup_in_memory_state(&workload.participants, workload.block_timestamp);
    let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));

    let mut group = c.benchmark_group("tip20_execution");
    group.throughput(Throughput::Elements(workload.transactions.len() as u64));
    group.bench_function("txgen_tip20_pure_execution", |b| {
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            let mut total_gas = 0u64;
            for _ in 0..iters {
                let db = db.clone();
                let start = Instant::now();
                let stats = execute_txs(
                    &config,
                    db,
                    &workload.transactions,
                    workload.block_timestamp,
                );
                elapsed += start.elapsed();
                total_gas = total_gas.saturating_add(stats.gas_used);
            }
            black_box(total_gas);
            elapsed
        })
    });
    group.finish();
}

criterion_group!(benches, tip20_execution);
criterion_main!(benches);
