//! Pure TIP20 execution benchmark.
//!
//! By default this generates txgen-style AA TIP20 transfers from the benchmark mnemonic. Set
//! `TEMPO_TIP20_EXEC_TXS` to a newline-delimited raw 2718 txgen output file to replay exact
//! txgen transactions against the in-memory fixed-cache execution path.

mod common;

use alloy_consensus::transaction::{Recovered, SignerRecoverable};
use alloy_eips::Decodable2718;
use alloy_evm::{Evm, EvmFactory};
use alloy_primitives::{Address, Bytes, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use common::{
    DEFAULT_ACCOUNT_COUNT, DEFAULT_BLOCK_TIMESTAMP, bench_env, execute_txs, fixture_from_seeded_db,
    hardfork_bench_cases, sign_precompile_call, txgen_signers,
};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use reth_revm::DatabaseCommit;
use revm::{
    context::JournalTr,
    database::{CacheDB, EmptyDB},
};
use std::{collections::BTreeSet, fs, hint::black_box, num::NonZeroU64, path::Path, sync::Arc};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::{TempoEvmConfig, TempoEvmFactory};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    error::TempoPrecompileError,
    nonce::NonceManager,
    storage::{StorageActions, StorageCtx},
    tip_fee_manager::TipFeeManager,
    tip20::{ISSUER_ROLE, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::TempoTxEnvelope;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const DEFAULT_TX_COUNT: usize = 4_096;
const PARTICIPANT_MINT_AMOUNT: u128 = 1_000_000_000_000_000_000;
const REWARD_BENCH_TX_COUNT: usize = 1_024;
const REWARD_DISTRIBUTION_AMOUNT: u128 = 1_000_000_000_000;
const REWARD_TRANSFER_AMOUNT: u128 = 1_000_000;

#[derive(Clone)]
struct Workload {
    transactions: Vec<Recovered<TempoTxEnvelope>>,
    participants: Vec<Address>,
    block_timestamp: u64,
}

#[derive(Clone, Copy)]
enum RewardSeedMode {
    None,
    SelfRecipient,
    SharedDelegate,
    DistinctDelegate,
}

#[derive(Clone, Copy)]
enum RewardBenchKind {
    Transfer {
        sender: RewardSeedMode,
        recipient: RewardSeedMode,
        reward_delta: bool,
    },
    ClaimRewards,
    DistributeReward {
        opted_in_accounts: usize,
    },
}

struct RewardBenchWorkload {
    name: &'static str,
    transactions: Vec<Recovered<TempoTxEnvelope>>,
    participants: Vec<Address>,
    delegates: Vec<Address>,
    kind: RewardBenchKind,
}

fn seed_in_memory_cache_db(
    participants: &[Address],
    block_timestamp: u64,
    reward_seed: Option<(&[Address], RewardBenchKind)>,
    hardfork: TempoHardfork,
) -> CacheDB<EmptyDB> {
    // This setup database only materializes the benchmark fixture in memory. The measured
    // execution path below uses Reth's fixed-cache execution provider, not CacheDB.
    let mut evm = TempoEvmFactory::default().create_evm(
        CacheDB::new(EmptyDB::default()),
        bench_env(hardfork, block_timestamp),
    );
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
        StorageActions::disabled(),
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

            if let Some((delegates, kind)) = reward_seed {
                seed_reward_bench_state(&mut token, admin, participants, delegates, kind)?;
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

fn seed_reward_bench_state(
    token: &mut TIP20Token,
    admin: Address,
    participants: &[Address],
    delegates: &[Address],
    kind: RewardBenchKind,
) -> Result<(), TempoPrecompileError> {
    match kind {
        RewardBenchKind::Transfer {
            sender,
            recipient,
            reward_delta,
        } => {
            for chunk in participants.chunks(2) {
                if let Some(sender_addr) = chunk.first().copied() {
                    apply_seed_reward_mode(token, sender_addr, sender, delegates)?;
                }
                if let Some(recipient_addr) = chunk.get(1).copied() {
                    apply_seed_reward_mode(token, recipient_addr, recipient, delegates)?;
                }
            }
            if reward_delta {
                token.distribute_reward(
                    admin,
                    ITIP20::distributeRewardCall {
                        amount: U256::from(REWARD_DISTRIBUTION_AMOUNT),
                    },
                )?;
            }
        }
        RewardBenchKind::ClaimRewards => {
            for participant in participants {
                token.set_reward_recipient(
                    *participant,
                    ITIP20::setRewardRecipientCall {
                        recipient: *participant,
                    },
                )?;
            }
            token.distribute_reward(
                admin,
                ITIP20::distributeRewardCall {
                    amount: U256::from(REWARD_DISTRIBUTION_AMOUNT),
                },
            )?;
            for participant in participants {
                token.update_rewards(*participant)?;
            }
        }
        RewardBenchKind::DistributeReward { opted_in_accounts } => {
            for participant in participants.iter().take(opted_in_accounts) {
                token.set_reward_recipient(
                    *participant,
                    ITIP20::setRewardRecipientCall {
                        recipient: *participant,
                    },
                )?;
            }
        }
    }
    Ok(())
}

fn apply_seed_reward_mode(
    token: &mut TIP20Token,
    account: Address,
    mode: RewardSeedMode,
    delegates: &[Address],
) -> Result<(), TempoPrecompileError> {
    let recipient = match mode {
        RewardSeedMode::None => return Ok(()),
        RewardSeedMode::SelfRecipient => account,
        RewardSeedMode::SharedDelegate => delegates[0],
        RewardSeedMode::DistinctDelegate => {
            delegates[account.as_slice()[19] as usize % delegates.len()]
        }
    };
    token.set_reward_recipient(account, ITIP20::setRewardRecipientCall { recipient })?;
    Ok(())
}

fn sign_tip20_transfer(
    signer: &PrivateKeySigner,
    recipient: Address,
    amount: U256,
) -> Recovered<TempoTxEnvelope> {
    sign_tip20_call(
        signer,
        Bytes::from(
            ITIP20::transferCall {
                to: recipient,
                amount,
            }
            .abi_encode(),
        ),
    )
}

fn sign_tip20_call(signer: &PrivateKeySigner, input: Bytes) -> Recovered<TempoTxEnvelope> {
    sign_precompile_call(signer, PATH_USD_ADDRESS, input)
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

fn reward_bench_workloads() -> Vec<RewardBenchWorkload> {
    let signers = txgen_signers(DEFAULT_ACCOUNT_COUNT);
    let participants: Vec<_> = signers.iter().map(|signer| signer.address()).collect();
    let delegates = vec![Address::repeat_byte(0xa1), Address::repeat_byte(0xa2)];

    vec![
        transfer_reward_workload(
            "tip20_transfer_rewards_opted_out",
            &signers,
            RewardSeedMode::None,
            RewardSeedMode::None,
            false,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_rewards_self_no_delta",
            &signers,
            RewardSeedMode::SelfRecipient,
            RewardSeedMode::SelfRecipient,
            false,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_rewards_self_with_delta",
            &signers,
            RewardSeedMode::SelfRecipient,
            RewardSeedMode::SelfRecipient,
            true,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_rewards_delegate_no_delta",
            &signers,
            RewardSeedMode::SharedDelegate,
            RewardSeedMode::SharedDelegate,
            false,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_rewards_delegate_with_delta",
            &signers,
            RewardSeedMode::SharedDelegate,
            RewardSeedMode::SharedDelegate,
            true,
            &delegates,
        ),
        transfer_reward_workload(
            "tip20_transfer_mixed_sender_recipient",
            &signers,
            RewardSeedMode::DistinctDelegate,
            RewardSeedMode::SelfRecipient,
            true,
            &delegates,
        ),
        RewardBenchWorkload {
            name: "tip20_claim_rewards",
            transactions: signers
                .iter()
                .take(REWARD_BENCH_TX_COUNT)
                .map(|signer| {
                    sign_tip20_call(
                        signer,
                        Bytes::from(ITIP20::claimRewardsCall {}.abi_encode()),
                    )
                })
                .collect(),
            participants: participants.clone(),
            delegates: delegates.clone(),
            kind: RewardBenchKind::ClaimRewards,
        },
        RewardBenchWorkload {
            name: "tip20_distribute_reward",
            transactions: signers
                .iter()
                .take(REWARD_BENCH_TX_COUNT)
                .map(|signer| {
                    sign_tip20_call(
                        signer,
                        Bytes::from(
                            ITIP20::distributeRewardCall {
                                amount: U256::from(REWARD_DISTRIBUTION_AMOUNT / 1_000),
                            }
                            .abi_encode(),
                        ),
                    )
                })
                .collect(),
            participants,
            delegates,
            kind: RewardBenchKind::DistributeReward {
                opted_in_accounts: DEFAULT_ACCOUNT_COUNT,
            },
        },
    ]
}

fn transfer_reward_workload(
    name: &'static str,
    signers: &[PrivateKeySigner],
    sender: RewardSeedMode,
    recipient: RewardSeedMode,
    reward_delta: bool,
    delegates: &[Address],
) -> RewardBenchWorkload {
    let participants: Vec<_> = signers.iter().map(|signer| signer.address()).collect();
    let transactions = (0..REWARD_BENCH_TX_COUNT)
        .map(|idx| {
            let signer = &signers[idx % signers.len()];
            let recipient = participants[(idx.wrapping_mul(17) + 1) % participants.len()];
            sign_tip20_transfer(signer, recipient, U256::from(REWARD_TRANSFER_AMOUNT))
        })
        .collect();

    RewardBenchWorkload {
        name,
        transactions,
        participants,
        delegates: delegates.to_vec(),
        kind: RewardBenchKind::Transfer {
            sender,
            recipient,
            reward_delta,
        },
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

fn tip20_execution(c: &mut Criterion) {
    let workload = workload();
    let hardfork_cases = hardfork_bench_cases();
    let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));

    for &(label, hardfork) in &hardfork_cases {
        let fixture = fixture_from_seeded_db(seed_in_memory_cache_db(
            &workload.participants,
            workload.block_timestamp,
            None,
            hardfork,
        ));
        execute_txs(
            &config,
            fixture.prewarm_state_db(),
            &workload.transactions,
            workload.block_timestamp,
            hardfork,
        );

        let mut group = c.benchmark_group(format!("{label}/tip20_execution"));
        group.throughput(Throughput::Elements(workload.transactions.len() as u64));
        group.bench_function("txgen_tip20_pure_execution", |b| {
            b.iter_batched(
                || fixture.state_db(),
                |db| {
                    let stats = execute_txs(
                        &config,
                        db,
                        &workload.transactions,
                        workload.block_timestamp,
                        hardfork,
                    );
                    black_box(stats.gas_used);
                },
                BatchSize::SmallInput,
            )
        });
        group.finish();
    }

    let reward_workloads = reward_bench_workloads();
    for &(label, hardfork) in &hardfork_cases {
        for reward_workload in &reward_workloads {
            let fixture = fixture_from_seeded_db(seed_in_memory_cache_db(
                &reward_workload.participants,
                DEFAULT_BLOCK_TIMESTAMP,
                Some((&reward_workload.delegates, reward_workload.kind)),
                hardfork,
            ));
            execute_txs(
                &config,
                fixture.prewarm_state_db(),
                &reward_workload.transactions,
                DEFAULT_BLOCK_TIMESTAMP,
                hardfork,
            );

            let mut group = c.benchmark_group(format!("{label}/tip20_rewards"));
            group.throughput(Throughput::Elements(
                reward_workload.transactions.len() as u64
            ));
            group.bench_function(reward_workload.name, |b| {
                b.iter_batched(
                    || fixture.state_db(),
                    |db| {
                        let stats = execute_txs(
                            &config,
                            db,
                            &reward_workload.transactions,
                            DEFAULT_BLOCK_TIMESTAMP,
                            hardfork,
                        );
                        black_box(stats.gas_used);
                    },
                    BatchSize::SmallInput,
                )
            });
            group.finish();
        }
    }
}

criterion_group!(benches, tip20_execution);
criterion_main!(benches);
