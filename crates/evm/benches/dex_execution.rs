//! Stablecoin DEX order execution benchmark.
//!
//! Generates txgen-style AA transactions that exercise DEX order storage against the in-memory
//! fixed-cache execution path. This is intended as a small CodSpeed/flamegraph target for
//! TIP-1062 order storage layout work.

#[allow(dead_code)]
mod common;

use alloy_consensus::transaction::Recovered;
use alloy_evm::{Evm, EvmFactory};
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolValue};
use common::{
    DEFAULT_ACCOUNT_COUNT, DEFAULT_BLOCK_TIMESTAMP, execute_txs, fixture_from_seeded_db,
    hardfork_bench_cases, txgen_signers,
};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use reth_revm::DatabaseCommit;
use revm::{
    context::JournalTr,
    database::{CacheDB, EmptyDB},
};
use std::{hint::black_box, sync::Arc};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_contracts::precompiles::{IStablecoinDEX, ITIP20, tip20_factory::createTokenCall};
use tempo_evm::{TempoEvmConfig, TempoEvmFactory};
use tempo_precompiles::{
    PATH_USD_ADDRESS, STABLECOIN_DEX_ADDRESS,
    error::TempoPrecompileError,
    nonce::NonceManager,
    stablecoin_dex::StablecoinDEX,
    storage::{StorageActions, StorageCtx},
    tip_fee_manager::TipFeeManager,
    tip20::{ISSUER_ROLE, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{TempoAddressExt, TempoTxEnvelope};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const PARTICIPANT_MINT_AMOUNT: u128 = 1_000_000_000_000_000_000;
const DEX_SCENARIO_TX_COUNT: usize = 256;
const DEX_ORDER_AMOUNT: u128 = 1_000_000_000;
const DEX_TX_GAS_LIMIT: u64 = 20_000_000;
const DEX_BASE_TOKEN_SALT: B256 = B256::ZERO;

struct DexBenchWorkload {
    name: &'static str,
    transactions: Vec<Recovered<TempoTxEnvelope>>,
    participants: Vec<Address>,
}

fn seed_dex_cache_db(
    participants: &[Address],
    block_timestamp: u64,
    hardfork: TempoHardfork,
) -> CacheDB<EmptyDB> {
    let mut evm = TempoEvmFactory::default().create_evm(
        CacheDB::new(EmptyDB::default()),
        common::bench_env(hardfork, block_timestamp),
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

            let mut quote = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            quote.grant_role_internal(admin, *ISSUER_ROLE)?;

            let base_token = TIP20Factory::new().create_token(
                admin,
                createTokenCall {
                    name: "benchBASE".to_string(),
                    symbol: "benchBASE".to_string(),
                    currency: "USD".to_string(),
                    quoteToken: PATH_USD_ADDRESS,
                    admin,
                    salt: DEX_BASE_TOKEN_SALT,
                },
            )?;
            let mut base = TIP20Token::from_address(base_token)?;
            base.grant_role_internal(admin, *ISSUER_ROLE)?;

            for participant in participants {
                let mint = ITIP20::mintCall {
                    to: *participant,
                    amount: U256::from(PARTICIPANT_MINT_AMOUNT),
                };
                quote.mint(admin, mint.clone())?;
                base.mint(admin, mint)?;
            }

            StablecoinDEX::new().initialize()?;
            TipFeeManager::new().initialize()?;
            NonceManager::new().initialize()?;
            Ok::<(), TempoPrecompileError>(())
        },
    )
    .expect("failed to seed DEX benchmark state");

    let evm_state = evm.ctx_mut().journaled_state.evm_state().clone();
    evm.db_mut().commit(evm_state);
    evm.finish().0
}

fn sign_dex_call(
    signer: &alloy_signer_local::PrivateKeySigner,
    input: Bytes,
) -> Recovered<TempoTxEnvelope> {
    sign_dex_calls(signer, vec![input])
}

fn sign_dex_calls(
    signer: &alloy_signer_local::PrivateKeySigner,
    inputs: Vec<Bytes>,
) -> Recovered<TempoTxEnvelope> {
    let calls = inputs
        .into_iter()
        .map(|input| tempo_primitives::transaction::Call {
            to: alloy_primitives::TxKind::Call(STABLECOIN_DEX_ADDRESS),
            value: U256::ZERO,
            input,
        })
        .collect();
    // Reuse the common single-call signer shape by constructing the multi-call tx locally.
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_signer::SignerSync;
    use common::{CHAIN_ID, DEFAULT_BLOCK_TIMESTAMP, TXGEN_FEE_PER_GAS};
    use std::num::NonZeroU64;
    use tempo_primitives::{
        AASigned, TempoSignature, TempoTransaction,
        transaction::{PrimitiveSignature, TEMPO_EXPIRING_NONCE_KEY},
    };

    let tx = TempoTransaction {
        chain_id: CHAIN_ID,
        fee_token: Some(PATH_USD_ADDRESS),
        max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
        max_fee_per_gas: TXGEN_FEE_PER_GAS,
        gas_limit: DEX_TX_GAS_LIMIT,
        calls,
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
        .expect("failed to sign generated DEX transaction");
    let signed = AASigned::new_unhashed(
        tx,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    );

    TempoTxEnvelope::from(signed)
        .try_into_recovered()
        .expect("generated DEX benchmark transaction should recover")
}

fn compute_tip20_address(sender: Address, salt: B256) -> Address {
    let hash = keccak256((sender, salt).abi_encode());
    let mut address_bytes = [0u8; 20];
    address_bytes[..12].copy_from_slice(&Address::TIP20_PREFIX);
    address_bytes[12..].copy_from_slice(&hash[..8]);
    Address::from(address_bytes)
}

fn dex_bench_workloads() -> Vec<DexBenchWorkload> {
    let signers = txgen_signers(DEFAULT_ACCOUNT_COUNT);
    let participants: Vec<_> = signers.iter().map(|signer| signer.address()).collect();
    let admin = participants
        .first()
        .copied()
        .unwrap_or_else(|| Address::repeat_byte(0x01));
    let base_token = compute_tip20_address(admin, DEX_BASE_TOKEN_SALT);
    let quote_token = PATH_USD_ADDRESS;
    let amount = DEX_ORDER_AMOUNT;
    let fill = amount / 4;

    let place = |is_bid, tick| {
        Bytes::from(
            IStablecoinDEX::placeCall {
                token: base_token,
                amount,
                isBid: is_bid,
                tick,
            }
            .abi_encode(),
        )
    };
    let place_flip = |is_bid, tick, flip_tick| {
        Bytes::from(
            IStablecoinDEX::placeFlipCall {
                token: base_token,
                amount,
                isBid: is_bid,
                tick,
                flipTick: flip_tick,
            }
            .abi_encode(),
        )
    };
    let cancel =
        |order_id| Bytes::from(IStablecoinDEX::cancelCall { orderId: order_id }.abi_encode());
    let swap_in = |token_in, token_out, amount_in| {
        Bytes::from(
            IStablecoinDEX::swapExactAmountInCall {
                tokenIn: token_in,
                tokenOut: token_out,
                amountIn: amount_in,
                minAmountOut: 0,
            }
            .abi_encode(),
        )
    };
    let swap_out = |token_in, token_out, amount_out| {
        Bytes::from(
            IStablecoinDEX::swapExactAmountOutCall {
                tokenIn: token_in,
                tokenOut: token_out,
                amountOut: amount_out,
                maxAmountIn: u128::MAX,
            }
            .abi_encode(),
        )
    };
    let ask_tick = |idx: usize| 1_500 - idx as i16 * 10;
    let bid_tick = |idx: usize| -1_500 + idx as i16 * 10;
    let signer = |idx: usize| &signers[idx % signers.len()];
    let place_order = |flip: bool, is_bid: bool, tick: i16| {
        if flip {
            place_flip(is_bid, tick, tick + if is_bid { 10 } else { -10 })
        } else {
            place(is_bid, tick)
        }
    };

    let workload = |name, transactions| DexBenchWorkload {
        name,
        transactions,
        participants: participants.clone(),
    };
    let many_single_call = |call: Bytes| {
        signers
            .iter()
            .take(4 * DEX_SCENARIO_TX_COUNT)
            .map(|signer| sign_dex_call(signer, call.clone()))
            .collect()
    };
    let scenario_txs = |build_calls: &dyn Fn(usize) -> Vec<Bytes>| {
        (0..DEX_SCENARIO_TX_COUNT)
            .map(|idx| sign_dex_calls(signer(idx), build_calls(idx)))
            .collect()
    };

    let cancel_orders = |flip: bool| {
        scenario_txs(&|idx| {
            let tick = bid_tick(idx);
            vec![place_order(flip, true, tick), cancel(idx as u128 + 1)]
        })
    };
    let fill_asks = |flip: bool, full: bool| {
        scenario_txs(&|idx| {
            let tick = ask_tick(idx);
            let fill_call = if full {
                swap_out(quote_token, base_token, amount)
            } else {
                swap_in(quote_token, base_token, fill)
            };
            vec![place_order(flip, false, tick), fill_call]
        })
    };
    let three_asks_fill_two_and_half = |flip: bool| {
        (0..DEX_SCENARIO_TX_COUNT)
            .flat_map(|idx| {
                let tick = ask_tick(idx);
                [
                    sign_dex_calls(
                        signer(idx * 2),
                        vec![
                            place_order(flip, false, tick),
                            place_order(flip, false, tick),
                            place_order(flip, false, tick),
                        ],
                    ),
                    sign_dex_call(
                        signer(idx * 2 + 1),
                        swap_out(quote_token, base_token, amount * 2 + amount / 2),
                    ),
                ]
            })
            .collect()
    };
    let flip_bid_full_fill = || {
        scenario_txs(&|idx| {
            let tick = bid_tick(idx);
            vec![
                place_order(true, true, tick),
                swap_in(base_token, quote_token, amount),
            ]
        })
    };

    vec![
        workload("dex_place_ask_orders", many_single_call(place(false, 0))),
        workload(
            "dex_place_flip_ask_orders",
            many_single_call(place_flip(false, 0, -10)),
        ),
        workload("dex_cancel_orders", cancel_orders(false)),
        workload("dex_cancel_flip_orders", cancel_orders(true)),
        workload("dex_partial_fill_asks_exact_in", fill_asks(false, false)),
        workload(
            "dex_partial_fill_flip_asks_exact_in",
            fill_asks(true, false),
        ),
        workload("dex_full_fill_asks_exact_out", fill_asks(false, true)),
        workload("dex_full_fill_flip_asks_exact_out", fill_asks(true, true)),
        workload(
            "dex_three_asks_fill_two_and_half",
            three_asks_fill_two_and_half(false),
        ),
        workload(
            "dex_three_flip_asks_fill_two_and_half",
            three_asks_fill_two_and_half(true),
        ),
        workload("dex_flip_bid_full_fill", flip_bid_full_fill()),
    ]
}
fn dex_order_execution(c: &mut Criterion) {
    let hardfork_cases = hardfork_bench_cases();
    let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));

    let dex_workloads = dex_bench_workloads();
    for &(label, hardfork) in &hardfork_cases {
        for dex_workload in &dex_workloads {
            let fixture = fixture_from_seeded_db(seed_dex_cache_db(
                &dex_workload.participants,
                DEFAULT_BLOCK_TIMESTAMP,
                hardfork,
            ));
            execute_txs(
                &config,
                fixture.prewarm_state_db(),
                &dex_workload.transactions,
                DEFAULT_BLOCK_TIMESTAMP,
                hardfork,
            );

            let mut group = c.benchmark_group(format!("{label}/stablecoin_dex"));
            group.throughput(Throughput::Elements(dex_workload.transactions.len() as u64));
            group.bench_function(dex_workload.name, |b| {
                b.iter_batched(
                    || fixture.state_db(),
                    |db| {
                        let stats = execute_txs(
                            &config,
                            db,
                            &dex_workload.transactions,
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

criterion_group!(benches, dex_order_execution);
criterion_main!(benches);
