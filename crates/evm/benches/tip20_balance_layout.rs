//! Compare token-first and holder-first balance tries, including the account trie.

use alloy_primitives::{Address, B256, U256, keccak256};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use reth_primitives_traits::Account;
use reth_trie::{
    HashedPostState, HashedStorage, StateRoot,
    hashed_cursor::{noop::NoopHashedCursorFactory, post_state::HashedPostStateCursorFactory},
    trie_cursor::{in_memory::InMemoryTrieCursorFactory, noop::NoopTrieCursorFactory},
};
use std::hint::black_box;
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    storage::StorageKey,
    tip20::{balances::holder_storage_address, tip20_slots},
};

fn holder(index: usize) -> Address {
    Address::from_slice(&keccak256(index.to_be_bytes()).as_slice()[12..])
}

fn balance_location(token: Address, holder: Address, holder_first: bool) -> (B256, B256) {
    let (address, slot) = if holder_first {
        (
            holder_storage_address(holder),
            token.mapping_slot(U256::from_be_slice(holder.as_slice())),
        )
    } else {
        (token, holder.mapping_slot(tip20_slots::BALANCES))
    };
    (keccak256(address), keccak256(slot.to_be_bytes::<32>()))
}

fn fixture(holder_count: usize, token_count: usize, holder_first: bool) -> HashedPostState {
    let mut state = HashedPostState::default();
    let code_hash = keccak256([0x00]);
    for holder_index in 0..holder_count {
        let holder = holder(holder_index);
        state.accounts.insert(
            keccak256(holder),
            Some(Account {
                nonce: 1,
                ..Default::default()
            }),
        );
        if holder_first {
            state.accounts.insert(
                keccak256(holder_storage_address(holder)),
                Some(Account {
                    bytecode_hash: Some(code_hash),
                    ..Default::default()
                }),
            );
        }
        for token_index in 0..token_count {
            let mut token = PATH_USD_ADDRESS;
            token.as_mut_slice()[19] = token_index as u8;
            state.accounts.insert(
                keccak256(token),
                Some(Account {
                    bytecode_hash: Some(code_hash),
                    ..Default::default()
                }),
            );
            let (address, slot) = balance_location(token, holder, holder_first);
            state
                .storages
                .entry(address)
                .or_default()
                .storage
                .insert(slot, U256::from(1_000_000));
        }
    }
    state
}

fn updates(holder_count: usize, changed_holders: usize, holder_first: bool) -> HashedPostState {
    let mut state = HashedPostState::default();
    for holder_index in 0..changed_holders.min(holder_count) {
        let (address, slot) =
            balance_location(PATH_USD_ADDRESS, holder(holder_index), holder_first);
        state
            .storages
            .entry(address)
            .or_insert_with(HashedStorage::default)
            .storage
            .insert(
                slot,
                if holder_index == 0 {
                    U256::from(1_000_000 - changed_holders.min(holder_count) + 1)
                } else {
                    U256::from(1_000_001)
                },
            );
    }
    state
}

fn balance_layout(c: &mut Criterion) {
    let mut group = c.benchmark_group("tip20_balance_layout");
    group.sample_size(10);
    for (holder_count, token_count) in [(10_000, 1), (10_000, 4), (100_000, 1)] {
        for holder_first in [false, true] {
            let label = if holder_first {
                "holder_first"
            } else {
                "token_first"
            };
            let state = fixture(holder_count, token_count, holder_first).into_sorted();
            let (_, base_nodes) = StateRoot::new(
                NoopTrieCursorFactory::default(),
                HashedPostStateCursorFactory::new(NoopHashedCursorFactory::default(), &state),
            )
            .root_with_updates()
            .expect("fixture root");
            let base_nodes = base_nodes.into_sorted();
            let id = format!("{label}/{holder_count}_holders/{token_count}_tokens");
            group.bench_with_input(
                BenchmarkId::new("full_root", &id),
                &state,
                |bench, state| {
                    bench.iter(|| {
                        black_box(
                            StateRoot::new(
                                NoopTrieCursorFactory::default(),
                                HashedPostStateCursorFactory::new(
                                    NoopHashedCursorFactory::default(),
                                    state,
                                ),
                            )
                            .root()
                            .expect("state root"),
                        )
                    });
                },
            );
            for (workload, changed_holders) in [("small_holder_set", 16), ("mass_payout", 4_096)] {
                let delta = updates(holder_count, changed_holders, holder_first);
                let prefix_sets = delta.construct_prefix_sets().freeze();
                let delta = delta.into_sorted();
                group.bench_function(BenchmarkId::new(workload, &id), |bench| {
                    bench.iter(|| {
                        let trie_cursors = InMemoryTrieCursorFactory::new(
                            NoopTrieCursorFactory::default(),
                            &base_nodes,
                        );
                        let base_cursors = HashedPostStateCursorFactory::new(
                            NoopHashedCursorFactory::default(),
                            &state,
                        );
                        let state_cursors = HashedPostStateCursorFactory::new(base_cursors, &delta);
                        black_box(
                            StateRoot::new(trie_cursors, state_cursors)
                                .with_prefix_sets(prefix_sets.clone())
                                .root_with_updates()
                                .expect("updated root"),
                        )
                    });
                });
            }
        }
    }
    group.finish();
}

criterion_group!(benches, balance_layout);
criterion_main!(benches);
