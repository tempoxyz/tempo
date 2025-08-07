use alloy::primitives::{Address, U256};
use criterion::{Criterion, criterion_group, criterion_main};
use std::{hint::black_box, sync::Arc};
use tempo_precompiles::contracts::{
    storage::hashmap::HashMapStorageProvider,
    tip20::{ISSUER_ROLE, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
    types::{ITIP20, ITIP20Factory, ITIP403Registry},
};

fn tip20_metadata(c: &mut Criterion) {
    c.bench_function("tip20_name", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();

        b.iter(|| {
            black_box(token.name());
        });
    });

    c.bench_function("tip20_symbol", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();

        b.iter(|| {
            black_box(token.symbol());
        });
    });

    c.bench_function("tip20_decimals", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();

        b.iter(|| {
            black_box(token.decimals());
        });
    });

    c.bench_function("tip20_currency", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();

        b.iter(|| {
            black_box(token.currency());
        });
    });

    c.bench_function("tip20_total_supply", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: user,
                    amount: U256::from(1000),
                },
            )
            .unwrap();

        b.iter(|| {
            black_box(token.total_supply());
        });
    });
}

fn tip20_view(c: &mut Criterion) {
    c.bench_function("tip20_balance_of", |b| {
        let admin = Address::from([0u8; 20]);
        let user1 = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: user1,
                    amount: U256::from(1000),
                },
            )
            .unwrap();

        b.iter(|| {
            black_box(token.balance_of(ITIP20::balanceOfCall { account: user1 }));
        });
    });

    c.bench_function("tip20_allowance", |b| {
        let admin = Address::from([0u8; 20]);
        let user1 = Address::from([1u8; 20]);
        let user2 = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: user1,
                    amount: U256::from(1000),
                },
            )
            .unwrap();
        token
            .approve(
                &user1,
                ITIP20::approveCall {
                    spender: user2,
                    amount: U256::from(500),
                },
            )
            .unwrap();

        b.iter(|| {
            black_box(token.allowance(ITIP20::allowanceCall {
                owner: user1,
                spender: user2,
            }));
        });
    });

    c.bench_function("tip20_nonces", |b| {
        let admin = Address::from([0u8; 20]);
        let user1 = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();

        b.iter(|| {
            black_box(token.nonces(ITIP20::noncesCall { owner: user1 }));
        });
    });

    c.bench_function("tip20_salts", |b| {
        let admin = Address::from([0u8; 20]);
        let user1 = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "TTK", 18, "USD", &admin)
            .unwrap();

        b.iter(|| {
            let salt = alloy::primitives::FixedBytes::<4>::from([1u8, 2u8, 3u8, 4u8]);
            black_box(token.salts(ITIP20::saltsCall { owner: user1, salt }));
        });
    });
}

criterion_group!(benches, tip20_metadata, tip20_view);
criterion_main!(benches);
