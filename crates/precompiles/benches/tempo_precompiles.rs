use alloy::primitives::{Address, U256};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tempo_precompiles::contracts::{
    storage::hashmap::HashMapStorageProvider,
    tip20::{ISSUER_ROLE, TIP20Token},
    types::ITIP20,
};

fn tip20_metadata(c: &mut Criterion) {
    c.bench_function("tip20_name", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", 18, "USD", &admin)
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
            .initialize("TestToken", "T", 18, "USD", &admin)
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
            .initialize("TestToken", "T", 18, "USD", &admin)
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
            .initialize("TestToken", "T", 18, "USD", &admin)
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
            .initialize("TestToken", "T", 18, "USD", &admin)
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

fn tip20_view(_c: &mut Criterion) {
    todo!()
}

fn tip20_mutate(_c: &mut Criterion) {
    todo!()
}

fn tip20_factory_metadata(_c: &mut Criterion) {
    todo!()
}

fn tip20_factory_view(_c: &mut Criterion) {
    todo!()
}

fn tip20_factory_mutate(_c: &mut Criterion) {
    todo!()
}

fn tip403_registry_metadata(_c: &mut Criterion) {
    todo!()
}

fn tip403_registry_view(_c: &mut Criterion) {
    todo!()
}

fn tip403_registry_mutate(_c: &mut Criterion) {
    todo!()
}

criterion_group!(
    benches,
    tip20_metadata,
    tip20_view,
    tip20_mutate,
    tip20_factory_metadata,
    tip20_factory_view,
    tip20_factory_mutate,
    tip403_registry_metadata,
    tip403_registry_view,
    tip403_registry_mutate
);
criterion_main!(benches);
