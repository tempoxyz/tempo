use alloy::primitives::{Address, U256};
use alloy_primitives::FixedBytes;
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
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.name();
        });
    });

    c.bench_function("tip20_symbol", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.symbol();
        });
    });

    c.bench_function("tip20_decimals", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.decimals();
        });
    });

    c.bench_function("tip20_currency", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.currency();
        });
    });

    c.bench_function("tip20_total_supply", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
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
            let t = black_box(&mut token);
            t.total_supply();
        });
    });
}

fn tip20_view(c: &mut Criterion) {
    c.bench_function("tip20_balance_of", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
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
            let t = black_box(&mut token);
            t.balance_of(ITIP20::balanceOfCall { account: user });
        });
    });

    c.bench_function("tip20_allowance", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        token
            .approve(
                &owner,
                ITIP20::approveCall {
                    spender,
                    amount: U256::from(500),
                },
            )
            .unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.allowance(ITIP20::allowanceCall { owner, spender });
        });
    });

    c.bench_function("tip20_nonces", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.nonces(ITIP20::noncesCall { owner });
        });
    });

    c.bench_function("tip20_salts", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let salt = FixedBytes::<4>::random();
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.salts(ITIP20::saltsCall { owner, salt });
        });
    });

    c.bench_function("tip20_supply_cap", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.supply_cap();
        });
    });

    c.bench_function("tip20_paused", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.paused();
        });
    });

    c.bench_function("tip20_transfer_policy_id", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.transfer_policy_id();
        });
    });

    c.bench_function("tip20_domain_separator", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            let t = black_box(&mut token);
            t.domain_separator();
        });
    });
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
