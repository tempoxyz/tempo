use alloy::primitives::{Address, U256};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tempo_precompiles::contracts::{
    storage::hashmap::HashMapStorageProvider,
    tip20::{ISSUER_ROLE, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
    types::{ITIP20, ITIP20Factory, ITIP403Registry},
};

fn tip20_token(c: &mut Criterion) {
    let mut group = c.benchmark_group("tip20_token");

    // Setup common data
    let admin = Address::from([0u8; 20]);
    let user1 = Address::from([1u8; 20]);
    let user2 = Address::from([2u8; 20]);
    let amount = U256::from(1000);
    let token_id = 1u64;

    group.bench_function("initialize", |b| {
        b.iter(|| {
            let mut storage = HashMapStorageProvider::new(1);
            let mut token = TIP20Token::new(token_id, &mut storage);
            black_box(
                token
                    .initialize("TestToken", "TTK", 18, "USD", &admin)
                    .unwrap(),
            );
        });
    });

    group.bench_function("mint", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut token = TIP20Token::new(token_id, &mut storage);
                token
                    .initialize("TestToken", "TTK", 18, "USD", &admin)
                    .unwrap();
                let mut roles = token.get_roles_contract();
                roles.grant_role_internal(&admin, *ISSUER_ROLE);
                (storage, token)
            },
            |(mut storage, mut token)| {
                black_box(
                    token
                        .mint(&admin, ITIP20::mintCall { to: user1, amount })
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("transfer", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut token = TIP20Token::new(token_id, &mut storage);
                token
                    .initialize("TestToken", "TTK", 18, "USD", &admin)
                    .unwrap();
                let mut roles = token.get_roles_contract();
                roles.grant_role_internal(&admin, *ISSUER_ROLE);
                token
                    .mint(&admin, ITIP20::mintCall { to: user1, amount })
                    .unwrap();
                (storage, token)
            },
            |(mut storage, mut token)| {
                black_box(
                    token
                        .transfer(
                            &user1,
                            ITIP20::transferCall {
                                to: user2,
                                amount: U256::from(100),
                            },
                        )
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("approve", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut token = TIP20Token::new(token_id, &mut storage);
                token
                    .initialize("TestToken", "TTK", 18, "USD", &admin)
                    .unwrap();
                (storage, token)
            },
            |(mut storage, mut token)| {
                black_box(
                    token
                        .approve(
                            &user1,
                            ITIP20::approveCall {
                                spender: user2,
                                amount,
                            },
                        )
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("balance_of", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut token = TIP20Token::new(token_id, &mut storage);
                token
                    .initialize("TestToken", "TTK", 18, "USD", &admin)
                    .unwrap();
                let mut roles = token.get_roles_contract();
                roles.grant_role_internal(&admin, *ISSUER_ROLE);
                token
                    .mint(&admin, ITIP20::mintCall { to: user1, amount })
                    .unwrap();
                (storage, token)
            },
            |(mut storage, mut token)| {
                black_box(token.balance_of(ITIP20::balanceOfCall { account: user1 }));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("burn", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut token = TIP20Token::new(token_id, &mut storage);
                token
                    .initialize("TestToken", "TTK", 18, "USD", &admin)
                    .unwrap();
                let mut roles = token.get_roles_contract();
                roles.grant_role_internal(&admin, *ISSUER_ROLE);
                token
                    .mint(&admin, ITIP20::mintCall { to: admin, amount })
                    .unwrap();
                (storage, token)
            },
            |(mut storage, mut token)| {
                black_box(
                    token
                        .burn(
                            &admin,
                            ITIP20::burnCall {
                                amount: U256::from(100),
                            },
                        )
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn tip20_factory(c: &mut Criterion) {
    let mut group = c.benchmark_group("tip20_factory");

    let admin = Address::from([0u8; 20]);

    group.bench_function("create_token", |b| {
        b.iter(|| {
            let mut storage = HashMapStorageProvider::new(1);
            let mut factory = TIP20Factory::new(&mut storage);
            black_box(
                factory
                    .create_token(
                        &admin,
                        ITIP20Factory::createTokenCall {
                            name: "TestToken".to_string(),
                            symbol: "TTK".to_string(),
                            decimals: 18,
                            currency: "USD".to_string(),
                            admin,
                        },
                    )
                    .unwrap(),
            );
        });
    });

    group.bench_function("token_id_counter", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut factory = TIP20Factory::new(&mut storage);
                // Create a few tokens to have a non-zero counter
                for i in 0..5 {
                    factory
                        .create_token(
                            &admin,
                            ITIP20Factory::createTokenCall {
                                name: format!("Token{}", i),
                                symbol: format!("T{}", i),
                                decimals: 18,
                                currency: "USD".to_string(),
                                admin,
                            },
                        )
                        .unwrap();
                }
                (storage, factory)
            },
            |(mut storage, mut factory)| {
                black_box(factory.token_id_counter());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn tip403_registry(c: &mut Criterion) {
    let mut group = c.benchmark_group("tip403_registry");

    let admin = Address::from([0u8; 20]);
    let user1 = Address::from([1u8; 20]);
    let user2 = Address::from([2u8; 20]);

    group.bench_function("create_policy", |b| {
        b.iter(|| {
            let mut storage = HashMapStorageProvider::new(1);
            let mut registry = TIP403Registry::new(&mut storage);
            black_box(
                registry
                    .create_policy(
                        &admin,
                        ITIP403Registry::createPolicyCall {
                            adminPolicyId: 1, // Always-allow policy
                            policyType: ITIP403Registry::PolicyType::WHITELIST,
                        },
                    )
                    .unwrap(),
            );
        });
    });

    group.bench_function("create_policy_with_accounts", |b| {
        b.iter(|| {
            let mut storage = HashMapStorageProvider::new(1);
            let mut registry = TIP403Registry::new(&mut storage);
            black_box(
                registry
                    .create_policy_with_accounts(
                        &admin,
                        ITIP403Registry::createPolicyWithAccountsCall {
                            adminPolicyId: 1,
                            policyType: ITIP403Registry::PolicyType::WHITELIST,
                            accounts: vec![user1, user2],
                        },
                    )
                    .unwrap(),
            );
        });
    });

    group.bench_function("is_authorized", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut registry = TIP403Registry::new(&mut storage);
                let policy_id = registry
                    .create_policy_with_accounts(
                        &admin,
                        ITIP403Registry::createPolicyWithAccountsCall {
                            adminPolicyId: 1,
                            policyType: ITIP403Registry::PolicyType::WHITELIST,
                            accounts: vec![user1],
                        },
                    )
                    .unwrap();
                (storage, registry, policy_id)
            },
            |(mut storage, mut registry, policy_id)| {
                black_box(registry.is_authorized(ITIP403Registry::isAuthorizedCall {
                    policyId: policy_id,
                    user: user1,
                }));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("modify_policy_whitelist", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut registry = TIP403Registry::new(&mut storage);
                let policy_id = registry
                    .create_policy(
                        &admin,
                        ITIP403Registry::createPolicyCall {
                            adminPolicyId: 1,
                            policyType: ITIP403Registry::PolicyType::WHITELIST,
                        },
                    )
                    .unwrap();
                (storage, registry, policy_id)
            },
            |(mut storage, mut registry, policy_id)| {
                black_box(
                    registry
                        .modify_policy_whitelist(
                            &admin,
                            ITIP403Registry::modifyPolicyWhitelistCall {
                                policyId: policy_id,
                                account: user1,
                                allowed: true,
                            },
                        )
                        .unwrap(),
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, tip20_token, tip20_factory, tip403_registry);
criterion_main!(benches);

