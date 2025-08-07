use alloy::primitives::{Address, U256};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tempo_precompiles::contracts::{
    storage::hashmap::HashMapStorageProvider,
    tip20::{ISSUER_ROLE, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
    types::{ITIP20, ITIP20Factory, ITIP403Registry},
};

fn tip20_metadata(c: &mut Criterion) {
    let admin = Address::from([0u8; 20]);
    let caller = Address::from([1u8; 20]);
    let token_id = 1u64;

    c.bench_function("tip20_name", |b| {
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
                black_box(token.name());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("tip20_symbol", |b| {
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
                black_box(token.symbol());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("tip20_decimals", |b| {
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
                black_box(token.decimals());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("tip20_currency", |b| {
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
                black_box(token.currency());
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("tip20_total_supply", |b| {
        b.iter_batched(
            || {
                let mut storage = HashMapStorageProvider::new(1);
                let mut token = TIP20Token::new(token_id, &mut storage);
                token
                    .initialize("TestToken", "TTK", 18, "USD", &admin)
                    .unwrap();
                let mut roles = token.get_roles_contract();
                roles.grant_role_internal(&admin, *ISSUER_ROLE);
                // Mint some tokens to have a non-zero supply
                token
                    .mint(&admin, ITIP20::mintCall { to: caller, amount: U256::from(1000) })
                    .unwrap();
                (storage, token)
            },
            |(mut storage, mut token)| {
                black_box(token.total_supply());
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn tip20_view(c: &mut Criterion) {
    let admin = Address::from([0u8; 20]);
    let user1 = Address::from([1u8; 20]);
    let user2 = Address::from([2u8; 20]);
    let amount = U256::from(1000);
    let token_id = 1u64;

    c.bench_function("tip20_balance_of", |b| {
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

    c.bench_function("tip20_allowance", |b| {
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
                // Set up an allowance
                token
                    .approve(&user1, ITIP20::approveCall { spender: user2, amount: U256::from(500) })
                    .unwrap();
                (storage, token)
            },
            |(mut storage, mut token)| {
                black_box(token.allowance(ITIP20::allowanceCall { owner: user1, spender: user2 }));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("tip20_nonces", |b| {
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
                black_box(token.nonces(ITIP20::noncesCall { owner: user1 }));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("tip20_salts", |b| {
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
                let salt = alloy::primitives::FixedBytes::<4>::from([1u8, 2u8, 3u8, 4u8]);
                black_box(token.salts(ITIP20::saltsCall { owner: user1, salt }));
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

// fn tip20_token_mint(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//     let user1 = Address::from([1u8; 20]);
//     let amount = U256::from(1000);
//     let token_id = 1u64;
//
//     c.bench_function("tip20_token_mint", |b| {
//         b.iter_batched(
//             || {
//                 let mut storage = HashMapStorageProvider::new(1);
//                 let mut token = TIP20Token::new(token_id, &mut storage);
//                 token
//                     .initialize("TestToken", "TTK", 18, "USD", &admin)
//                     .unwrap();
//                 let mut roles = token.get_roles_contract();
//                 roles.grant_role_internal(&admin, *ISSUER_ROLE);
//                 (storage, token)
//             },
//             |(mut storage, mut token)| {
//                 black_box(
//                     token
//                         .mint(&admin, ITIP20::mintCall { to: user1, amount })
//                         .unwrap(),
//                 );
//             },
//             criterion::BatchSize::SmallInput,
//         );
//     });
// }
//
// fn tip20_token_transfer(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//     let user1 = Address::from([1u8; 20]);
//     let user2 = Address::from([2u8; 20]);
//     let amount = U256::from(1000);
//     let token_id = 1u64;
//
//     c.bench_function("tip20_token_transfer", |b| {
//         b.iter_batched(
//             || {
//                 let mut storage = HashMapStorageProvider::new(1);
//                 let mut token = TIP20Token::new(token_id, &mut storage);
//                 token
//                     .initialize("TestToken", "TTK", 18, "USD", &admin)
//                     .unwrap();
//                 let mut roles = token.get_roles_contract();
//                 roles.grant_role_internal(&admin, *ISSUER_ROLE);
//                 token
//                     .mint(&admin, ITIP20::mintCall { to: user1, amount })
//                     .unwrap();
//                 (storage, token)
//             },
//             |(mut storage, mut token)| {
//                 black_box(
//                     token
//                         .transfer(
//                             &user1,
//                             ITIP20::transferCall {
//                                 to: user2,
//                                 amount: U256::from(100),
//                             },
//                         )
//                         .unwrap(),
//                 );
//             },
//             criterion::BatchSize::SmallInput,
//         );
//     });
// }
//
// fn tip20_token_approve(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//     let user1 = Address::from([1u8; 20]);
//     let user2 = Address::from([2u8; 20]);
//     let amount = U256::from(1000);
//     let token_id = 1u64;
//
//     c.bench_function("tip20_token_approve", |b| {
//         b.iter_batched(
//             || {
//                 let mut storage = HashMapStorageProvider::new(1);
//                 let mut token = TIP20Token::new(token_id, &mut storage);
//                 token
//                     .initialize("TestToken", "TTK", 18, "USD", &admin)
//                     .unwrap();
//                 (storage, token)
//             },
//             |(mut storage, mut token)| {
//                 black_box(
//                     token
//                         .approve(
//                             &user1,
//                             ITIP20::approveCall {
//                                 spender: user2,
//                                 amount,
//                             },
//                         )
//                         .unwrap(),
//                 );
//             },
//             criterion::BatchSize::SmallInput,
//         );
//     });
// }
//
// fn tip20_token_balance_of(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//     let user1 = Address::from([1u8; 20]);
//     let amount = U256::from(1000);
//     let token_id = 1u64;
//
//     c.bench_function("tip20_token_balance_of", |b| {
//         b.iter_batched(
//             || {
//                 let mut storage = HashMapStorageProvider::new(1);
//                 let mut token = TIP20Token::new(token_id, &mut storage);
//                 token
//                     .initialize("TestToken", "TTK", 18, "USD", &admin)
//                     .unwrap();
//                 let mut roles = token.get_roles_contract();
//                 roles.grant_role_internal(&admin, *ISSUER_ROLE);
//                 token
//                     .mint(&admin, ITIP20::mintCall { to: user1, amount })
//                     .unwrap();
//                 (storage, token)
//             },
//             |(mut storage, mut token)| {
//                 black_box(token.balance_of(ITIP20::balanceOfCall { account: user1 }));
//             },
//             criterion::BatchSize::SmallInput,
//         );
//     });
// }
//
// fn tip20_token_burn(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//     let amount = U256::from(1000);
//     let token_id = 1u64;
//
//     c.bench_function("tip20_token_burn", |b| {
//         b.iter_batched(
//             || {
//                 let mut storage = HashMapStorageProvider::new(1);
//                 let mut token = TIP20Token::new(token_id, &mut storage);
//                 token
//                     .initialize("TestToken", "TTK", 18, "USD", &admin)
//                     .unwrap();
//                 let mut roles = token.get_roles_contract();
//                 roles.grant_role_internal(&admin, *ISSUER_ROLE);
//                 token
//                     .mint(&admin, ITIP20::mintCall { to: admin, amount })
//                     .unwrap();
//                 (storage, token)
//             },
//             |(mut storage, mut token)| {
//                 black_box(
//                     token
//                         .burn(
//                             &admin,
//                             ITIP20::burnCall {
//                                 amount: U256::from(100),
//                             },
//                         )
//                         .unwrap(),
//                 );
//             },
//             criterion::BatchSize::SmallInput,
//         );
//     });
// }
//
// fn tip20_factory_create_token(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//
//     c.bench_function("tip20_factory_create_token", |b| {
//         b.iter(|| {
//             let mut storage = HashMapStorageProvider::new(1);
//             let mut factory = TIP20Factory::new(&mut storage);
//             black_box(
//                 factory
//                     .create_token(
//                         &admin,
//                         ITIP20Factory::createTokenCall {
//                             name: "TestToken".to_string(),
//                             symbol: "TTK".to_string(),
//                             decimals: 18,
//                             currency: "USD".to_string(),
//                             admin,
//                         },
//                     )
//                     .unwrap(),
//             );
//         });
//     });
// }
//
// fn tip20_factory_token_id_counter(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//
//     c.bench_function("tip20_factory_token_id_counter", |b| {
//         b.iter_batched(
//             || {
//                 let mut storage = HashMapStorageProvider::new(1);
//                 let mut factory = TIP20Factory::new(&mut storage);
//                 // Create a few tokens to have a non-zero counter
//                 for i in 0..5 {
//                     factory
//                         .create_token(
//                             &admin,
//                             ITIP20Factory::createTokenCall {
//                                 name: format!("Token{}", i),
//                                 symbol: format!("T{}", i),
//                                 decimals: 18,
//                                 currency: "USD".to_string(),
//                                 admin,
//                             },
//                         )
//                         .unwrap();
//                 }
//                 (storage, factory)
//             },
//             |(mut storage, mut factory)| {
//                 black_box(factory.token_id_counter());
//             },
//             criterion::BatchSize::SmallInput,
//         );
//     });
// }
//
// fn tip403_registry_create_policy(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//
//     c.bench_function("tip403_registry_create_policy", |b| {
//         b.iter(|| {
//             let mut storage = HashMapStorageProvider::new(1);
//             let mut registry = TIP403Registry::new(&mut storage);
//             black_box(
//                 registry
//                     .create_policy(
//                         &admin,
//                         ITIP403Registry::createPolicyCall {
//                             adminPolicyId: 1, // Always-allow policy
//                             policyType: ITIP403Registry::PolicyType::WHITELIST,
//                         },
//                     )
//                     .unwrap(),
//             );
//         });
//     });
// }
//
// fn tip403_registry_create_policy_with_accounts(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//     let user1 = Address::from([1u8; 20]);
//     let user2 = Address::from([2u8; 20]);
//
//     c.bench_function("tip403_registry_create_policy_with_accounts", |b| {
//         b.iter(|| {
//             let mut storage = HashMapStorageProvider::new(1);
//             let mut registry = TIP403Registry::new(&mut storage);
//             black_box(
//                 registry
//                     .create_policy_with_accounts(
//                         &admin,
//                         ITIP403Registry::createPolicyWithAccountsCall {
//                             adminPolicyId: 1,
//                             policyType: ITIP403Registry::PolicyType::WHITELIST,
//                             accounts: vec![user1, user2],
//                         },
//                     )
//                     .unwrap(),
//             );
//         });
//     });
// }
//
// fn tip403_registry_is_authorized(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//     let user1 = Address::from([1u8; 20]);
//
//     c.bench_function("tip403_registry_is_authorized", |b| {
//         b.iter_batched(
//             || {
//                 let mut storage = HashMapStorageProvider::new(1);
//                 let mut registry = TIP403Registry::new(&mut storage);
//                 let policy_id = registry
//                     .create_policy_with_accounts(
//                         &admin,
//                         ITIP403Registry::createPolicyWithAccountsCall {
//                             adminPolicyId: 1,
//                             policyType: ITIP403Registry::PolicyType::WHITELIST,
//                             accounts: vec![user1],
//                         },
//                     )
//                     .unwrap();
//                 (storage, registry, policy_id)
//             },
//             |(mut storage, mut registry, policy_id)| {
//                 black_box(registry.is_authorized(ITIP403Registry::isAuthorizedCall {
//                     policyId: policy_id,
//                     user: user1,
//                 }));
//             },
//             criterion::BatchSize::SmallInput,
//         );
//     });
// }
//
// fn tip403_registry_modify_policy_whitelist(c: &mut Criterion) {
//     let admin = Address::from([0u8; 20]);
//     let user1 = Address::from([1u8; 20]);
//
//     c.bench_function("tip403_registry_modify_policy_whitelist", |b| {
//         b.iter_batched(
//             || {
//                 let mut storage = HashMapStorageProvider::new(1);
//                 let mut registry = TIP403Registry::new(&mut storage);
//                 let policy_id = registry
//                     .create_policy(
//                         &admin,
//                         ITIP403Registry::createPolicyCall {
//                             adminPolicyId: 1,
//                             policyType: ITIP403Registry::PolicyType::WHITELIST,
//                         },
//                     )
//                     .unwrap();
//                 (storage, registry, policy_id)
//             },
//             |(mut storage, mut registry, policy_id)| {
//                 black_box(
//                     registry
//                         .modify_policy_whitelist(
//                             &admin,
//                             ITIP403Registry::modifyPolicyWhitelistCall {
//                                 policyId: policy_id,
//                                 account: user1,
//                                 allowed: true,
//                             },
//                         )
//                         .unwrap(),
//                 );
//             },
//             criterion::BatchSize::SmallInput,
//         );
//     });
// }

criterion_group!(
    benches,
    tip20_metadata,
    tip20_view,
    // tip20_token_mint,
    // tip20_token_transfer,
    // tip20_token_approve,
    // tip20_token_balance_of,
    // tip20_token_burn,
    // tip20_factory_create_token,
    // tip20_factory_token_id_counter,
    // tip403_registry_create_policy,
    // tip403_registry_create_policy_with_accounts,
    // tip403_registry_is_authorized,
    // tip403_registry_modify_policy_whitelist
);
criterion_main!(benches);
