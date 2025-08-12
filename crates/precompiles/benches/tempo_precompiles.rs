use alloy::primitives::{Address, U256};
use alloy_primitives::FixedBytes;
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
            black_box(token.balance_of(ITIP20::balanceOfCall { account: user }));
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
            black_box(token.allowance(ITIP20::allowanceCall { owner, spender }));
        });
    });

    c.bench_function("tip20_nonces", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            black_box(token.nonces(ITIP20::noncesCall { owner }));
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
            black_box(token.salts(ITIP20::saltsCall { owner, salt }));
        });
    });

    c.bench_function("tip20_supply_cap", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            black_box(token.supply_cap());
        });
    });

    c.bench_function("tip20_paused", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            black_box(token.paused());
        });
    });

    c.bench_function("tip20_transfer_policy_id", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            black_box(token.transfer_policy_id());
        });
    });

    c.bench_function("tip20_domain_separator", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        b.iter(|| {
            black_box(token.domain_separator());
        });
    });
}

fn tip20_mutate(c: &mut Criterion) {
    c.bench_function("tip20_mint", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        let amount = U256::from(100);
        b.iter(|| {
            black_box(token.mint(&admin, ITIP20::mintCall { to: user, amount })
                .unwrap());
        });
    });

    c.bench_function("tip20_burn", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        // Pre-mint tokens for burning
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: admin,
                    amount: U256::from(1000000),
                },
            )
            .unwrap();

        let amount = U256::from(100);
        b.iter(|| {
            black_box(token.burn(&admin, ITIP20::burnCall { amount }).unwrap());
        });
    });

    c.bench_function("tip20_approve", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();

        let amount = U256::from(500);
        b.iter(|| {
            black_box(token.approve(&owner, ITIP20::approveCall { spender, amount })
                .unwrap());
        });
    });

    c.bench_function("tip20_transfer", |b| {
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        // Pre-mint tokens for transfers
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: from,
                    amount: U256::from(1000000),
                },
            )
            .unwrap();

        let amount = U256::from(100);
        b.iter(|| {
            black_box(token.transfer(&from, ITIP20::transferCall { to, amount })
                .unwrap());
        });
    });

    c.bench_function("tip20_transfer_from", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let recipient = Address::from([3u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        // Pre-mint tokens and set allowance
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: owner,
                    amount: U256::from(1000000),
                },
            )
            .unwrap();
        token
            .approve(
                &owner,
                ITIP20::approveCall {
                    spender,
                    amount: U256::MAX, // Unlimited allowance to avoid updating in bench
                },
            )
            .unwrap();

        let amount = U256::from(100);

        b.iter(|| {
            black_box(token.transfer_from(
                &spender,
                ITIP20::transferFromCall {
                    from: owner,
                    to: recipient,
                    amount,
                },
            )
            .unwrap();
        });
    });

    c.bench_function("tip20_transfer_with_memo", |b| {
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let memo = FixedBytes::<32>::random();
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        // Pre-mint tokens for transfers
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: from,
                    amount: U256::from(1000000),
                },
            )
            .unwrap();

        let amount = U256::from(100);
        b.iter(|| {
            black_box(token.transfer_with_memo(&from, ITIP20::transferWithMemoCall { to, amount, memo })
                .unwrap());
        });
    });

    c.bench_function("tip20_pause", |b| {
        use tempo_precompiles::contracts::tip20::PAUSE_ROLE;
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *PAUSE_ROLE);

        b.iter(|| {
            black_box(token.pause(&admin, ITIP20::pauseCall {}).unwrap());
        });
    });

    c.bench_function("tip20_unpause", |b| {
        use tempo_precompiles::contracts::tip20::UNPAUSE_ROLE;
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let mut roles = token.get_roles_contract();
        roles.grant_role_internal(&admin, *UNPAUSE_ROLE);

        b.iter(|| {
            black_box(token.unpause(&admin, ITIP20::unpauseCall {}).unwrap());
        });
    });

    c.bench_function("tip20_set_supply_cap", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let counter = U256::from(10000);

        b.iter(|| {
            black_box(token.set_supply_cap(
                &admin,
                ITIP20::setSupplyCapCall {
                    newSupplyCap: counter,
                },
            )
            .unwrap();
        });
    });

    c.bench_function("tip20_change_transfer_policy_id", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("TestToken", "T", "USD", &admin).unwrap();
        let policy_id = 2;

        b.iter(|| {
            black_box(token.change_transfer_policy_id(
                &admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy_id,
                },
            )
            .unwrap();
        });
    });
}

fn tip20_factory_view(c: &mut Criterion) {
    c.bench_function("tip20_factory_token_id_counter", |b| {
        let mut storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut storage);

        b.iter(|| {
            let f = black_box(&mut factory);
            f.token_id_counter();
        });
    });
}

fn tip20_factory_mutate(c: &mut Criterion) {
    c.bench_function("tip20_factory_create_token", |b| {
        let sender = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut storage);

        let create_call = ITIP20Factory::createTokenCall {
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            admin: sender,
        };

        b.iter(|| {
            let f = black_box(&mut factory);
            f.create_token(&sender, create_call.clone()).unwrap();
        });
    });
}

fn tip403_registry_view(c: &mut Criterion) {
    c.bench_function("tip403_registry_policy_id_counter", |b| {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);

        b.iter(|| {
            let result = black_box(&mut registry).policy_id_counter();
            black_box(result);
        });
    });

    c.bench_function("tip403_registry_policy_data", |b| {
        let admin = Address::from([0u8; 20]);
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

        b.iter(|| {
            let call = black_box(ITIP403Registry::policyDataCall {
                policyId: policy_id,
            });
            let result = black_box(&mut registry).policy_data(call);
            black_box(result);
        });
    });

    c.bench_function("tip403_registry_is_authorized", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
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

        b.iter(|| {
            let call = black_box(ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user,
            });
            let result = black_box(&mut registry).is_authorized(call);
            black_box(result);
        });
    });
}

fn tip403_registry_mutate(c: &mut Criterion) {
    c.bench_function("tip403_registry_create_policy", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);

        b.iter(|| {
            let call = black_box(ITIP403Registry::createPolicyCall {
                adminPolicyId: 1,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            });
            let result = black_box(&mut registry)
                .create_policy(&admin, call)
                .unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip403_registry_create_policy_with_accounts", |b| {
        let admin = Address::from([0u8; 20]);
        let account1 = Address::from([1u8; 20]);
        let account2 = Address::from([2u8; 20]);
        let accounts = vec![account1, account2];
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);

        b.iter(|| {
            let call = black_box(ITIP403Registry::createPolicyWithAccountsCall {
                adminPolicyId: 1,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
                accounts: accounts.clone(),
            });
            let result = black_box(&mut registry)
                .create_policy_with_accounts(&admin, call)
                .unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip403_registry_set_policy_admin", |b| {
        let admin = Address::from([0u8; 20]);
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

        b.iter(|| {
            let call = black_box(ITIP403Registry::setPolicyAdminCall {
                policyId: policy_id,
                adminPolicyId: 1,
            });
            black_box(&mut registry)
                .set_policy_admin(&admin, call)
                .unwrap();
            black_box(());
        });
    });

    c.bench_function("tip403_registry_modify_policy_whitelist", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
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

        b.iter(|| {
            let call = black_box(ITIP403Registry::modifyPolicyWhitelistCall {
                policyId: policy_id,
                account: user,
                allowed: true,
            });
            black_box(&mut registry)
                .modify_policy_whitelist(&admin, call)
                .unwrap();
            black_box(());
        });
    });

    c.bench_function("tip403_registry_modify_policy_blacklist", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let policy_id = registry
            .create_policy(
                &admin,
                ITIP403Registry::createPolicyCall {
                    adminPolicyId: 1,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )
            .unwrap();

        b.iter(|| {
            let call = black_box(ITIP403Registry::modifyPolicyBlacklistCall {
                policyId: policy_id,
                account: user,
                restricted: true,
            });
            black_box(&mut registry)
                .modify_policy_blacklist(&admin, call)
                .unwrap();
            black_box(());
        });
    });
}

criterion_group!(
    benches,
    tip20_metadata,
    tip20_view,
    tip20_mutate,
    tip20_factory_view,
    tip20_factory_mutate,
    tip403_registry_view,
    tip403_registry_mutate
);
criterion_main!(benches);
