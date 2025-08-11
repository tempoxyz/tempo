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
            let r = black_box(&mut registry);
            r.policy_id_counter();
        });
    });

    c.bench_function("tip403_registry_policy_data", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let policy_id = registry.create_policy(
            &admin,
            ITIP403Registry::createPolicyCall {
                adminPolicyId: 1,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            },
        ).unwrap();

        b.iter(|| {
            let r = black_box(&mut registry);
            r.policy_data(ITIP403Registry::policyDataCall { policyId: policy_id });
        });
    });

    c.bench_function("tip403_registry_is_authorized", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let policy_id = registry.create_policy(
            &admin,
            ITIP403Registry::createPolicyCall {
                adminPolicyId: 1,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            },
        ).unwrap();

        b.iter(|| {
            let r = black_box(&mut registry);
            r.is_authorized(ITIP403Registry::isAuthorizedCall { policyId: policy_id, user });
        });
    });
}

fn tip403_registry_mutate(c: &mut Criterion) {
    c.bench_function("tip403_registry_create_policy", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);

        b.iter(|| {
            let r = black_box(&mut registry);
            r.create_policy(
                &admin,
                ITIP403Registry::createPolicyCall {
                    adminPolicyId: 1,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            ).unwrap();
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
            let r = black_box(&mut registry);
            r.create_policy_with_accounts(
                &admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    adminPolicyId: 1,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                    accounts: accounts.clone(),
                },
            ).unwrap();
        });
    });

    c.bench_function("tip403_registry_set_policy_admin", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let policy_id = registry.create_policy(
            &admin,
            ITIP403Registry::createPolicyCall {
                adminPolicyId: 1,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            },
        ).unwrap();

        b.iter(|| {
            let r = black_box(&mut registry);
            r.set_policy_admin(
                &admin,
                ITIP403Registry::setPolicyAdminCall {
                    policyId: policy_id,
                    adminPolicyId: 1,
                },
            ).unwrap();
        });
    });

    c.bench_function("tip403_registry_modify_policy_whitelist", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let policy_id = registry.create_policy(
            &admin,
            ITIP403Registry::createPolicyCall {
                adminPolicyId: 1,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            },
        ).unwrap();

        b.iter(|| {
            let r = black_box(&mut registry);
            r.modify_policy_whitelist(
                &admin,
                ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: policy_id,
                    account: user,
                    allowed: true,
                },
            ).unwrap();
        });
    });

    c.bench_function("tip403_registry_modify_policy_blacklist", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
        let policy_id = registry.create_policy(
            &admin,
            ITIP403Registry::createPolicyCall {
                adminPolicyId: 1,
                policyType: ITIP403Registry::PolicyType::BLACKLIST,
            },
        ).unwrap();

        b.iter(|| {
            let r = black_box(&mut registry);
            r.modify_policy_blacklist(
                &admin,
                ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: user,
                    restricted: true,
                },
            ).unwrap();
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
