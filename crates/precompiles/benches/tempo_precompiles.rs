use alloy::primitives::{Address, FixedBytes, U256};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tempo_precompiles::{
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    test_util::TIP20Setup,
    tip20::{ISSUER_ROLE, PAUSE_ROLE, UNPAUSE_ROLE, abi::IToken as _},
    tip403_registry::{ITIP403Registry, TIP403Registry},
};

fn tip20_metadata(c: &mut Criterion) {
    c.bench_function("tip20_name", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let result = token.name().unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_symbol", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let result = token.symbol().unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_decimals", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let result = token.decimals().unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_currency", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let result = token.currency().unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_total_supply", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
            token.mint(admin, user, U256::from(1000)).unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let result = token.total_supply().unwrap();
                black_box(result);
            });
        });
    });
}

fn tip20_view(c: &mut Criterion) {
    c.bench_function("tip20_balance_of", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
            token.mint(admin, user, U256::from(1000)).unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let user = black_box(user);
                let result = token.balance_of(user).unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_allowance", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            token.approve(owner, spender, U256::from(500)).unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let owner = black_box(owner);
                let spender = black_box(spender);
                let result = token.allowance(owner, spender).unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_supply_cap", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let result = token.supply_cap().unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_paused", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let result = token.paused().unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_transfer_policy_id", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();

            b.iter(|| {
                let token = black_box(&mut token);
                let result = token.transfer_policy_id().unwrap();
                black_box(result);
            });
        });
    });
}

fn tip20_mutate(c: &mut Criterion) {
    c.bench_function("tip20_mint", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *ISSUER_ROLE);

            let amount = U256::from(100);
            b.iter(|| {
                let token = black_box(&mut token);
                let admin = black_box(admin);
                let user = black_box(user);
                let amount = black_box(amount);
                token.mint(admin, user, amount).unwrap();
            });
        });
    });

    c.bench_function("tip20_burn", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
            // Pre-mint tokens for burning
            token.mint(admin, admin, U256::from(u128::MAX)).unwrap();

            let amount = U256::ONE;
            b.iter(|| {
                let token = black_box(&mut token);
                let admin = black_box(admin);
                let amount = black_box(amount);
                token.burn(admin, amount).unwrap();
            });
        });
    });

    c.bench_function("tip20_approve", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();

            let amount = U256::from(500);
            b.iter(|| {
                let token = black_box(&mut token);
                let owner = black_box(owner);
                let spender = black_box(spender);
                let amount = black_box(amount);
                let result = token.approve(owner, spender, amount).unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_transfer", |b| {
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
            // Pre-mint tokens for transfers
            token.mint(admin, from, U256::from(u128::MAX)).unwrap();

            let amount = U256::ONE;
            b.iter(|| {
                let token = black_box(&mut token);
                let from = black_box(from);
                let to = black_box(to);
                let amount = black_box(amount);
                let result = token.transfer(from, to, amount).unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_transfer_from", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let recipient = Address::from([3u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
            // Pre-mint tokens and set allowance
            token.mint(admin, owner, U256::from(u128::MAX)).unwrap();
            token
                .approve(owner, spender, U256::from(u128::MAX))
                .unwrap();

            let amount = U256::ONE;

            b.iter(|| {
                let token = black_box(&mut token);
                let spender = black_box(spender);
                let owner = black_box(owner);
                let recipient = black_box(recipient);
                let amount = black_box(amount);
                let result = token
                    .transfer_from(spender, owner, recipient, amount)
                    .unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip20_transfer_with_memo", |b| {
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let memo = FixedBytes::<32>::random();
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
            // Pre-mint tokens for transfers
            token.mint(admin, from, U256::from(u128::MAX)).unwrap();

            let amount = U256::ONE;
            b.iter(|| {
                let token = black_box(&mut token);
                let from = black_box(from);
                let to = black_box(to);
                let amount = black_box(amount);
                let memo = black_box(memo);
                token.transfer_with_memo(from, to, amount, memo).unwrap();
            });
        });
    });

    c.bench_function("tip20_pause", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *PAUSE_ROLE);

            b.iter(|| {
                let token = black_box(&mut token);
                let admin = black_box(admin);
                token.pause(admin).unwrap();
            });
        });
    });

    c.bench_function("tip20_unpause", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let _ = token.grant_role_internal(admin, *UNPAUSE_ROLE);

            b.iter(|| {
                let token = black_box(&mut token);
                let admin = black_box(admin);
                token.unpause(admin).unwrap();
            });
        });
    });

    c.bench_function("tip20_set_supply_cap", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let counter = U256::from(10000);

            b.iter(|| {
                let token = black_box(&mut token);
                let admin = black_box(admin);
                let counter = black_box(counter);
                token.set_supply_cap(admin, counter).unwrap();
            });
        });
    });

    c.bench_function("tip20_change_transfer_policy_id", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("TestToken", "TEST", admin)
                .apply()
                .unwrap();
            let policy_id = 2;

            b.iter(|| {
                let token = black_box(&mut token);
                let admin = black_box(admin);
                let policy_id = black_box(policy_id);
                token.change_transfer_policy_id(admin, policy_id).unwrap();
            });
        });
    });
}

fn tip20_factory_mutate(c: &mut Criterion) {
    c.bench_function("tip20_factory_create_token", |b| {
        let sender = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            // Setup pathUSD first
            TIP20Setup::path_usd(sender).apply().unwrap();
            let mut counter = 0u64;

            b.iter(|| {
                counter += 1;
                let result = TIP20Setup::create("Test", "TEST", sender)
                    .with_salt(FixedBytes::from(U256::from(counter)))
                    .apply()
                    .unwrap();
                black_box(result);
            });
        });
    });
}

fn tip403_registry_view(c: &mut Criterion) {
    c.bench_function("tip403_registry_policy_id_counter", |b| {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            b.iter(|| {
                let registry = black_box(&mut registry);
                let result = registry.policy_id_counter().unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip403_registry_policy_data", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            let policy_id = registry
                .create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: ITIP403Registry::PolicyType::WHITELIST,
                    },
                )
                .unwrap();

            b.iter(|| {
                let registry = black_box(&mut registry);
                let call = black_box(ITIP403Registry::policyDataCall {
                    policyId: policy_id,
                });
                let result = registry.policy_data(call).unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip403_registry_is_authorized", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            let policy_id = registry
                .create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: ITIP403Registry::PolicyType::WHITELIST,
                    },
                )
                .unwrap();

            b.iter(|| {
                let registry = black_box(&mut registry);
                let call = black_box(ITIP403Registry::isAuthorizedCall {
                    policyId: policy_id,
                    user,
                });
                let result = registry.is_authorized(call).unwrap();
                black_box(result);
            });
        });
    });
}

fn tip403_registry_mutate(c: &mut Criterion) {
    c.bench_function("tip403_registry_create_policy", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            b.iter(|| {
                let registry = black_box(&mut registry);
                let admin = black_box(admin);
                let call = black_box(ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                });
                let result = registry.create_policy(admin, call).unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip403_registry_create_policy_with_accounts", |b| {
        let admin = Address::from([0u8; 20]);
        let account1 = Address::from([1u8; 20]);
        let account2 = Address::from([2u8; 20]);
        let accounts = vec![account1, account2];
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            b.iter(|| {
                let registry = black_box(&mut registry);
                let admin = black_box(admin);
                let call = black_box(ITIP403Registry::createPolicyWithAccountsCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                    accounts: accounts.clone(),
                });
                let result = registry.create_policy_with_accounts(admin, call).unwrap();
                black_box(result);
            });
        });
    });

    c.bench_function("tip403_registry_set_policy_admin", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            let policy_id = registry
                .create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: ITIP403Registry::PolicyType::WHITELIST,
                    },
                )
                .unwrap();

            b.iter(|| {
                let registry = black_box(&mut registry);
                let admin = black_box(admin);
                let call = black_box(ITIP403Registry::setPolicyAdminCall {
                    policyId: policy_id,
                    admin,
                });
                registry.set_policy_admin(admin, call).unwrap();
            });
        });
    });

    c.bench_function("tip403_registry_modify_policy_whitelist", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            let policy_id = registry
                .create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: ITIP403Registry::PolicyType::WHITELIST,
                    },
                )
                .unwrap();

            b.iter(|| {
                let registry = black_box(&mut registry);
                let admin = black_box(admin);
                let call = black_box(ITIP403Registry::modifyPolicyWhitelistCall {
                    policyId: policy_id,
                    account: user,
                    allowed: true,
                });
                registry.modify_policy_whitelist(admin, call).unwrap();
            });
        });
    });

    c.bench_function("tip403_registry_modify_policy_blacklist", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();
            let policy_id = registry
                .create_policy(
                    admin,
                    ITIP403Registry::createPolicyCall {
                        admin,
                        policyType: ITIP403Registry::PolicyType::BLACKLIST,
                    },
                )
                .unwrap();

            b.iter(|| {
                let registry = black_box(&mut registry);
                let admin = black_box(admin);
                let call = black_box(ITIP403Registry::modifyPolicyBlacklistCall {
                    policyId: policy_id,
                    account: user,
                    restricted: true,
                });
                registry.modify_policy_blacklist(admin, call).unwrap();
            });
        });
    });
}

criterion_group!(
    benches,
    tip20_metadata,
    tip20_view,
    tip20_mutate,
    tip20_factory_mutate,
    tip403_registry_view,
    tip403_registry_mutate
);
criterion_main!(benches);
