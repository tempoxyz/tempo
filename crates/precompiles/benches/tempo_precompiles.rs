use alloy::primitives::{Address, FixedBytes, U256};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    storage::hashmap::HashMapStorageProvider,
    tip20::{ISSUER_ROLE, ITIP20, PAUSE_ROLE, TIP20Token, UNPAUSE_ROLE},
    tip20_factory::{ITIP20Factory, TIP20Factory},
    tip403_registry::{ITIP403Registry, TIP403Registry},
};

fn tip20_metadata(c: &mut Criterion) {
    c.bench_function("tip20_name", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let result = token.name().unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_symbol", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let result = token.symbol().unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_decimals", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let result = token.decimals().unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_currency", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let result = token.currency().unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_total_supply", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: user,
                    amount: U256::from(1000),
                },
            )
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let result = token.total_supply().unwrap();
            black_box(result);
        });
    });
}

fn tip20_view(c: &mut Criterion) {
    c.bench_function("tip20_balance_of", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: user,
                    amount: U256::from(1000),
                },
            )
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let call = black_box(ITIP20::balanceOfCall { account: user });
            let result = token.balance_of(call).unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_allowance", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        token
            .approve(
                owner,
                ITIP20::approveCall {
                    spender,
                    amount: U256::from(500),
                },
            )
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let call = black_box(ITIP20::allowanceCall { owner, spender });
            let result = token.allowance(call).unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_supply_cap", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let result = token.supply_cap().unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_paused", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let result = token.paused().unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_transfer_policy_id", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();

        b.iter(|| {
            let token = black_box(&mut token);
            let result = token.transfer_policy_id().unwrap();
            black_box(result);
        });
    });
}

fn tip20_mutate(c: &mut Criterion) {
    c.bench_function("tip20_mint", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *ISSUER_ROLE);

        let amount = U256::from(100);
        b.iter(|| {
            let token = black_box(&mut token);
            let admin = black_box(admin);
            let call = black_box(ITIP20::mintCall { to: user, amount });
            token.mint(admin, call).unwrap();
        });
    });

    c.bench_function("tip20_burn", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
        // Pre-mint tokens for burning
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: admin,
                    amount: U256::MAX,
                },
            )
            .unwrap();

        let amount = U256::ONE;
        b.iter(|| {
            let token = black_box(&mut token);
            let admin = black_box(admin);
            let call = black_box(ITIP20::burnCall { amount });
            token.burn(admin, call).unwrap();
        });
    });

    c.bench_function("tip20_approve", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();

        let amount = U256::from(500);
        b.iter(|| {
            let token = black_box(&mut token);
            let owner = black_box(owner);
            let call = black_box(ITIP20::approveCall { spender, amount });
            let result = token.approve(owner, call).unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_transfer", |b| {
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
        // Pre-mint tokens for transfers
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: from,
                    amount: U256::MAX,
                },
            )
            .unwrap();

        let amount = U256::ONE;
        b.iter(|| {
            let token = black_box(&mut token);
            let from = black_box(from);
            let call = black_box(ITIP20::transferCall { to, amount });
            let result = token.transfer(from, call).unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_transfer_from", |b| {
        let admin = Address::from([0u8; 20]);
        let owner = Address::from([1u8; 20]);
        let spender = Address::from([2u8; 20]);
        let recipient = Address::from([3u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
        // Pre-mint tokens and set allowance
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: owner,
                    amount: U256::MAX,
                },
            )
            .unwrap();
        token
            .approve(
                owner,
                ITIP20::approveCall {
                    spender,
                    amount: U256::MAX,
                },
            )
            .unwrap();

        let amount = U256::ONE;

        b.iter(|| {
            let token = black_box(&mut token);
            let spender = black_box(spender);
            let call = black_box(ITIP20::transferFromCall {
                from: owner,
                to: recipient,
                amount,
            });
            let result = token.transfer_from(spender, call).unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip20_transfer_with_memo", |b| {
        let admin = Address::from([0u8; 20]);
        let from = Address::from([1u8; 20]);
        let to = Address::from([2u8; 20]);
        let memo = FixedBytes::<32>::random();
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *ISSUER_ROLE);
        // Pre-mint tokens for transfers
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: from,
                    amount: U256::MAX,
                },
            )
            .unwrap();

        let amount = U256::ONE;
        b.iter(|| {
            let token = black_box(&mut token);
            let from = black_box(from);
            let call = black_box(ITIP20::transferWithMemoCall { to, amount, memo });
            token.transfer_with_memo(from, call).unwrap();
        });
    });

    c.bench_function("tip20_pause", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *PAUSE_ROLE);

        b.iter(|| {
            let token = black_box(&mut token);
            let admin = black_box(admin);
            let call = black_box(ITIP20::pauseCall {});
            token.pause(admin, call).unwrap();
        });
    });

    c.bench_function("tip20_unpause", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let _ = token.grant_role_internal(admin, *UNPAUSE_ROLE);

        b.iter(|| {
            let token = black_box(&mut token);
            let admin = black_box(admin);
            let call = black_box(ITIP20::unpauseCall {});
            token.unpause(admin, call).unwrap();
        });
    });

    c.bench_function("tip20_set_supply_cap", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let counter = U256::from(10000);

        b.iter(|| {
            let token = black_box(&mut token);
            let admin = black_box(admin);
            let call = black_box(ITIP20::setSupplyCapCall {
                newSupplyCap: counter,
            });
            token.set_supply_cap(admin, call).unwrap();
        });
    });

    c.bench_function("tip20_change_transfer_policy_id", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize("TestToken", "T", "USD", PATH_USD_ADDRESS, admin)
            .unwrap();
        let policy_id = 2;

        b.iter(|| {
            let token = black_box(&mut token);
            let admin = black_box(admin);
            let call = black_box(ITIP20::changeTransferPolicyIdCall {
                newPolicyId: policy_id,
            });
            token.change_transfer_policy_id(admin, call).unwrap();
        });
    });
}

fn tip20_factory_view(c: &mut Criterion) {
    c.bench_function("tip20_factory_token_id_counter", |b| {
        let mut storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut storage);

        b.iter(|| {
            let factory = black_box(&mut factory);
            let result = factory.token_id_counter().unwrap();
            black_box(result);
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
            quoteToken: PATH_USD_ADDRESS,
            admin: sender,
        };

        b.iter(|| {
            let factory = black_box(&mut factory);
            let sender = black_box(sender);
            let call = black_box(create_call.clone());
            let result = factory.create_token(sender, call).unwrap();
            black_box(result);
        });
    });
}

fn tip403_registry_view(c: &mut Criterion) {
    c.bench_function("tip403_registry_policy_id_counter", |b| {
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);

        b.iter(|| {
            let registry = black_box(&mut registry);
            let result = registry.policy_id_counter().unwrap();
            black_box(result);
        });
    });

    c.bench_function("tip403_registry_policy_data", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
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

    c.bench_function("tip403_registry_is_authorized", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
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
}

fn tip403_registry_mutate(c: &mut Criterion) {
    c.bench_function("tip403_registry_create_policy", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);

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

    c.bench_function("tip403_registry_create_policy_with_accounts", |b| {
        let admin = Address::from([0u8; 20]);
        let account1 = Address::from([1u8; 20]);
        let account2 = Address::from([2u8; 20]);
        let accounts = vec![account1, account2];
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);

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

    c.bench_function("tip403_registry_set_policy_admin", |b| {
        let admin = Address::from([0u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
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

    c.bench_function("tip403_registry_modify_policy_whitelist", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
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

    c.bench_function("tip403_registry_modify_policy_blacklist", |b| {
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);
        let mut storage = HashMapStorageProvider::new(1);
        let mut registry = TIP403Registry::new(&mut storage);
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
