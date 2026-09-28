use super::*;
use crate::{
    Precompile,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
    test_util::TIP20Setup,
    tip403_registry::REJECT_ALL_POLICY_ID,
};
use alloy::{
    primitives::{address, keccak256},
    sol_types::{SolCall, SolError},
};
use proptest::prelude::*;
use tempo_contracts::precompiles::{
    AccountKeychainError, AccountKeychainEvent, IAccountKeychain, UnknownFunctionSelector,
};

#[test]
fn burn_at_selectors_activate_at_t12() -> eyre::Result<()> {
    let admin = Address::random();
    for &spec in TempoHardfork::VARIANTS {
        let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut token = TIP20Setup::create("Token", "TKN", admin)
                .with_issuer(admin)
                .with_role(admin, BURN_AT_ROLE)
                .with_mint(admin, U256::from(10))
                .clear_events()
                .apply()?;
            let role = token.call(&ITIP20::BURN_AT_ROLECall {}.abi_encode(), admin)?;
            let burn = token.call(
                &ITIP20::burnAtCall {
                    from: admin,
                    amount: U256::ONE,
                }
                .abi_encode(),
                admin,
            )?;
            if spec.is_t12() {
                assert!(role.is_success());
                assert_eq!(
                    ITIP20::BURN_AT_ROLECall::abi_decode_returns(&role.bytes)?,
                    keccak256("BURN_AT_ROLE")
                );
                assert!(burn.is_success());
                assert_eq!(token.get_balance(admin)?, U256::from(9));
            } else {
                for output in [role, burn] {
                    assert!(output.is_revert());
                    UnknownFunctionSelector::abi_decode(&output.bytes)?;
                }
                assert_eq!(token.get_balance(admin)?, U256::from(10));
                assert_eq!(token.total_supply()?, U256::from(10));
                assert!(token.emitted_events().is_empty());
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn burn_at_requires_its_own_role_and_respects_pause() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
    let admin = Address::random();
    let burner = Address::random();
    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        let mut token = TIP20Setup::create("Token", "TKN", admin)
            .with_issuer(admin)
            .with_role(burner, BURN_BLOCKED_ROLE)
            .with_role(admin, PAUSE_ROLE)
            .with_role(admin, UNPAUSE_ROLE)
            .with_mint(admin, U256::from(10))
            .apply()?;
        let call = ITIP20::burnAtCall {
            from: admin,
            amount: U256::ZERO,
        };
        // Neither the issuer nor the blocked-burn role grants arbitrary burning authority.
        for caller in [admin, burner] {
            assert_eq!(
                token.burn_at(caller, call.clone()),
                Err(RolesAuthError::unauthorized().into())
            );
        }
        assert_eq!(
            token.get_role_admin(IRolesAuth::getRoleAdminCall { role: BURN_AT_ROLE })?,
            DEFAULT_ADMIN_ROLE
        );
        token.grant_role(
            admin,
            IRolesAuth::grantRoleCall {
                role: BURN_AT_ROLE,
                account: burner,
            },
        )?;
        token.burn_at(burner, call.clone())?;
        token.pause(admin, ITIP20::pauseCall {})?;
        assert_eq!(
            token.burn_at(burner, call.clone()),
            Err(TIP20Error::contract_paused().into())
        );
        token.unpause(admin, ITIP20::unpauseCall {})?;
        token.revoke_role(
            admin,
            IRolesAuth::revokeRoleCall {
                role: BURN_AT_ROLE,
                account: burner,
            },
        )?;
        assert_eq!(
            token.burn_at(burner, call),
            Err(RolesAuthError::unauthorized().into())
        );
        assert_eq!(token.get_balance(admin)?, U256::from(10));
        assert_eq!(token.total_supply()?, U256::from(10));
        Ok(())
    })
}

#[test]
fn burn_at_ignores_policy_and_emits_caller_and_holder() -> eyre::Result<()> {
    let admin = Address::random();
    let holder = Address::random();
    let burner = Address::random();
    for policy in [ALLOW_ALL_POLICY_ID, REJECT_ALL_POLICY_ID] {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut token = TIP20Setup::create("Token", "TKN", admin)
                .with_issuer(admin)
                .with_role(burner, BURN_AT_ROLE)
                .with_mint(holder, U256::from(100))
                .apply()?;
            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy,
                },
            )?;
            for amount in [U256::ZERO, U256::from(100)] {
                token.clear_emitted_events();
                token.burn_at(
                    burner,
                    ITIP20::burnAtCall {
                        from: holder,
                        amount,
                    },
                )?;
                assert_eq!(token.get_balance(holder)?, U256::from(100) - amount);
                assert_eq!(token.total_supply()?, U256::from(100) - amount);
                token.assert_emitted_events(vec![
                    TIP20Event::transfer(holder, Address::ZERO, amount),
                    TIP20Event::burn_at(burner, holder, amount),
                ]);
            }
            assert_eq!(
                token.burn_at(
                    burner,
                    ITIP20::burnAtCall {
                        from: holder,
                        amount: U256::ONE
                    }
                ),
                Err(TIP20Error::insufficient_balance(U256::ZERO, U256::ONE, token.address).into()),
            );
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn burn_at_and_burn_blocked_share_protected_addresses() -> eyre::Result<()> {
    let admin = Address::random();
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        let mut token = TIP20Setup::create("Token", "TKN", admin)
            .with_role(admin, BURN_AT_ROLE)
            .with_role(admin, BURN_BLOCKED_ROLE)
            .apply()?;
        token.change_transfer_policy_id(
            admin,
            ITIP20::changeTransferPolicyIdCall {
                newPolicyId: REJECT_ALL_POLICY_ID,
            },
        )?;
        for from in [
            token.address,
            TIP_FEE_MANAGER_ADDRESS,
            STABLECOIN_DEX_ADDRESS,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            RECEIVE_POLICY_GUARD_ADDRESS,
            // Protect the entire reserved prefix, including undeployed portals and the zero suffix.
            address!("5AD0000000000000000000000000000000000000"),
            address!("5AD0000000000000000000000000000000000001"),
            address!("5AD000000000000000000000ffffffffffffffff"),
        ] {
            for amount in [U256::ZERO, U256::ONE] {
                assert_eq!(
                    token.burn_at(admin, ITIP20::burnAtCall { from, amount }),
                    Err(TIP20Error::protected_address().into())
                );
                assert_eq!(
                    token.burn_blocked(admin, from, amount, true),
                    Err(TIP20Error::protected_address().into())
                );
            }
        }
        // Adjacent prefixes are ordinary balances, not protected protocol custody.
        token.burn_at(
            admin,
            ITIP20::burnAtCall {
                from: address!("5AD0000000000000000000010000000000000001"),
                amount: U256::ZERO,
            },
        )?;
        Ok(())
    })
}

#[test]
fn burn_blocked_portal_protection_preserves_pre_t12_behavior() -> eyre::Result<()> {
    let admin = Address::random();
    let portal = address!("5AD0000000000000000000000000000000000001");
    for spec in [TempoHardfork::T11, TempoHardfork::T12] {
        let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut token = TIP20Setup::create("Token", "TKN", admin)
                .with_issuer(admin)
                .with_role(admin, BURN_BLOCKED_ROLE)
                .with_mint(portal, U256::from(10))
                .apply()?;
            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: REJECT_ALL_POLICY_ID,
                },
            )?;
            let result = token.burn_blocked(admin, portal, U256::ONE, true);
            if spec.is_t12() {
                assert_eq!(result, Err(TIP20Error::protected_address().into()));
                assert_eq!(token.get_balance(portal)?, U256::from(10));
            } else {
                result?;
                assert_eq!(token.get_balance(portal)?, U256::from(9));
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn burn_at_preserves_settled_rewards() -> eyre::Result<()> {
    let admin = Address::random();
    let holder = Address::random();
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        let mut token = TIP20Setup::create("Token", "TKN", admin)
            .with_issuer(admin)
            .with_role(admin, BURN_AT_ROLE)
            .with_mint(holder, U256::from(100))
            .apply()?;
        // Seed reward state settled before T8, including the balance backing the claim.
        token.set_balance(token.address, U256::from(20))?;
        token.set_total_supply(U256::from(120))?;
        token.global_reward_per_token.write(U256::from(3))?;
        token.opted_in_supply.write(100)?;
        token.user_reward_info[holder].write(UserRewardInfo {
            reward_recipient: holder,
            reward_per_token: U256::from(2),
            reward_balance: U256::from(20),
        })?;
        token.burn_at(
            admin,
            ITIP20::burnAtCall {
                from: holder,
                amount: U256::from(100),
            },
        )?;
        let rewards = token.get_user_reward_info(holder)?;
        assert_eq!(rewards.reward_recipient, holder);
        assert_eq!(rewards.reward_per_token, U256::from(2));
        assert_eq!(rewards.reward_balance, U256::from(20));
        assert_eq!(token.get_global_reward_per_token()?, U256::from(3));
        assert_eq!(token.get_opted_in_supply()?, 100);
        assert_eq!(token.get_balance(token.address)?, U256::from(20));
        assert_eq!(token.claim_rewards(holder)?, U256::from(20));
        assert_eq!(token.get_balance(holder)?, U256::from(20));
        Ok(())
    })
}

fn authorize_burn_key(
    account: Address,
    key: Address,
    token: Address,
    period: u64,
) -> Result<AccountKeychain> {
    let mut keychain = AccountKeychain::new();
    keychain.initialize()?;
    keychain.set_tx_origin(account)?;
    keychain.authorize_key(
        account,
        key,
        IAccountKeychain::SignatureType::Secp256k1,
        IAccountKeychain::KeyRestrictions {
            expiry: u64::MAX,
            enforceLimits: true,
            limits: vec![IAccountKeychain::TokenLimit {
                token,
                amount: U256::from(100),
                period,
            }],
            allowAnyCalls: true,
            allowedCalls: vec![],
        },
        None,
    )?;
    keychain.set_transaction_key(key)?;
    Ok(keychain)
}

#[test]
fn burn_at_charges_the_holder_access_key_and_resets_periodic_limits() -> eyre::Result<()> {
    let admin = Address::random();
    let holder = Address::random();
    let bridge = Address::random();
    let key = Address::random();
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
    storage.set_timestamp(U256::from(1000));
    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        let mut token = TIP20Setup::create("Token", "TKN", admin)
            .with_issuer(admin)
            .with_role(bridge, BURN_AT_ROLE)
            .with_mint(holder, U256::from(300))
            .with_mint(bridge, U256::from(200))
            .apply()?;
        let mut keychain = authorize_burn_key(holder, key, token.address, 60)?;
        keychain.clear_emitted_events();
        token.burn_at(
            bridge,
            ITIP20::burnAtCall {
                from: holder,
                amount: U256::from(100),
            },
        )?;
        keychain.assert_emitted_events(vec![AccountKeychainEvent::access_key_spend(
            holder,
            key,
            token.address,
            U256::from(100),
            U256::ZERO,
        )]);
        assert_eq!(
            token.burn_at(
                bridge,
                ITIP20::burnAtCall {
                    from: holder,
                    amount: U256::ONE
                }
            ),
            Err(AccountKeychainError::spending_limit_exceeded().into())
        );
        // Burning a different account must not charge the transaction origin's exhausted limit.
        token.burn_at(
            bridge,
            ITIP20::burnAtCall {
                from: bridge,
                amount: U256::from(200),
            },
        )?;
        StorageCtx.set_timestamp(U256::from(1060));
        token.burn_at(
            bridge,
            ITIP20::burnAtCall {
                from: holder,
                amount: U256::from(40),
            },
        )?;
        assert_eq!(
            keychain.get_remaining_limit(IAccountKeychain::getRemainingLimitCall {
                account: holder,
                keyId: key,
                token: token.address
            })?,
            U256::from(60)
        );
        Ok(())
    })
}

proptest! {
    #[test]
    fn burn_at_conserves_supply(balance in any::<u128>(), requested in any::<u128>()) {
        let admin = Address::repeat_byte(1);
        let holder = Address::repeat_byte(2);
        let amount = U256::from(requested.min(balance));
        let balance = U256::from(balance);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut token = TIP20Setup::create("Token", "TKN", admin)
                .with_issuer(admin)
                .with_role(admin, BURN_AT_ROLE)
                .apply()?;
            token.set_balance(holder, balance)?;
            token.set_total_supply(balance)?;
            token.burn_at(admin, ITIP20::burnAtCall { from: holder, amount })?;
            assert_eq!(token.get_balance(holder)?, balance - amount);
            assert_eq!(token.total_supply()?, balance - amount);
            assert_eq!(token.get_balance(Address::ZERO)?, U256::ZERO);
            Ok(())
        }).unwrap();
    }
}

#[test]
fn burn_at_bridge_access_key_spending_and_reverts_in_evm() -> eyre::Result<()> {
    use crate::storage::actions::StorageActions;
    use alloy::{
        primitives::{Bytes, TxKind},
        sol_types::SolEvent,
    };
    use alloy_evm::{Evm, EvmEnv};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use revm::{
        DatabaseCommit,
        context::{CfgEnv, TxEnv, result::ExecutionResult},
        database::{CacheDB, EmptyDB},
        state::{AccountInfo, Bytecode},
    };
    use tempo_evm::{TempoBlockEnv, evm::TempoEvm};
    use tempo_primitives::{
        TempoSignature,
        transaction::{Call, KeychainSignature, PrimitiveSignature},
    };
    use tempo_revm::{TempoBatchCallEnv, TempoTxEnv};

    // Forward calldata to the token, bubbling its result. The second bridge deliberately
    // reverts after a successful burn to exercise rollback of an enclosing contract call.
    fn bridge_runtime(token: Address, revert_after_burn: bool, catch_failure: bool) -> Bytecode {
        let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x5f, 0x73];
        code.extend_from_slice(token.as_slice());
        code.extend_from_slice(&[0x5a, 0xf1, 0x3d, 0x5f, 0x5f, 0x3e]);
        let success = u8::try_from(code.len() + 6).unwrap();
        code.extend_from_slice(&[
            0x60,
            success,
            0x57,
            0x3d,
            0x5f,
            if catch_failure { 0xf3 } else { 0xfd },
            0x5b,
            0x3d,
            0x5f,
        ]);
        code.push(if revert_after_burn { 0xfd } else { 0xf3 });
        Bytecode::new_raw(code.into())
    }

    let holder = Address::repeat_byte(0x11);
    let bridge = Address::repeat_byte(0x22);
    let reverting_bridge = Address::repeat_byte(0x33);
    let catching_bridge = Address::repeat_byte(0x44);
    let key = PrivateKeySigner::random();
    let mut cfg = CfgEnv::default();
    cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T12);
    let mut evm = TempoEvm::new(
        CacheDB::new(EmptyDB::default()),
        EvmEnv {
            cfg_env: cfg,
            block_env: TempoBlockEnv::default(),
        },
    );
    let token = StorageCtx::enter_ctx(
        evm.ctx_mut(),
        StorageActions::disabled(),
        || -> Result<Address> {
            TIP20Setup::path_usd(holder).with_issuer(holder).apply()?;
            let token = TIP20Setup::create("Token", "TKN", holder)
                .with_issuer(holder)
                .with_role(bridge, BURN_AT_ROLE)
                .with_role(reverting_bridge, BURN_AT_ROLE)
                .with_role(catching_bridge, BURN_AT_ROLE)
                .with_mint(holder, U256::from(40))
                .apply()?;
            authorize_burn_key(holder, key.address(), token.address, 0)?;
            Ok(token.address)
        },
    )?;
    let setup_state = evm.ctx_mut().journaled_state.finalize();
    evm.db_mut().commit(setup_state);
    for (address, revert_after_burn, catch_failure) in [
        (bridge, false, false),
        (reverting_bridge, true, false),
        (catching_bridge, false, true),
    ] {
        let code = bridge_runtime(token, revert_after_burn, catch_failure);
        evm.db_mut().insert_account_info(
            address,
            AccountInfo {
                code_hash: code.hash_slow(),
                code: Some(code),
                ..Default::default()
            },
        );
    }

    for (nonce, (target, amount, succeeds, expected_balance, expected_limit, token_logs)) in [
        (bridge, 50, false, 40, 100, 0), // limit is sufficient, balance is not
        (catching_bridge, 50, true, 40, 100, 0), // child failure is caught; no limit deduction leaks
        (bridge, 20, true, 20, 80, 2),
        (reverting_bridge, 10, false, 20, 80, 0), // successful child burn is rolled back
        (bridge, 81, false, 20, 80, 0),           // limit is exceeded
        (bridge, 0, true, 20, 80, 2),
    ]
    .into_iter()
    .enumerate()
    {
        let data: Bytes = ITIP20::burnAtCall {
            from: holder,
            amount: U256::from(amount),
        }
        .abi_encode()
        .into();
        let signature_hash = keccak256(&data);
        let signature =
            key.sign_hash_sync(&KeychainSignature::signing_hash(signature_hash, holder))?;
        let result = evm.transact_raw(TempoTxEnv {
            inner: TxEnv {
                caller: holder,
                gas_limit: 1_000_000,
                gas_price: 0,
                kind: TxKind::Call(target),
                nonce: nonce as u64,
                data: data.clone(),
                ..Default::default()
            },
            fee_token: Some(PATH_USD_ADDRESS),
            tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                signature: TempoSignature::Keychain(KeychainSignature::new(
                    holder,
                    PrimitiveSignature::Secp256k1(signature),
                )),
                signature_hash,
                aa_calls: vec![Call {
                    to: TxKind::Call(target),
                    value: U256::ZERO,
                    input: data,
                }],
                ..Default::default()
            })),
            ..Default::default()
        })?;
        if succeeds {
            assert!(result.result.is_success(), "{nonce}: {:?}", result.result);
            assert_eq!(
                result
                    .result
                    .logs()
                    .iter()
                    .filter(|log| log.address == token)
                    .count(),
                token_logs
            );
        } else {
            assert!(
                matches!(result.result, ExecutionResult::Revert { .. }),
                "{nonce}: {:?}",
                result.result
            );
            assert!(result.result.logs().iter().all(|log| log.address != token));
        }
        let spends: Vec<_> = result
            .result
            .logs()
            .iter()
            .filter(|log| log.address == crate::ACCOUNT_KEYCHAIN_ADDRESS)
            .filter_map(|log| IAccountKeychain::AccessKeySpend::decode_log(log).ok())
            .filter(|log| log.data.token == token)
            .collect();
        assert_eq!(spends.len(), token_logs / 2);
        if let Some(spend) = spends.first() {
            assert_eq!(spend.data.amount, U256::from(amount));
        }
        evm.db_mut().commit(result.state);
        StorageCtx::enter_ctx(
            evm.ctx_mut(),
            StorageActions::disabled(),
            || -> Result<()> {
                let token = TIP20Token::from_address(token)?;
                assert_eq!(token.get_balance(holder)?, U256::from(expected_balance));
                assert_eq!(token.total_supply()?, U256::from(expected_balance));
                assert_eq!(
                    AccountKeychain::new().get_remaining_limit(
                        IAccountKeychain::getRemainingLimitCall {
                            account: holder,
                            keyId: key.address(),
                            token: token.address,
                        }
                    )?,
                    U256::from(expected_limit)
                );
                Ok(())
            },
        )?;
    }
    Ok(())
}
