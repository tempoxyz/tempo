// Additional regression coverage introduced with the EVM2 migration.
use super::*;

#[test]
fn test_resolve_fee_context_warms_balance_without_fee_collection() {
    use tempo_precompiles::storage::{
        PrecompileStorageProvider, evm::EvmPrecompileStorageProvider,
    };

    for (spec, disable_fee, gas_price) in [
        (TempoHardfork::T1, false, 0),
        (TempoHardfork::T7, false, 0),
        (TempoHardfork::T7, true, 1_000_000_000_000),
    ] {
        let mut evm = storage_evm(spec);
        if disable_fee {
            let mut version = *evm.version();
            version.features.remove(EvmFeatures::FEE_CHARGE);
            evm.set_execution_config(
                ExecutionConfig::for_spec_and_version(spec, version),
                spec,
                tempo_tx_registry(spec.into()),
                NoPrecompiles::default(),
            );
        }
        let token = DEFAULT_FEE_TOKEN;
        let slot = TIP20Token::from_address(token).unwrap().balances[SIGNER].slot();
        insert_storage(&mut evm, token, slot, U256::from(42));
        let tx = fee_tx_env(SIGNER, token, 100_000, gas_price);
        let context = TempoHandlerHooks::resolve_fee_context(&mut evm, &tx).unwrap();
        assert_eq!(context.collected, U256::ZERO);

        // The first metered balance read must pay only the warm SLOAD cost.
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
        assert_eq!(provider.sload(token, slot).unwrap(), U256::from(42));
        assert_eq!(
            provider.gas_used(),
            100,
            "balance should be warm for {spec:?}, disable_fee={disable_fee}"
        );
    }
}

#[test]
fn test_resolve_fee_context_validates_max_fee_when_collection_is_disabled() {
    let fee_payer = Address::random();
    let gas_limit = 100_000;
    let gas_price = 1_000_000_000_000_u128;
    let max_fee = calc_gas_balance_spending(gas_limit, gas_price);
    let mut evm = storage_evm(TempoHardfork::T7);
    let mut version = *evm.version();
    version.features.remove(EvmFeatures::FEE_CHARGE);
    evm.set_execution_config(
        ExecutionConfig::for_spec_and_version(TempoHardfork::T7, version),
        TempoHardfork::T7,
        tempo_tx_registry(SpecId::OSAKA),
        NoPrecompiles::default(),
    );

    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        TIP20Setup::path_usd(fee_payer)
            .with_issuer(fee_payer)
            .with_mint(fee_payer, max_fee - U256::ONE)
            .apply()
    })
    .expect("pathUSD setup succeeds");

    let tx = fee_tx_env(fee_payer, PATH_USD_ADDRESS, gas_limit, gas_price);
    let result = TempoHandlerHooks::resolve_fee_context(&mut evm, &tx);

    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::CollectFeePreTx(
                        FeePaymentError::InsufficientFeeTokenBalance { fee, balance },
                    )) if *fee == max_fee && *balance == max_fee - U256::ONE
                )
        ),
        "disabled fee collection must still validate max-fee balance, got: {result:?}"
    );
}

#[test]
fn test_resolve_fee_context_validates_fee_token_when_collection_is_disabled() {
    let fee_payer = Address::random();
    let admin = Address::random();
    let gas_limit = 100_000;
    let gas_price = 1_000_000_000_000_u128;
    let max_fee = calc_gas_balance_spending(gas_limit, gas_price);
    let mut evm = storage_evm(TempoHardfork::T7);
    let mut version = *evm.version();
    version.features.remove(EvmFeatures::FEE_CHARGE);
    evm.set_execution_config(
        ExecutionConfig::for_spec_and_version(TempoHardfork::T7, version),
        TempoHardfork::T7,
        tempo_tx_registry(SpecId::OSAKA),
        NoPrecompiles::default(),
    );

    let fee_token = StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        TIP20Setup::create("Euro", "EUR", admin)
            .currency("EUR")
            .with_issuer(admin)
            .with_mint(fee_payer, max_fee)
            .apply()
            .map(|token| token.address())
    })
    .expect("EUR token setup succeeds");

    let tx = fee_tx_env(fee_payer, fee_token, gas_limit, gas_price);
    let result = TempoHandlerHooks::resolve_fee_context(&mut evm, &tx);

    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::FeeTokenNotUsdCurrency { address, currency })
                        if *address == fee_token && currency == "EUR"
                )
        ),
        "disabled fee collection must still validate the fee token, got: {result:?}"
    );
}

#[test]
fn test_collect_fee_pre_tx_requires_max_fee_balance() {
    let fee_payer = Address::random();
    let gas_limit = 100_000;
    let base_fee = 1_000_000_000_u64;
    let max_priority_fee_per_gas = 1_000_000_000_u128;
    let max_fee_per_gas = 1_000_000_000_000_u128;
    let collected =
        calc_gas_balance_spending(gas_limit, u128::from(base_fee) + max_priority_fee_per_gas);
    let max_fee = calc_gas_balance_spending(gas_limit, max_fee_per_gas);
    assert!(collected < max_fee);
    let mut test = storage_evm(TempoHardfork::default());
    let mut block = *test.block();
    block.basefee = U256::from(base_fee);
    test.set_block(block);

    StorageCtx::enter_evm_without_tip1060_accounting(&mut test, || {
        TIP20Setup::path_usd(fee_payer)
            .with_issuer(fee_payer)
            .with_mint(fee_payer, collected)
            .apply()
    })
    .expect("pathUSD setup succeeds");

    let tx = aa_env_for(
        fee_payer,
        TempoTransaction {
            chain_id: 1,
            fee_token: Some(PATH_USD_ADDRESS),
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            calls: Vec::new(),
            ..Default::default()
        },
    );

    let result = collect_fee_pre_tx(&mut test, &tx);

    assert!(
        matches!(
            result,
            Err(ref error)
                if matches!(
                    error.external_ref::<TempoInvalidTransaction>(),
                    Some(TempoInvalidTransaction::CollectFeePreTx(
                        FeePaymentError::InsufficientFeeTokenBalance { fee, balance },
                    )) if *fee == max_fee && *balance == collected
                )
        ),
        "fee payer must afford max_fee_per_gas, got: {result:?}"
    );
}

#[test]
fn test_2d_authorization_refund_for_absent_caller() {
    for spec in [TempoHardfork::Genesis, TempoHardfork::T0, TempoHardfork::T1] {
        for self_authorization in [false, true] {
            let signer = PrivateKeySigner::random();
            let caller = signer.address();
            let other = PrivateKeySigner::random();
            let authority = if self_authorization { &signer } else { &other };
            let authorization = alloy_eips::eip7702::Authorization {
                chain_id: U256::ONE,
                address: Address::repeat_byte(0x33),
                nonce: 0,
            };
            let signature = authority
                .sign_hash_sync(&authorization.signature_hash())
                .unwrap();
            let gas_limit = 1_000_000;
            let gas_price = 1_000_000_000_000;
            let balance = calc_gas_balance_spending(gas_limit, gas_price);
            let mut evm = test_evm(spec);
            StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
                TIP20Setup::path_usd(caller)
                    .with_issuer(caller)
                    .with_mint(caller, balance)
                    .apply()
            })
            .unwrap();
            assert!(
                evm.state_mut()
                    .account_info_untracked(&caller)
                    .unwrap()
                    .is_none()
            );
            assert!(
                evm.state_mut()
                    .account_info_untracked(&authority.address())
                    .unwrap()
                    .is_none()
            );

            let tx = TempoTransaction {
                chain_id: 1,
                nonce_key: U256::ONE,
                gas_limit,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: gas_price,
                fee_token: Some(PATH_USD_ADDRESS),
                tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                    authorization,
                    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
                )],
                calls: vec![call(Bytes::new())],
                ..Default::default()
            };
            let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
            let env: TempoTxEnv = Recovered::new_unchecked(
                TempoTxEnvelope::AA(tx.into_signed(TempoSignature::Primitive(
                    PrimitiveSignature::Secp256k1(signature),
                ))),
                caller,
            )
            .into();
            let result = evm
                .transact(&Recovered::new_unchecked(env, caller))
                .unwrap()
                .commit();
            assert!(
                result.status,
                "{spec:?}, self_authorization={self_authorization}: {result:?}"
            );
            let spent = if spec.is_t1() { 533_500 } else { 68_100 };
            let refund = if !spec.is_t1() && self_authorization {
                12_500
            } else {
                0
            };
            assert_eq!(result.total_gas_spent, spent);
            assert_eq!(
                result.refunded, refund,
                "{spec:?}, self_authorization={self_authorization}"
            );
            assert_eq!(result.tx_gas_used(), spent - refund);
            StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
                assert_eq!(
                    TIP20Token::from_address(PATH_USD_ADDRESS).unwrap().balances[caller]
                        .read()
                        .unwrap(),
                    balance - calc_gas_balance_spending(spent - refund, gas_price),
                );
                assert_eq!(
                    NonceManager::new().nonces[caller][U256::ONE]
                        .read()
                        .unwrap(),
                    1
                );
            });
            if !self_authorization {
                assert!(
                    evm.state_mut()
                        .account_info_untracked(&caller)
                        .unwrap()
                        .is_none(),
                    "touching an absent caller must not persist an empty account"
                );
            }
        }
    }
}

#[test_case::test_case(TempoHardfork::T1)]
#[test_case::test_case(TempoHardfork::T1B)]
#[test_case::test_case(TempoHardfork::T4)]
fn test_aa_create_protocol_nonce_overflow(spec: TempoHardfork) {
    use evm2::bytecode::Bytecode;

    for nonce_key in [U256::ONE, TEMPO_EXPIRING_NONCE_KEY] {
        for protocol_nonce in [u64::MAX, u64::MAX - 1] {
            for with_followup_call in [false, true] {
                let mut evm = test_evm(spec);
                evm.overlay_db_mut().insert_account_info(
                    &SIGNER,
                    AccountInfo::default().with_nonce(protocol_nonce),
                );
                let target = Address::repeat_byte(0x22);
                evm.overlay_db_mut().insert_account_info(
                    &target,
                    AccountInfo::default().with_code(Bytecode::new_legacy(
                        alloy_primitives::bytes!("602a60005260206000f3"),
                    )),
                );
                let mut calls = vec![Call {
                    to: TxKind::Create,
                    value: U256::ZERO,
                    // Deploy a single STOP byte.
                    input: alloy_primitives::bytes!("600060005360016000f3"),
                }];
                if with_followup_call {
                    calls.push(Call {
                        to: TxKind::Call(target),
                        value: U256::ZERO,
                        input: Bytes::new(),
                    });
                }
                let tx = TempoTransaction {
                    chain_id: 1,
                    nonce_key,
                    valid_before: Some(30.try_into().unwrap()),
                    gas_limit: 1_000_000,
                    fee_token: Some(PATH_USD_ADDRESS),
                    calls,
                    ..Default::default()
                };
                let (intrinsic, _, _) = intrinsic(spec, tx.clone(), secp256k1_signature()).unwrap();
                let env = aa_env_for(SIGNER, tx);
                let replay_hash = if spec.is_t1b() {
                    env.unique_tx_identifier()
                } else {
                    env.tx_hash()
                };
                let result = evm
                    .transact(&Recovered::new_unchecked(env, SIGNER))
                    .unwrap()
                    .commit();
                assert!(result.status, "{result:?}");
                let overflow = protocol_nonce == u64::MAX;
                if overflow {
                    assert_eq!(result.created_address, None);
                    assert_eq!(
                        result.total_gas_spent,
                        intrinsic + if with_followup_call { 18 } else { 0 }
                    );
                }
                if with_followup_call {
                    assert_eq!(result.output.as_ref(), U256::from(42).to_be_bytes::<32>());
                } else if overflow {
                    assert!(result.output.is_empty());
                }
                assert_eq!(evm.state_mut().account(&SIGNER).unwrap().nonce(), u64::MAX);
                let created = evm
                    .state_mut()
                    .account_info_untracked(&SIGNER.create(protocol_nonce))
                    .unwrap();
                if overflow {
                    assert!(
                        created.is_none(),
                        "overflow must not create an account: {created:?}"
                    );
                } else {
                    assert_eq!(created.unwrap().code_hash, alloy_primitives::keccak256([0]));
                }
                StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
                    let nonces = NonceManager::new();
                    if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
                        assert!(nonces.is_expiring_nonce_seen(replay_hash, 0).unwrap());
                    } else {
                        assert_eq!(nonces.nonces[SIGNER][nonce_key].read().unwrap(), 1);
                    }
                });
            }
        }
    }
}

/// Genesis revalidates nonce gas when a 2D CREATE also creates the caller account.
#[test]
fn test_genesis_2d_create_gas_revalidation() {
    for (caller_nonce, gas_limit, should_succeed, expected_gas) in [
        (0, 90_000, false, 100_100),
        (0, 100_099, false, 100_100),
        (0, 100_100, true, 100_100),
        (1, 90_000, true, 75_100),
    ] {
        let mut evm = test_evm(TempoHardfork::Genesis);
        evm.overlay_db_mut()
            .insert_account_info(&SIGNER, AccountInfo::default().with_nonce(caller_nonce));
        let env = aa_env_for(
            SIGNER,
            TempoTransaction {
                chain_id: 1,
                nonce_key: U256::ONE,
                gas_limit,
                fee_token: Some(PATH_USD_ADDRESS),
                calls: vec![Call {
                    to: TxKind::Create,
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                ..Default::default()
            },
        );
        // 21k base + 32k CREATE + 22,100 nonce gas, plus 25k when caller nonce is zero.
        let result = evm.transact(&Recovered::new_unchecked(env, SIGNER));
        if should_succeed {
            let result = result.expect("sufficient CREATE gas").commit();
            assert!(result.status, "CREATE failed: {result:?}");
            assert_eq!(result.tx_gas_used(), expected_gas);
        } else {
            assert!(
                matches!(
                    result,
                    Err(HandlerError::IntrinsicGasTooLow { got, required })
                        if got == gas_limit && required == expected_gas
                ),
                "caller_nonce={caller_nonce}, gas_limit={gas_limit}: expected full intrinsic gas rejection, got {result:?}"
            );
        }
    }
}

/// Pre-T0 nonce charges could exceed the gas limit after validation. Historical execution
/// succeeds with the unbounded budget, while receipt gas and fees are reduced to the gas floor.
#[test]
fn test_genesis_intrinsic_overflow_settlement() {
    let gas_limit = 30_000;
    let gas_price = 1_000_000_000_000;
    let floor_gas = 21_000;
    let balance = calc_gas_balance_spending(gas_limit, gas_price);
    let mut evm = test_evm(TempoHardfork::Genesis);
    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        TIP20Setup::path_usd(SIGNER)
            .with_issuer(SIGNER)
            .with_mint(SIGNER, balance)
            .apply()
    })
    .expect("pathUSD setup succeeds");

    let env = aa_env_for(
        SIGNER,
        TempoTransaction {
            chain_id: 1,
            nonce_key: U256::ONE,
            gas_limit,
            max_priority_fee_per_gas: gas_price,
            max_fee_per_gas: gas_price,
            fee_token: Some(PATH_USD_ADDRESS),
            calls: vec![call(Bytes::new())],
            ..Default::default()
        },
    );
    let result = evm
        .transact(&Recovered::new_unchecked(env, SIGNER))
        .expect("Genesis accepts nonce gas exceeding the validated limit")
        .commit();

    assert!(result.status, "historical execution succeeds: {result:?}");
    assert_eq!(result.total_gas_spent, 0);
    assert_eq!(result.refunded, 0);
    assert_eq!(result.tx_gas_used(), floor_gas);
    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        assert_eq!(
            NonceManager::new().nonces[SIGNER][U256::ONE]
                .read()
                .expect("nonce read succeeds"),
            1,
        );
        assert_eq!(
            TIP20Token::from_address(PATH_USD_ADDRESS)
                .expect("pathUSD address")
                .balances[SIGNER]
                .read()
                .expect("payer balance read succeeds"),
            balance - calc_gas_balance_spending(floor_gas, gas_price),
            "only the gas floor is charged; the rest of the upfront fee is returned",
        );
    });
}

#[test]
fn registers_transaction_types_by_fork() {
    let frontier = tempo_tx_registry(SpecId::FRONTIER);
    assert!(frontier.contains(0));
    assert!(!frontier.contains(1));
    assert!(!frontier.contains(2));
    assert!(!frontier.contains(4));
    assert!(frontier.contains(0x76));

    let prague = tempo_tx_registry(SpecId::PRAGUE);
    assert!(prague.contains(0));
    assert!(prague.contains(1));
    assert!(prague.contains(2));
    assert!(prague.contains(4));
    assert!(prague.contains(0x76));
}

#[test]
fn builds_evm_with_matching_tempo_spec_and_fee_rules() {
    let evm = build_tempo_evm(
        TempoHardfork::T7,
        4242,
        TempoBlockEnv::default(),
        InMemoryDB::default(),
        NoPrecompiles::default(),
        TempoEvmExt::default(),
    );

    assert_eq!(evm.version().chain_id, 4242);
    assert_eq!(evm.config_spec_id(), TempoHardfork::T7);
    assert!(!evm.version().features.contains(EvmFeatures::BALANCE_CHECK));
    assert!(!evm.version().features.contains(EvmFeatures::BALANCE_TOP_UP));
    assert!(evm.version().features.contains(EvmFeatures::FEE_CHARGE));
    assert_eq!(evm.version().gas_params[GasId::MaxRefundQuotient], 1);
}

struct FailingStorageDb {
    address: Address,
    successful_reads: usize,
    error: DatabaseError,
}

impl DynDatabase for FailingStorageDb {
    fn get_account(&mut self, _address: &Address) -> Result<Option<AccountInfo>, DatabaseError> {
        Ok(Some(AccountInfo::default().with_nonce(1)))
    }

    fn get_code_by_hash(&mut self, _hash: &B256) -> Result<Bytecode, DatabaseError> {
        Ok(Bytecode::default())
    }

    fn get_storage(&mut self, address: &Address, _key: &U256) -> Result<U256, DatabaseError> {
        if *address == self.address {
            if self.successful_reads == 0 {
                return Err(self.error.clone());
            }
            self.successful_reads -= 1;
        }
        Ok(U256::ZERO)
    }

    fn get_block_hash(&mut self, _number: &U256) -> Result<B256, DatabaseError> {
        Ok(B256::ZERO)
    }
}

fn injected_database_error(fatal: bool) -> DatabaseError {
    DatabaseError::new(std::io::Error::other("injected database failure"), fatal)
}

#[test]
fn nonce_database_failures_reach_handler_and_validation() {
    for fatal in [false, true] {
        for (nonce_key, index) in [
            (U256::ONE, None),
            (TEMPO_EXPIRING_NONCE_KEY, None),
            (TEMPO_EXPIRING_NONCE_KEY, Some(1)),
        ] {
            let mut tx = aa_env(
                TempoTransaction {
                    chain_id: 1,
                    nonce_key,
                    valid_before: Some(20.try_into().unwrap()),
                    gas_limit: 1_000_000,
                    fee_token: Some(PATH_USD_ADDRESS),
                    calls: vec![Call {
                        to: TxKind::Call(Address::ZERO),
                        value: U256::ZERO,
                        input: Bytes::new(),
                    }],
                    ..Default::default()
                },
                secp256k1_signature(),
            );
            tx.set_expiring_nonce_idx(index);
            let expected = injected_database_error(fatal);
            // Fail each successive backing storage read, including loads needed by writes.
            // Stop once every read has been covered and the nonce operation succeeds.
            for nonce_check in [false, true] {
                let mut reached_success = false;
                for successful_reads in 0..16 {
                    let mut evm = build_tempo_evm(
                        TempoHardfork::T7,
                        1,
                        TempoBlockEnv::default(),
                        FailingStorageDb {
                            address: NONCE_PRECOMPILE_ADDRESS,
                            successful_reads,
                            error: expected.clone(),
                        },
                        NoPrecompiles::default(),
                        TempoEvmExt::default(),
                    );
                    let mut version = *evm.version();
                    version.features.set(EvmFeatures::NONCE_CHECK, nonce_check);
                    evm.set_execution_config(
                        ExecutionConfig::for_spec_and_version(TempoHardfork::T7, version),
                        TempoHardfork::T7,
                        tempo_tx_registry(SpecId::from(TempoHardfork::T7)),
                        NoPrecompiles::default(),
                    );
                    match apply_nonce(&mut evm, &tx, tx.as_aa().unwrap()) {
                        Err(HandlerError::Database(error)) => {
                            assert_eq!(error, expected);
                            assert_eq!(error.is_fatal(), fatal);
                        }
                        Ok(_) => {
                            assert!(successful_reads > 0);
                            reached_success = true;
                            break;
                        }
                        result => panic!("expected database failure, got {result:?}"),
                    }
                }
                assert!(reached_success, "nonce read sweep did not reach completion");
            }

            let mut evm = build_tempo_evm(
                TempoHardfork::T7,
                1,
                TempoBlockEnv::default(),
                FailingStorageDb {
                    address: NONCE_PRECOMPILE_ADDRESS,
                    successful_reads: 0,
                    error: expected.clone(),
                },
                NoPrecompiles::default(),
                TempoEvmExt::default(),
            );
            evm.ext_mut().skip_valid_after_check = true;
            evm.ext_mut().skip_liquidity_check = true;
            let error = evm
                .validate_tx(&Recovered::new_unchecked(tx, SIGNER))
                .unwrap_err();
            let HandlerError::Database(error) = error else {
                panic!("expected database failure, got {error:?}");
            };
            assert_eq!(error, expected);
            assert_eq!(error.is_fatal(), fatal);
        }
    }
}

#[test]
fn fee_diagnostic_failure_preserves_insufficient_liquidity() {
    for error in [
        TempoPrecompileError::Database(injected_database_error(false)),
        TempoPrecompileError::Database(injected_database_error(true)),
        TempoPrecompileError::Fatal("injected validator token lookup failure".to_string()),
    ] {
        let mut evm = storage_evm(TempoHardfork::T5);
        evm.ext_mut().fee_manager = Arc::new(ValidatorTokenLookupFailsFeeManager(error));
        let result = TempoHandlerHooks::collect_fee(
            &mut evm,
            TempoFeeContext {
                fee_payer: SIGNER,
                fee_token: PATH_USD_ADDRESS,
                collected: U256::ONE,
            },
            None,
        );
        let error = result.unwrap_err();
        let Some(TempoInvalidTransaction::CollectFeePreTx(actual)) =
            error.external_ref::<TempoInvalidTransaction>()
        else {
            panic!("expected fee validation error, got {error:?}");
        };
        assert_eq!(
            *actual,
            FeePaymentError::InsufficientAmmLiquidity {
                user_token: None,
                validator_token: None,
                fee: U256::ONE,
            },
        );
    }
}
