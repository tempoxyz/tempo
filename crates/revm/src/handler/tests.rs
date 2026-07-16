use super::*;
use crate::{
    ProtocolFeeManager, TempoBlockEnv, TempoTxEnv, evm::TempoEvm, gas_params::tempo_gas_params,
    tx::TempoBatchCallEnv,
};
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use proptest::prelude::*;
use revm::{
    Context, Journal, MainContext,
    context::CfgEnv,
    database::{CacheDB, EmptyDB},
    handler::Handler,
    interpreter::{
        InstructionResult, InterpreterResult, gas::COLD_ACCOUNT_ACCESS_COST,
        instructions::utility::IntoU256,
    },
    primitives::hardfork::SpecId,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{DEFAULT_FEE_TOKEN, ITIPFeeAMM};
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, storage::ContractStorage, test_util::TIP20Setup,
    tip_fee_manager::TipFeeManager,
};
use tempo_primitives::transaction::{
    Call, RecoveredTempoAuthorization, TempoSignature, TempoSignedAuthorization,
    tt_signature::{P256SignatureWithPreHash, WebAuthnSignature},
};

fn create_test_journal() -> Journal<CacheDB<EmptyDB>> {
    let db = CacheDB::new(EmptyDB::default());
    Journal::new(db)
}

type TestHandlerEvmResult<T> =
    Result<T, EVMError<<CacheDB<EmptyDB> as revm::Database>::Error, TempoInvalidTransaction>>;

struct TestHandlerEvm {
    evm: TempoEvm<CacheDB<EmptyDB>, ()>,
    handler: TempoEvmHandler<CacheDB<EmptyDB>, ()>,
}

impl TestHandlerEvm {
    fn tx(spec: TempoHardfork, configure_tx_env: impl FnOnce(&mut TempoTxEnv)) -> Self {
        let mut tx_env = TempoTxEnv::default();
        configure_tx_env(&mut tx_env);
        Self::new(spec, tx_env)
    }

    fn aa(
        spec: TempoHardfork,
        aa_env: TempoBatchCallEnv,
        configure_tx_env: impl FnOnce(&mut TempoTxEnv),
    ) -> Self {
        let mut tx_env = TempoTxEnv {
            tempo_tx_env: Some(Box::new(aa_env)),
            ..Default::default()
        };
        configure_tx_env(&mut tx_env);
        Self::new(spec, tx_env)
    }

    fn new(spec: TempoHardfork, tx_env: TempoTxEnv) -> Self {
        Self::with_cfg(spec, tx_env, |_| {})
    }

    fn with_cfg(
        spec: TempoHardfork,
        tx_env: TempoTxEnv,
        configure: impl FnOnce(&mut CfgEnv<TempoHardfork>),
    ) -> Self {
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = spec;
        cfg.gas_params = tempo_gas_params(spec);
        configure(&mut cfg);

        let ctx = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(TempoBlockEnv::default())
            .with_cfg(cfg)
            .with_tx(tx_env)
            .with_new_journal(create_test_journal());

        Self {
            evm: TempoEvm::new(ctx, ()),
            handler: TempoEvmHandler::new(),
        }
    }

    fn cfg(&mut self) -> &CfgEnv<TempoHardfork> {
        &self.evm.ctx().cfg
    }

    fn gas_params(&mut self) -> &GasParams {
        &self.cfg().gas_params
    }

    fn validate_env(&mut self) -> TestHandlerEvmResult<()> {
        self.handler.validate_env(&mut self.evm)
    }

    fn validate_initial_tx_gas(&mut self) -> InitialAndFloorGas {
        self.handler
            .validate_initial_tx_gas(&mut self.evm)
            .expect("initial gas validation should succeed")
    }

    fn validate_against_state_and_deduct_caller(&mut self) -> TestHandlerEvmResult<()> {
        self.handler
            .validate_against_state_and_deduct_caller(&mut self.evm, &mut Default::default())
    }

    fn with_fee_manager<F>(self, fee_manager: F) -> Self
    where
        F: ProtocolFeeManager<CacheDB<EmptyDB>> + 'static,
    {
        let Self { evm, handler } = self;
        Self {
            evm: evm.with_fee_manager(fee_manager),
            handler,
        }
    }

    fn execute(&mut self, init_gas: &InitialAndFloorGas) -> FrameResult {
        self.handler
            .execution(&mut self.evm, init_gas)
            .expect("execution should return a frame result")
    }
}

#[derive(Debug)]
struct ValidatorTokenLookupFailsFeeManager;

impl<DB: Database> ProtocolFeeManager<DB> for ValidatorTokenLookupFailsFeeManager {
    fn get_fee_token(
        &self,
        _journal: &mut Journal<DB>,
        tx: &TempoTxEnv,
        _fee_payer: Address,
        _spec: TempoHardfork,
        _actions: StorageActions,
    ) -> tempo_precompiles::error::Result<Address> {
        Ok(tx.fee_token.unwrap_or(DEFAULT_FEE_TOKEN))
    }

    fn get_validator_token(
        &self,
        _journal: &mut Journal<DB>,
        _beneficiary: Address,
        _spec: TempoHardfork,
        _actions: StorageActions,
    ) -> tempo_precompiles::error::Result<Address> {
        Err(TempoPrecompileError::Fatal(
            "injected validator token lookup failure".to_string(),
        ))
    }

    fn collect_fee_pre_tx(
        &self,
        _ctx: ProtocolFeeContext<'_, DB>,
        _fee_payer: Address,
        _user_token: Address,
        _max_amount: U256,
        _beneficiary: Address,
        _skip_liquidity_check: bool,
    ) -> tempo_precompiles::error::Result<Address> {
        Err(TempoPrecompileError::TIPFeeAMMError(
            TIPFeeAMMError::InsufficientLiquidity(ITIPFeeAMM::InsufficientLiquidity {}),
        ))
    }

    fn collect_fee_post_tx(
        &self,
        _ctx: ProtocolFeeContext<'_, DB>,
        _fee_payer: Address,
        _actual_spending: U256,
        _refund_amount: U256,
        _fee_token: Address,
        _beneficiary: Address,
    ) -> tempo_precompiles::error::Result<U256> {
        Ok(U256::ZERO)
    }
}

#[test]
fn test_invalid_fee_token_rejected() {
    // Test that an invalid fee token (non-TIP20 address) is rejected with a typed error
    // rather than panicking. This validates the check in validate_against_state_and_deduct_caller that
    // guards against invalid tokens reaching get_token_balance.
    let invalid_token = Address::random(); // Random address won't have TIP20 prefix
    assert!(
        !invalid_token.is_tip20(),
        "Test requires a non-TIP20 address"
    );

    let mut test = TestHandlerEvm::tx(TempoHardfork::default(), |tx_env| {
        tx_env.fee_token = Some(invalid_token);
    });

    let result = test.validate_against_state_and_deduct_caller();

    assert!(
        matches!(
            result,
            Err(EVMError::Transaction(TempoInvalidTransaction::FeeTokenNotTip20 { address })) if address == invalid_token
        ),
        "Should reject non-TIP20 fee token with FeeTokenNotTip20 error"
    );
}

#[test]
fn test_non_usd_fee_token_rejected() {
    let admin = Address::random();
    let mut test = TestHandlerEvm::tx(TempoHardfork::default(), |tx_env| {
        tx_env.inner.gas_limit = 100_000;
        tx_env.inner.gas_price = 1_000_000_000;
        tx_env.inner.gas_priority_fee = Some(1_000_000_000);
    });

    let fee_token =
        StorageCtx::enter_ctx(&mut test.evm.inner.ctx, StorageActions::disabled(), || {
            TIP20Setup::create("Euro", "EUR", admin)
                .currency("EUR")
                .apply()
                .map(|token| token.address())
        })
        .expect("EUR token setup succeeds");

    test.evm.inner.ctx.tx.fee_token = Some(fee_token);

    let result = test.validate_against_state_and_deduct_caller();

    assert!(
        matches!(
            result,
            Err(EVMError::Transaction(TempoInvalidTransaction::FeeTokenNotUsdCurrency {
                address,
                currency,
            })) if address == fee_token && currency == "EUR"
        ),
        "Should reject non-USD fee token with FeeTokenNotUsdCurrency error"
    );
}

#[test]
fn test_paused_fee_token_rejected() {
    let admin = Address::random();
    let fee_payer = Address::random();
    let fee = U256::from(100_000_000_000_000_u64);
    let mut test = TestHandlerEvm::tx(TempoHardfork::default(), |tx_env| {
        tx_env.inner.caller = fee_payer;
        tx_env.inner.gas_limit = 100_000;
        tx_env.inner.gas_price = 1_000_000_000;
        tx_env.inner.gas_priority_fee = Some(1_000_000_000);
    });

    let fee_token =
        StorageCtx::enter_ctx(&mut test.evm.inner.ctx, StorageActions::disabled(), || {
            let mut token = TIP20Setup::create("Paused USD", "PUSD", admin)
                .with_issuer(admin)
                .with_role(admin, *tempo_precompiles::tip20::PAUSE_ROLE)
                .with_mint(fee_payer, fee)
                .apply()?;
            token.pause(admin, tempo_precompiles::tip20::ITIP20::pauseCall {})?;
            Ok::<_, TempoPrecompileError>(token.address())
        })
        .expect("paused USD token setup succeeds");

    test.evm.inner.ctx.tx.fee_token = Some(fee_token);

    let result = test.validate_against_state_and_deduct_caller();

    assert!(
        matches!(
            result,
            Err(EVMError::Transaction(TempoInvalidTransaction::FeeTokenPaused { address })) if address == fee_token
        ),
        "Should reject paused fee token with FeeTokenPaused error"
    );
}

#[test]
fn test_collect_fee_pre_tx_insufficient_liquidity_reports_pair_from_handler() -> eyre::Result<()> {
    use tempo_contracts::precompiles::IFeeManager;

    let admin = Address::random();
    let fee_payer = Address::random();
    let validator = Address::random();
    let gas_limit = 1_000;
    let gas_price = 1_000_000_000_000_u128;
    let fee = calc_gas_balance_spending(gas_limit, gas_price);

    let mut test = TestHandlerEvm::tx(TempoHardfork::T5, |tx_env| {
        tx_env.inner.caller = fee_payer;
        tx_env.inner.gas_limit = gas_limit;
        tx_env.inner.gas_price = gas_price;
        tx_env.inner.gas_priority_fee = Some(gas_price);
    });
    test.evm.inner.ctx.block.beneficiary = validator;

    let (user_token, validator_token) =
        StorageCtx::enter_ctx(&mut test.evm.inner.ctx, StorageActions::disabled(), || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(fee_payer, fee)
                .with_approval(fee_payer, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .apply()?;

            TipFeeManager::new().set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            Ok::<_, TempoPrecompileError>((user_token.address(), validator_token.address()))
        })?;

    test.evm.inner.ctx.tx.fee_token = Some(user_token);

    let result = test.validate_against_state_and_deduct_caller();

    assert!(
        matches!(
            result,
            Err(EVMError::Transaction(TempoInvalidTransaction::CollectFeePreTx(ref err)))
                if *err == FeePaymentError::InsufficientAmmLiquidity {
                    user_token: Some(user_token),
                    validator_token: Some(validator_token),
                    fee,
                }
        ),
        "expected pair-aware insufficient liquidity error, got: {result:?}"
    );

    Ok(())
}

#[test]
fn test_collect_fee_pre_tx_insufficient_liquidity_falls_back_when_pair_lookup_fails()
-> eyre::Result<()> {
    let admin = Address::random();
    let fee_payer = Address::random();
    let gas_limit = 1_000;
    let gas_price = 1_000_000_000_000_u128;
    let fee = calc_gas_balance_spending(gas_limit, gas_price);

    let mut test = TestHandlerEvm::tx(TempoHardfork::T5, |tx_env| {
        tx_env.inner.caller = fee_payer;
        tx_env.inner.gas_limit = gas_limit;
        tx_env.inner.gas_price = gas_price;
        tx_env.inner.gas_priority_fee = Some(gas_price);
    })
    .with_fee_manager(ValidatorTokenLookupFailsFeeManager);

    let user_token =
        StorageCtx::enter_ctx(&mut test.evm.inner.ctx, StorageActions::disabled(), || {
            TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(fee_payer, fee)
                .apply()
                .map(|token| token.address())
        })?;

    test.evm.inner.ctx.tx.fee_token = Some(user_token);

    let result = test.validate_against_state_and_deduct_caller();

    assert!(
        matches!(
            result,
            Err(EVMError::Transaction(TempoInvalidTransaction::CollectFeePreTx(ref err)))
                if *err == FeePaymentError::InsufficientAmmLiquidity {
                    user_token: None,
                    validator_token: None,
                    fee,
                }
        ),
        "expected generic insufficient liquidity error when pair lookup fails, got: {result:?}"
    );

    Ok(())
}

#[test]
fn test_self_sponsored_fee_payer_rejected_post_t2() {
    let caller = Address::random();
    let invalid_token = Address::random();

    let mut test = TestHandlerEvm::tx(TempoHardfork::T2, |tx_env| {
        tx_env.inner.caller = caller;
        tx_env.fee_token = Some(invalid_token);
        tx_env.fee_payer = Some(Some(caller));
    });

    let result = test.validate_env();
    assert!(matches!(
        result,
        Err(EVMError::Transaction(
            TempoInvalidTransaction::SelfSponsoredFeePayer
        ))
    ));
}

#[test]
fn test_self_sponsored_fee_payer_not_rejected_pre_t4() {
    let caller = Address::random();
    let invalid_token = Address::random();

    let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::default();
    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.spec = TempoHardfork::T1C;

    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            caller,
            ..Default::default()
        },
        fee_token: Some(invalid_token),
        fee_payer: Some(Some(caller)),
        ..Default::default()
    };

    let mut evm: TempoEvm<CacheDB<EmptyDB>, ()> = TempoEvm::new(
        Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(TempoBlockEnv::default())
            .with_cfg(cfg)
            .with_tx(tx_env),
        (),
    );

    let result = handler.validate_env(&mut evm);
    assert!(result.is_ok());
}

#[test]
fn test_get_token_balance() -> eyre::Result<()> {
    let mut journal = create_test_journal();
    // Use PATH_USD_ADDRESS which has the TIP20 prefix
    let token = PATH_USD_ADDRESS;
    let account = Address::random();
    let expected_balance = U256::random();

    // Set up initial balance
    let balance_slot = TIP20Token::from_address(token)?.balances[account].slot();
    journal.load_account(token)?;
    journal
        .sstore(token, balance_slot, expected_balance)
        .unwrap();

    let balance = get_token_balance(&mut journal, token, account)?;
    assert_eq!(balance, expected_balance);

    Ok(())
}

#[test]
fn test_get_fee_token() -> eyre::Result<()> {
    let journal = create_test_journal();
    let mut ctx: TempoContext<_> = Context::mainnet()
        .with_db(CacheDB::new(EmptyDB::default()))
        .with_block(TempoBlockEnv::default())
        .with_cfg(Default::default())
        .with_tx(TempoTxEnv::default())
        .with_new_journal(journal);
    let user = Address::random();
    ctx.tx.inner.caller = user;
    let validator = Address::random();
    ctx.block.beneficiary = validator;
    let user_fee_token = Address::random();
    let validator_fee_token = Address::random();
    let tx_fee_token = Address::random();

    // Set validator token
    let validator_slot = TipFeeManager::new().validator_tokens[validator].slot();
    ctx.journaled_state.load_account(TIP_FEE_MANAGER_ADDRESS)?;
    ctx.journaled_state
        .sstore(
            TIP_FEE_MANAGER_ADDRESS,
            validator_slot,
            validator_fee_token.into_u256(),
        )
        .unwrap();

    {
        let fee_token = ctx.journaled_state.get_fee_token(
            &ctx.tx,
            user,
            ctx.cfg.spec,
            tempo_precompiles::storage::StorageActions::disabled(),
        )?;
        assert_eq!(DEFAULT_FEE_TOKEN, fee_token);
    }

    // Set user token
    let user_slot = TipFeeManager::new().user_tokens[user].slot();
    ctx.journaled_state
        .sstore(
            TIP_FEE_MANAGER_ADDRESS,
            user_slot,
            user_fee_token.into_u256(),
        )
        .unwrap();

    {
        let fee_token = ctx.journaled_state.get_fee_token(
            &ctx.tx,
            user,
            ctx.cfg.spec,
            tempo_precompiles::storage::StorageActions::disabled(),
        )?;
        assert_eq!(user_fee_token, fee_token);
    }

    // Set tx fee token
    ctx.tx.fee_token = Some(tx_fee_token);
    let fee_token = ctx.journaled_state.get_fee_token(
        &ctx.tx,
        user,
        ctx.cfg.spec,
        tempo_precompiles::storage::StorageActions::disabled(),
    )?;
    assert_eq!(tx_fee_token, fee_token);

    Ok(())
}

#[test]
fn test_aa_gas_single_call_vs_normal_tx() {
    use crate::TempoBatchCallEnv;
    use alloy_primitives::{Bytes, TxKind};
    use revm::interpreter::gas::calculate_initial_tx_gas;
    use tempo_primitives::transaction::{Call, TempoSignature};
    let gas_params = GasParams::default();

    // Test that AA tx with secp256k1 and single call matches normal tx + per-call overhead
    let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes
    let to = Address::random();

    // Single call for AA
    let call = Call {
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )), // dummy secp256k1 sig
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    // Calculate AA gas
    let spec = tempo_chainspec::hardfork::TempoHardfork::default();
    let aa_gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>, // no access list
        spec,
    )
    .unwrap();

    // Calculate expected gas using revm's function for equivalent normal tx
    let normal_tx_gas = calculate_initial_tx_gas(
        spec.into(),
        &calldata,
        false, // not create
        0,     // no access list accounts
        0,     // no access list storage
        0,     // no authorization list
    );

    // AA with secp256k1 + single call should match normal tx exactly
    assert_eq!(
        aa_gas.initial_total_gas(),
        normal_tx_gas.initial_total_gas()
    );
}

#[test]
fn test_aa_gas_multiple_calls_overhead() {
    use crate::TempoBatchCallEnv;
    use alloy_primitives::{Bytes, TxKind};
    use revm::interpreter::gas::calculate_initial_tx_gas;
    use tempo_primitives::transaction::{Call, TempoSignature};

    let calldata = Bytes::from(vec![1, 2, 3]); // 3 non-zero bytes

    let calls = vec![
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        },
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        },
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata.clone(),
        },
    ];

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: calls,
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let spec = tempo_chainspec::hardfork::TempoHardfork::default();
    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        spec,
    )
    .unwrap();

    // Calculate base gas for a single normal tx
    let base_tx_gas = calculate_initial_tx_gas(spec.into(), &calldata, false, 0, 0, 0);

    // For 3 calls: base (21k) + 3*calldata + 2*per-call overhead (calls 2 and 3)
    // = 21k + 2*(calldata cost) + 2*COLD_ACCOUNT_ACCESS_COST
    let expected = base_tx_gas.initial_total_gas()
        + 2 * (calldata.len() as u64 * 16)
        + 2 * COLD_ACCOUNT_ACCESS_COST;
    // Should charge per-call overhead for calls beyond the first
    assert_eq!(gas.initial_total_gas(), expected,);
}

#[test]
fn test_aa_gas_p256_signature() {
    use crate::TempoBatchCallEnv;
    use alloy_primitives::{B256, Bytes, TxKind};
    use revm::interpreter::gas::calculate_initial_tx_gas;
    use tempo_primitives::transaction::{
        Call, TempoSignature, tt_signature::P256SignatureWithPreHash,
    };

    let spec = SpecId::CANCUN;
    let calldata = Bytes::from(vec![1, 2]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: B256::ZERO,
            pub_key_y: B256::ZERO,
            pre_hash: false,
        })),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate base gas for normal tx
    let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

    // Expected: normal tx + P256_VERIFY_GAS
    let expected = base_gas.initial_total_gas() + P256_VERIFY_GAS;
    assert_eq!(gas.initial_total_gas(), expected,);
}

#[test]
fn test_aa_gas_create_call() {
    use crate::TempoBatchCallEnv;
    use alloy_primitives::{Bytes, TxKind};
    use revm::interpreter::gas::calculate_initial_tx_gas;
    use tempo_primitives::transaction::{Call, TempoSignature};

    let spec = SpecId::CANCUN; // Post-Shanghai
    let initcode = Bytes::from(vec![0x60, 0x80]); // 2 bytes

    let call = Call {
        to: TxKind::Create,
        value: U256::ZERO,
        input: initcode.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate expected using revm's function for CREATE tx
    let base_gas = calculate_initial_tx_gas(
        spec, &initcode, true, // is_create = true
        0, 0, 0,
    );

    // AA CREATE should match normal CREATE exactly
    assert_eq!(gas.initial_total_gas(), base_gas.initial_total_gas(),);
}

#[test]
fn test_aa_gas_value_transfer() {
    use crate::TempoBatchCallEnv;
    use alloy_primitives::{Bytes, TxKind};
    use tempo_primitives::transaction::{Call, TempoSignature};

    let calldata = Bytes::from(vec![1]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::from(1000), // Non-zero value
        input: calldata,
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let res = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );

    assert_eq!(
        res.unwrap_err(),
        TempoInvalidTransaction::ValueTransferNotAllowedInAATx
    );
}

#[test]
fn test_aa_gas_access_list() {
    use crate::TempoBatchCallEnv;
    use alloy_primitives::{Bytes, TxKind};
    use revm::interpreter::gas::calculate_initial_tx_gas;
    use tempo_primitives::transaction::{Call, TempoSignature};

    let spec = SpecId::CANCUN;
    let calldata = Bytes::from(vec![]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    // Test without access list
    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate expected using revm's function
    let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

    // Expected: normal tx
    assert_eq!(gas.initial_total_gas(), base_gas.initial_total_gas(),);
}

#[test]
fn test_key_authorization_rlp_encoding() {
    use alloy_primitives::{Address, U256};
    use tempo_primitives::transaction::{
        SignatureType, TokenLimit, key_authorization::KeyAuthorization,
    };

    // Create test data
    let chain_id = 1u64;
    let key_type = SignatureType::Secp256k1;
    let key_id = Address::random();
    let expiry = 1000u64;
    let limits = vec![
        TokenLimit {
            token: Address::random(),
            limit: U256::from(100),
            period: 0,
        },
        TokenLimit {
            token: Address::random(),
            limit: U256::from(200),
            period: 0,
        },
    ];

    // Compute hash using the helper function
    let hash1 = KeyAuthorization::unrestricted(chain_id, key_type, key_id)
        .with_expiry(expiry)
        .with_limits(limits.clone())
        .signature_hash();

    // Compute again to verify consistency
    let hash2 = KeyAuthorization::unrestricted(chain_id, key_type, key_id)
        .with_expiry(expiry)
        .with_limits(limits.clone())
        .signature_hash();

    assert_eq!(hash1, hash2, "Hash computation should be deterministic");

    // Verify that different chain_id produces different hash
    let hash3 = KeyAuthorization::unrestricted(2, key_type, key_id)
        .with_expiry(expiry)
        .with_limits(limits)
        .signature_hash();
    assert_ne!(
        hash1, hash3,
        "Different chain_id should produce different hash"
    );
}

#[test]
fn test_aa_gas_floor_gas_prague() {
    use crate::TempoBatchCallEnv;
    use alloy_primitives::{Bytes, TxKind};
    use revm::interpreter::gas::calculate_initial_tx_gas;
    use tempo_primitives::transaction::{Call, TempoSignature};

    let spec = SpecId::PRAGUE;
    let calldata = Bytes::from(vec![1, 2, 3, 4, 5]); // 5 non-zero bytes

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate expected floor gas using revm's function
    let base_gas = calculate_initial_tx_gas(spec, &calldata, false, 0, 0, 0);

    // Floor gas should match revm's calculation for same calldata
    assert_eq!(
        gas.floor_gas, base_gas.floor_gas,
        "Should calculate floor gas for Prague matching revm"
    );
}

/// This test will start failing once we get the balance transfer enabled
/// PR that introduced [`TempoInvalidTransaction::ValueTransferNotAllowed`] https://github.com/tempoxyz/tempo/pull/759
#[test]
fn test_zero_value_transfer() -> eyre::Result<()> {
    use crate::TempoEvm;

    // Create a test context with a transaction that has a non-zero value
    let ctx = Context::mainnet()
        .with_db(CacheDB::new(EmptyDB::default()))
        .with_block(Default::default())
        .with_cfg(Default::default())
        .with_tx(TempoTxEnv::default());
    let mut evm = TempoEvm::new(ctx, ());

    // Set a non-zero value on the transaction
    evm.ctx.tx.inner.value = U256::from(1000);

    // Create the handler
    let handler = TempoEvmHandler::<_, ()>::new();

    // Call validate_env and expect it to fail with ValueTransferNotAllowed
    let result = handler.validate_env(&mut evm);

    if let Err(EVMError::Transaction(err)) = result {
        assert_eq!(err, TempoInvalidTransaction::ValueTransferNotAllowed);
    } else {
        panic!("Expected ValueTransferNotAllowed error");
    }

    Ok(())
}

#[test]
fn test_key_authorization_gas_with_limits() {
    use tempo_primitives::transaction::{
        KeyAuthorization, SignatureType, SignedKeyAuthorization, TokenLimit,
    };

    // Helper to create key auth with N limits
    let create_key_auth = |num_limits: usize| -> SignedKeyAuthorization {
        let mut auth =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random());
        if num_limits > 0 {
            auth = auth.with_limits(
                (0..num_limits)
                    .map(|_| TokenLimit {
                        token: Address::random(),
                        limit: U256::from(1000),
                        period: 0,
                    })
                    .collect(),
            );
        }
        auth.into_signed(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ))
    };

    // Test 0 limits: base (27k) + ecrecover (3k) = 30,000
    let (gas_0, state_0) = calculate_key_authorization_gas(
        &create_key_auth(0),
        &GasParams::default(),
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );
    assert_eq!(
        gas_0,
        KEY_AUTH_BASE_GAS + ECRECOVER_GAS,
        "0 limits should be 30,000"
    );
    assert_eq!(state_0, 0, "pre-T1B has no state gas");

    // Test 1 limit: 30,000 + 22,000 = 52,000
    let (gas_1, state_1) = calculate_key_authorization_gas(
        &create_key_auth(1),
        &GasParams::default(),
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );
    assert_eq!(
        gas_1,
        KEY_AUTH_BASE_GAS + ECRECOVER_GAS + KEY_AUTH_PER_LIMIT_GAS,
        "1 limit should be 52,000"
    );
    assert_eq!(state_1, 0, "pre-T1B has no state gas");

    // Test 2 limits: 30,000 + 44,000 = 74,000
    let (gas_2, _) = calculate_key_authorization_gas(
        &create_key_auth(2),
        &GasParams::default(),
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );
    assert_eq!(
        gas_2,
        KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS,
        "2 limits should be 74,000"
    );

    // Test 3 limits: 30,000 + 66,000 = 96,000
    let (gas_3, _) = calculate_key_authorization_gas(
        &create_key_auth(3),
        &GasParams::default(),
        tempo_chainspec::hardfork::TempoHardfork::default(),
    );
    assert_eq!(
        gas_3,
        KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 3 * KEY_AUTH_PER_LIMIT_GAS,
        "3 limits should be 96,000"
    );

    // T1B branch: gas = sig_gas + SLOAD + SSTORE * (1 + num_limits) + buffer
    let t1b_gas_params = crate::gas_params::tempo_gas_params(TempoHardfork::T1B);
    let sstore =
        t1b_gas_params.get(revm::context_interface::cfg::GasId::sstore_set_without_load_cost());
    let sload =
        t1b_gas_params.warm_storage_read_cost() + t1b_gas_params.cold_storage_additional_cost();
    const BUFFER: u64 = 2_000;

    for num_limits in 0..=3 {
        let (gas, state_gas) = calculate_key_authorization_gas(
            &create_key_auth(num_limits),
            &t1b_gas_params,
            TempoHardfork::T1B,
        );
        let expected = ECRECOVER_GAS + sload + sstore * (1 + num_limits as u64) + BUFFER;
        assert_eq!(gas, expected, "T1B with {num_limits} limits");
        assert_eq!(state_gas, 0, "T1B has no state gas");
    }

    let t3_gas_params = crate::gas_params::tempo_gas_params(TempoHardfork::T3);
    let t3_sstore =
        t3_gas_params.get(revm::context_interface::cfg::GasId::sstore_set_without_load_cost());
    let t3_sload =
        t3_gas_params.warm_storage_read_cost() + t3_gas_params.cold_storage_additional_cost();

    for num_limits in 0..=3 {
        let num_sstores = 1 + 2 * num_limits as u64;
        let (gas, state_gas) = calculate_key_authorization_gas(
            &create_key_auth(num_limits),
            &t3_gas_params,
            TempoHardfork::T3,
        );
        let expected = ECRECOVER_GAS + t3_sload + t3_sstore * num_sstores + BUFFER;
        assert_eq!(gas, expected, "T3 with {num_limits} limits");
        assert_eq!(state_gas, 0, "T3 has no state gas");
    }

    // T4 with T4 gas params: regular sstore = 19,900, state gas = 230,000 per SSTORE
    let t4_gas_params = crate::gas_params::tempo_gas_params(TempoHardfork::T4);
    let t4_sstore =
        t4_gas_params.get(revm::context_interface::cfg::GasId::sstore_set_without_load_cost());
    let t4_sload =
        t4_gas_params.warm_storage_read_cost() + t4_gas_params.cold_storage_additional_cost();
    let t4_sstore_state =
        t4_gas_params.get(revm::context_interface::cfg::GasId::sstore_set_state_gas());

    for num_limits in 0..=3 {
        let num_sstores = 1 + 2 * num_limits as u64;
        let (gas, state_gas) = calculate_key_authorization_gas(
            &create_key_auth(num_limits),
            &t4_gas_params,
            TempoHardfork::T4,
        );
        let expected_state = t4_sstore_state * num_sstores;
        let expected =
            ECRECOVER_GAS + t4_sload + t4_sstore * num_sstores + BUFFER + 5_000 + expected_state;
        assert_eq!(gas, expected, "T4 with {num_limits} limits");
        assert_eq!(
            state_gas, expected_state,
            "T4 state gas with {num_limits} limits"
        );
    }

    let t5_gas_params = crate::gas_params::tempo_gas_params(TempoHardfork::T5);
    let t5_sload =
        t5_gas_params.warm_storage_read_cost() + t5_gas_params.cold_storage_additional_cost();
    let base_t5_key_auth = create_key_auth(0);
    let mut witness_t5_key_auth = create_key_auth(0);
    witness_t5_key_auth.authorization = witness_t5_key_auth
        .authorization
        .with_witness(B256::repeat_byte(0x53));

    let (base_t5_gas, base_t5_state_gas) =
        calculate_key_authorization_gas(&base_t5_key_auth, &t5_gas_params, TempoHardfork::T5);
    let (witness_t5_gas, witness_t5_state_gas) =
        calculate_key_authorization_gas(&witness_t5_key_auth, &t5_gas_params, TempoHardfork::T5);

    assert_eq!(
        witness_t5_gas - base_t5_gas,
        t5_sload + KEY_AUTH_EXTRA_EVENT_BUFFER,
        "T5 witness adds one burned-witness SLOAD and one event"
    );
    assert_eq!(
        witness_t5_state_gas - base_t5_state_gas,
        0,
        "T5 witness authorization does not add state gas"
    );

    let t6_gas_params = crate::gas_params::tempo_gas_params(TempoHardfork::T6);
    let base_t6_key_auth = create_key_auth(0);
    let mut account_bound_t6_key_auth = create_key_auth(0);
    account_bound_t6_key_auth.authorization = account_bound_t6_key_auth
        .authorization
        .with_account(Address::random());
    let mut admin_t6_key_auth = create_key_auth(0);
    admin_t6_key_auth.authorization = admin_t6_key_auth
        .authorization
        .into_admin(Address::random());
    let mut unbound_admin_t6_key_auth = create_key_auth(0);
    unbound_admin_t6_key_auth.authorization.is_admin = true;

    let (base_t6_gas, base_t6_state_gas) =
        calculate_key_authorization_gas(&base_t6_key_auth, &t6_gas_params, TempoHardfork::T6);
    let (account_bound_t6_gas, account_bound_t6_state_gas) = calculate_key_authorization_gas(
        &account_bound_t6_key_auth,
        &t6_gas_params,
        TempoHardfork::T6,
    );
    let (admin_t6_gas, admin_t6_state_gas) =
        calculate_key_authorization_gas(&admin_t6_key_auth, &t6_gas_params, TempoHardfork::T6);
    let (unbound_admin_t6_gas, unbound_admin_t6_state_gas) = calculate_key_authorization_gas(
        &unbound_admin_t6_key_auth,
        &t6_gas_params,
        TempoHardfork::T6,
    );

    assert_eq!(
        account_bound_t6_gas - base_t6_gas,
        0,
        "T6 account-bound authorization does not add key authorization gas"
    );
    assert_eq!(
        admin_t6_gas - base_t6_gas,
        KEY_AUTH_EXTRA_EVENT_BUFFER,
        "T6 account-bound admin authorization charges one extra event buffer"
    );
    assert_eq!(
        admin_t6_gas - account_bound_t6_gas,
        KEY_AUTH_EXTRA_EVENT_BUFFER,
        "T6 admin authorization pays one extra event buffer over non-admin account-bound authorization"
    );
    assert_eq!(
        unbound_admin_t6_gas - base_t6_gas,
        KEY_AUTH_EXTRA_EVENT_BUFFER,
        "T6 root-signed admin authorization without account charges only the extra event buffer"
    );
    assert_eq!(
        account_bound_t6_state_gas, base_t6_state_gas,
        "T6 account binding does not add state gas"
    );
    assert_eq!(
        admin_t6_state_gas, base_t6_state_gas,
        "T6 admin authorization event buffer does not add state gas"
    );
    assert_eq!(
        unbound_admin_t6_state_gas, base_t6_state_gas,
        "T6 unbound admin authorization does not add state gas"
    );

    let scoped = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
        .with_allowed_calls(vec![tempo_primitives::transaction::CallScope {
            target: Address::random(),
            selector_rules: vec![tempo_primitives::transaction::SelectorRule {
                selector: [0xa9, 0x05, 0x9c, 0xbb],
                recipients: vec![Address::random(), Address::random()],
            }],
        }])
        .into_signed(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ));

    let (gas, state_gas) =
        calculate_key_authorization_gas(&scoped, &t3_gas_params, TempoHardfork::T3);
    let expected = ECRECOVER_GAS + t3_sload + t3_sstore * (1 + 12) + BUFFER;
    assert_eq!(
        gas, expected,
        "T3 scope writes should keep current main accounting"
    );
    assert_eq!(state_gas, 0, "T3 has no state gas");

    let (gas, state_gas) =
        calculate_key_authorization_gas(&scoped, &t4_gas_params, TempoHardfork::T4);
    // 1 key write + 12 scope slots = 13 SSTOREs:
    // account mode(1) + target insertion rows(3) + selector insertion rows(3)
    // + constrained selector recipient-length(1) + recipients values+positions(2*2).
    // The rounded surcharge adds 5k base + 7k per target + 7k per selector + 5k per
    // recipient, which keeps larger scope trees from being materially underpriced.
    let num_sstores = 1 + 12;
    let expected_state = t4_sstore_state * num_sstores;
    let expected =
        ECRECOVER_GAS + t4_sload + t4_sstore * num_sstores + BUFFER + 29_000 + expected_state;
    assert_eq!(gas, expected, "T4 scope writes should be fully charged");
    assert_eq!(state_gas, expected_state, "T4 scope state gas");
    let multi_scope =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
            .with_allowed_calls(vec![
                tempo_primitives::transaction::CallScope {
                    target: Address::random(),
                    selector_rules: vec![
                        tempo_primitives::transaction::SelectorRule {
                            selector: [0xa9, 0x05, 0x9c, 0xbb],
                            recipients: vec![],
                        },
                        tempo_primitives::transaction::SelectorRule {
                            selector: [0x09, 0x5e, 0xa7, 0xb3],
                            recipients: vec![],
                        },
                    ],
                },
                tempo_primitives::transaction::CallScope {
                    target: Address::random(),
                    selector_rules: vec![],
                },
            ])
            .into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ));

    let (gas, state_gas) =
        calculate_key_authorization_gas(&multi_scope, &t3_gas_params, TempoHardfork::T3);
    let expected = ECRECOVER_GAS + t3_sload + t3_sstore * 14 + BUFFER;
    assert_eq!(
        gas, expected,
        "T3 scope writes should keep current main accounting"
    );
    assert_eq!(state_gas, 0, "T3 has no state gas");

    let (gas, state_gas) =
        calculate_key_authorization_gas(&multi_scope, &t4_gas_params, TempoHardfork::T4);
    let expected_state = t4_sstore_state * 12;
    let expected = ECRECOVER_GAS + t4_sload + t4_sstore * 12 + BUFFER + 33_000 + expected_state;
    assert_eq!(
        gas, expected,
        "T4 scope writes should only charge storage-creating rows"
    );
    assert_eq!(state_gas, expected_state, "T4 scope state gas");
}

#[test]
fn test_t4_key_authorization_matches_tip1016_sstore_regular_cost() {
    use tempo_primitives::transaction::{KeyAuthorization, SignatureType};

    let key_auth = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
        .into_signed(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ));

    // TIP-1016 is opt-in via amsterdam_eip8037; manually enable for this test.
    let gas_params = crate::gas_params::tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);

    let sig_gas = ECRECOVER_GAS + primitive_signature_verification_gas(&key_auth.signature);
    let sload = gas_params.warm_storage_read_cost() + gas_params.cold_storage_additional_cost();
    let scope_extra_gas = call_scope_extra_gas(&key_auth.authorization);
    let (regular_gas, state_gas) =
        calculate_key_authorization_gas(&key_auth, &gas_params, TempoHardfork::T4);
    let helper_sstore_regular = regular_gas - sig_gas - sload - 2_000 - scope_extra_gas;

    assert_eq!(helper_sstore_regular, 20_000);
    assert_eq!(state_gas, 230_000);
}

#[test]
fn test_t7_key_authorization_intrinsic_includes_storage_credit_value() {
    use tempo_chainspec::constants::gas::SSTORE_CREATE_COST;
    use tempo_primitives::transaction::{KeyAuthorization, SignatureType};

    let key_auth = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
        .into_signed(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        ));

    let gas_params = crate::gas_params::tempo_gas_params(TempoHardfork::T7);
    let sig_gas = ECRECOVER_GAS + primitive_signature_verification_gas(&key_auth.signature);
    let sload = gas_params.warm_storage_read_cost() + gas_params.cold_storage_additional_cost();
    let scope_extra_gas = call_scope_extra_gas(&key_auth.authorization);
    let (regular_gas, state_gas) =
        calculate_key_authorization_gas(&key_auth, &gas_params, TempoHardfork::T7);
    let helper_sstore_regular = regular_gas - sig_gas - sload - 2_000 - scope_extra_gas;

    assert_eq!(
        gas_params.get(GasId::sstore_set_without_load_cost()),
        SSTORE_CREATE_COST - STORAGE_CREDIT_VALUE,
        "T7 gas table should expose only the SSTORE residual"
    );
    assert_eq!(
        helper_sstore_regular, SSTORE_CREATE_COST,
        "key authorization intrinsic gas must include the TIP-1060 creditable portion"
    );
    assert_eq!(state_gas, 0, "T7 without TIP-1016 has no state gas split");
}

#[test]
fn test_translate_allowed_calls_for_precompile_preserves_empty_nested_allow_all_lists() {
    use tempo_primitives::transaction::{CallScope, KeyAuthorization, SelectorRule, SignatureType};

    let empty_selector_rules =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
            .with_allowed_calls(vec![CallScope {
                target: Address::random(),
                selector_rules: vec![],
            }])
            .into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ));

    let translated = translate_allowed_calls_for_precompile(&empty_selector_rules);
    assert_eq!(translated.len(), 1);
    assert!(translated[0].selectorRules.is_empty());

    let empty_recipients =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
            .with_allowed_calls(vec![CallScope {
                target: Address::random(),
                selector_rules: vec![SelectorRule {
                    selector: [0xa9, 0x05, 0x9c, 0xbb],
                    recipients: vec![],
                }],
            }])
            .into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ));

    let translated = translate_allowed_calls_for_precompile(&empty_recipients);
    assert_eq!(translated.len(), 1);
    assert_eq!(translated[0].selectorRules.len(), 1);
    assert!(translated[0].selectorRules[0].recipients.is_empty());
}

#[test]
fn test_key_authorization_gas_in_batch() {
    use crate::TempoBatchCallEnv;
    use alloy_primitives::{Bytes, TxKind};
    use revm::interpreter::gas::calculate_initial_tx_gas;
    use tempo_primitives::transaction::{
        Call, KeyAuthorization, SignatureType, SignedKeyAuthorization, TempoSignature, TokenLimit,
    };

    let calldata = Bytes::from(vec![1, 2, 3]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata.clone(),
    };

    // Create key authorization with 2 limits
    let key_auth: SignedKeyAuthorization =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::random())
            .with_limits(vec![
                TokenLimit {
                    token: Address::random(),
                    limit: U256::from(1000),
                    period: 0,
                },
                TokenLimit {
                    token: Address::random(),
                    limit: U256::from(2000),
                    period: 0,
                },
            ])
            .into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ));

    let aa_env_with_key_auth = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call.clone()],
        key_authorization: Some(key_auth),
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let aa_env_without_key_auth = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    // Calculate gas WITH key authorization
    let gas_with_key_auth = calculate_aa_batch_intrinsic_gas(
        &aa_env_with_key_auth,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Calculate gas WITHOUT key authorization
    let gas_without_key_auth = calculate_aa_batch_intrinsic_gas(
        &aa_env_without_key_auth,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap();

    // Expected key auth gas: 30,000 (base + ecrecover) + 2 * 22,000 (limits) = 74,000
    let expected_key_auth_gas = KEY_AUTH_BASE_GAS + ECRECOVER_GAS + 2 * KEY_AUTH_PER_LIMIT_GAS;

    assert_eq!(
        gas_with_key_auth.initial_total_gas() - gas_without_key_auth.initial_total_gas(),
        expected_key_auth_gas,
        "Key authorization should add exactly {expected_key_auth_gas} gas to batch",
    );

    // Also verify absolute values
    let spec = tempo_chainspec::hardfork::TempoHardfork::default();
    let base_tx_gas = calculate_initial_tx_gas(spec.into(), &calldata, false, 0, 0, 0);
    let expected_without = base_tx_gas.initial_total_gas(); // no cold access for single call
    let expected_with = expected_without + expected_key_auth_gas;

    assert_eq!(
        gas_without_key_auth.initial_total_gas(),
        expected_without,
        "Gas without key auth should match expected"
    );
    assert_eq!(
        gas_with_key_auth.initial_total_gas(),
        expected_with,
        "Gas with key auth should match expected"
    );
}

#[test]
fn test_2d_nonce_gas_in_intrinsic_gas() {
    use crate::gas_params::tempo_gas_params;
    use revm::{context_interface::cfg::GasId, handler::Handler};

    const BASE_INTRINSIC_GAS: u64 = 21_000;

    for spec in [
        TempoHardfork::Genesis,
        TempoHardfork::T0,
        TempoHardfork::T1,
        TempoHardfork::T1A,
        TempoHardfork::T1B,
        TempoHardfork::T2,
    ] {
        let gas_params = tempo_gas_params(spec);

        let make_evm = |nonce: u64, nonce_key: U256| {
            let journal = Journal::new(CacheDB::new(EmptyDB::default()));
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.spec = spec;
            cfg.gas_params = gas_params.clone();
            let ctx = Context::mainnet()
                .with_db(CacheDB::new(EmptyDB::default()))
                .with_block(TempoBlockEnv::default())
                .with_cfg(cfg)
                .with_tx(TempoTxEnv {
                    inner: revm::context::TxEnv {
                        gas_limit: 1_000_000,
                        nonce,
                        ..Default::default()
                    },
                    tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                        aa_calls: vec![Call {
                            to: TxKind::Call(Address::random()),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        }],
                        nonce_key,
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .with_new_journal(journal);
            TempoEvm::<_, ()>::new(ctx, ())
        };

        let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

        // Case 1: Protocol nonce (nonce_key == 0, nonce > 0) - no additional gas
        {
            let mut evm = make_evm(5, U256::ZERO);
            let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
            assert_eq!(
                gas.initial_total_gas(),
                BASE_INTRINSIC_GAS,
                "{spec:?}: protocol nonce (nonce_key=0, nonce>0) should have no extra gas"
            );
        }

        // Case 2: nonce_key != 0, nonce == 0
        {
            let expected = if spec.is_t1() {
                // T1+: any nonce==0 charges new_account_cost (250k)
                BASE_INTRINSIC_GAS + gas_params.get(GasId::new_account_cost())
            } else {
                // Pre-T1: charges gas_new_nonce_key for new 2D key
                BASE_INTRINSIC_GAS + spec.gas_new_nonce_key()
            };
            let mut evm = make_evm(0, U256::ONE);
            let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
            assert_eq!(
                gas.initial_total_gas(),
                expected,
                "{spec:?}: nonce_key!=0, nonce==0 gas mismatch"
            );
        }

        // Case 3: Existing 2D nonce key (nonce_key != 0, nonce > 0)
        {
            let mut evm = make_evm(5, U256::ONE);
            let gas = handler.validate_initial_tx_gas(&mut evm).unwrap();
            assert_eq!(
                gas.initial_total_gas(),
                BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(),
                "{spec:?}: existing 2D nonce key gas mismatch"
            );
        }
    }
}

#[test]
fn test_2d_nonce_gas_limit_validation() {
    use crate::gas_params::tempo_gas_params;
    use revm::{context_interface::cfg::GasId, handler::Handler};

    const BASE_INTRINSIC_GAS: u64 = 21_000;

    for spec in [
        TempoHardfork::Genesis,
        TempoHardfork::T0,
        TempoHardfork::T1,
        TempoHardfork::T2,
    ] {
        let gas_params = tempo_gas_params(spec);

        // Build spec-specific test cases: (gas_limit, nonce, expected_result)
        let nonce_zero_gas = if spec.is_t1() {
            gas_params.get(GasId::new_account_cost())
        } else {
            spec.gas_new_nonce_key()
        };
        let nonce_zero_state_gas = gas_params.new_account_state_gas();
        let nonce_zero_total = nonce_zero_gas + nonce_zero_state_gas;

        let cases = if spec.is_t0() {
            let mut cases = vec![
                (BASE_INTRINSIC_GAS + nonce_zero_total, 0, true), // Exactly sufficient for nonce==0 (exec + state)
                (BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(), 1, true), // Exactly sufficient for existing key
            ];
            // Insufficient: below total required for nonce==0
            cases.push((BASE_INTRINSIC_GAS + nonce_zero_total - 1, 0u64, false));
            cases
        } else {
            // Genesis: nonce gas is added AFTER validation, so lower gas_limit still passes
            vec![
                (BASE_INTRINSIC_GAS + 10_000, 0u64, true), // Passes validation (nonce gas added after)
                (BASE_INTRINSIC_GAS + nonce_zero_gas, 0, true), // Also passes
                (BASE_INTRINSIC_GAS + spec.gas_existing_nonce_key(), 1, true), // Also passes
                (BASE_INTRINSIC_GAS - 1, 0, false),        // Below base intrinsic gas
            ]
        };

        for (gas_limit, nonce, should_succeed) in cases {
            let journal = Journal::new(CacheDB::new(EmptyDB::default()));
            let mut cfg = CfgEnv::<TempoHardfork>::default();
            cfg.spec = spec;
            cfg.gas_params = gas_params.clone();
            let ctx = Context::mainnet()
                .with_db(CacheDB::new(EmptyDB::default()))
                .with_block(TempoBlockEnv::default())
                .with_cfg(cfg)
                .with_tx(TempoTxEnv {
                    inner: revm::context::TxEnv {
                        gas_limit,
                        nonce,
                        ..Default::default()
                    },
                    tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                        aa_calls: vec![Call {
                            to: TxKind::Call(Address::random()),
                            value: U256::ZERO,
                            input: Bytes::new(),
                        }],
                        nonce_key: U256::ONE,
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .with_new_journal(journal);

            let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
            let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();
            let result = handler.validate_initial_tx_gas(&mut evm);

            if should_succeed {
                assert!(
                    result.is_ok(),
                    "{spec:?}: gas_limit={gas_limit}, nonce={nonce}: expected success but got error"
                );
            } else {
                let err = result.expect_err(&format!(
                    "{spec:?}: gas_limit={gas_limit}, nonce={nonce}: should fail"
                ));
                assert!(
                    matches!(
                        err.as_invalid_tx_err(),
                        Some(TempoInvalidTransaction::EthInvalidTransaction(
                            InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
                        ))
                    ),
                    "Expected CallGasCostMoreThanGasLimit, got: {err:?}"
                );
            }
        }
    }
}

#[test]
fn test_t3_scope_validation_moves_to_execution() {
    const CALL_SCOPE_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    let caller = Address::repeat_byte(0x11);
    let access_key = Address::repeat_byte(0x22);
    let target = DEFAULT_FEE_TOKEN;

    let signature =
        TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
            caller,
            tempo_primitives::transaction::PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ),
        ));

    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.spec = TempoHardfork::T3;

    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            caller,
            gas_limit: 1_000_000,
            kind: TxKind::Call(target),
            ..Default::default()
        },
        fee_token: Some(DEFAULT_FEE_TOKEN),
        tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
            signature,
            aa_calls: vec![Call {
                to: TxKind::Call(target),
                value: U256::ZERO,
                input: Bytes::from_static(&CALL_SCOPE_SELECTOR),
            }],
            signature_hash: B256::ZERO,
            override_key_id: Some(access_key),
            ..Default::default()
        })),
        ..Default::default()
    };

    let mut test = TestHandlerEvm::with_cfg(TempoHardfork::T3, tx_env, |cfg_override| {
        *cfg_override = cfg;
    });

    StorageCtx::enter_ctx(&mut test.evm.inner.ctx, StorageActions::disabled(), || {
        let mut keychain = AccountKeychain::new();

        keychain.initialize().expect("keychain initialized");
        keychain
            .set_transaction_key(Address::ZERO)
            .expect("root key setup succeeds");
        keychain
            .set_tx_origin(caller)
            .expect("tx.origin setup succeeds");
        keychain
            .authorize_key(
                caller,
                access_key,
                PrecompileSignatureType::Secp256k1,
                KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: false,
                    allowedCalls: vec![PrecompileCallScope {
                        target,
                        selectorRules: vec![PrecompileSelectorRule {
                            selector: CALL_SCOPE_SELECTOR.into(),
                            recipients: vec![],
                        }],
                    }],
                },
                None,
            )
            .expect("access key authorization succeeds");
    });

    let init_gas = test.validate_initial_tx_gas();
    assert!(
        init_gas.floor_gas <= init_gas.initial_total_gas(),
        "test requires floor gas to not exceed intrinsic gas"
    );

    test.evm.inner.ctx.tx.inner.gas_limit = init_gas.initial_total_gas();

    test.validate_against_state_and_deduct_caller()
        .expect("scope validation no longer runs during state validation");

    let result = test.execute(&init_gas);

    assert!(
        matches!(
            result.instruction_result(),
            revm::interpreter::InstructionResult::PrecompileOOG
        ),
        "expected scope validation to fail during execution with OOG, got: {:?}",
        result.instruction_result()
    );
    assert_eq!(
        result.gas().limit(),
        init_gas.initial_total_gas(),
        "batch OOG should report the full tx gas budget"
    );
    assert_eq!(
        result.gas().total_gas_spent(),
        init_gas.initial_total_gas(),
        "batch OOG should consume the full tx gas budget"
    );
    assert_eq!(result.gas().refunded(), 0);
}

#[test]
fn test_t3_scope_validation_returns_call_not_allowed_revert_data() {
    use alloy_sol_types::SolInterface;
    use tempo_contracts::precompiles::AccountKeychainError;

    const ALLOWED_SELECTOR: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    const DENIED_SELECTOR: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];

    let caller = Address::repeat_byte(0x11);
    let access_key = Address::repeat_byte(0x22);
    let target = DEFAULT_FEE_TOKEN;

    let signature =
        TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
            caller,
            tempo_primitives::transaction::PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ),
        ));

    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.spec = TempoHardfork::T3;

    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            caller,
            gas_limit: 1_000_000,
            kind: TxKind::Call(target),
            ..Default::default()
        },
        fee_token: Some(DEFAULT_FEE_TOKEN),
        tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
            signature,
            aa_calls: vec![Call {
                to: TxKind::Call(target),
                value: U256::ZERO,
                input: Bytes::from_static(&DENIED_SELECTOR),
            }],
            signature_hash: B256::ZERO,
            override_key_id: Some(access_key),
            ..Default::default()
        })),
        ..Default::default()
    };

    let ctx = Context::mainnet()
        .with_db(CacheDB::new(EmptyDB::default()))
        .with_block(TempoBlockEnv::default())
        .with_cfg(cfg)
        .with_tx(tx_env.clone())
        .with_new_journal(create_test_journal());

    let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
    let mut handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

    StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
        let mut keychain = AccountKeychain::new();

        keychain.initialize().expect("keychain initialized");
        keychain
            .set_transaction_key(Address::ZERO)
            .expect("root key setup succeeds");
        keychain
            .set_tx_origin(caller)
            .expect("tx.origin setup succeeds");
        keychain
            .authorize_key(
                caller,
                access_key,
                PrecompileSignatureType::Secp256k1,
                KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: false,
                    allowedCalls: vec![PrecompileCallScope {
                        target,
                        selectorRules: vec![PrecompileSelectorRule {
                            selector: ALLOWED_SELECTOR.into(),
                            recipients: vec![],
                        }],
                    }],
                },
                None,
            )
            .expect("access key authorization succeeds");
    });

    let init_gas = handler
        .validate_initial_tx_gas(&mut evm)
        .expect("initial gas validation should succeed");

    handler
        .validate_against_state_and_deduct_caller(&mut evm, &mut Default::default())
        .expect("scope validation no longer runs during state validation");

    let result = handler
        .execution(&mut evm, &init_gas)
        .expect("execution should return a frame result");

    let expected_revert: Bytes = AccountKeychainError::call_not_allowed().abi_encode().into();

    assert_eq!(result.instruction_result(), InstructionResult::Revert);
    assert_eq!(result.output().data(), &expected_revert);
    assert!(
        result.gas().total_gas_spent() < tx_env.gas_limit,
        "prevalidate revert must not consume the full gas_limit"
    );
}

#[test]
fn test_t3_scope_validation_empty_calls_returns_custom_error() {
    let caller = Address::repeat_byte(0x11);
    let access_key = Address::repeat_byte(0x22);

    let signature =
        TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
            caller,
            tempo_primitives::transaction::PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ),
        ));

    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.spec = TempoHardfork::T3;

    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            caller,
            gas_limit: 1_000_000,
            ..Default::default()
        },
        tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
            signature,
            aa_calls: vec![],
            signature_hash: B256::ZERO,
            override_key_id: Some(access_key),
            ..Default::default()
        })),
        ..Default::default()
    };

    let ctx = Context::mainnet()
        .with_db(CacheDB::new(EmptyDB::default()))
        .with_block(TempoBlockEnv::default())
        .with_cfg(cfg)
        .with_tx(tx_env)
        .with_new_journal(create_test_journal());

    let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
    let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();
    let mut remaining_gas = 100_000;

    let err = handler
        .prevalidate_keychain_call_scopes(&mut evm, &[], &mut remaining_gas, 0)
        .expect_err("empty calls should return an error instead of panicking");

    match err {
        EVMError::Custom(msg) => {
            assert_eq!(msg, "AA transactions must contain at least one call");
        }
        other => panic!("expected custom error, got: {other:?}"),
    }
}

/// TIP-1060: T7 removes the EIP-3529 one-fifth refund cap; pre-T7 keeps it.
#[test]
fn test_refund_cap_removed_on_t7() {
    use revm::{
        Context, Journal,
        context::CfgEnv,
        database::{CacheDB, EmptyDB},
        handler::FrameResult,
        interpreter::{CallOutcome, Gas, InstructionResult, InterpreterResult},
    };

    // Refund (50k) deliberately exceeds one fifth of the gas used (100k / 5 = 20k).
    const SPENT: u64 = 100_000;
    const REFUND: i64 = 50_000;
    const CAPPED: i64 = (SPENT / 5) as i64;

    let refunded_for_spec = |spec: TempoHardfork| -> i64 {
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = spec;
        let ctx = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(TempoBlockEnv::default())
            .with_cfg(cfg)
            .with_tx(TempoTxEnv::default())
            .with_new_journal(Journal::new(CacheDB::new(EmptyDB::default())));
        let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
        let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

        let mut gas = Gas::new(SPENT);
        gas.set_spent(SPENT);
        gas.record_refund(REFUND);
        let mut frame_result = FrameResult::Call(CallOutcome::new(
            InterpreterResult::new(InstructionResult::Stop, Bytes::new(), gas),
            0..0,
        ));

        handler.refund(&mut evm, &mut frame_result, 0);
        frame_result.gas().refunded()
    };

    assert_eq!(
        refunded_for_spec(TempoHardfork::T6),
        CAPPED,
        "pre-T7 must cap the refund at one fifth of gas used"
    );
    assert_eq!(
        refunded_for_spec(TempoHardfork::T7),
        REFUND,
        "T7 must credit the full refund, with no EIP-3529 cap"
    );
}

#[test]
fn test_multicall_gas_refund_accounting() {
    use crate::evm::TempoEvm;
    use alloy_primitives::{Bytes, TxKind};
    use revm::{
        Context, Journal,
        context::CfgEnv,
        database::{CacheDB, EmptyDB},
        handler::FrameResult,
        interpreter::{CallOutcome, Gas, InstructionResult, InterpreterResult},
    };
    use tempo_primitives::transaction::Call;

    const GAS_LIMIT: u64 = 1_000_000;
    const INTRINSIC_GAS: u64 = 21_000;
    // Mock call's gas: (CALL_0, CALL_1)
    const SPENT: (u64, u64) = (1000, 500);
    const REFUND: (i64, i64) = (100, 50);

    // Create minimal EVM context
    let db = CacheDB::new(EmptyDB::default());
    let journal = Journal::new(db);
    let ctx = Context::mainnet()
        .with_db(CacheDB::new(EmptyDB::default()))
        .with_block(TempoBlockEnv::default())
        .with_cfg(CfgEnv::default())
        .with_tx(TempoTxEnv {
            inner: revm::context::TxEnv {
                gas_limit: GAS_LIMIT,
                ..Default::default()
            },
            ..Default::default()
        })
        .with_new_journal(journal);

    let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());
    let mut handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

    // Create mock calls
    let calls = vec![
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        },
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        },
    ];

    let (mut call_idx, calls_gas) = (0, [(SPENT.0, REFUND.0), (SPENT.1, REFUND.1)]);
    let result = handler.execute_multi_call_with(
        &mut evm,
        GAS_LIMIT - INTRINSIC_GAS,
        0,
        calls,
        |_handler, _evm, gas, _reservoir| {
            let (spent, refund) = calls_gas[call_idx];
            call_idx += 1;

            // Create gas with specific spent and refund values
            let mut gas = Gas::new(gas);
            gas.set_spent(spent);
            gas.record_refund(refund);

            // Mock successful frame result
            Ok(FrameResult::Call(CallOutcome::new(
                InterpreterResult::new(InstructionResult::Stop, Bytes::new(), gas),
                0..0,
            )))
        },
    );

    let result = result.expect("execute_multi_call_with should succeed");
    let final_gas = result.gas();

    assert_eq!(
        final_gas.total_gas_spent(),
        INTRINSIC_GAS + SPENT.0 + SPENT.1,
        "Total spent should be intrinsic_gas + sum of all calls' spent values"
    );
    assert_eq!(
        final_gas.refunded(),
        REFUND.0 + REFUND.1,
        "Total refund should be sum of all calls' refunded values"
    );
    assert_eq!(
        final_gas.used(),
        INTRINSIC_GAS + SPENT.0 + SPENT.1 - (REFUND.0 + REFUND.1) as u64,
        "used() should be spent - refund"
    );
}

/// Strategy for optional u64 timestamps.
fn arb_opt_timestamp() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![Just(None), any::<u64>().prop_map(Some)]
}

/// Helper to create a secp256k1 signature for testing gas calculations.
///
/// Note: We use a test signature rather than real valid/invalid signatures because
/// these gas calculation functions only depend on the signature *type* (Secp256k1,
/// P256, WebAuthn), not on cryptographic validity. Signature verification happens
/// separately during `recover_signer()` before transactions enter the pool.
fn secp256k1_sig() -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        alloy_primitives::Signature::test_signature(),
    ))
}

/// Helper to create a TempoBatchCallEnv with specified calls.
fn make_aa_env(calls: Vec<Call>) -> TempoBatchCallEnv {
    TempoBatchCallEnv {
        signature: secp256k1_sig(),
        aa_calls: calls,
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    }
}

/// Helper to create a single-call TempoBatchCallEnv with given calldata.
fn make_single_call_env(calldata: Bytes) -> TempoBatchCallEnv {
    make_aa_env(vec![Call {
        to: TxKind::Call(Address::ZERO),
        value: U256::ZERO,
        input: calldata,
    }])
}

/// Helper to create a multi-call TempoBatchCallEnv with N empty calls.
fn make_multi_call_env(num_calls: usize) -> TempoBatchCallEnv {
    make_aa_env(
        (0..num_calls)
            .map(|_| Call {
                to: TxKind::Call(Address::ZERO),
                value: U256::ZERO,
                input: Bytes::new(),
            })
            .collect(),
    )
}

/// Helper to compute AA batch gas with no access list.
fn compute_aa_gas(env: &TempoBatchCallEnv) -> InitialAndFloorGas {
    calculate_aa_batch_intrinsic_gas(
        env,
        &GasParams::default(),
        None::<std::iter::Empty<&AccessListItem>>,
        tempo_chainspec::hardfork::TempoHardfork::default(),
    )
    .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Property: validate_time_window returns Ok if (after <= ts < before)
    #[test]
    fn proptest_validate_time_window_correctness(
        valid_after in arb_opt_timestamp(),
        valid_before in arb_opt_timestamp(),
        block_timestamp in any::<u64>(),
    ) {
        let result = validate_time_window(valid_after, valid_before, block_timestamp);

        let after_ok = valid_after.is_none_or(|after| block_timestamp >= after);
        let before_ok = valid_before.is_none_or(|before| block_timestamp < before);
        let expected_valid = after_ok && before_ok;

        prop_assert_eq!(result.is_ok(), expected_valid,
            "valid_after={:?}, valid_before={:?}, block_ts={}, result={:?}",
            valid_after, valid_before, block_timestamp, result);
    }

    /// Property: validate_time_window with None constraints always succeeds
    #[test]
    fn proptest_validate_time_window_none_always_valid(block_timestamp in any::<u64>()) {
        prop_assert!(validate_time_window(None, None, block_timestamp).is_ok());
    }

    /// Property: validate_time_window with valid_after=0 is equivalent to None
    ///
    /// This tests the equivalence property: Some(0) and None for valid_after should produce
    /// identical results regardless of what valid_before is. We intentionally don't constrain
    /// valid_before because we're testing that the equivalence holds in all cases (both when
    /// valid_before causes success and when it causes failure).
    #[test]
    fn proptest_validate_time_window_zero_after_equivalent_to_none(
        valid_before in arb_opt_timestamp(),
        block_timestamp in any::<u64>(),
    ) {
        let with_zero = validate_time_window(Some(0), valid_before, block_timestamp);
        let with_none = validate_time_window(None, valid_before, block_timestamp);
        prop_assert_eq!(with_zero.is_ok(), with_none.is_ok());
    }

    /// Property: validate_time_window - if before <= after, the window is empty
    #[test]
    fn proptest_validate_time_window_empty_window(
        valid_after in 1u64..=u64::MAX,
        offset in 0u64..1000u64,
    ) {
        let valid_before = valid_after.saturating_sub(offset);
        let result = validate_time_window(Some(valid_after), Some(valid_before), valid_after);
        prop_assert!(result.is_err(), "Empty window should reject all timestamps");
    }

    /// Property: signature gas ordering is consistent: secp256k1 <= p256 <= webauthn
    #[test]
    fn proptest_signature_gas_ordering(webauthn_data_len in 0usize..1000) {
        let secp_sig = PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature());
        let p256_sig = PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO, pre_hash: false,
        });
        let webauthn_sig = PrimitiveSignature::WebAuthn(WebAuthnSignature {
            r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO,
            webauthn_data: Bytes::from(vec![0u8; webauthn_data_len]),
        });

        let secp_gas = primitive_signature_verification_gas(&secp_sig);
        let p256_gas = primitive_signature_verification_gas(&p256_sig);
        let webauthn_gas = primitive_signature_verification_gas(&webauthn_sig);

        prop_assert!(secp_gas <= p256_gas, "secp256k1 should be <= p256");
        prop_assert!(p256_gas <= webauthn_gas, "p256 should be <= webauthn");
    }

    /// Property: gas calculation monotonicity - more calldata means more gas (non-zero bytes)
    /// Non-zero bytes cost 16 gas each, so monotonicity holds for uniform non-zero calldata.
    #[test]
    fn proptest_gas_monotonicity_calldata_nonzero(
        calldata_len1 in 0usize..1000,
        calldata_len2 in 0usize..1000,
    ) {
        let gas1 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len1])));
        let gas2 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len2])));

        if calldata_len1 <= calldata_len2 {
            prop_assert!(gas1.initial_total_gas() <= gas2.initial_total_gas(),
                "More calldata should mean more gas: len1={}, gas1={}, len2={}, gas2={}",
                calldata_len1, gas1.initial_total_gas(), calldata_len2, gas2.initial_total_gas());
        } else {
            prop_assert!(gas1.initial_total_gas() >= gas2.initial_total_gas(),
                "Less calldata should mean less gas: len1={}, gas1={}, len2={}, gas2={}",
                calldata_len1, gas1.initial_total_gas(), calldata_len2, gas2.initial_total_gas());
        }
    }

    /// Property: gas calculation monotonicity - more calldata means more gas (zero bytes)
    /// Zero bytes cost 4 gas each, so monotonicity holds for uniform zero calldata.
    #[test]
    fn proptest_gas_monotonicity_calldata_zero(
        calldata_len1 in 0usize..1000,
        calldata_len2 in 0usize..1000,
    ) {
        let gas1 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len1])));
        let gas2 = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len2])));

        if calldata_len1 <= calldata_len2 {
            prop_assert!(gas1.initial_total_gas() <= gas2.initial_total_gas(),
                "More zero-byte calldata should mean more gas: len1={}, gas1={}, len2={}, gas2={}",
                calldata_len1, gas1.initial_total_gas(), calldata_len2, gas2.initial_total_gas());
        } else {
            prop_assert!(gas1.initial_total_gas() >= gas2.initial_total_gas(),
                "Less zero-byte calldata should mean less gas: len1={}, gas1={}, len2={}, gas2={}",
                calldata_len1, gas1.initial_total_gas(), calldata_len2, gas2.initial_total_gas());
        }
    }

    /// Property: zero-byte calldata costs less gas than non-zero byte calldata of same length.
    /// Zero bytes cost 4 gas each, non-zero bytes cost 16 gas each.
    #[test]
    fn proptest_zero_bytes_cheaper_than_nonzero(calldata_len in 1usize..1000) {
        let zero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len])));
        let nonzero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len])));

        prop_assert!(zero_gas.initial_total_gas() < nonzero_gas.initial_total_gas(),
            "Zero-byte calldata should cost less: len={}, zero_gas={}, nonzero_gas={}",
            calldata_len, zero_gas.initial_total_gas(), nonzero_gas.initial_total_gas());
    }

    /// Property: mixed calldata gas is bounded by all-zero and all-nonzero extremes.
    /// Gas for mixed calldata should be between gas for all-zero and all-nonzero of same length.
    #[test]
    fn proptest_mixed_calldata_gas_bounded(
        calldata_len in 1usize..500,
        nonzero_ratio in 0u8..=100,
    ) {
        // Create mixed calldata where nonzero_ratio% of bytes are non-zero
        let calldata: Vec<u8> = (0..calldata_len)
            .map(|i| if (i * 100 / calldata_len) < nonzero_ratio as usize { 1u8 } else { 0u8 })
            .collect();

        let mixed_gas = compute_aa_gas(&make_single_call_env(Bytes::from(calldata)));
        let zero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![0u8; calldata_len])));
        let nonzero_gas = compute_aa_gas(&make_single_call_env(Bytes::from(vec![1u8; calldata_len])));

        prop_assert!(mixed_gas.initial_total_gas() >= zero_gas.initial_total_gas(),
            "Mixed calldata gas should be >= all-zero gas: mixed={}, zero={}",
            mixed_gas.initial_total_gas(), zero_gas.initial_total_gas());
        prop_assert!(mixed_gas.initial_total_gas() <= nonzero_gas.initial_total_gas(),
            "Mixed calldata gas should be <= all-nonzero gas: mixed={}, nonzero={}",
            mixed_gas.initial_total_gas(), nonzero_gas.initial_total_gas());
    }

    /// Property: gas calculation monotonicity - more calls means more gas
    #[test]
    fn proptest_gas_monotonicity_call_count(
        num_calls1 in 1usize..10,
        num_calls2 in 1usize..10,
    ) {
        let gas1 = compute_aa_gas(&make_multi_call_env(num_calls1));
        let gas2 = compute_aa_gas(&make_multi_call_env(num_calls2));

        if num_calls1 <= num_calls2 {
            prop_assert!(gas1.initial_total_gas() <= gas2.initial_total_gas(),
                "More calls should mean more gas: calls1={}, gas1={}, calls2={}, gas2={}",
                num_calls1, gas1.initial_total_gas(), num_calls2, gas2.initial_total_gas());
        } else {
            prop_assert!(gas1.initial_total_gas() >= gas2.initial_total_gas(),
                "Fewer calls should mean less gas: calls1={}, gas1={}, calls2={}, gas2={}",
                num_calls1, gas1.initial_total_gas(), num_calls2, gas2.initial_total_gas());
        }
    }

    /// Property: AA batch gas with Secp256k1 signature equals exactly 21k base + cold access
    ///
    /// For minimal AA transactions (Secp256k1 sig, no calldata, no access list):
    /// - Base: 21,000 (same base stipend as regular transactions)
    /// - Plus: COLD_ACCOUNT_ACCESS_COST per additional call beyond the first
    ///
    /// AA transactions use the same 21k base as regular transactions because
    /// Secp256k1 signature verification adds 0 extra gas. Other signature types
    /// (P256, WebAuthn) add 5,000+ gas beyond this base.
    #[test]
    fn proptest_gas_aa_secp256k1_exact_bounds(num_calls in 1usize..5) {
        let gas = compute_aa_gas(&make_multi_call_env(num_calls));

        // Expected exactly: 21k base + cold account access for each additional call
        let expected = 21_000 + COLD_ACCOUNT_ACCESS_COST * (num_calls.saturating_sub(1) as u64);
        prop_assert_eq!(gas.initial_total_gas(), expected,
            "Gas {} should equal expected {} for {} calls (21k + {}*COLD_ACCOUNT_ACCESS_COST)",
            gas.initial_total_gas(), expected, num_calls, num_calls.saturating_sub(1));
    }

    /// Property: first_call returns the first call for AA transactions with any number of calls
    #[test]
    fn proptest_first_call_returns_first_for_aa(num_calls in 1usize..10) {
        let calls: Vec<Call> = (0..num_calls)
            .map(|i| Call {
                to: TxKind::Call(Address::with_last_byte(i as u8)),
                value: U256::ZERO,
                input: Bytes::from(vec![i as u8; i + 1]),
            })
            .collect();

        let expected_addr = Address::with_last_byte(0);
        let expected_input = vec![0u8; 1];

        let tx_env = TempoTxEnv {
            inner: revm::context::TxEnv::default(),
            tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                aa_calls: calls,
                signature: secp256k1_sig(),
                signature_hash: B256::ZERO,
                ..Default::default()
            })),
            ..Default::default()
        };

        let first = tx_env.first_call();
        prop_assert!(first.is_some(), "first_call should return Some for non-empty AA calls");

        let (kind, input) = first.unwrap();
        prop_assert_eq!(*kind, TxKind::Call(expected_addr), "Should return first call's address");
        prop_assert_eq!(input, expected_input.as_slice(), "Should return first call's input");
    }

    /// Property: first_call returns None for AA transaction with zero calls
    #[test]
    fn proptest_first_call_empty_aa(_dummy in 0u8..1) {
        let tx_env = TempoTxEnv {
            inner: revm::context::TxEnv::default(),
            tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                aa_calls: vec![],
                signature: secp256k1_sig(),
                signature_hash: B256::ZERO,
                ..Default::default()
            })),
            ..Default::default()
        };

        prop_assert!(tx_env.first_call().is_none(), "first_call should return None for empty AA calls");
    }

    /// Property: first_call returns inner tx data for non-AA transactions
    #[test]
    fn proptest_first_call_non_aa(calldata_len in 0usize..100) {
        let calldata = Bytes::from(vec![0xab_u8; calldata_len]);
        let target = Address::random();

        let tx_env = TempoTxEnv {
            inner: revm::context::TxEnv {
                kind: TxKind::Call(target),
                data: calldata.clone(),
                ..Default::default()
            },
            tempo_tx_env: None,
            ..Default::default()
        };

        let first = tx_env.first_call();
        prop_assert!(first.is_some(), "first_call should return Some for non-AA tx");

        let (kind, input) = first.unwrap();
        prop_assert_eq!(*kind, TxKind::Call(target), "Should return inner tx kind");
        prop_assert_eq!(input, calldata.as_ref(), "Should return inner tx data");
    }

    /// Property: calculate_key_authorization_gas is monotonic in number of limits
    #[test]
    fn proptest_key_auth_gas_monotonic_limits(
        num_limits1 in 0usize..10,
        num_limits2 in 0usize..10,
    ) {
        use tempo_primitives::transaction::{
            SignatureType, SignedKeyAuthorization,
            key_authorization::KeyAuthorization,
            TokenLimit as PrimTokenLimit,
        };

        let make_key_auth = |num_limits: usize| -> SignedKeyAuthorization {
            let mut auth =
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO);
            if num_limits > 0 {
                auth = auth.with_limits((0..num_limits).map(|i| PrimTokenLimit {
                    token: Address::with_last_byte(i as u8),
                    limit: U256::from(1000),
                    period: 0,
                }).collect());
            }
            auth.into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ))
        };

        // Test both pre-T1B and T1B branches
        for (gas_params, spec) in [
            (GasParams::default(), tempo_chainspec::hardfork::TempoHardfork::default()),
            (crate::gas_params::tempo_gas_params(TempoHardfork::T1B), TempoHardfork::T1B),
        ] {
            let (gas1, _) = calculate_key_authorization_gas(&make_key_auth(num_limits1), &gas_params, spec);
            let (gas2, _) = calculate_key_authorization_gas(&make_key_auth(num_limits2), &gas_params, spec);

            if num_limits1 <= num_limits2 {
                prop_assert!(gas1 <= gas2,
                    "{spec:?}: More limits should mean more gas: limits1={}, gas1={}, limits2={}, gas2={}",
                    num_limits1, gas1, num_limits2, gas2);
            } else {
                prop_assert!(gas1 >= gas2,
                    "{spec:?}: Fewer limits should mean less gas: limits1={}, gas1={}, limits2={}, gas2={}",
                    num_limits1, gas1, num_limits2, gas2);
            }
        }
    }

    /// Property: calculate_key_authorization_gas minimum is KEY_AUTH_BASE_GAS + ECRECOVER_GAS
    #[test]
    fn proptest_key_auth_gas_minimum(
        sig_type in 0u8..3,
        num_limits in 0usize..5,
    ) {
        use tempo_primitives::transaction::{
            SignatureType, TokenLimit as PrimTokenLimit, key_authorization::KeyAuthorization,
        };

        let signature = match sig_type {
            0 => PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature()),
            1 => PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO, pre_hash: false,
            }),
            _ => PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r: B256::ZERO, s: B256::ZERO, pub_key_x: B256::ZERO, pub_key_y: B256::ZERO,
                webauthn_data: Bytes::new(),
            }),
        };

        let mut auth =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::ZERO);
        if num_limits > 0 {
            auth = auth.with_limits((0..num_limits).map(|i| PrimTokenLimit {
                token: Address::with_last_byte(i as u8),
                limit: U256::from(1000),
                period: 0,
            }).collect());
        }
        let key_auth = auth.into_signed(signature);

        // Pre-T1B: minimum is KEY_AUTH_BASE_GAS + ECRECOVER_GAS
        let (gas, _) = calculate_key_authorization_gas(&key_auth, &GasParams::default(), tempo_chainspec::hardfork::TempoHardfork::default());
        let min_gas = KEY_AUTH_BASE_GAS + ECRECOVER_GAS;
        prop_assert!(gas >= min_gas,
            "Pre-T1B: Key auth gas should be at least {min_gas}, got {gas}");

        // T1B: minimum is ECRECOVER_GAS + sload + sstore (0 limits)
        let t1b_params = crate::gas_params::tempo_gas_params(TempoHardfork::T1B);
        let (gas_t1b, _) = calculate_key_authorization_gas(&key_auth, &t1b_params, TempoHardfork::T1B);
        let sstore = t1b_params.get(revm::context_interface::cfg::GasId::sstore_set_without_load_cost());
        let sload = t1b_params.warm_storage_read_cost() + t1b_params.cold_storage_additional_cost();
        let min_t1b = ECRECOVER_GAS + sload + sstore;
        prop_assert!(gas_t1b >= min_t1b,
            "T1B: Key auth gas should be at least {min_t1b}, got {gas_t1b}");
    }
}

/// Test that T1 hardfork correctly charges 250k gas for nonce == 0.
///
/// This test validates [TIP-1000]'s requirement:
/// "Tempo transactions with any `nonce_key` and `nonce == 0` require an additional 250,000 gas"
///
/// The test proves the audit finding (claiming only 22,100 gas is charged) is a false positive
/// by using delta-based assertions: gas(nonce=0) - gas(nonce>0) == new_account_cost.
///
/// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
#[test]
fn test_t1_2d_nonce_key_charges_250k_gas() {
    use crate::gas_params::tempo_gas_params;
    use revm::{context_interface::cfg::GasId, handler::Handler};

    // Deterministic test addresses
    const TEST_TARGET: Address = Address::new([0xAA; 20]);
    const TEST_NONCE_KEY: U256 = U256::from_limbs([42, 0, 0, 0]);
    const SPEC: TempoHardfork = TempoHardfork::T1;
    const NEW_NONCE_KEY_GAS: u64 = SPEC.gas_new_nonce_key();
    const EXISTING_NONCE_KEY_GAS: u64 = SPEC.gas_existing_nonce_key();

    // Create T1 config with TIP-1000 gas params
    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.spec = SPEC;
    cfg.gas_params = tempo_gas_params(TempoHardfork::T1);

    // Get the expected new_account_cost dynamically from gas params
    let new_account_cost = cfg.gas_params.get(GasId::new_account_cost());
    assert_eq!(
        new_account_cost, 250_000,
        "T1 gas params should have 250k new_account_cost"
    );

    // Helper to create EVM context for testing
    let make_evm = |cfg: CfgEnv<TempoHardfork>, nonce: u64, nonce_key: U256| {
        let journal = Journal::new(CacheDB::new(EmptyDB::default()));
        let ctx = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(TempoBlockEnv::default())
            .with_cfg(cfg)
            .with_tx(TempoTxEnv {
                inner: revm::context::TxEnv {
                    gas_limit: 1_000_000,
                    nonce,
                    ..Default::default()
                },
                tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                    aa_calls: vec![Call {
                        to: TxKind::Call(TEST_TARGET),
                        value: U256::ZERO,
                        input: Bytes::new(),
                    }],
                    nonce_key,
                    ..Default::default()
                })),
                ..Default::default()
            })
            .with_new_journal(journal);
        TempoEvm::<_, ()>::new(ctx, ())
    };

    // Case 1: nonce == 0 with 2D nonce key -> should include new_account_cost
    let mut evm_nonce_zero = make_evm(cfg.clone(), 0, TEST_NONCE_KEY);
    let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();
    let gas_nonce_zero = handler
        .validate_initial_tx_gas(&mut evm_nonce_zero)
        .unwrap();

    // Case 2: nonce > 0 with same 2D nonce key -> should charge EXISTING_NONCE_KEY_GAS (5k)
    // This tests that existing 2D nonce keys are charged 5k gas per TIP-1000 Invariant 3
    let mut evm_nonce_five = make_evm(cfg.clone(), 5, TEST_NONCE_KEY);
    let gas_nonce_five = handler
        .validate_initial_tx_gas(&mut evm_nonce_five)
        .unwrap();

    // Delta-based assertion: the difference should be new_account_cost - EXISTING_NONCE_KEY_GAS
    // nonce=0 charges 250k (new account), nonce>0 charges 5k (existing key update)
    let gas_delta = gas_nonce_zero.initial_total_gas() - gas_nonce_five.initial_total_gas();
    let expected_delta = new_account_cost - EXISTING_NONCE_KEY_GAS;
    assert_eq!(
        gas_delta, expected_delta,
        "T1 gas difference between nonce=0 and nonce>0 should be {expected_delta} (new_account_cost - EXISTING_NONCE_KEY_GAS), got {gas_delta}"
    );

    // Verify it's NOT using the pre-T1 NEW_NONCE_KEY_GAS (22,100)
    assert_ne!(
        gas_delta, NEW_NONCE_KEY_GAS,
        "T1 should NOT use pre-T1 NEW_NONCE_KEY_GAS ({NEW_NONCE_KEY_GAS}) for nonce=0 transactions"
    );

    // Case 3: nonce == 0 with regular nonce (nonce_key=0) -> same +250k charge
    let mut evm_regular_nonce = make_evm(cfg, 0, U256::ZERO);
    let gas_regular = handler
        .validate_initial_tx_gas(&mut evm_regular_nonce)
        .unwrap();

    assert_eq!(
        gas_nonce_zero.initial_total_gas(),
        gas_regular.initial_total_gas(),
        "nonce=0 should charge the same regardless of nonce_key (2D vs regular)"
    );
}

/// Test that T1 hardfork correctly charges 5k gas for existing 2D nonce keys (nonce > 0).
///
/// This test validates [TIP-1000] Invariant 3:
/// "SSTORE operations that modify existing non-zero state (non-zero to non-zero)
/// MUST continue to charge 5,000 gas"
///
/// When using an existing 2D nonce key (nonce_key != 0 && nonce > 0), the nonce value
/// transitions from N to N+1 (non-zero to non-zero), which must charge EXISTING_NONCE_KEY_GAS.
///
/// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
#[test]
fn test_t1_existing_2d_nonce_key_charges_5k_gas() {
    use crate::gas_params::tempo_gas_params;
    use revm::handler::Handler;

    const BASE_INTRINSIC_GAS: u64 = 21_000;
    const TEST_TARGET: Address = Address::new([0xBB; 20]);
    const TEST_NONCE_KEY: U256 = U256::from_limbs([99, 0, 0, 0]);
    const SPEC: TempoHardfork = TempoHardfork::T1;
    const EXISTING_NONCE_KEY_GAS: u64 = SPEC.gas_existing_nonce_key();

    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.spec = SPEC;
    cfg.gas_params = tempo_gas_params(TempoHardfork::T1);

    let make_evm = |cfg: CfgEnv<TempoHardfork>, nonce: u64, nonce_key: U256| {
        let journal = Journal::new(CacheDB::new(EmptyDB::default()));
        let ctx = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(TempoBlockEnv::default())
            .with_cfg(cfg)
            .with_tx(TempoTxEnv {
                inner: revm::context::TxEnv {
                    gas_limit: 1_000_000,
                    nonce,
                    ..Default::default()
                },
                tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                    aa_calls: vec![Call {
                        to: TxKind::Call(TEST_TARGET),
                        value: U256::ZERO,
                        input: Bytes::new(),
                    }],
                    nonce_key,
                    ..Default::default()
                })),
                ..Default::default()
            })
            .with_new_journal(journal);
        TempoEvm::<_, ()>::new(ctx, ())
    };

    let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

    // Case 1: Existing 2D nonce key (nonce > 0) should charge EXISTING_NONCE_KEY_GAS
    let mut evm_existing_key = make_evm(cfg.clone(), 5, TEST_NONCE_KEY);
    let gas_existing = handler
        .validate_initial_tx_gas(&mut evm_existing_key)
        .unwrap();

    assert_eq!(
        gas_existing.initial_total_gas(),
        BASE_INTRINSIC_GAS + EXISTING_NONCE_KEY_GAS,
        "T1 existing 2D nonce key (nonce>0) should charge BASE + EXISTING_NONCE_KEY_GAS ({EXISTING_NONCE_KEY_GAS})"
    );

    // Case 2: Regular nonce (nonce_key = 0) with nonce > 0 should NOT charge extra gas
    let mut evm_regular = make_evm(cfg, 5, U256::ZERO);
    let gas_regular = handler.validate_initial_tx_gas(&mut evm_regular).unwrap();

    assert_eq!(
        gas_regular.initial_total_gas(),
        BASE_INTRINSIC_GAS,
        "T1 regular nonce (nonce_key=0, nonce>0) should only charge BASE intrinsic gas"
    );

    // Verify the delta between 2D and regular nonce is exactly EXISTING_NONCE_KEY_GAS
    let gas_delta = gas_existing.initial_total_gas() - gas_regular.initial_total_gas();
    assert_eq!(
        gas_delta, EXISTING_NONCE_KEY_GAS,
        "Difference between existing 2D nonce and regular nonce should be EXISTING_NONCE_KEY_GAS ({EXISTING_NONCE_KEY_GAS})"
    );
}

mod keychain {
    use super::*;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS;
    use tempo_primitives::transaction::{
        KeychainSignature, KeychainVersion, SignatureType,
        key_authorization::{KeyAuthorization, TokenLimit as PrimTokenLimit},
    };

    fn generate_keypair() -> (PrivateKeySigner, Address) {
        let signer = PrivateKeySigner::random();
        let addr = signer.address();
        (signer, addr)
    }

    fn sign_key_auth(
        signer: &PrivateKeySigner,
        key_auth: KeyAuthorization,
    ) -> tempo_primitives::transaction::SignedKeyAuthorization {
        let sig = signer
            .sign_hash_sync(&key_auth.signature_hash())
            .expect("signing failed");
        key_auth.into_signed(PrimitiveSignature::Secp256k1(sig))
    }

    fn test_sig() -> PrimitiveSignature {
        PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature())
    }

    /// Build EVM + handler with a keychain-signature AA tx.
    ///
    /// - `signature`: outer keychain signature; when `None` a default V2
    ///   keychain sig for `user` is used.
    /// - `seed_key`: when `true` the access key is pre-authorized in
    ///   keychain storage (existing-key path).
    fn make_evm(
        user: Address,
        access_key: Address,
        key_auth: Option<tempo_primitives::transaction::SignedKeyAuthorization>,
        spec: TempoHardfork,
        signature: Option<TempoSignature>,
        seed_key: bool,
    ) -> (
        TempoEvm<CacheDB<EmptyDB>, ()>,
        TempoEvmHandler<CacheDB<EmptyDB>, ()>,
    ) {
        let sig = signature
            .unwrap_or_else(|| TempoSignature::Keychain(KeychainSignature::new(user, test_sig())));
        let mut cfg = CfgEnv::<TempoHardfork>::default();
        cfg.spec = spec;

        let tx = TempoTxEnv {
            inner: revm::context::TxEnv {
                caller: user,
                gas_limit: 1_000_000,
                kind: TxKind::Call(Address::ZERO),
                ..Default::default()
            },
            fee_token: Some(DEFAULT_FEE_TOKEN),
            tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
                signature: sig,
                aa_calls: vec![Call {
                    to: TxKind::Call(Address::ZERO),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                key_authorization: key_auth,
                signature_hash: B256::ZERO,
                override_key_id: Some(access_key),
                ..Default::default()
            })),
            ..Default::default()
        };

        let ctx = Context::mainnet()
            .with_db(CacheDB::new(EmptyDB::default()))
            .with_block(TempoBlockEnv::default())
            .with_cfg(cfg)
            .with_tx(tx)
            .with_new_journal(create_test_journal());

        let mut evm: TempoEvm<_, ()> = TempoEvm::new(ctx, ());

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            let mut kc = AccountKeychain::new();
            kc.initialize().unwrap();
            kc.set_transaction_key(Address::ZERO).unwrap();
            kc.set_tx_origin(user).unwrap();
            if seed_key {
                kc.authorize_key(
                    user,
                    access_key,
                    PrecompileSignatureType::Secp256k1,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                    None,
                )
                .unwrap();
            }
        });

        (evm, TempoEvmHandler::new())
    }

    #[test]
    fn test_key_authorization_invalid_signature_rejected() {
        let (_, user) = generate_keypair();
        let key = Address::random();
        let (bad_signer, _) = generate_keypair();

        let signed = sign_key_auth(
            &bad_signer,
            KeyAuthorization::unrestricted(1337, SignatureType::Secp256k1, key),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, true);

        assert!(matches!(
            h.validate_env(&mut evm),
            Err(EVMError::Transaction(
                TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot { .. }
            ))
        ));
    }

    #[test]
    fn test_key_authorization_mismatched_key_id_rejected() {
        let (signer, user) = generate_keypair();
        let wrong_key = Address::random();
        let tx_key = Address::random();

        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1337, SignatureType::Secp256k1, wrong_key),
        );
        let (mut evm, h) = make_evm(user, tx_key, Some(signed), TempoHardfork::T2, None, true);

        assert!(matches!(
            h.validate_env(&mut evm),
            Err(EVMError::Transaction(
                TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys
            ))
        ));
    }

    #[test]
    fn test_key_authorization_chain_id_wildcard() {
        for spec in [TempoHardfork::T1B, TempoHardfork::T2] {
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_auth(
                &signer,
                KeyAuthorization::unrestricted(0, SignatureType::Secp256k1, key),
            );
            let (mut evm, h) = make_evm(user, key, Some(signed), spec, None, false);

            if !spec.is_t1c()
                && let Some(aa_env) = evm.tx.tempo_tx_env.as_mut()
                && let TempoSignature::Keychain(keychain_sig) = &mut aa_env.signature
            {
                // Overwrite the signature version pre-T1C to bypass the version check.
                keychain_sig.version = KeychainVersion::V1;
            }
            let result = h.validate_env(&mut evm);
            if !spec.is_t1c() {
                assert!(
                    result.is_ok(),
                    "{spec:?}: chain_id=0 wildcard should be accepted pre-T1C, got: {result:?}"
                );
            } else {
                assert!(
                    result.is_err(),
                    "{spec:?}: chain_id=0 wildcard should be rejected post-T1C, got: {result:?}"
                );
            }
        }
    }

    #[test]
    fn test_key_authorization_chain_id_wrong_and_matching() {
        // Both pre-T1C and post-T1C: wrong chain_id rejected, matching accepted.
        for spec in [TempoHardfork::T1B, TempoHardfork::T2] {
            // Wrong chain_id → rejected
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_auth(
                &signer,
                KeyAuthorization::unrestricted(99999, SignatureType::Secp256k1, key),
            );
            let (mut evm, h) = make_evm(user, key, Some(signed), spec, None, true);
            assert!(
                h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default())
                    .is_err(),
                "{spec:?}: wrong chain_id should be rejected"
            );

            // Matching chain_id (1 = default CfgEnv) → accepted
            let (signer, user) = generate_keypair();
            let key = Address::random();
            let signed = sign_key_auth(
                &signer,
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key),
            );
            let (mut evm, h) = make_evm(user, key, Some(signed), spec, None, true);
            let result =
                h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
            assert!(
                !matches!(&result, Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason })) if reason.contains("chain_id")),
                "{spec:?}: matching chain_id should be accepted, got: {result:?}"
            );
        }
    }

    #[test]
    fn test_key_authorization_expiry_cached_for_pool_maintenance() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let expiry = u64::MAX - 1;

        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_expiry(expiry),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, false);

        let _ = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert_eq!(evm.key_expiry, Some(expiry));
    }

    #[test]
    fn test_key_authorization_witness_rejected_before_t5() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_witness(B256::repeat_byte(0x53)),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T4, None, false);

        let result = h.validate_env(&mut evm);
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("before T5")
            ),
            "witness-bearing key authorization should be rejected before T5, got: {result:?}"
        );
    }

    #[test]
    fn test_t5_key_authorization_witness_is_not_burned_in_state() {
        use tempo_precompiles::account_keychain::isKeyAuthorizationWitnessBurnedCall;

        let (signer, user) = generate_keypair();
        let key = Address::random();
        let witness = B256::repeat_byte(0x54);
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_witness(witness),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T5, None, false);

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert!(
            result.is_ok(),
            "T5 witness authorization should pass: {result:?}"
        );

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            let keychain = AccountKeychain::new();
            assert!(
                !keychain
                    .is_key_authorization_witness_burned(isKeyAuthorizationWitnessBurnedCall {
                        account: user,
                        witness,
                    })
                    .expect("witness read succeeds"),
                "T5 key authorization must not burn its witness"
            );
        });
    }

    #[test]
    fn test_t6_admin_key_authorization_fields_rejected_before_t6() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).into_admin(user),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T5, None, false);

        let result = h.validate_env(&mut evm);
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("not active before T6")
            ),
            "admin key authorization fields should be rejected before T6, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_account_mismatch() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let wrong_account = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .into_admin(wrong_account),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = h.validate_env(&mut evm);
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("account mismatch")
            ),
            "admin key authorization should be bound to tx.caller, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_root_admin_key_authorization_allows_omitted_account() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let mut key_auth = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key);
        key_auth.is_admin = true;
        assert_eq!(key_auth.account, None);

        let signed = sign_key_auth(&signer, key_auth);
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let env_result = h.validate_env(&mut evm);
        assert!(
            env_result.is_ok(),
            "root-signed admin key authorization should pass stateless validation, got: {env_result:?}"
        );

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert!(
            result.is_ok(),
            "root-signed admin key authorization should not require account, got: {result:?}"
        );

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            let keychain = AccountKeychain::new();
            assert!(
                keychain
                    .is_admin_key(user, key)
                    .expect("admin key status read succeeds"),
                "root-signed admin key should be registered as admin"
            );
        });
    }

    #[test]
    fn test_t6_root_signed_key_authorization_rejects_admin_keychain_submission() {
        let (root_signer, user) = generate_keypair();
        let (_, admin_key) = generate_keypair();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &root_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key),
        );
        let (mut evm, h) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = h.validate_env(&mut evm);
        assert!(
            matches!(
                &env_result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("root transaction signature")
            ),
            "root-signed key authorization should require a root transaction signature, got: {env_result:?}"
        );
    }

    #[test]
    fn test_t6_root_key_authorization_rejects_account_mismatch() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let wrong_account = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_account(wrong_account),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = h.validate_env(&mut evm);
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("key authorization account mismatch")
            ),
            "root-signed key authorization should be bound to tx.caller, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_restrictions() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key)
                .with_expiry(u64::MAX)
                .into_admin(user),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T6, None, false);

        let result = h.validate_env(&mut evm);
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("cannot carry expiry")
            ),
            "admin key authorization should reject restrictions, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_can_authorize_different_admin_key() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::WebAuthn, child_key).into_admin(user),
        );
        let (mut evm, h) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = h.validate_env(&mut evm);
        assert!(
            env_result.is_ok(),
            "admin access key authorization should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert!(
            result.is_ok(),
            "admin access key should authorize a different admin key, got: {result:?}"
        );

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            let keychain = AccountKeychain::new();
            assert!(
                keychain
                    .is_admin_key(user, child_key)
                    .expect("admin key status read succeeds"),
                "child key should be registered as admin"
            );
        });
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_different_transaction_admin_key() {
        let (authorization_signer, authorization_admin_key) = generate_keypair();
        let (_, tx_admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &authorization_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (mut evm, h) = make_evm(
            user,
            tx_admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let result = h.validate_env(&mut evm);
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("must be signed by transaction key")
            ),
            "admin-signed key authorization must use the transaction admin key; auth signer {authorization_admin_key}, tx signer {tx_admin_key}, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_non_admin_authorization_requires_account_binding() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key),
        );
        let (mut evm, h) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let result = h.validate_env(&mut evm);
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("admin-signed key authorization account mismatch")
            ),
            "admin-signed non-admin authorization without account binding should fail in validate_env, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_key_authorization_rejects_admin_signature_type_mismatch() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (mut evm, h) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = h.validate_env(&mut evm);
        assert!(
            env_result.is_ok(),
            "admin-signed key authorization should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::WebAuthn, None)
                .expect("root authorizes WebAuthn admin key");
        });

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("SignatureTypeMismatch")
            ),
            "admin-signed key authorization should reject sidecar signature type mismatch, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_access_key_non_admin_authorization_rejects_account_replay() {
        use tempo_precompiles::account_keychain::getKeyCall;

        let (admin_signer, admin_key) = generate_keypair();
        let alice = Address::random();
        let bob = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(alice),
        );

        let (mut alice_evm, alice_handler) = make_evm(
            alice,
            admin_key,
            Some(signed.clone()),
            TempoHardfork::T6,
            None,
            false,
        );
        let alice_env_result = alice_handler.validate_env(&mut alice_evm);
        assert!(
            alice_env_result.is_ok(),
            "account-bound authorization should pass Alice stateless validation, got: {alice_env_result:?}"
        );

        StorageCtx::enter_ctx(&mut alice_evm.inner.ctx, StorageActions::disabled(), || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(alice, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes Alice admin key");
        });

        let alice_result = alice_handler
            .validate_against_state_and_deduct_caller(&mut alice_evm, &mut Default::default());
        assert!(
            alice_result.is_ok(),
            "account-bound admin-signed non-admin authorization should pass for Alice, got: {alice_result:?}"
        );
        StorageCtx::enter_ctx(&mut alice_evm.inner.ctx, StorageActions::disabled(), || {
            let keychain = AccountKeychain::new();
            let key = keychain
                .get_key(getKeyCall {
                    account: alice,
                    keyId: child_key,
                })
                .expect("child key read succeeds");
            assert_eq!(key.keyId, child_key, "child key should be registered");
            assert!(
                !keychain
                    .is_admin_key(alice, child_key)
                    .expect("admin key status read succeeds"),
                "child key should not be admin"
            );
        });

        let (mut bob_evm, bob_handler) =
            make_evm(bob, admin_key, Some(signed), TempoHardfork::T6, None, false);

        let bob_result = bob_handler.validate_env(&mut bob_evm);
        assert!(
            matches!(
                &bob_result,
                Err(EVMError::Transaction(TempoInvalidTransaction::KeychainValidationFailed { reason }))
                    if reason.contains("key authorization account mismatch")
            ),
            "Alice-bound authorization should not replay for Bob, got: {bob_result:?}"
        );
    }

    #[test]
    fn test_t6_admin_delegation_does_not_apply_child_fee_limit() {
        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let gas_limit = 100_000;
        let fee = U256::from(gas_limit);
        let child_spending_limit = fee - U256::ONE;

        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_limits(vec![PrimTokenLimit {
                    token: DEFAULT_FEE_TOKEN,
                    limit: child_spending_limit,
                    period: 60,
                }])
                .with_account(user),
        );
        let (mut evm, h) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );
        evm.inner.ctx.tx.inner.gas_limit = gas_limit;
        evm.inner.ctx.tx.inner.gas_price = 1_000_000_000_000;
        evm.inner.ctx.tx.inner.gas_priority_fee = Some(1_000_000_000_000);

        let env_result = h.validate_env(&mut evm);
        assert!(
            env_result.is_ok(),
            "admin delegation should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            TIP20Setup::path_usd(user)
                .with_issuer(user)
                .with_mint(user, fee * U256::from(2))
                .apply()
                .expect("pathUSD setup succeeds");

            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert!(
            result.is_ok(),
            "admin delegation should not precharge fees against child key limits, got: {result:?}"
        );
    }

    #[test]
    fn test_t6_admin_delegation_preserves_admin_transaction_key() {
        use tempo_precompiles::account_keychain::getTransactionKeyCall;

        let (admin_signer, admin_key) = generate_keypair();
        let user = Address::random();
        let child_key = Address::random();
        let signed = sign_key_auth(
            &admin_signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, child_key)
                .with_account(user),
        );
        let (mut evm, h) = make_evm(
            user,
            admin_key,
            Some(signed),
            TempoHardfork::T6,
            None,
            false,
        );

        let env_result = h.validate_env(&mut evm);
        assert!(
            env_result.is_ok(),
            "admin delegation should pass stateless validation, got: {env_result:?}"
        );

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            let mut keychain = AccountKeychain::new();
            keychain
                .authorize_admin_key(user, admin_key, PrecompileSignatureType::Secp256k1, None)
                .expect("root authorizes admin key");
        });

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert!(
            result.is_ok(),
            "admin delegation should pass, got: {result:?}"
        );

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            let keychain = AccountKeychain::new();
            let transaction_key = keychain
                .get_transaction_key(getTransactionKeyCall {}, user)
                .expect("transaction key read succeeds");
            assert_eq!(
                transaction_key, admin_key,
                "admin delegation must preserve the signer key as transaction key"
            );
        });
    }

    #[test]
    fn test_keychain_signature_with_valid_authorized_key() {
        let (mut evm, h) = make_evm(
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            None,
            TempoHardfork::T2,
            None,
            true,
        );

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert!(
            !matches!(
                result,
                Err(EVMError::Transaction(
                    TempoInvalidTransaction::KeychainValidationFailed { .. }
                ))
            ),
            "Valid authorized key should pass, got: {result:?}"
        );
    }

    #[test]
    fn test_keychain_version_rejection() {
        let caller = Address::random();

        // V1 (legacy) rejected post-T1C
        let v1 = TempoSignature::Keychain(KeychainSignature::new_v1(caller, test_sig()));
        let (mut evm, h) = make_evm(
            caller,
            Address::ZERO,
            None,
            TempoHardfork::T2,
            Some(v1),
            false,
        );
        assert!(matches!(
            h.validate_env(&mut evm),
            Err(EVMError::Transaction(
                TempoInvalidTransaction::LegacyKeychainSignature
            ))
        ));

        // V2 rejected pre-T1C
        let v2 = TempoSignature::Keychain(KeychainSignature::new(caller, test_sig()));
        let (mut evm, h) = make_evm(
            caller,
            Address::ZERO,
            None,
            TempoHardfork::T1B,
            Some(v2),
            false,
        );
        assert!(matches!(
            h.validate_env(&mut evm),
            Err(EVMError::Transaction(
                TempoInvalidTransaction::V2KeychainBeforeActivation
            ))
        ));
    }

    #[test]
    fn test_key_authorization_without_existing_key_passes() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T2, None, false);

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());
        assert!(
            !matches!(
                result,
                Err(EVMError::Transaction(
                    TempoInvalidTransaction::KeychainValidationFailed { .. }
                        | TempoInvalidTransaction::AccessKeyCannotAuthorizeOtherKeys
                        | TempoInvalidTransaction::KeyAuthorizationNotSignedByRoot { .. }
                        | TempoInvalidTransaction::KeychainPrecompileError { .. }
                ))
            ),
            "Same-tx auth+use should pass when key does not exist, got: {result:?}"
        );
    }

    #[test]
    fn test_same_tx_key_authorization_rejects_fee_above_new_limit_before_auth() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let gas_limit = 100_000;
        let fee = U256::from(gas_limit);
        let spending_limit = fee - U256::ONE;

        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_limits(vec![
                PrimTokenLimit {
                    token: DEFAULT_FEE_TOKEN,
                    limit: spending_limit,
                    period: 60,
                },
            ]),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T3, None, false);
        evm.inner.ctx.tx.inner.gas_limit = gas_limit;
        evm.inner.ctx.tx.inner.gas_price = 1_000_000_000_000;
        evm.inner.ctx.tx.inner.gas_priority_fee = Some(1_000_000_000_000);

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            TIP20Setup::path_usd(user)
                .with_issuer(user)
                .with_mint(user, fee * U256::from(2))
                .apply()
                .expect("pathUSD setup succeeds");
        });

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());

        assert!(
            matches!(
                &result,
                Err(EVMError::Transaction(TempoInvalidTransaction::CollectFeePreTx(
                    FeePaymentError::Other(reason)
                ))) if reason.contains("SpendingLimitExceeded")
            ),
            "same-tx auth+use should reject fee above the new key limit before auth, got: {result:?}"
        );
        assert_eq!(evm.collected_fee, U256::ZERO);
        assert!(
            evm.inner
                .ctx
                .journaled_state
                .inner
                .logs
                .iter()
                .all(|log| log.address != ACCOUNT_KEYCHAIN_ADDRESS),
            "fee-limit rejection must happen before key authorization emits events"
        );
    }

    #[test]
    fn test_stale_collected_fee_not_charged_to_zero_fee_same_tx_auth_use() {
        let (signer, user) = generate_keypair();
        let key = Address::random();
        let stale_fee = U256::from(100_000);
        let spending_limit = stale_fee - U256::ONE;

        let signed = sign_key_auth(
            &signer,
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key).with_limits(vec![
                PrimTokenLimit {
                    token: DEFAULT_FEE_TOKEN,
                    limit: spending_limit,
                    period: 60,
                },
            ]),
        );
        let (mut evm, h) = make_evm(user, key, Some(signed), TempoHardfork::T3, None, false);
        evm.collected_fee = stale_fee;
        evm.inner.ctx.tx.inner.gas_limit = 100_000;
        evm.inner.ctx.tx.inner.gas_price = 0;
        evm.inner.ctx.tx.inner.gas_priority_fee = Some(0);

        StorageCtx::enter_ctx(&mut evm.inner.ctx, StorageActions::disabled(), || {
            TIP20Setup::path_usd(user)
                .with_issuer(user)
                .with_mint(user, stale_fee * U256::from(2))
                .apply()
                .expect("pathUSD setup succeeds");
        });

        h.validate_env(&mut evm)
            .expect("zero-fee same-tx auth/use env validation should pass");
        assert_eq!(evm.collected_fee, U256::ZERO);

        let result = h.validate_against_state_and_deduct_caller(&mut evm, &mut Default::default());

        assert!(
            result.is_ok(),
            "zero-fee same-tx auth/use must not charge stale fee, got: {result:?}"
        );
        assert_eq!(evm.collected_fee, U256::ZERO);
    }
}

/// TIP-1016: Standard CREATE tx should populate initial_state_gas with
/// create_state_gas when state gas is enabled (T4+).
/// Note: new_account_state_gas for the caller (nonce==0 with 2D nonce) is added
/// later in validate_against_state_and_deduct_caller, not in upstream initial_tx_gas.
#[test]
fn test_state_gas_standard_create_tx_populates_initial_state_gas() {
    // TIP-1016 is opt-in via amsterdam_eip8037; manually enable for this test.
    let gas_params = crate::gas_params::tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let init_gas = gas_params.initial_tx_gas(
        &initcode, true, // is_create
        0, 0, 0,
    );

    let expected_state_gas = gas_params.create_state_gas();

    assert!(
        expected_state_gas > 0,
        "State gas constants should be non-zero"
    );
    assert_eq!(
        init_gas.initial_state_gas,
        expected_state_gas,
        "CREATE tx should have initial_state_gas = create_state_gas ({})",
        gas_params.create_state_gas()
    );
}

/// TIP-1016: Standard CALL tx should have zero initial_state_gas.
#[test]
fn test_state_gas_standard_call_tx_zero_initial_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let calldata = Bytes::from(vec![1, 2, 3]);

    let init_gas = gas_params.initial_tx_gas(
        &calldata, false, // not create
        0, 0, 0,
    );

    assert_eq!(
        init_gas.initial_state_gas, 0,
        "CALL tx should have zero initial_state_gas"
    );
}

/// TIP-1016: AA CREATE tx should populate initial_state_gas.
#[test]
fn test_state_gas_aa_create_tx_populates_initial_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let call = Call {
        to: TxKind::Create,
        value: U256::ZERO,
        input: initcode,
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    let expected_state_gas = gas_params.create_state_gas();

    assert_eq!(
        gas.initial_state_gas, expected_state_gas,
        "AA CREATE tx should have initial_state_gas = create_state_gas"
    );
}

/// TIP-1016: AA CALL tx should have zero initial_state_gas.
#[test]
fn test_state_gas_aa_call_tx_zero_initial_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let calldata = Bytes::from(vec![1, 2, 3]);

    let call = Call {
        to: TxKind::Call(Address::random()),
        value: U256::ZERO,
        input: calldata,
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    assert_eq!(
        gas.initial_state_gas, 0,
        "AA CALL tx should have zero initial_state_gas"
    );
}

/// TIP-1016: validate_initial_tx_gas for standard CREATE tx should set
/// initial_state_gas when T4 is active and state gas is enabled.
#[test]
fn test_state_gas_validate_initial_tx_gas_create_t4() {
    let initcode = Bytes::from(vec![0x60, 0x80]);
    let mut test = TestHandlerEvm::tx(TempoHardfork::T4, |tx_env| {
        tx_env.inner.gas_limit = 60_000_000;
        tx_env.inner.kind = TxKind::Create;
        tx_env.inner.data = initcode;
    });
    let init_gas = test.validate_initial_tx_gas();

    // create_state_gas (from upstream initial_tx_gas for CREATE) +
    // new_account_state_gas (from Tempo's nonce==0 check for the caller)
    let expected_state_gas =
        test.gas_params().create_state_gas() + test.gas_params().new_account_state_gas();

    assert_eq!(
        init_gas.initial_state_gas, expected_state_gas,
        "T4 CREATE tx with nonce==0 should have create_state_gas + new_account_state_gas"
    );
}

/// TIP-1016: When enable_amsterdam_eip8037 is true, tx gas limit can exceed the cap
/// (upstream revm validation skips the cap check).
#[test]
fn test_state_gas_tx_gas_limit_above_cap_allowed() {
    let calldata = Bytes::from(vec![1, 2, 3]);

    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            gas_limit: 60_000_000,
            kind: TxKind::Call(Address::random()),
            data: calldata,
            ..Default::default()
        },
        ..Default::default()
    };

    // TIP-1016 is opt-in via amsterdam_eip8037; manually enable for this test.
    let mut test = TestHandlerEvm::with_cfg(TempoHardfork::T4, tx_env, |cfg| {
        cfg.tx_gas_limit_cap = Some(30_000_000);
        cfg.enable_amsterdam_eip8037 = true;
        cfg.gas_params =
            crate::gas_params::tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);
    });

    // validate_env should pass even though gas_limit > cap
    let result = test.validate_env();
    assert!(
        result.is_ok(),
        "With enable_amsterdam_eip8037=true, tx gas limit above cap should be allowed, got: {:?}",
        result.err()
    );
}

/// TIP-1016: When enable_amsterdam_eip8037 is false (pre-T4), tx gas limit above cap is rejected.
#[test]
fn test_state_gas_tx_gas_limit_above_cap_rejected_pre_t4() {
    let calldata = Bytes::from(vec![1, 2, 3]);

    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            gas_limit: 60_000_000, // Double the cap
            kind: TxKind::Call(Address::random()),
            data: calldata,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut test = TestHandlerEvm::with_cfg(TempoHardfork::T1, tx_env, |cfg| {
        cfg.tx_gas_limit_cap = Some(30_000_000);
    });

    // validate_env should reject: gas_limit > cap with state gas disabled
    let result = test.validate_env();
    assert!(
        result.is_err(),
        "With enable_amsterdam_eip8037=false, tx gas limit above cap should be rejected"
    );
}

/// TIP-1016 regression: subblock fee-payment halt must not exceed the gas cap.
#[test]
fn test_subblock_fee_payment_halt_clamps_to_gas_cap_t4() {
    const CAP: u64 = 30_000_000;
    const TX_GAS_LIMIT: u64 = 60_000_000;

    let aa_env = TempoBatchCallEnv {
        subblock_transaction: true,
        ..Default::default()
    };
    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            gas_limit: TX_GAS_LIMIT,
            kind: TxKind::Call(Address::random()),
            ..Default::default()
        },
        tempo_tx_env: Some(Box::new(aa_env)),
        ..Default::default()
    };

    let mut test = TestHandlerEvm::with_cfg(TempoHardfork::T4, tx_env, |cfg| {
        cfg.tx_gas_limit_cap = Some(CAP);
        cfg.enable_amsterdam_eip8037 = true;
        cfg.gas_params =
            crate::gas_params::tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);
    });

    // Sanity: T4 must actually have the cap-skip enabled so tx_gas_limit > cap is legal.
    assert!(
        test.cfg().enable_amsterdam_eip8037,
        "T4 must enable enable_amsterdam_eip8037 for this regression to apply"
    );

    let err = EVMError::Transaction(TempoInvalidTransaction::EthInvalidTransaction(
        InvalidTransaction::LackOfFundForMaxFee {
            fee: Box::new(U256::ZERO),
            balance: Box::new(U256::ZERO),
        },
    ));

    let result = test
        .handler
        .catch_error(&mut test.evm, err)
        .expect("subblock fee-payment failure must be converted to a halt, not a hard error");

    match result {
        ExecutionResult::Halt { reason, gas, .. } => {
            assert!(
                matches!(reason, TempoHaltReason::SubblockTxFeePayment),
                "expected SubblockTxFeePayment halt, got {reason:?}"
            );
            assert_eq!(
                gas.total_gas_spent(),
                CAP,
                "regular gas charged on subblock fee-payment halt must be clamped to \
                     tx_gas_limit_cap (got {} for tx.gas_limit={} cap={})",
                gas.total_gas_spent(),
                TX_GAS_LIMIT,
                CAP,
            );
            assert_eq!(
                gas.state_gas_spent_final(),
                0,
                "halt reports zero state gas"
            );
        }
        other => panic!("expected ExecutionResult::Halt, got {other:?}"),
    }
}

#[test]
fn test_subblock_paused_fee_token_halts_as_fee_payment_failure() {
    let aa_env = TempoBatchCallEnv {
        subblock_transaction: true,
        ..Default::default()
    };
    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            gas_limit: 100_000,
            kind: TxKind::Call(Address::random()),
            ..Default::default()
        },
        tempo_tx_env: Some(Box::new(aa_env)),
        ..Default::default()
    };

    let mut test = TestHandlerEvm::with_cfg(TempoHardfork::T4, tx_env, |cfg| {
        cfg.tx_gas_limit_cap = Some(30_000_000);
        cfg.enable_amsterdam_eip8037 = true;
        cfg.gas_params =
            crate::gas_params::tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);
    });

    let err = EVMError::Transaction(TempoInvalidTransaction::FeeTokenPaused {
        address: PATH_USD_ADDRESS,
    });

    let result = test
        .handler
        .catch_error(&mut test.evm, err)
        .expect("subblock paused fee-token failure must be converted to a halt");

    match result {
        ExecutionResult::Halt { reason, gas, .. } => {
            assert!(
                matches!(reason, TempoHaltReason::SubblockTxFeePayment),
                "expected SubblockTxFeePayment halt, got {reason:?}"
            );
            assert_eq!(gas.total_gas_spent(), 100_000);
            assert_eq!(
                gas.state_gas_spent_final(),
                0,
                "halt reports zero state gas"
            );
        }
        other => panic!("expected ExecutionResult::Halt, got {other:?}"),
    }
}

/// TIP-1016: Pre-T4 behavior unchanged - initial_state_gas is still populated
/// by upstream revm for CREATE txs (it's a property of gas_params, not gating).
/// But enable_amsterdam_eip8037=false means the reservoir won't be used.
#[test]
fn test_state_gas_backward_compat_t1_no_state_gas_enabled() {
    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.spec = TempoHardfork::T1;
    cfg.gas_params = tempo_gas_params(TempoHardfork::T1);

    assert!(
        !cfg.enable_amsterdam_eip8037,
        "Pre-T4 should NOT have enable_amsterdam_eip8037"
    );

    let calldata = Bytes::from(vec![1, 2, 3]);

    let journal = Journal::new(CacheDB::new(EmptyDB::default()));
    let tx_env = TempoTxEnv {
        inner: revm::context::TxEnv {
            gas_limit: 1_000_000,
            kind: TxKind::Call(Address::random()),
            data: calldata,
            ..Default::default()
        },
        ..Default::default()
    };

    let ctx = Context::mainnet()
        .with_db(CacheDB::new(EmptyDB::default()))
        .with_block(TempoBlockEnv::default())
        .with_cfg(cfg)
        .with_tx(tx_env)
        .with_new_journal(journal);
    let mut evm = TempoEvm::<_, ()>::new(ctx, ());
    let handler: TempoEvmHandler<CacheDB<EmptyDB>, ()> = TempoEvmHandler::new();

    let init_gas = handler.validate_initial_tx_gas(&mut evm).unwrap();

    // CALL tx - no state gas in either case
    assert_eq!(init_gas.initial_state_gas, 0);
}

/// TIP-1016: AA batch with multiple calls including CREATE should track
/// state gas for the CREATE call only.
#[test]
fn test_state_gas_aa_mixed_batch_create_and_call() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let calldata = Bytes::from(vec![1, 2, 3]);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let calls = vec![
        Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: calldata,
        },
        Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode,
        },
    ];

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: calls,
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    // Only the CREATE call contributes state gas
    let expected_state_gas = gas_params.create_state_gas();

    assert_eq!(
        gas.initial_state_gas, expected_state_gas,
        "Mixed batch should have state gas only from CREATE call"
    );
}

/// TIP-1016: AA batch with multiple CREATE calls accumulates state gas.
#[test]
fn test_state_gas_aa_multiple_create_calls() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let calls = vec![
        Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode.clone(),
        },
        Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: initcode,
        },
    ];

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: calls,
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    // Two CREATE calls should accumulate state gas
    let per_create_state_gas = gas_params.create_state_gas();

    assert_eq!(
        gas.initial_state_gas,
        per_create_state_gas * 2,
        "Multiple CREATE calls should accumulate initial_state_gas"
    );
}

/// TIP-1016: In multi-call execution, per-call init gas uses
/// `InitialAndFloorGas::new(0, 0)` so state gas is only deducted once
/// upfront via `calculate_aa_batch_intrinsic_gas`, not per call.
#[test]
fn test_state_gas_multi_call_per_call_init_has_zero_state_gas() {
    let zero_init_gas = InitialAndFloorGas::new(0, 0);
    assert_eq!(
        zero_init_gas.initial_state_gas, 0,
        "Per-call init gas in multi-call must have zero initial_state_gas; \
             state gas is deducted once upfront, not per call"
    );
}

/// TIP-1016: Multi-call corrected gas (success path) must use flattened
/// reconstruction (Gas::new_spent + erase_cost) to be robust under the
/// EIP-8037 reservoir model, and must preserve accumulated state_gas_spent.
#[test]
fn test_state_gas_multi_call_corrected_gas_success_preserves_state_gas() {
    let gas_limit: u64 = 1_000_000;
    let total_gas_spent: u64 = 400_000;
    let accumulated_state_gas: i64 = 150_000;
    let accumulated_refund: i64 = 5_000;

    // Simulate flattened gas reconstruction (same pattern as execute_multi_call_with)
    let mut corrected_gas = Gas::new_spent_with_reservoir(gas_limit, 0);
    corrected_gas.erase_cost(gas_limit - total_gas_spent);
    corrected_gas.set_refund(accumulated_refund);
    corrected_gas.set_state_gas_spent(accumulated_state_gas);

    assert_eq!(
        corrected_gas.total_gas_spent(),
        total_gas_spent,
        "Flattened gas must have correct spent"
    );
    assert_eq!(
        corrected_gas.used(),
        total_gas_spent - accumulated_refund as u64,
        "Flattened gas must have correct used (spent - refunded)"
    );
    assert_eq!(
        corrected_gas.state_gas_spent(),
        accumulated_state_gas,
        "Corrected gas must preserve accumulated state_gas_spent"
    );
    assert_eq!(
        corrected_gas.reservoir(),
        0,
        "Flattened gas must have zero reservoir"
    );
}

/// TIP-1016: AA auth list entries with nonce==0 should track state gas.
#[test]
fn test_state_gas_aa_auth_list_nonce_zero() {
    // TIP-1016 is opt-in via amsterdam_eip8037; manually enable for this test.
    let gas_params = crate::gas_params::tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }],
        tempo_authorization_list: vec![RecoveredTempoAuthorization::new(
            TempoSignedAuthorization::new_unchecked(
                alloy_eips::eip7702::Authorization {
                    chain_id: U256::ONE,
                    address: Address::random(),
                    nonce: 0,
                },
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    alloy_primitives::Signature::test_signature(),
                )),
            ),
        )],
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    // State gas = per-auth state gas (225k) + nonce==0 account creation state gas (225k)
    // Use hard-coded expected values to catch missing gas_params overrides.
    assert_eq!(
        gas.initial_state_gas,
        225_000 + 225_000,
        "Auth list entry should track per-auth state gas (225k) + nonce==0 account creation state gas (225k)"
    );
}

/// TIP-1016: AA nonce==0 new account should track state gas in T4.
#[test]
fn test_state_gas_aa_nonce_zero_new_account() {
    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }],
        nonce_key: U256::ONE,
        ..Default::default()
    };

    let mut test = TestHandlerEvm::aa(TempoHardfork::T4, aa_env, |tx_env| {
        tx_env.inner.gas_limit = 60_000_000;
        tx_env.inner.nonce = 0;
    });
    let init_gas = test.validate_initial_tx_gas();

    assert_eq!(
        init_gas.initial_state_gas,
        test.gas_params().new_account_state_gas(),
        "AA tx with nonce==0 should track new_account_state_gas in T4"
    );
}

/// TIP-1016: Auth list state gas (GasId 254) must be zero on T1.
#[test]
fn test_state_gas_auth_list_zero_on_t1() {
    let gas_params = tempo_gas_params(TempoHardfork::T1);
    assert_eq!(
        gas_params.new_account_state_gas(),
        0,
        "Auth account creation state gas must be zero on T1"
    );

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }],
        tempo_authorization_list: vec![RecoveredTempoAuthorization::new(
            TempoSignedAuthorization::new_unchecked(
                alloy_eips::eip7702::Authorization {
                    chain_id: U256::ONE,
                    address: Address::random(),
                    nonce: 0,
                },
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    alloy_primitives::Signature::test_signature(),
                )),
            ),
        )],
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T1,
    )
    .unwrap();

    assert_eq!(
        gas.initial_state_gas, 0,
        "T1 auth list nonce==0 should have zero initial_state_gas"
    );
}

/// TIP-1016: Standard tx with nonce==0 should track state gas on T4 only.
#[test]
fn test_state_gas_standard_tx_nonce_zero_t4() {
    let calldata = Bytes::from(vec![1, 2, 3]);
    let mut test = TestHandlerEvm::tx(TempoHardfork::T4, |tx_env| {
        tx_env.inner.gas_limit = 60_000_000;
        tx_env.inner.kind = TxKind::Call(Address::random());
        tx_env.inner.nonce = 0;
        tx_env.inner.data = calldata;
    });
    let init_gas = test.validate_initial_tx_gas();

    assert_eq!(
        init_gas.initial_state_gas,
        test.gas_params().new_account_state_gas(),
        "T4 standard tx with nonce==0 should track new_account_state_gas"
    );
}

/// TIP-1016: Standard tx with nonce==0 should NOT track state gas on T1.
#[test]
fn test_state_gas_standard_tx_nonce_zero_t1_no_state_gas() {
    let calldata = Bytes::from(vec![1, 2, 3]);

    let mut test = TestHandlerEvm::tx(TempoHardfork::T1, |tx_env| {
        tx_env.inner.gas_limit = 60_000_000;
        tx_env.inner.kind = TxKind::Call(Address::random());
        tx_env.inner.nonce = 0;
        tx_env.inner.data = calldata;
    });
    let init_gas = test.validate_initial_tx_gas();

    assert_eq!(
        init_gas.initial_state_gas, 0,
        "T1 standard tx with nonce==0 must NOT track state gas"
    );
}

/// TIP-1016: `initial_total_gas >= initial_state_gas` invariant must hold for
/// AA CREATE calls. Without this, `execute_multi_call_with()` computes
/// `regular_initial_gas = initial_total_gas.saturating_sub(initial_state_gas)` as 0,
/// giving the transaction its full gas_limit for free.
#[test]
fn test_state_gas_aa_create_total_gas_includes_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);
    let initcode = Bytes::from(vec![0x60, 0x80]);

    let call = Call {
        to: TxKind::Create,
        value: U256::ZERO,
        input: initcode,
    };

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![call],
        key_authorization: None,
        signature_hash: B256::ZERO,
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    assert!(
        gas.initial_total_gas() >= gas.initial_state_gas,
        "invariant violated: initial_total_gas ({}) < initial_state_gas ({})",
        gas.initial_total_gas(),
        gas.initial_state_gas,
    );
}

/// TIP-1016: `initial_total_gas >= initial_state_gas` invariant must hold for
/// AA auth list entries with nonce==0.
#[test]
fn test_state_gas_aa_auth_nonce_zero_total_gas_includes_state_gas() {
    let gas_params = tempo_gas_params(TempoHardfork::T4);

    let aa_env = TempoBatchCallEnv {
        signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
            alloy_primitives::Signature::test_signature(),
        )),
        aa_calls: vec![Call {
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::from(vec![1, 2, 3]),
        }],
        tempo_authorization_list: vec![RecoveredTempoAuthorization::new(
            TempoSignedAuthorization::new_unchecked(
                alloy_eips::eip7702::Authorization {
                    chain_id: U256::ONE,
                    address: Address::random(),
                    nonce: 0,
                },
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    alloy_primitives::Signature::test_signature(),
                )),
            ),
        )],
        ..Default::default()
    };

    let gas = calculate_aa_batch_intrinsic_gas(
        &aa_env,
        &gas_params,
        None::<std::iter::Empty<&AccessListItem>>,
        TempoHardfork::T4,
    )
    .unwrap();

    assert!(
        gas.initial_total_gas() >= gas.initial_state_gas,
        "invariant violated: initial_total_gas ({}) < initial_state_gas ({})",
        gas.initial_total_gas(),
        gas.initial_state_gas,
    );
}

/// TIP-1016: CREATE state gas is charged upfront and must be spent even if a later AA step reverts.
#[test]
fn test_state_gas_failed_batch_preserves_upfront_create_intrinsic_gas() {
    let tx_gas_limit = 1_000_000u64;
    let (calls, call_results) = (
        vec![
            Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: Bytes::from(vec![0x60, 0x80]),
            },
            Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: Bytes::new(),
            },
        ],
        [
            (InstructionResult::Stop, 10_000u64),
            (InstructionResult::Revert, 7_000u64),
        ],
    );

    let aa_env = make_aa_env(calls.clone());
    let mut test = TestHandlerEvm::aa(TempoHardfork::T4, aa_env, |tx_env| {
        tx_env.inner.caller = Address::random();
        tx_env.inner.gas_limit = tx_gas_limit;
        // Keep nonce != 0 so this isolates CREATE state gas from caller account-creation gas.
        tx_env.inner.nonce = 1;
    });

    let init_gas = test.validate_initial_tx_gas();
    assert_eq!(
        init_gas.initial_state_gas,
        test.gas_params().create_state_gas(),
        "first-call CREATE should contribute create_state_gas to AA intrinsic gas"
    );
    let (gas_limit, reservoir) = test.evm.initial_gas_and_reservoir(&init_gas);

    let mut call_idx = 0usize;
    let result = test
        .handler
        .execute_multi_call_with(
            &mut test.evm,
            gas_limit,
            reservoir,
            calls,
            |_handler, _evm, gas, _reservoir| {
                // Feed the batch executor deterministic per-call outcomes without running real EVM code.
                let (instruction_result, spent) = call_results[call_idx];
                call_idx += 1;

                let mut gas = Gas::new(gas);
                gas.set_spent(spent);

                Ok(FrameResult::Call(CallOutcome::new(
                    InterpreterResult::new(instruction_result, Bytes::new(), gas),
                    0..0,
                )))
            },
        )
        .expect("execute_multi_call_with should return a failed frame result");

    let expected_spent =
        init_gas.initial_total_gas() + call_results.iter().map(|(_, spent)| spent).sum::<u64>();

    // Pays CREATE state gas + both call costs. CREATE is charged upfront via intrinsic gas, and NOT refunded.
    assert_eq!(result.instruction_result(), InstructionResult::Revert);
    assert_eq!(result.gas().total_gas_spent(), expected_spent);
    assert_eq!(result.gas().remaining(), tx_gas_limit - expected_spent);
    assert_eq!(result.gas().state_gas_spent(), 0);
    assert_eq!(result.gas().reservoir(), 0);
}
