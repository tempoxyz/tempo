use super::*;
use crate::block::execution_gas_used;
use evm2::TxResult;
use reth_evm::BlockExecutorFactory;

const CALLER: Address = Address::repeat_byte(0x71);
const CONTRACT: Address = Address::repeat_byte(0x72);

/// Ported from the revm TIP-1016 branch. Calling the just-deployed contract
/// proves CREATE succeeded before the later call rolls the entire batch back.
#[test]
fn test_t14_aa_failed_batch_refunds_rolled_back_create_state_gas() -> eyre::Result<()> {
    let signer = P256KeyPair::random();
    let created = signer.address.create(1);
    let batch = signer.sign_tx(
        TxBuilder::new()
            .nonce(1)
            .create(&bytes!("600580600b6000396000f360006000fd"))
            .call(created, &[])
            .gas_limit(5_000_000)
            .build(),
    )?;
    for cap in [100_000, 16_777_216] {
        let run = |zero_create_state_gas| -> eyre::Result<u64> {
            let mut evm = evm(cap);
            fund_account_with_nonce(&mut evm, signer.address, 1);
            if zero_create_state_gas {
                let mut version = *evm.version();
                version.gas_params[evm2::version::GasId::CreateState] = 0;
                let precompiles = tempo_precompiles::TempoPrecompiles::<TempoEvmTypes>::new(
                    TempoHardfork::T14,
                    evm.ext().actions.clone(),
                    evm.ext().non_creditable_slots.clone(),
                );
                evm.set_execution_config(
                    ExecutionConfig::for_spec_and_version(TempoHardfork::T14, version),
                    TempoHardfork::T14,
                    tempo_tx_registry(SpecId::OSAKA),
                    precompiles,
                );
            }
            let result = evm.transact_commit(
                Recovered::new_unchecked(TempoTxEnvelope::AA(batch.clone()), signer.address).into(),
            )?;
            assert_eq!(result.stop, evm2::interpreter::InstrStop::Revert);
            assert_eq!(result.state_gas_spent, 0);
            assert!(evm.state_mut().account(&created)?.load_code()?.is_empty());
            Ok(result.tx_gas_used())
        };
        assert_eq!(
            run(false)?,
            run(true)?,
            "rolled-back CREATE must not be billed"
        );
    }
    Ok(())
}

fn evm(cap: u64) -> TempoEvm<'static> {
    let spec = TempoHardfork::T14;
    let mut version = tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, false);
    version.chain_id = 1;
    version.tx_gas_limit_cap = cap;
    version
        .features
        .remove(EvmFeatures::BALANCE_CHECK | EvmFeatures::BALANCE_TOP_UP);
    let mut evm = crate::TempoEvmConfig::moderato().evm_with_env(
        InMemoryDB::default(),
        crate::TempoEvmEnv::new_with_version(
            spec,
            TempoBlockEnv {
                gas_limit: U256::from(30_000_000),
                ..Default::default()
            },
            version,
        ),
    );
    fund_account_with_nonce(&mut evm, CALLER, 1);
    evm.overlay_db_mut().insert_account_info(
        &STORAGE_CREDITS_ADDRESS,
        AccountInfo::default().with_nonce(1),
    );
    evm
}

fn install(evm: &mut TempoEvm<'static>, address: Address, code: Bytecode) {
    evm.overlay_db_mut()
        .insert_account_info(&address, AccountInfo::default().with_code(code));
}

fn run_storage(
    mode: CreditMode,
    body: &[u8],
    credits: u64,
    cap: u64,
    limit: u64,
) -> eyre::Result<(TxResult<TempoEvmTypes>, TempoEvm<'static>)> {
    let mut evm = evm(cap);
    install(&mut evm, CONTRACT, bytecode_with_tip1060_mode(mode, body));
    seed_storage_credit_balance(&mut evm, CONTRACT, credits);
    let result = evm.transact_commit(legacy_tx_env(
        CALLER,
        1,
        CONTRACT.into(),
        Bytes::new(),
        limit,
    ))?;
    Ok((result, evm))
}

#[test]
fn storage_modes_use_state_gas_with_and_without_a_reservoir() -> eyre::Result<()> {
    // Exercise no reservoir, partial spill, and a reservoir that funds the whole charge.
    for (cap, limit) in [(1_000_000, 800_000), (600_000, 800_000), (100_000, 800_000)] {
        for mode in [CreditMode::Refund, CreditMode::Preserve, CreditMode::Direct] {
            for credits in [0, 1] {
                let (result, mut evm) =
                    run_storage(mode, &hex!("600160005500"), credits, cap, limit)?;
                assert!(
                    result.status,
                    "{mode:?}, credits={credits}, cap={cap}: {:?}",
                    result.stop
                );
                let consumed = credits != 0 && mode != CreditMode::Preserve;
                assert_eq!(
                    result.state_gas_spent,
                    if consumed { 0 } else { STORAGE_CREDIT_VALUE }
                );
                assert_eq!(
                    storage_credit_balance(&mut evm, CONTRACT),
                    credits - u64::from(consumed)
                );
                assert_eq!(
                    result.refunded, 0,
                    "state settlement must not enter the execution refund counter"
                );
                assert!(execution_gas_used(&result) < 60_000);
                assert!(result.tx_gas_used() <= limit);
            }
        }
    }
    Ok(())
}

#[test]
fn create_clear_set_follows_credit_modes_without_eip8037_slot_refills() -> eyre::Result<()> {
    for mode in [CreditMode::Refund, CreditMode::Preserve, CreditMode::Direct] {
        for cap in [100_000, 2_000_000] {
            let (result, mut evm) = run_storage(
                mode,
                &hex!("60016000556000600055600260005500"),
                0,
                cap,
                1_000_000,
            )?;
            assert!(result.status);
            let preserve = mode == CreditMode::Preserve;
            assert_eq!(
                result.state_gas_spent,
                STORAGE_CREDIT_VALUE * if preserve { 2 } else { 1 }
            );
            assert_eq!(
                storage_credit_balance(&mut evm, CONTRACT),
                u64::from(preserve)
            );
            assert_eq!(result.refunded, 5_000);
            assert!(execution_gas_used(&result) < 60_000);
        }
    }
    Ok(())
}

#[test]
fn revert_and_halt_restore_state_gas_but_halt_consumes_spill() -> eyre::Result<()> {
    for (cap, limit) in [(100_000, 800_000), (1_000_000, 800_000)] {
        for (ending, halt) in [(hex!("60006000fd").to_vec(), false), (vec![0xfe], true)] {
            let mut code = hex!("6001600055").to_vec();
            code.extend(ending);
            let (result, mut evm) = run_storage(CreditMode::Refund, &code, 1, cap, limit)?;
            assert!(!result.status);
            assert_eq!(result.state_gas_spent, 0);
            assert_eq!(result.refunded, 0);
            assert_eq!(storage_credit_balance(&mut evm, CONTRACT), 1);
            if halt {
                assert_eq!(result.tx_gas_used(), cap.min(limit));
            } else {
                assert!(result.tx_gas_used() < 60_000);
            }
        }
    }
    Ok(())
}

#[test]
fn gas_opcode_only_sees_the_execution_budget() -> eyre::Result<()> {
    let mut evm = evm(100_000);
    install(
        &mut evm,
        CONTRACT,
        Bytecode::new_raw(bytes!("5a60005260206000f3")),
    );
    let result = evm.transact_commit(legacy_tx_env(
        CALLER,
        1,
        CONTRACT.into(),
        Bytes::new(),
        2_000_000,
    ))?;
    assert!(result.status);
    assert_eq!(
        U256::from_be_slice(&result.output),
        U256::from(100_000 - 21_000 - 2)
    );
    assert_eq!(result.state_gas_spent, 0);
    Ok(())
}

#[test]
fn system_calls_keep_their_entire_execution_budget() -> eyre::Result<()> {
    let mut evm = evm(100_000);
    install(
        &mut evm,
        CONTRACT,
        Bytecode::new_raw(bytes!("5a60005260206000f3")),
    );
    let result = evm
        .system_call(SystemTx::new(CONTRACT, Bytes::new()).with_gas_limit(200_000))?
        .detach();
    assert!(result.result.status);
    assert_eq!(
        U256::from_be_slice(&result.result.output),
        U256::from(200_000 - 2)
    );
    Ok(())
}

#[test]
fn large_contract_deploys_above_transaction_and_block_gas_limits() -> eyre::Result<()> {
    let mut evm = evm(16_000_000);
    // Return 24 KiB of zero-initialized memory as runtime code.
    let result = evm.transact_commit(legacy_tx_env(
        CALLER,
        1,
        TxKind::Create,
        bytes!("6160006000f3"),
        70_000_000,
    ))?;
    assert!(result.status, "{:?}", result.stop);
    assert_eq!(result.state_gas_spent, 468_000 + 24_576 * 2_300);
    assert!(result.tx_gas_used() > 30_000_000);
    assert!(execution_gas_used(&result) < 16_000_000);
    Ok(())
}

#[test]
fn create_revert_and_existing_leaf_do_not_pay_account_state_gas() -> eyre::Result<()> {
    for existing in [false, true] {
        for revert in [false, true] {
            let mut evm = evm(100_000);
            if existing {
                evm.overlay_db_mut().insert_account_info(
                    &CALLER.create(1),
                    AccountInfo::default().with_balance(U256::ONE),
                );
            }
            let code = if revert {
                bytes!("60006000fd")
            } else {
                bytes!("60006000f3")
            };
            let result =
                evm.transact_commit(legacy_tx_env(CALLER, 1, TxKind::Create, code, 800_000))?;
            assert_eq!(result.status, !revert);
            assert_eq!(
                result.state_gas_spent,
                if !existing && !revert { 468_000 } else { 0 }
            );
        }
    }
    Ok(())
}

#[test]
fn calldata_floor_counts_against_execution_even_with_state_spending() -> eyre::Result<()> {
    let mut evm = evm(100_000);
    install(
        &mut evm,
        CONTRACT,
        Bytecode::new_raw(bytes!("600160005500")),
    );
    let result = evm.transact_commit(legacy_tx_env(
        CALLER,
        1,
        CONTRACT.into(),
        vec![1; 1_000].into(),
        800_000,
    ))?;
    assert!(result.status);
    assert_eq!(result.floor_gas, 61_000);
    assert_eq!(execution_gas_used(&result), 61_000);
    assert_eq!(result.state_gas_spent, STORAGE_CREDIT_VALUE);

    let mut evm = self::evm(50_000);
    assert!(
        evm.transact_detach(legacy_tx_env(
            CALLER,
            1,
            CONTRACT.into(),
            vec![1; 1_000].into(),
            800_000
        ))
        .is_err()
    );
    Ok(())
}

#[test]
fn aa_batch_failure_refills_prior_calls_in_lifo_order() -> eyre::Result<()> {
    let signer = P256KeyPair::random();
    let failing = Address::repeat_byte(0x73);
    for cap in [100_000, 2_000_000] {
        for (ending, halt) in [(bytes!("60006000fd"), false), (bytes!("fe"), true)] {
            let mut evm = evm(cap);
            fund_account_with_nonce(&mut evm, signer.address, 1);
            install(
                &mut evm,
                CONTRACT,
                Bytecode::new_raw(bytes!("600160005500")),
            );
            install(&mut evm, failing, Bytecode::new_raw(ending));
            let tx = signer.sign_tx(
                TxBuilder::new()
                    .nonce(1)
                    .call(CONTRACT, &[])
                    .call(failing, &[])
                    .gas_limit(800_000)
                    .build(),
            )?;
            let result = evm.transact_commit(
                Recovered::new_unchecked(TempoTxEnvelope::AA(tx), signer.address).into(),
            )?;
            assert!(!result.status);
            assert_eq!(result.state_gas_spent, 0);
            if halt {
                assert_eq!(result.tx_gas_used(), cap.min(800_000));
            } else {
                assert!(result.tx_gas_used() < 60_000);
            }
            assert_eq!(
                evm.overlay_db_mut().get_storage(&CONTRACT, &U256::ZERO)?,
                U256::ZERO
            );
        }
    }
    Ok(())
}

#[test]
fn precompile_storage_uses_credit_policy_and_execution_first_charging() -> eyre::Result<()> {
    for mode in [CreditMode::Refund, CreditMode::Preserve, CreditMode::Direct] {
        let mut evm = evm(100_000);
        seed_storage_credit_balance(&mut evm, CONTRACT, 1);
        let (result, gas) = StorageCtx::enter_evm_with_gas_limit(&mut evm, 50_000, 500_000, || {
            StorageCredits::new().set_mode(CONTRACT, tip1060_abi_mode(mode))?;
            StorageCtx.sstore(CONTRACT, U256::ZERO, U256::ONE)
        });
        result?;
        assert_eq!(
            gas.state_gas_spent(),
            if mode == CreditMode::Direct {
                0
            } else {
                245_000
            }
        );
        assert_eq!(gas.state_gas_spilled(), 0);
        assert_eq!(gas.refunded(), 0);
    }
    let mut evm = evm(100_000);
    let (result, gas) = StorageCtx::enter_evm_with_gas_limit(&mut evm, 2_301, 500_000, || {
        StorageCtx.sstore(CONTRACT, U256::ZERO, U256::ONE)
    });
    assert!(result.is_err());
    assert_eq!(gas.state_gas_spent(), 0);
    assert_eq!(gas.reservoir(), 500_000);
    Ok(())
}

#[test]
fn precompile_code_deposit_hashes_all_words_and_charges_state_last() -> eyre::Result<()> {
    for existing in [false, true] {
        let mut evm = evm(100_000);
        if existing {
            evm.overlay_db_mut()
                .insert_account_info(&CONTRACT, AccountInfo::default().with_nonce(1));
        }
        let (result, gas) =
            StorageCtx::enter_evm_with_gas_limit(&mut evm, 50_000, 1_000_000, || {
                StorageCtx.set_code(CONTRACT, vec![0; 33].into())
            });
        result?;
        assert_eq!(
            gas.spent(),
            33 * 200 + 12 + if existing { 0 } else { 32_000 }
        );
        assert_eq!(
            gas.state_gas_spent(),
            33 * 2_300 + if existing { 0 } else { 468_000 }
        );
    }
    let mut evm = evm(100_000);
    let (result, gas) = StorageCtx::enter_evm_with_gas_limit(&mut evm, 32_001, 1_000_000, || {
        // Model the enclosing call's rollback when charging fails after code installation.
        let _checkpoint = StorageCtx.checkpoint();
        StorageCtx.set_code(CONTRACT, vec![0; 33].into())
    });
    assert!(result.is_err());
    assert_eq!(gas.state_gas_spent(), 0);
    assert!(evm.state_mut().account(&CONTRACT)?.load_code()?.is_empty());
    Ok(())
}

#[test]
fn native_checkpoint_rollback_restores_state_gas_without_refunding_execution() -> eyre::Result<()> {
    for reservoir in [0, 300_000, 1_000_000] {
        let mut evm = evm(1_000_000);
        let (result, gas) =
            StorageCtx::enter_evm_with_gas_limit(&mut evm, 1_000_000, reservoir, || {
                StorageCtx.sstore(CONTRACT, U256::ZERO, U256::ONE)?;
                let before = (StorageCtx.gas_used(), StorageCtx.reservoir());
                {
                    let _outer = StorageCtx.checkpoint();
                    StorageCtx.sstore(CONTRACT, U256::ONE, U256::ONE)?;
                    let inner = StorageCtx.checkpoint();
                    StorageCtx.sstore(CONTRACT, U256::from(2), U256::ONE)?;
                    inner.commit();
                }
                assert_eq!(StorageCtx.reservoir(), before.1);
                assert!(StorageCtx.gas_used() > before.0);
                assert_eq!(StorageCtx.sload(CONTRACT, U256::ONE)?, U256::ZERO);
                assert_eq!(StorageCtx.sload(CONTRACT, U256::from(2))?, U256::ZERO);
                Ok::<_, tempo_precompiles::error::TempoPrecompileError>(())
            });
        result?;
        assert_eq!(gas.state_gas_spent(), 245_000);
        assert_eq!(
            gas.state_gas_spilled(),
            245_000u64.saturating_sub(reservoir)
        );
    }
    Ok(())
}

#[test]
fn delegation_state_gas_persists_on_revert_and_is_charged_for_redelegation() -> eyre::Result<()> {
    use alloy_consensus::TxEip7702;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    let signer = PrivateKeySigner::random();
    for nonce in [0, 1] {
        for revert in [false, true] {
            let mut evm = evm(100_000);
            if nonce != 0 {
                evm.overlay_db_mut().insert_account_info(
                    &signer.address(),
                    AccountInfo::default()
                        .with_nonce(nonce)
                        .with_code(Bytecode::new_eip7702(CONTRACT)),
                );
            }
            install(
                &mut evm,
                CONTRACT,
                Bytecode::new_raw(if revert {
                    bytes!("60006000fd")
                } else {
                    bytes!("00")
                }),
            );
            let auth = Authorization {
                chain_id: U256::ONE,
                address: CONTRACT,
                nonce,
            };
            let signature = signer.sign_hash_sync(&auth.signature_hash())?;
            let tx = TxEip7702 {
                chain_id: 1,
                nonce: 1,
                gas_limit: 1_000_000,
                to: CONTRACT,
                authorization_list: vec![auth.into_signed(signature)],
                ..Default::default()
            };
            let tx = TempoTxEnvelope::Eip7702(Signed::new_unhashed(
                tx,
                alloy_primitives::Signature::test_signature(),
            ));
            let result = evm.transact_commit(Recovered::new_unchecked(tx, CALLER).into())?;
            assert_eq!(result.status, !revert);
            assert_eq!(
                result.state_gas_spent,
                if nonce == 0 { 450_000 } else { 225_000 }
            );
            assert_eq!(result.refunded, 0);
            assert_eq!(
                evm.state_mut().account(&signer.address())?.nonce(),
                nonce + 1
            );
            assert_eq!(
                evm.state_mut()
                    .account(&signer.address())?
                    .load_code()?
                    .eip7702_address(),
                Some(CONTRACT)
            );
        }
    }
    Ok(())
}

#[test]
fn aa_delegation_state_gas_survives_execution_revert() -> eyre::Result<()> {
    let signer = P256KeyPair::random();
    let authority = P256KeyPair::random();
    let mut evm = evm(100_000);
    fund_account_with_nonce(&mut evm, signer.address, 1);
    install(&mut evm, CONTRACT, Bytecode::new_raw(bytes!("60006000fd")));
    let auth = authority.create_signed_authorization(CONTRACT)?;
    let signed = signer.sign_tx(
        TxBuilder::new()
            .nonce(1)
            .call(CONTRACT, &[])
            .authorization(auth)
            .gas_limit(1_000_000)
            .build(),
    )?;
    let result = evm.transact_commit(
        Recovered::new_unchecked(TempoTxEnvelope::AA(signed), signer.address).into(),
    )?;
    assert!(!result.status);
    assert_eq!(result.state_gas_spent, 450_000);
    assert_eq!(evm.state_mut().account(&authority.address)?.nonce(), 1);
    Ok(())
}
