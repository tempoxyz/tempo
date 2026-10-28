//! Account config-commitment reads and writes through precompile storage.

use alloy_primitives::{Address, B256, Bytes, U256};
use evm2::{
    BaseEvmConfigSelector, Evm, EvmTypesHost, ExecutionConfig, SpecId, Version,
    evm::{InMemoryDB, precompile::NoPrecompiles},
    interpreter::GasTracker,
    precompiles::PrecompileError,
    registry::TxRegistry,
    version::{GasId, GasParams},
};
use tempo_chainspec::{gas_params::version, hardfork::TempoHardfork};
use tempo_precompiles::{
    configurable_account::CONFIGURABLE_ACCOUNT_CODE_HASH,
    error::TempoPrecompileError,
    storage::{
        ConfigCommitmentWriteGas, PrecompileStorageProvider, StorageCtx,
        evm::EvmPrecompileStorageProvider, hashmap::HashMapStorageProvider,
    },
};
use tempo_primitives::{TempoBlockEnv, TempoBlockExt, account::encode_config_commitment};

struct TestTypes;

impl EvmTypesHost for TestTypes {
    type ConfigSelector = BaseEvmConfigSelector;
    type SpecId = SpecId;
    type Tx = ();
    type EvmExt = ();
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = ();
    type BlockEnvExt = TempoBlockExt;
    type Host<'a> = Evm<'a, Self>;
}

const ACCOUNT: Address = Address::repeat_byte(1);
const INITIAL: B256 = B256::repeat_byte(2);
const ROTATED: B256 = B256::repeat_byte(3);

fn new_evm(spec: TempoHardfork, amsterdam_eip8037_enabled: bool) -> Evm<'static, TestTypes> {
    new_evm_with_version(version(SpecId::OSAKA, spec, amsterdam_eip8037_enabled))
}

fn new_evm_with_version(version: Version) -> Evm<'static, TestTypes> {
    Evm::<TestTypes>::new_with_execution_config(
        ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
        SpecId::OSAKA,
        TempoBlockEnv::default(),
        TxRegistry::new(),
        InMemoryDB::default(),
        NoPrecompiles::default(),
    )
}

fn gas_params(spec: TempoHardfork, amsterdam_eip8037_enabled: bool) -> GasParams {
    version(SpecId::OSAKA, spec, amsterdam_eip8037_enabled).gas_params
}

/// Runs `f` inside a [`StorageCtx`] over the in-memory provider, then over the EVM provider.
fn on_each_provider(spec: TempoHardfork, is_static: bool, f: impl Fn()) {
    let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
    storage.set_is_static(is_static);
    StorageCtx::enter(&mut storage, &f);

    let mut evm = new_evm(spec, false);
    let mut gas_tracker = GasTracker::new(u64::MAX);
    let mut storage =
        EvmPrecompileStorageProvider::new(&mut evm, &mut gas_tracker, spec, is_static);
    StorageCtx::enter(&mut storage, &f);
}

fn is_invalid_write(result: Result<(), TempoPrecompileError>) -> bool {
    matches!(
        result,
        Err(TempoPrecompileError::InvalidConfigCommitmentWrite)
    )
}

#[test]
fn write_then_read() {
    on_each_provider(TempoHardfork::T14, false, || {
        let mut ctx = StorageCtx;
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);

        ctx.set_config_commitment(ACCOUNT, INITIAL, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), INITIAL);
        assert_eq!(
            ctx.with_account_info(ACCOUNT, |info| Ok(info.code_hash))
                .unwrap(),
            CONFIGURABLE_ACCOUNT_CODE_HASH
        );
        assert_eq!(
            ctx.config_commitment(Address::repeat_byte(9)).unwrap(),
            B256::ZERO
        );

        ctx.set_config_commitment(ACCOUNT, ROTATED, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), ROTATED);
        assert_eq!(
            ctx.with_account_info(ACCOUNT, |info| Ok(info.code_hash))
                .unwrap(),
            CONFIGURABLE_ACCOUNT_CODE_HASH
        );
    });
}

#[test]
fn rejects_zero_pre_t14_and_static_writes() {
    on_each_provider(TempoHardfork::T14, false, || {
        let mut ctx = StorageCtx;
        for gas in [
            ConfigCommitmentWriteGas::Intrinsic,
            ConfigCommitmentWriteGas::Precompile,
        ] {
            assert!(is_invalid_write(ctx.set_config_commitment(
                ACCOUNT,
                B256::ZERO,
                gas
            )));
        }
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
    });

    for fork in [TempoHardfork::T12, TempoHardfork::T13] {
        on_each_provider(fork, false, || {
            let mut ctx = StorageCtx;
            assert!(is_invalid_write(ctx.set_config_commitment(
                ACCOUNT,
                INITIAL,
                ConfigCommitmentWriteGas::Intrinsic
            )));
            assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
        });
    }

    on_each_provider(TempoHardfork::T14, true, || {
        let mut ctx = StorageCtx;
        assert!(is_invalid_write(ctx.set_config_commitment(
            ACCOUNT,
            INITIAL,
            ConfigCommitmentWriteGas::Precompile
        )));
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
    });
}

#[test]
fn intrinsic_write_requires_empty_commitment() {
    on_each_provider(TempoHardfork::T14, false, || {
        let mut ctx = StorageCtx;
        ctx.set_config_commitment(ACCOUNT, INITIAL, ConfigCommitmentWriteGas::Intrinsic)
            .unwrap();
        for commitment in [INITIAL, ROTATED] {
            assert!(is_invalid_write(ctx.set_config_commitment(
                ACCOUNT,
                commitment,
                ConfigCommitmentWriteGas::Intrinsic
            )));
            assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), INITIAL);
        }

        ctx.set_config_commitment(ACCOUNT, INITIAL, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), INITIAL);
    });
}

#[test]
fn checkpoint_revert_restores_commitment() {
    on_each_provider(TempoHardfork::T14, false, || {
        let mut ctx = StorageCtx;
        let outer = ctx.checkpoint();
        ctx.set_config_commitment(ACCOUNT, INITIAL, ConfigCommitmentWriteGas::Intrinsic)
            .unwrap();

        let inner = ctx.checkpoint();
        ctx.set_config_commitment(ACCOUNT, ROTATED, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), ROTATED);
        drop(inner);
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), INITIAL);

        assert_eq!(
            ctx.with_account_info(ACCOUNT, |info| Ok(info.code_hash))
                .unwrap(),
            CONFIGURABLE_ACCOUNT_CODE_HASH
        );

        let inner = ctx.checkpoint();
        ctx.set_config_commitment(ACCOUNT, ROTATED, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        inner.commit();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), ROTATED);
        drop(outer);
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
        assert_eq!(
            ctx.with_account_info(ACCOUNT, |info| Ok(info.code_hash))
                .unwrap(),
            alloy_primitives::KECCAK256_EMPTY
        );
    });
}

#[test]
fn evm_storage_reads_and_writes_commitments() {
    let spec = TempoHardfork::T14;
    let params = gas_params(spec, false);
    let new_account = params.get(GasId::NewAccountCost);
    let mut evm = new_evm(spec, false);
    {
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
        let before = storage.gas_used();
        storage
            .with_account_info(Address::repeat_byte(9), &mut |_| {})
            .unwrap();
        let account_access = storage.gas_used() - before;
        assert!(account_access > 0);

        // A read is a normal account access, cold for every account touched the first time.
        let before = storage.gas_used();
        assert_eq!(storage.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
        assert_eq!(storage.gas_used() - before, account_access);

        // The first precompile write registers the commitment, priced like account creation,
        // and creates the account.
        let before = storage.gas_used();
        storage
            .set_config_commitment(ACCOUNT, INITIAL, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        assert_eq!(storage.gas_used() - before, 2 * new_account);
        assert_eq!(storage.state_gas_used(), 2 * params.new_account_state_gas());
        assert_eq!(storage.config_commitment(ACCOUNT).unwrap(), INITIAL);

        // Rotation pays only the update charge; the account already exists.
        let state_gas = storage.state_gas_used();
        let before = storage.gas_used();
        storage
            .set_config_commitment(ACCOUNT, ROTATED, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        assert_eq!(storage.gas_used() - before, 5_000);
        assert_eq!(storage.state_gas_used(), state_gas);
        assert_eq!(storage.config_commitment(ACCOUNT).unwrap(), ROTATED);

        // An intrinsic registration was priced with the transaction, account creation included.
        let fresh = Address::repeat_byte(4);
        let before = storage.gas_used();
        storage
            .set_config_commitment(fresh, INITIAL, ConfigCommitmentWriteGas::Intrinsic)
            .unwrap();
        assert_eq!(storage.gas_used(), before);
        assert_eq!(storage.state_gas_used(), state_gas);
        assert!(is_invalid_write(storage.set_config_commitment(
            fresh,
            ROTATED,
            ConfigCommitmentWriteGas::Intrinsic
        )));
        assert_eq!(storage.gas_used(), before);
        assert_eq!(storage.gas_refunded(), 0);
    }

    // The commitment lives in the journaled account extension.
    {
        let account = evm.state_mut().account(&ACCOUNT).unwrap();
        let info = account.get().unwrap();
        assert_eq!(&info.extension[..], &encode_config_commitment(ROTATED)[..]);
    }

    // An account holding only a commitment is not empty, so empty-account cleanup keeps it.
    {
        let fresh = evm.state_mut().account(&Address::repeat_byte(4)).unwrap();
        assert!(!fresh.get().unwrap().is_empty());
    }

    // Balance and nonce changes keep the commitment.
    {
        let mut account = evm.state_mut().account(&ACCOUNT).unwrap();
        account.set_balance(U256::from(7));
        assert!(account.bump_nonce());
    }
    let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
    assert_eq!(storage.config_commitment(ACCOUNT).unwrap(), ROTATED);
}

#[test]
fn evm_static_write_is_rejected_uncharged() {
    let spec = TempoHardfork::T14;
    let mut evm = new_evm(spec, false);
    let mut gas_tracker = GasTracker::new(u64::MAX);
    let mut storage = EvmPrecompileStorageProvider::new(&mut evm, &mut gas_tracker, spec, true);
    assert_eq!(storage.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
    let before = storage.gas_used();
    for gas in [
        ConfigCommitmentWriteGas::Intrinsic,
        ConfigCommitmentWriteGas::Precompile,
    ] {
        assert!(is_invalid_write(
            storage.set_config_commitment(ACCOUNT, INITIAL, gas)
        ));
    }
    assert_eq!(storage.gas_used(), before);
    assert_eq!(storage.state_gas_used(), 0);
    assert_eq!(storage.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
}

/// A commitment write to an account holding `previous`, with its expected regular and state gas.
struct WriteCase {
    previous: B256,
    cost: u64,
    state_gas: u64,
}

#[test]
fn evm_write_gas_boundary() {
    let spec = TempoHardfork::T14;
    let params = gas_params(spec, false);
    let registration = 2 * params.get(GasId::NewAccountCost);
    for WriteCase {
        previous,
        cost,
        state_gas,
    } in [
        WriteCase {
            previous: B256::ZERO,
            cost: registration,
            state_gas: 2 * params.new_account_state_gas(),
        },
        WriteCase {
            previous: INITIAL,
            cost: 5_000,
            state_gas: 0,
        },
    ] {
        for shortfall in [1, 0] {
            let mut evm = new_evm(spec, false);
            {
                let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
                if !previous.is_zero() {
                    storage
                        .set_config_commitment(
                            ACCOUNT,
                            previous,
                            ConfigCommitmentWriteGas::Intrinsic,
                        )
                        .unwrap();
                }
                // Pay for the prerequisite account read separately from the write budget.
                assert_eq!(storage.config_commitment(ACCOUNT).unwrap(), previous);
            }
            let reservoir = 100_000;
            let mut gas_tracker =
                GasTracker::new_with_execution_gas_and_reservoir(cost - shortfall, reservoir);
            {
                let mut storage =
                    EvmPrecompileStorageProvider::new(&mut evm, &mut gas_tracker, spec, false);
                let result = storage.set_config_commitment(
                    ACCOUNT,
                    ROTATED,
                    ConfigCommitmentWriteGas::Precompile,
                );
                if shortfall == 0 {
                    result.unwrap();
                    assert_eq!(storage.gas_used(), cost);
                    assert_eq!(storage.state_gas_used(), state_gas);
                    assert_eq!(storage.reservoir(), reservoir - state_gas);
                } else {
                    assert_eq!(result, Err(TempoPrecompileError::OutOfGas));
                }
                assert_eq!(storage.state_gas_spilled(), 0);
                assert_eq!(storage.gas_refunded(), 0);
            }
            let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
            assert_eq!(
                storage.config_commitment(ACCOUNT).unwrap(),
                if shortfall == 0 { ROTATED } else { previous }
            );
        }
    }
}

#[test]
fn evm_registration_state_gas_spills_into_regular_gas() {
    // No T14 schedule prices new-account state gas yet, so set it here to pin the spill path.
    let spec = TempoHardfork::T14;
    let state_gas = 100_000;
    let mut version = version(SpecId::OSAKA, spec, false);
    version.gas_params[GasId::NewAccountState] = state_gas;
    // The commitment write and the account creation each charge it.
    let state_gas = 2 * u64::from(state_gas);
    let regular = 2 * version.gas_params.get(GasId::NewAccountCost);
    let mut evm = new_evm_with_version(version);
    let reservoir = state_gas / 4;
    let mut gas_tracker = GasTracker::new_with_execution_gas_and_reservoir(u64::MAX / 2, reservoir);
    let mut storage = EvmPrecompileStorageProvider::new(&mut evm, &mut gas_tracker, spec, false);
    storage
        .set_config_commitment(ACCOUNT, INITIAL, ConfigCommitmentWriteGas::Precompile)
        .unwrap();
    let spill = state_gas - reservoir;
    assert_eq!(storage.state_gas_used(), state_gas);
    assert_eq!(storage.state_gas_spilled(), spill);
    assert_eq!(storage.reservoir(), 0);
    assert_eq!(storage.gas_used(), regular + spill);
}

#[test]
fn invalid_write_reverts_without_data() {
    let error = TempoPrecompileError::InvalidConfigCommitmentWrite;
    assert!(!error.is_system_error());
    assert_eq!(error.selector(), [0u8; 4]);

    let Err(PrecompileError::Revert(bytes)) = error.into_precompile_result() else {
        panic!("expected a revert");
    };
    assert_eq!(bytes, Bytes::new());
}
