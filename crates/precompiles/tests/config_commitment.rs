//! Account config-commitment reads and writes through precompile storage.

use alloy_primitives::{Address, B256, Bytes};
use evm2::{
    evm::{InMemoryDB, precompile::NoPrecompiles},
    precompiles::PrecompileError,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoEvmExt, build_tempo_evm};
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{ConfigCommitmentWriteGas, StorageCtx, hashmap::HashMapStorageProvider},
};
use tempo_primitives::TempoBlockEnv;

const ACCOUNT: Address = Address::repeat_byte(1);
const INITIAL: B256 = B256::repeat_byte(2);
const ROTATED: B256 = B256::repeat_byte(3);

fn t14_storage() -> HashMapStorageProvider {
    HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14)
}

fn is_invalid_write(result: Result<(), TempoPrecompileError>) -> bool {
    matches!(
        result,
        Err(TempoPrecompileError::InvalidConfigCommitmentWrite)
    )
}

#[test]
fn write_then_read() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        let mut ctx = StorageCtx;
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);

        ctx.set_config_commitment(ACCOUNT, INITIAL, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), INITIAL);
        assert_eq!(
            ctx.config_commitment(Address::repeat_byte(9)).unwrap(),
            B256::ZERO
        );

        ctx.set_config_commitment(ACCOUNT, ROTATED, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), ROTATED);
    });
}

#[test]
fn rejects_zero_pre_t14_and_static_writes() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, fork);
        StorageCtx::enter(&mut storage, || {
            let mut ctx = StorageCtx;
            assert!(is_invalid_write(ctx.set_config_commitment(
                ACCOUNT,
                INITIAL,
                ConfigCommitmentWriteGas::Intrinsic
            )));
            assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
        });
    }

    let mut storage = t14_storage();
    storage.set_is_static(true);
    StorageCtx::enter(&mut storage, || {
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
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
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
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
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

        ctx.set_code(ACCOUNT, Bytes::new()).unwrap();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), INITIAL);

        let inner = ctx.checkpoint();
        ctx.set_config_commitment(ACCOUNT, ROTATED, ConfigCommitmentWriteGas::Precompile)
            .unwrap();
        inner.commit();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), ROTATED);
        drop(outer);
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
    });
}

#[test]
fn evm_storage_reads_zero_and_rejects_writes() {
    let mut evm = build_tempo_evm(
        TempoHardfork::T14,
        1,
        TempoBlockEnv::default(),
        InMemoryDB::default(),
        NoPrecompiles::default(),
        TempoEvmExt::default(),
    );
    StorageCtx::enter_evm(&mut evm, || {
        let mut ctx = StorageCtx;
        let before = ctx.gas_used();
        ctx.with_account_info(Address::repeat_byte(9), |_| Ok(()))
            .unwrap();
        let account_access = ctx.gas_used() - before;
        assert!(account_access > 0);

        let before = ctx.gas_used();
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
        assert_eq!(ctx.gas_used() - before, account_access);

        // Each read touches the account it was asked about, so another fresh account is cold too.
        let before = ctx.gas_used();
        assert_eq!(
            ctx.config_commitment(Address::repeat_byte(2)).unwrap(),
            B256::ZERO
        );
        assert_eq!(ctx.gas_used() - before, account_access);

        for gas in [
            ConfigCommitmentWriteGas::Intrinsic,
            ConfigCommitmentWriteGas::Precompile,
        ] {
            assert!(is_invalid_write(
                ctx.set_config_commitment(ACCOUNT, INITIAL, gas)
            ));
        }
        assert_eq!(ctx.config_commitment(ACCOUNT).unwrap(), B256::ZERO);
    });
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
