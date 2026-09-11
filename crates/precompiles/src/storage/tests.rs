use super::{
    ConfigCommitmentWriteGas as WriteGas, PrecompileStorageProvider,
    hashmap::HashMapStorageProvider,
};
use alloy::primitives::{Address, B256};
use revm::state::Bytecode;
use tempo_chainspec::hardfork::TempoHardfork;

pub(super) fn exercise_rollback(provider: &mut impl PrecompileStorageProvider) {
    let address = Address::repeat_byte(1);
    let initial = B256::repeat_byte(2);
    let rotated = B256::repeat_byte(3);
    let outer = provider.checkpoint();
    assert!(
        provider
            .set_config_commitment(address, initial, WriteGas::PrepaidTreeUpdate)
            .is_err()
    );
    provider
        .set_config_commitment(address, initial, WriteGas::Intrinsic)
        .unwrap();
    for commitment in [initial, rotated] {
        assert!(matches!(
            provider.set_config_commitment(address, commitment, WriteGas::Intrinsic),
            Err(crate::error::TempoPrecompileError::InvalidConfigCommitmentWrite)
        ));
        assert_eq!(provider.config_commitment(address).unwrap(), initial);
    }
    let inner = provider.checkpoint();
    provider
        .set_config_commitment(address, rotated, WriteGas::PrepaidTreeUpdate)
        .unwrap();
    assert_eq!(provider.config_commitment(address).unwrap(), rotated);
    provider.checkpoint_revert(inner);
    assert_eq!(provider.config_commitment(address).unwrap(), initial);
    let inner = provider.checkpoint();
    provider
        .set_config_commitment(address, rotated, WriteGas::Precompile)
        .unwrap();
    assert_eq!(provider.config_commitment(address).unwrap(), rotated);
    provider.checkpoint_revert(inner);
    assert_eq!(provider.config_commitment(address).unwrap(), initial);
    provider.set_code(address, Bytecode::default()).unwrap();
    assert_eq!(provider.config_commitment(address).unwrap(), initial);
    let inner = provider.checkpoint();
    provider
        .set_config_commitment(address, rotated, WriteGas::Precompile)
        .unwrap();
    provider.checkpoint_commit(inner);
    provider.checkpoint_revert(outer);
    assert_eq!(provider.config_commitment(address).unwrap(), B256::ZERO);
}

#[test]
fn hashmap_commitment_nested_rollback() {
    exercise_rollback(&mut HashMapStorageProvider::new_with_spec(
        1,
        TempoHardfork::T12,
    ));
}

#[test]
fn commitment_write_validation() {
    let mut provider = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
    let address = Address::repeat_byte(1);
    let hash = B256::repeat_byte(2);
    provider
        .set_config_commitment(address, hash, WriteGas::Precompile)
        .unwrap();
    provider
        .set_config_commitment(address, hash, WriteGas::Precompile)
        .unwrap();
    assert!(matches!(
        provider.set_config_commitment(address, hash, WriteGas::Intrinsic),
        Err(crate::error::TempoPrecompileError::InvalidConfigCommitmentWrite)
    ));
    assert!(
        provider
            .set_config_commitment(address, B256::ZERO, WriteGas::Intrinsic)
            .is_err()
    );
    let mut historical = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
    assert!(
        historical
            .set_config_commitment(address, hash, WriteGas::Intrinsic)
            .is_err()
    );
}
