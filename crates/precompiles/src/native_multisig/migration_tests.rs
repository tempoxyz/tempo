use super::*;
use crate::{
    Precompile,
    storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider},
};
use alloy::{
    primitives::{address, keccak256},
    sol_types::SolCall,
};
use revm::{precompile::PrecompileStatus, state::Bytecode};
use tempo_chainspec::hardfork::TempoHardfork;

fn storage(enabled: bool) -> HashMapStorageProvider {
    HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14)
        .with_multisig_recovery_factory(Address::repeat_byte(0x71))
        .with_account_migration_enabled(enabled)
}

fn owners() -> Vec<INativeMultisig::MultisigOwner> {
    vec![INativeMultisig::MultisigOwner {
        owner: Address::repeat_byte(0x22),
        weight: 1,
    }]
}

fn authorize(native: &mut NativeMultisig, root: Address, only_call: bool) {
    native.set_authority(root, Address::ZERO).unwrap();
    native.set_migration_authority(root, only_call).unwrap();
}

#[test]
fn migration_deterministic_salt_and_positive_version_match_known_vector() {
    let root = address!("cd4114e47cbfbfed3dff96b6c73d48e5d493d43c");
    let salt = alloy::primitives::b256!(
        "01c82c51b4db209b87793a7241683072ee7a5651ae401d03eedaa86eed2efd43"
    );
    assert_eq!(
        keccak256([b"tempo:multisig:upgrade".as_slice(), root.as_slice()].concat()),
        salt
    );
    let mut provider = storage(true);
    StorageCtx::enter(&mut provider, || {
        let mut native = NativeMultisig::new();
        authorize(&mut native, root, true);
        let mut owners = owners();
        owners[0].owner = root;
        let expected = config(salt, 1, 1, owners.clone()).commitment().unwrap();
        assert_eq!(native.upgrade_account(root, 1, owners).unwrap(), expected);
        assert_eq!(native.get_config_commitment(root).unwrap(), expected);
        assert!(root_key_retired(root).unwrap());
        assert_eq!(
            native.upgrade_account(root, 1, Vec::new()),
            Err(NativeMultisigError::account_already_configurable().into())
        );
    });
    assert_eq!(provider.events[&NATIVE_MULTISIG_ADDRESS].len(), 1);
}

#[test]
fn migration_activation_and_transaction_authority_are_fail_closed() {
    let root = Address::repeat_byte(0x33);
    for (enabled, authorized, only_call, expected) in [
        (
            false,
            root,
            true,
            NativeMultisigError::migration_not_active(),
        ),
        (
            true,
            Address::ZERO,
            true,
            NativeMultisigError::primitive_root_required(),
        ),
        (
            true,
            Address::repeat_byte(0x44),
            true,
            NativeMultisigError::primitive_root_required(),
        ),
        (
            true,
            root,
            false,
            NativeMultisigError::upgrade_must_be_only_call(),
        ),
    ] {
        let mut provider = storage(enabled);
        StorageCtx::enter(&mut provider, || {
            let mut native = NativeMultisig::new();
            native.set_authority(root, Address::ZERO).unwrap();
            native
                .set_migration_authority(authorized, only_call)
                .unwrap();
            assert_eq!(
                native.upgrade_account(root, 1, owners()),
                Err(expected.into())
            );
            assert_eq!(native.get_config_commitment(root).unwrap(), B256::ZERO);
        });
        assert!(provider.events.is_empty());
    }
}

#[test]
fn migration_rejects_code_delegation_reserved_addresses_and_registered_accounts() {
    let root = Address::repeat_byte(0x33);
    for bytecode in [
        Bytecode::new_legacy(vec![0x00].into()),
        Bytecode::new_eip7702(Address::repeat_byte(0x44)),
    ] {
        let mut provider = storage(true);
        provider.set_code(root, bytecode).unwrap();
        StorageCtx::enter(&mut provider, || {
            let mut native = NativeMultisig::new();
            authorize(&mut native, root, true);
            assert_eq!(
                native.upgrade_account(root, 1, owners()),
                Err(NativeMultisigError::account_has_code().into())
            );
            assert_eq!(native.get_config_commitment(root).unwrap(), B256::ZERO);
        });
    }
    for root in [
        Address::ZERO,
        NATIVE_MULTISIG_ADDRESS,
        address!("20c0000000000000000000000000000000000001"),
    ] {
        let mut provider = storage(true);
        StorageCtx::enter(&mut provider, || {
            let mut native = NativeMultisig::new();
            authorize(&mut native, root, true);
            assert!(native.upgrade_account(root, 1, owners()).is_err());
            assert_eq!(native.get_config_commitment(root).unwrap(), B256::ZERO);
        });
    }
}

#[test]
fn migration_invalid_configurations_never_write_or_emit() {
    let root = Address::repeat_byte(0x33);
    let owner = |byte, weight| INativeMultisig::MultisigOwner {
        owner: Address::repeat_byte(byte),
        weight,
    };
    let cases = [
        (1, vec![]),
        (0, owners()),
        (2, owners()),
        (1, vec![owner(0, 1)]),
        (1, vec![owner(0x22, 0)]),
        (1, vec![owner(0x22, 1), owner(0x22, 1)]),
        (1, vec![owner(0x23, 1), owner(0x22, 1)]),
        (1, vec![owner(0x22, 255), owner(0x23, 1)]),
        (9, (1..=9).map(|byte| owner(byte, 1)).collect()),
        (1, (1..=49).map(|byte| owner(byte, 1)).collect()),
    ];
    for (threshold, owners) in cases {
        let mut provider = storage(true);
        StorageCtx::enter(&mut provider, || {
            let mut native = NativeMultisig::new();
            authorize(&mut native, root, true);
            assert_eq!(
                native.upgrade_account(root, threshold, owners),
                Err(NativeMultisigError::invalid_config().into())
            );
            assert_eq!(native.get_config_commitment(root).unwrap(), B256::ZERO);
        });
        assert!(provider.events.is_empty());
    }
}

#[test]
fn migration_abi_and_journal_rollback_preserve_original_state() {
    let root = Address::repeat_byte(0x33);
    let mut provider = storage(true);
    StorageCtx::enter(&mut provider, || {
        let mut native = NativeMultisig::new();
        authorize(&mut native, root, true);
        let checkpoint = StorageCtx.checkpoint();
        let output = native
            .call(
                &INativeMultisig::upgradeAccountCall {
                    threshold: 1,
                    owners: owners(),
                }
                .abi_encode(),
                root,
            )
            .unwrap();
        assert_eq!(output.status, PrecompileStatus::Success);
        assert!(!native.get_config_commitment(root).unwrap().is_zero());
        drop(checkpoint);
        assert_eq!(native.get_config_commitment(root).unwrap(), B256::ZERO);
        assert!(!root_key_retired(root).unwrap());
    });
    assert!(provider.events.is_empty());
}
