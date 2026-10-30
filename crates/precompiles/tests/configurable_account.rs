//! Configurable account precompile calls through its ABI, and the keychain grants that depend on
//! an account's configuration.

use alloy::{
    primitives::{Address, B256, Bytes, keccak256},
    sol_types::{SolCall, SolEvent, SolInterface},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    AccountKeychainError, CONFIGURABLE_ACCOUNT_ADDRESS, ConfigurableAccountError,
    IAccountKeychain::{KeyRestrictions, SignatureType},
    IConfigurableAccount,
};
use tempo_precompiles::{
    Precompile,
    account_keychain::AccountKeychain,
    configurable_account::{
        CONFIGURABLE_ACCOUNT_CODE, ConfigurableAccount, UpgradeEligibility, config,
    },
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
};
use tempo_primitives::transaction::configurable_account::{
    CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, MAX_CONFIGURABLE_ACCOUNT_OWNERS,
};

mod common;

use common::{PrecompileOutput, PrecompileStatus};

const OWNER: Address = Address::repeat_byte(0x22);
const EOA: Address = Address::repeat_byte(0x33);
/// A configurable account whose commitment tests seed directly.
const ACCOUNT: Address = Address::repeat_byte(0x66);

fn t14_storage() -> HashMapStorageProvider {
    HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14)
}

fn weighted_owners(
    entries: &[(Address, u8)],
) -> Vec<IConfigurableAccount::ConfigurableAccountOwner> {
    entries
        .iter()
        .map(|&(owner, weight)| IConfigurableAccount::ConfigurableAccountOwner { owner, weight })
        .collect()
}

fn call(sender: Address, call: impl SolCall) -> PrecompileOutput {
    let before = StorageCtx.gas_used();
    let result = ConfigurableAccount::new().call(&call.abi_encode(), sender);
    PrecompileOutput::new(result, StorageCtx.gas_used() - before)
}

fn returns<C: SolCall>(output: PrecompileOutput) -> C::Return {
    assert_eq!(output.status, PrecompileStatus::Success, "{output:?}");
    C::abi_decode_returns(&output.bytes).unwrap()
}

#[track_caller]
fn assert_reverts(output: PrecompileOutput, expected: ConfigurableAccountError) {
    assert_eq!(output.status, PrecompileStatus::Revert, "{expected:?}");
    assert_eq!(
        output.bytes,
        Bytes::from(expected.abi_encode()),
        "{expected:?}"
    );
}

fn commitment_of(account: Address) -> B256 {
    returns::<IConfigurableAccount::getConfigCommitmentCall>(call(
        Address::ZERO,
        IConfigurableAccount::getConfigCommitmentCall { account },
    ))
}

fn update(
    sender: Address,
    current: &IConfigurableAccount::ConfigurableAccountConfig,
    threshold: u8,
    owners: &[IConfigurableAccount::ConfigurableAccountOwner],
) -> PrecompileOutput {
    call(
        sender,
        IConfigurableAccount::updateConfigCall {
            current: current.clone(),
            threshold,
            owners: owners.to_vec(),
        },
    )
}

fn upgrade(
    sender: Address,
    threshold: u8,
    owners: &[IConfigurableAccount::ConfigurableAccountOwner],
) -> PrecompileOutput {
    call(
        sender,
        IConfigurableAccount::upgradeAccountCall {
            threshold,
            owners: owners.to_vec(),
        },
    )
}

fn seed_authority(origin: Address, directly_authorized: Address, eligibility: UpgradeEligibility) {
    ConfigurableAccount::new()
        .set_authority(origin, directly_authorized, eligibility)
        .unwrap();
}

fn seed_commitment(account: Address, commitment: B256) {
    StorageCtx
        .set_config_commitment(account, commitment)
        .unwrap();
}

#[test]
fn rotation_requires_committed_current_leaf_and_direct_authority() {
    let mut storage = t14_storage();
    let (account, owners) = StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let account = ACCOUNT;
        let mut current = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        assert_eq!(commitment_of(account), B256::ZERO);
        assert_reverts(
            update(account, &current, 1, &owners),
            ConfigurableAccountError::unauthorized_configurable_account_caller(),
        );
        seed_authority(account, account, UpgradeEligibility::NotSoleCall);
        assert_reverts(
            update(account, &current, 1, &owners),
            ConfigurableAccountError::invalid_config(),
        );
        seed_commitment(
            account,
            config(B256::ZERO, 0, 1, &owners).commitment().unwrap(),
        );
        returns::<IConfigurableAccount::updateConfigCall>(update(account, &current, 1, &owners));
        assert_reverts(
            update(account, &current, 1, &owners),
            ConfigurableAccountError::invalid_config(),
        );
        current.version = 1;
        returns::<IConfigurableAccount::updateConfigCall>(update(account, &current, 1, &owners));
        assert_eq!(
            commitment_of(account),
            config(B256::ZERO, 2, 1, &owners).commitment().unwrap()
        );
        (account, owners)
    });

    let events: Vec<_> = (1..=2)
        .map(|version| {
            IConfigurableAccount::ConfigurableAccountConfigUpdated {
                account,
                salt: B256::ZERO,
                version,
                threshold: 1,
                owners: owners.clone(),
            }
            .encode_log_data()
        })
        .collect();
    assert_eq!(storage.get_events(CONFIGURABLE_ACCOUNT_ADDRESS), &events);
}

#[test]
fn update_config_requires_the_sender_as_direct_authority() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let account = ACCOUNT;
        let current = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        seed_commitment(
            account,
            config(B256::ZERO, 0, 1, &owners).commitment().unwrap(),
        );
        for (sender, origin, directly_authorized) in [
            (Address::ZERO, Address::ZERO, Address::ZERO),
            (account, account, EOA),
        ] {
            seed_authority(
                origin,
                directly_authorized,
                UpgradeEligibility::PrimitiveRoot,
            );
            assert_reverts(
                update(sender, &current, 1, &owners),
                ConfigurableAccountError::unauthorized_configurable_account_caller(),
            );
        }
        // The direct authority alone decides: the origin is not consulted.
        seed_authority(EOA, account, UpgradeEligibility::NotSoleCall);
        returns::<IConfigurableAccount::updateConfigCall>(update(account, &current, 1, &owners));
    });
}

#[test]
fn update_config_rejects_invalid_current_and_next_configs() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let account = ACCOUNT;
        seed_authority(account, account, UpgradeEligibility::NotSoleCall);
        let initial = config(B256::ZERO, 0, 1, &owners).commitment().unwrap();
        seed_commitment(account, initial);

        // A current configuration that fails validation is stale, so it gets `InvalidConfig`.
        let current = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 0,
            owners: owners.clone(),
        };
        assert_reverts(
            update(account, &current, 1, &owners),
            ConfigurableAccountError::invalid_config(),
        );

        // So does one with too many owners to encode.
        let too_many = (0..=MAX_CONFIGURABLE_ACCOUNT_OWNERS)
            .map(|i| IConfigurableAccount::ConfigurableAccountOwner {
                owner: Address::with_last_byte(i as u8 + 1),
                weight: 1,
            })
            .collect();
        let current = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: too_many,
        };
        assert_reverts(
            update(account, &current, 1, &owners),
            ConfigurableAccountError::invalid_config(),
        );

        let current = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        assert_reverts(
            update(account, &current, 0, &owners),
            ConfigurableAccountError::invalid_threshold(),
        );
        assert_reverts(
            update(account, &current, 1, &[]),
            ConfigurableAccountError::invalid_configurable_account_owner(),
        );
        assert_eq!(commitment_of(account), initial);

        let last = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: u64::MAX,
            threshold: 1,
            owners: owners.clone(),
        };
        StorageCtx
            .set_config_commitment(
                account,
                config(B256::ZERO, u64::MAX, 1, &owners)
                    .commitment()
                    .unwrap(),
            )
            .unwrap();
        assert_reverts(
            update(account, &last, 1, &owners),
            ConfigurableAccountError::invalid_config(),
        );
    });
}

#[test]
fn config_error_precedence_through_abi() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        // The next configuration of an account at a valid current one is validated in full.
        let current_owners = weighted_owners(&[(OWNER, 1)]);
        let current = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 1,
            threshold: 1,
            owners: current_owners.clone(),
        };
        let initial = config(B256::ZERO, 1, 1, &current_owners)
            .commitment()
            .unwrap();
        seed_authority(ACCOUNT, ACCOUNT, UpgradeEligibility::NotSoleCall);
        seed_commitment(ACCOUNT, initial);
        struct Case {
            name: &'static str,
            threshold: u8,
            owners: Vec<(u8, u8)>,
            expected: ConfigurableAccountError,
        }
        for Case {
            name: case,
            threshold,
            owners,
            expected,
        } in [
            Case {
                name: "empty before threshold",
                threshold: 0,
                owners: vec![],
                expected: ConfigurableAccountError::invalid_configurable_account_owner(),
            },
            Case {
                name: "count before threshold",
                threshold: 0,
                owners: vec![(0, 0); 49],
                expected: ConfigurableAccountError::too_many_owners(),
            },
            Case {
                name: "threshold before address",
                threshold: 0,
                owners: vec![(0, 0)],
                expected: ConfigurableAccountError::invalid_threshold(),
            },
            Case {
                name: "address before weight",
                threshold: 1,
                owners: vec![(0x11, 0), (0, 1)],
                expected: ConfigurableAccountError::invalid_configurable_account_owner(),
            },
            Case {
                name: "weight before duplicate",
                threshold: 1,
                owners: vec![(0x11, 1), (0x11, 1), (0x22, 0)],
                expected: ConfigurableAccountError::invalid_weight(),
            },
            Case {
                name: "nonadjacent duplicate before order",
                threshold: 1,
                owners: vec![(0x22, 1), (0x11, 1), (0x22, 1)],
                expected: ConfigurableAccountError::duplicate_owner(),
            },
            Case {
                name: "order before total weight",
                threshold: 1,
                owners: vec![(0x22, 128), (0x11, 128)],
                expected: ConfigurableAccountError::invalid_owner_order(),
            },
        ] {
            let owners: Vec<_> = owners
                .into_iter()
                .map(
                    |(owner, weight)| IConfigurableAccount::ConfigurableAccountOwner {
                        owner: Address::repeat_byte(owner),
                        weight,
                    },
                )
                .collect();
            let result = update(ACCOUNT, &current, threshold, &owners);
            assert_eq!(result.status, PrecompileStatus::Revert, "{case}");
            assert_eq!(result.bytes, expected.abi_encode(), "{case}");
        }
        assert_eq!(commitment_of(ACCOUNT), initial);
    });
}

#[test]
fn mutating_calls_reject_static_context() {
    let mut storage = t14_storage();
    storage.set_is_static(true);
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let account = ACCOUNT;
        assert_eq!(commitment_of(account), B256::ZERO);
        let current = IConfigurableAccount::ConfigurableAccountConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        for output in [
            update(account, &current, 1, &owners),
            upgrade(EOA, 1, &owners),
        ] {
            assert!(
                matches!(output.status, PrecompileStatus::Halt(_)),
                "{output:?}"
            );
            assert!(output.bytes.is_empty());
        }
    });
}

#[test]
fn upgrade_account_checks_eligibility_code_and_commitment_in_order() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let with_code = Address::repeat_byte(0x44);
        seed_commitment(with_code, B256::repeat_byte(9));
        // Deliberately replace the protocol marker to test rejection precedence for invalid code.
        StorageCtx
            .set_code(with_code, Bytes::from_static(&[0x00]))
            .unwrap();
        let configured = Address::repeat_byte(0x55);
        seed_commitment(configured, B256::repeat_byte(9));

        // An unseeded context rejects every migration.
        assert_reverts(
            upgrade(EOA, 1, &owners),
            ConfigurableAccountError::upgrade_must_be_only_call(),
        );
        for (sender, eligibility, expected) in [
            (
                with_code,
                UpgradeEligibility::NotSoleCall,
                ConfigurableAccountError::upgrade_must_be_only_call(),
            ),
            (
                with_code,
                UpgradeEligibility::NotPrimitiveRoot,
                ConfigurableAccountError::primitive_root_required(),
            ),
            (
                with_code,
                UpgradeEligibility::PrimitiveRoot,
                ConfigurableAccountError::account_has_code(),
            ),
            (
                configured,
                UpgradeEligibility::PrimitiveRoot,
                ConfigurableAccountError::account_already_configurable(),
            ),
        ] {
            seed_authority(sender, sender, eligibility);
            assert_reverts(upgrade(sender, 1, &owners), expected);
        }

        // The sender must be the transaction origin, whatever the eligibility says.
        for eligibility in [
            UpgradeEligibility::NotPrimitiveRoot,
            UpgradeEligibility::PrimitiveRoot,
        ] {
            seed_authority(OWNER, EOA, eligibility);
            assert_reverts(
                upgrade(EOA, 1, &owners),
                ConfigurableAccountError::upgrade_must_be_only_call(),
            );
        }

        // Configuration errors are all reported as an invalid config.
        seed_authority(EOA, EOA, UpgradeEligibility::PrimitiveRoot);
        for (threshold, owners) in [
            (0, owners.clone()),
            (1, vec![]),
            (2, owners),
            (
                1,
                weighted_owners(&[(OWNER, 1), (Address::repeat_byte(0x11), 1)]),
            ),
        ] {
            assert_reverts(
                upgrade(EOA, threshold, &owners),
                ConfigurableAccountError::invalid_config(),
            );
        }
        assert_eq!(commitment_of(EOA), B256::ZERO);
    });
}

#[test]
fn upgrade_account_installs_a_version_one_commitment() {
    let mut storage = t14_storage();
    // The root key may also be listed as an owner.
    let owners = weighted_owners(&[(OWNER, 1), (EOA, 1)]);
    let salt = keccak256([CONFIGURABLE_ACCOUNT_UPGRADE_DOMAIN, EOA.as_slice()].concat());
    let expected = config(salt, 1, 2, &owners).commitment().unwrap();
    StorageCtx::enter(&mut storage, || {
        seed_authority(EOA, EOA, UpgradeEligibility::PrimitiveRoot);
        assert_eq!(
            returns::<IConfigurableAccount::upgradeAccountCall>(upgrade(EOA, 2, &owners)),
            expected
        );
        assert_eq!(commitment_of(EOA), expected);
        assert_reverts(
            upgrade(EOA, 2, &owners),
            ConfigurableAccountError::account_already_configurable(),
        );

        // The upgraded account rotates like any other configurable account.
        let current = IConfigurableAccount::ConfigurableAccountConfig {
            salt,
            version: 1,
            threshold: 2,
            owners: owners.clone(),
        };
        returns::<IConfigurableAccount::updateConfigCall>(update(EOA, &current, 1, &owners));
        assert_eq!(
            commitment_of(EOA),
            config(salt, 2, 1, &owners).commitment().unwrap()
        );
    });

    let upgraded = IConfigurableAccount::AccountUpgraded {
        account: EOA,
        commitment: expected,
        salt,
        threshold: 2,
        owners: owners.clone(),
    }
    .encode_log_data();
    let updated = IConfigurableAccount::ConfigurableAccountConfigUpdated {
        account: EOA,
        salt,
        version: 2,
        threshold: 1,
        owners,
    }
    .encode_log_data();
    assert_eq!(
        storage.get_events(CONFIGURABLE_ACCOUNT_ADDRESS),
        &[upgraded, updated]
    );
}

/// Committed parents keep grant authority with the protocol marker; incompatible code is rejected.
/// Uncommitted parents retain their existing grant behavior.
#[test]
fn committed_parent_requires_protocol_marker_to_authorize_keys() {
    let parent = Address::repeat_byte(0x11);
    let key = Address::repeat_byte(0x22);
    let codes = [
        ("unchanged", Bytes::new()),
        ("marker", CONFIGURABLE_ACCOUNT_CODE),
        ("bytecode", Bytes::from_static(&[0x00])),
        (
            "delegation",
            Bytes::from_iter(
                [0xef, 0x01, 0x00]
                    .into_iter()
                    .chain(Address::repeat_byte(0x33)),
            ),
        ),
    ];
    for committed in [false, true] {
        for (kind, code) in &codes {
            let mut storage = t14_storage();
            StorageCtx::enter(&mut storage, || {
                let mut keychain = AccountKeychain::new();
                keychain.initialize().unwrap();
                keychain.set_tx_origin(parent).unwrap();
                if committed {
                    seed_commitment(parent, B256::repeat_byte(1));
                }
                if !code.is_empty() {
                    StorageCtx.set_code(parent, code.clone()).unwrap();
                }
                let result = keychain.authorize_key(
                    parent,
                    key,
                    SignatureType::Secp256k1,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: vec![],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                    None,
                );
                let expected =
                    if committed && !code.is_empty() && *code != CONFIGURABLE_ACCOUNT_CODE {
                        Err(AccountKeychainError::invalid_key_id().into())
                    } else {
                        Ok(())
                    };
                assert_eq!(
                    result, expected,
                    "committed={committed}, parent code: {kind}"
                );
            });
        }
    }
}
