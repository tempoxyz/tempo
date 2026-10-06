use super::*;
use crate::{
    Precompile, expect_precompile_revert,
    storage::{PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider},
};
use alloy::sol_types::{SolCall, SolEvent, SolInterface};

fn field(value: u64) -> B256 {
    U256::from(value).into()
}

fn create(publisher: &mut KeyPublisher, owner: Address, keys: Vec<B256>) -> Result<B256> {
    publisher.create_publisher(
        owner,
        IKeyPublisher::createPublisherCall {
            salt: field(42),
            owner,
            initialKeys: vec![IKeyPublisher::IssuerKeys {
                issuer: field(1),
                keyHashes: keys,
            }],
        },
    )
}

#[test]
fn publisher_id_and_solidity_storage_layout() -> eyre::Result<()> {
    let owner = Address::repeat_byte(1);
    let mut storage = HashMapStorageProvider::new(1337);
    let publisher_id = StorageCtx::enter(&mut storage, || -> Result<B256> {
        let mut publisher = KeyPublisher::new();
        let publisher_id = create(&mut publisher, owner, vec![field(2), field(3)])?;
        assert_eq!(
            publisher_id,
            KeyPublisher::compute_publisher_id(owner, field(42))
        );
        assert_eq!(publisher.owner(publisher_id)?, owner);
        assert_eq!(
            publisher.active_keys(publisher_id, field(1))?,
            vec![field(2), field(3)]
        );
        assert_eq!(
            publisher.key_valid_until(publisher_id, field(1), field(2))?,
            ACTIVE
        );
        Ok(publisher_id)
    })?;
    let owner_slot = U256::from_be_bytes(keccak256((publisher_id, U256::ZERO).abi_encode()).0);
    assert_eq!(
        storage.sload(KEY_PUBLISHER_ADDRESS, owner_slot)?,
        U256::from_be_slice(owner.as_slice())
    );
    let publisher_slot = keccak256((publisher_id, U256::from(2)).abi_encode());
    let issuer_slot = keccak256((field(1), publisher_slot).abi_encode());
    let key_slot = U256::from_be_bytes(keccak256((field(2), issuer_slot).abi_encode()).0);
    assert_eq!(
        storage.sload(KEY_PUBLISHER_ADDRESS, key_slot)?,
        U256::from(ACTIVE)
    );
    let events = storage.get_events(KEY_PUBLISHER_ADDRESS);
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].topics()[0],
        IKeyPublisher::PublisherCreated::SIGNATURE_HASH
    );
    assert_eq!(
        events[1].topics()[0],
        IKeyPublisher::KeysSet::SIGNATURE_HASH
    );
    Ok(())
}

#[test]
fn rotation_grace_boundaries_and_revocation() -> eyre::Result<()> {
    let owner = Address::repeat_byte(1);
    let mut storage = HashMapStorageProvider::new(1337);
    storage.set_timestamp(U256::from(100));
    StorageCtx::enter(&mut storage, || -> Result<()> {
        let mut publisher = KeyPublisher::new();
        let publisher_id = create(&mut publisher, owner, vec![field(2), field(3)])?;
        publisher.set_keys(
            owner,
            IKeyPublisher::setKeysCall {
                publisherId: publisher_id,
                issuer: field(1),
                keyHashes: vec![field(3), field(4)],
            },
        )?;
        assert_eq!(
            publisher.key_valid_until(publisher_id, field(1), field(2))?,
            3_700
        );
        assert!(publisher.is_key_active(publisher_id, field(1), field(2))?);
        publisher.storage.set_timestamp(U256::from(3_700));
        assert!(publisher.is_key_active(publisher_id, field(1), field(2))?);
        publisher.storage.set_timestamp(U256::from(3_701));
        assert!(!publisher.is_key_active(publisher_id, field(1), field(2))?);
        publisher.revoke_key(
            owner,
            IKeyPublisher::revokeKeyCall {
                publisherId: publisher_id,
                issuer: field(1),
                keyHash: field(3),
            },
        )?;
        assert!(!publisher.is_key_active(publisher_id, field(1), field(3))?);
        assert_eq!(
            publisher.active_keys(publisher_id, field(1))?,
            vec![field(4)]
        );
        publisher.set_keys(
            owner,
            IKeyPublisher::setKeysCall {
                publisherId: publisher_id,
                issuer: field(1),
                keyHashes: vec![field(2), field(3)],
            },
        )?;
        assert_eq!(
            publisher.key_valid_until(publisher_id, field(1), field(2))?,
            ACTIVE
        );
        assert_eq!(
            publisher.key_valid_until(publisher_id, field(1), field(3))?,
            ACTIVE
        );
        publisher.set_keys(
            owner,
            IKeyPublisher::setKeysCall {
                publisherId: publisher_id,
                issuer: field(1),
                keyHashes: vec![],
            },
        )?;
        assert!(publisher.active_keys(publisher_id, field(1))?.is_empty());
        assert_eq!(
            publisher.key_valid_until(publisher_id, field(1), field(3))?,
            7_301
        );
        publisher.revoke_key(
            owner,
            IKeyPublisher::revokeKeyCall {
                publisherId: publisher_id,
                issuer: field(1),
                keyHash: field(2),
            },
        )?;
        assert!(!publisher.is_key_active(publisher_id, field(1), field(2))?);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn ownership_and_unknown_views() -> eyre::Result<()> {
    let owner = Address::repeat_byte(1);
    let other = Address::repeat_byte(2);
    let mut storage = HashMapStorageProvider::new(1337);
    StorageCtx::enter(&mut storage, || -> Result<()> {
        let mut publisher = KeyPublisher::new();
        assert_eq!(publisher.owner(field(99))?, Address::ZERO);
        assert!(publisher.active_keys(field(99), B256::ZERO)?.is_empty());
        assert_eq!(
            publisher.key_valid_until(field(99), B256::ZERO, B256::ZERO)?,
            0
        );
        assert!(!publisher.is_key_active(field(99), B256::ZERO, B256::ZERO)?);
        let publisher_id = create(&mut publisher, owner, vec![field(2)])?;
        let keys = IKeyPublisher::setKeysCall {
            publisherId: publisher_id,
            issuer: field(1),
            keyHashes: vec![],
        };
        assert_eq!(
            publisher.set_keys(other, keys.clone()),
            Err(KeyPublisherError::unauthorized().into())
        );
        assert_eq!(
            create(&mut publisher, owner, vec![field(2)]),
            Err(KeyPublisherError::publisher_exists().into())
        );
        assert_eq!(
            publisher.transfer_ownership(
                owner,
                IKeyPublisher::transferOwnershipCall {
                    publisherId: publisher_id,
                    newOwner: Address::ZERO
                }
            ),
            Err(KeyPublisherError::zero_address().into())
        );
        publisher.transfer_ownership(
            owner,
            IKeyPublisher::transferOwnershipCall {
                publisherId: publisher_id,
                newOwner: other,
            },
        )?;
        assert_eq!(
            publisher.set_keys(owner, keys.clone()),
            Err(KeyPublisherError::unauthorized().into())
        );
        publisher.set_keys(other, keys)?;
        assert_eq!(publisher.owner(publisher_id)?, other);
        assert_eq!(
            publisher.revoke_key(
                other,
                IKeyPublisher::revokeKeyCall {
                    publisherId: field(99),
                    issuer: field(1),
                    keyHash: field(2)
                }
            ),
            Err(KeyPublisherError::unknown_publisher().into())
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn invalid_lists_do_not_create_publishers() -> eyre::Result<()> {
    let owner = Address::repeat_byte(1);
    let mut storage = HashMapStorageProvider::new(1337);
    StorageCtx::enter(&mut storage, || -> Result<()> {
        let mut publisher = KeyPublisher::new();
        for (keys, expected) in [
            (vec![B256::ZERO], KeyPublisherError::invalid_field_element()),
            (
                vec![BN254_SCALAR_FIELD.into()],
                KeyPublisherError::invalid_field_element(),
            ),
            (
                vec![field(3), field(2)],
                KeyPublisherError::keys_not_sorted(),
            ),
            (
                vec![field(2), field(2)],
                KeyPublisherError::keys_not_sorted(),
            ),
            (
                (1..=17).map(field).collect(),
                KeyPublisherError::too_many_keys(),
            ),
        ] {
            assert_eq!(create(&mut publisher, owner, keys), Err(expected.into()));
            assert_eq!(
                publisher.owner(KeyPublisher::compute_publisher_id(owner, field(42)))?,
                Address::ZERO
            );
        }
        let invalid_issuers = IKeyPublisher::createPublisherCall {
            salt: field(42),
            owner,
            initialKeys: vec![
                IKeyPublisher::IssuerKeys {
                    issuer: field(2),
                    keyHashes: vec![],
                },
                IKeyPublisher::IssuerKeys {
                    issuer: field(1),
                    keyHashes: vec![],
                },
            ],
        };
        assert_eq!(
            publisher.create_publisher(owner, invalid_issuers),
            Err(KeyPublisherError::issuers_not_sorted().into())
        );
        assert_eq!(
            publisher.create_publisher(
                owner,
                IKeyPublisher::createPublisherCall {
                    salt: field(42),
                    owner: Address::ZERO,
                    initialKeys: vec![]
                }
            ),
            Err(KeyPublisherError::zero_address().into())
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn abi_dispatch_and_selector_coverage() -> eyre::Result<()> {
    let owner = Address::repeat_byte(1);
    let mut storage = HashMapStorageProvider::new(1337);
    StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
        let mut publisher = KeyPublisher::new();
        let calldata = IKeyPublisher::createPublisherCall {
            salt: field(42),
            owner,
            initialKeys: vec![],
        }
        .abi_encode();
        let output = publisher.call(&calldata, owner)?;
        assert!(output.is_success());
        let publisher_id = KeyPublisher::compute_publisher_id(owner, field(42));
        assert_eq!(
            IKeyPublisher::createPublisherCall::abi_decode_returns(&output.bytes)?,
            publisher_id
        );
        let output = publisher.call(&calldata, owner);
        expect_precompile_revert(&output, KeyPublisherError::publisher_exists());
        let unsupported = crate::test_util::check_selector_coverage(
            &mut publisher,
            IKeyPublisher::IKeyPublisherCalls::SELECTORS,
            "IKeyPublisher",
            IKeyPublisher::IKeyPublisherCalls::name_by_selector,
        );
        crate::test_util::assert_full_coverage([unsupported]);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn registration_is_opt_in_and_dev_chain_only() {
    for chain_id in [1337, 4217, 42431] {
        let cfg = revm::context::CfgEnv::default().with_chain_id(chain_id);
        let precompiles = crate::tempo_precompiles(
            &cfg,
            crate::storage::actions::StorageActions::disabled(),
            std::rc::Rc::new(std::cell::RefCell::new(
                crate::storage_credits::NonCreditableSlots::empty(),
            )),
        );
        assert_eq!(
            precompiles.get(&KEY_PUBLISHER_ADDRESS).is_some(),
            cfg!(feature = "experimental-oidc") && chain_id == 1337,
        );
    }
}
