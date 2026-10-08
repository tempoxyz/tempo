//! [TIP-1132] Key Publisher precompile. Enabled on `TempoHardfork::T14`.
//!
//! Publishers list the identity-provider keys that ZK signatures ([TIP-1131]) may use. Each ZK
//! signature names one publisher, so a publisher affects only the addresses that name it.
//!
//! [TIP-1131]: <https://docs.tempo.xyz/protocol/tips/tip-1131>
//! [TIP-1132]: <https://docs.tempo.xyz/protocol/tips/tip-1132>

pub mod dispatch;

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolValue,
};
pub use tempo_contracts::precompiles::{
    IKeyPublisher, KEY_PUBLISHER_ADDRESS, KeyPublisherError, KeyPublisherEvent,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::BN254_SCALAR_FIELD;

/// How long a key dropped by `setKeys` stays valid, in seconds. Longer than the 600-second
/// maximum window of scheme `0x01`, so a sign-in in progress survives a routine rotation.
pub const KEY_GRACE_PERIOD: u64 = 3_600;

/// Most keys a publisher may list for one issuer.
pub const MAX_KEYS_PER_ISSUER: usize = 16;

/// `keyValidUntil` value of a listed key.
pub const ACTIVE: u64 = u64::MAX;

/// [TIP-1132] Key Publisher contract.
///
/// The struct fields define the Solidity storage layout: `owners` at slot 0, `activeKeySets` at
/// slot 1, and `keyValidUntil` at slot 2. Nodes read `keyValidUntil` directly during ZK
/// signature validation; see [`key_valid_until_slot`].
///
/// [TIP-1132]: <https://docs.tempo.xyz/protocol/tips/tip-1132>
#[contract(addr = KEY_PUBLISHER_ADDRESS)]
pub struct KeyPublisher {
    /// `publisherId => owner`. A publisher exists exactly when its owner is nonzero.
    owners: Mapping<B256, Address>,
    /// `publisherId => issuer => active key hashes`, strictly ascending.
    active_key_sets: Mapping<B256, Mapping<B256, Vec<B256>>>,
    /// `publisherId => issuer => keyHash => valid until`: [`ACTIVE`] while listed, the end of the
    /// grace period after the key is dropped, or zero if never listed or revoked.
    key_valid_until: Mapping<B256, Mapping<B256, Mapping<B256, u64>>>,
}

/// Returns the storage slot of `keyValidUntil[publisher_id][issuer][key_hash]`.
pub fn key_valid_until_slot(publisher_id: B256, issuer: B256, key_hash: B256) -> U256 {
    KeyPublisher::new().key_valid_until[publisher_id][issuer][key_hash].slot()
}

/// Returns whether a `keyValidUntil` value allows ZK signatures at `timestamp`.
pub const fn is_key_active_at(valid_until: u64, timestamp: u64) -> bool {
    valid_until != 0 && timestamp <= valid_until
}

/// Returns `keccak256(abi.encode(creator, salt))`.
pub fn compute_publisher_id(creator: Address, salt: B256) -> B256 {
    alloy::primitives::keccak256((creator, salt).abi_encode())
}

impl KeyPublisher {
    /// Initializes the contract by setting its bytecode marker.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Creates the publisher `keccak256(abi.encode(msg_sender, salt))` and lists its first keys.
    ///
    /// # Errors
    /// - `ZeroAddress`: `owner` is zero.
    /// - `PublisherExists`: the publisher already has an owner.
    /// - `IssuersNotSorted`: the issuers in `initialKeys` are not strictly ascending.
    /// - Any error of [`Self::set_keys`] argument validation, for each entry.
    pub fn create_publisher(
        &mut self,
        msg_sender: Address,
        call: IKeyPublisher::createPublisherCall,
    ) -> Result<B256> {
        if call.owner.is_zero() {
            return Err(KeyPublisherError::zero_address().into());
        }
        let publisher_id = self.publisher_id(msg_sender, call.salt)?;
        if !self.owners[publisher_id].read()?.is_zero() {
            return Err(KeyPublisherError::publisher_exists().into());
        }
        if call
            .initialKeys
            .windows(2)
            .any(|pair| pair[0].issuer >= pair[1].issuer)
        {
            return Err(KeyPublisherError::issuers_not_sorted().into());
        }
        for entry in &call.initialKeys {
            validate_keys(entry.issuer, &entry.keyHashes)?;
        }

        self.owners[publisher_id].write(call.owner)?;
        self.emit_event(KeyPublisherEvent::publisher_created(
            publisher_id,
            msg_sender,
            call.owner,
        ))?;
        for entry in call.initialKeys {
            self.replace_keys(publisher_id, entry.issuer, entry.keyHashes)?;
        }
        Ok(publisher_id)
    }

    /// Returns the ID that `creator` gets for `salt`.
    pub fn publisher_id(&self, creator: Address, salt: B256) -> Result<B256> {
        self.storage.keccak256(&(creator, salt).abi_encode())
    }

    /// Transfers a publisher to `newOwner`, effective immediately.
    ///
    /// # Errors
    /// - `UnknownPublisher`, then `Unauthorized`: see [`Self::set_keys`].
    /// - `ZeroAddress`: `newOwner` is zero.
    pub fn transfer_ownership(
        &mut self,
        msg_sender: Address,
        call: IKeyPublisher::transferOwnershipCall,
    ) -> Result<()> {
        let previous = self.authorize(call.publisherId, msg_sender)?;
        if call.newOwner.is_zero() {
            return Err(KeyPublisherError::zero_address().into());
        }
        self.owners[call.publisherId].write(call.newOwner)?;
        self.emit_event(KeyPublisherEvent::ownership_transferred(
            call.publisherId,
            previous,
            call.newOwner,
        ))
    }

    /// Replaces an issuer's active keys. Listed keys become [`ACTIVE`]; previously active keys
    /// that are not listed stay valid for [`KEY_GRACE_PERIOD`].
    ///
    /// # Errors
    /// - `UnknownPublisher`: the publisher does not exist.
    /// - `Unauthorized`: `msg_sender` is not the publisher's owner.
    /// - `InvalidFieldElement`: the issuer or a key hash is zero or not below the BN254 scalar
    ///   field modulus.
    /// - `KeysNotSorted`: `keyHashes` is not strictly ascending.
    /// - `TooManyKeys`: `keyHashes` has more than [`MAX_KEYS_PER_ISSUER`] entries.
    pub fn set_keys(
        &mut self,
        msg_sender: Address,
        call: IKeyPublisher::setKeysCall,
    ) -> Result<()> {
        self.authorize(call.publisherId, msg_sender)?;
        validate_keys(call.issuer, &call.keyHashes)?;
        self.replace_keys(call.publisherId, call.issuer, call.keyHashes)
    }

    /// Revokes a key immediately, with no grace period. Revoking an inactive key succeeds.
    ///
    /// # Errors
    /// - `UnknownPublisher`, `Unauthorized`, and `InvalidFieldElement`: see [`Self::set_keys`].
    pub fn revoke_key(
        &mut self,
        msg_sender: Address,
        call: IKeyPublisher::revokeKeyCall,
    ) -> Result<()> {
        let IKeyPublisher::revokeKeyCall {
            publisherId: publisher_id,
            issuer,
            keyHash: key_hash,
        } = call;
        self.authorize(publisher_id, msg_sender)?;
        validate_field_element(issuer)?;
        validate_field_element(key_hash)?;

        self.key_valid_until[publisher_id][issuer][key_hash].write(0)?;
        let mut keys = self.active_key_sets[publisher_id][issuer].read()?;
        if let Ok(index) = keys.binary_search(&key_hash) {
            keys.remove(index);
            self.active_key_sets[publisher_id][issuer].write(keys)?;
        }
        self.emit_event(KeyPublisherEvent::key_revoked(
            publisher_id,
            issuer,
            key_hash,
        ))
    }

    /// Returns a publisher's owner, or the zero address if it does not exist.
    pub fn owner(&self, publisher_id: B256) -> Result<Address> {
        self.owners[publisher_id].read()
    }

    /// Returns an issuer's active keys in ascending order.
    pub fn active_keys(&self, publisher_id: B256, issuer: B256) -> Result<Vec<B256>> {
        self.active_key_sets[publisher_id][issuer].read()
    }

    /// Returns a key's `keyValidUntil` value.
    pub fn key_valid_until(&self, publisher_id: B256, issuer: B256, key_hash: B256) -> Result<u64> {
        self.key_valid_until[publisher_id][issuer][key_hash].read()
    }

    /// Returns whether ZK signatures may use a key in the current block.
    pub fn is_key_active(&self, publisher_id: B256, issuer: B256, key_hash: B256) -> Result<bool> {
        let valid_until = self.key_valid_until(publisher_id, issuer, key_hash)?;
        let now = self.storage.timestamp().saturating_to::<u64>();
        Ok(is_key_active_at(valid_until, now))
    }

    /// Checks that the publisher exists and `msg_sender` owns it, returning the owner.
    fn authorize(&self, publisher_id: B256, msg_sender: Address) -> Result<Address> {
        let owner = self.owners[publisher_id].read()?;
        if owner.is_zero() {
            return Err(KeyPublisherError::unknown_publisher().into());
        }
        if owner != msg_sender {
            return Err(KeyPublisherError::unauthorized().into());
        }
        Ok(owner)
    }

    /// Replaces an issuer's active list with validated, sorted `key_hashes`.
    fn replace_keys(
        &mut self,
        publisher_id: B256,
        issuer: B256,
        key_hashes: Vec<B256>,
    ) -> Result<()> {
        let now = self.storage.timestamp().saturating_to::<u64>();
        let grace_until = now.saturating_add(KEY_GRACE_PERIOD);

        // Both lists are strictly ascending, so membership is a binary search.
        for dropped in self.active_key_sets[publisher_id][issuer].read()? {
            if key_hashes.binary_search(&dropped).is_err() {
                self.key_valid_until[publisher_id][issuer][dropped].write(grace_until)?;
            }
        }
        for key_hash in &key_hashes {
            self.key_valid_until[publisher_id][issuer][*key_hash].write(ACTIVE)?;
        }
        self.active_key_sets[publisher_id][issuer].write(key_hashes.clone())?;
        self.emit_event(KeyPublisherEvent::keys_set(
            publisher_id,
            issuer,
            key_hashes,
            grace_until,
        ))
    }
}

/// Validates `setKeys` arguments, in the order TIP-1132 lists its errors.
fn validate_keys(issuer: B256, key_hashes: &[B256]) -> Result<()> {
    validate_field_element(issuer)?;
    for key_hash in key_hashes {
        validate_field_element(*key_hash)?;
    }
    if key_hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(KeyPublisherError::keys_not_sorted().into());
    }
    if key_hashes.len() > MAX_KEYS_PER_ISSUER {
        return Err(KeyPublisherError::too_many_keys().into());
    }
    Ok(())
}

/// Requires a nonzero value below the BN254 scalar field modulus.
fn validate_field_element(value: B256) -> Result<()> {
    let value = U256::from_be_bytes(value.0);
    if value.is_zero() || value >= BN254_SCALAR_FIELD {
        return Err(KeyPublisherError::invalid_field_element().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{PrecompileStorageProvider, StorageCtx, hashmap::HashMapStorageProvider},
    };
    use tempo_chainspec::hardfork::TempoHardfork;

    const NOW: u64 = 1_700_000_000;
    const CREATOR: Address = Address::repeat_byte(0xc0);
    const OWNER: Address = Address::repeat_byte(0x0e);

    fn key(n: u8) -> B256 {
        B256::with_last_byte(n)
    }

    fn with_publisher(
        initial: Vec<IKeyPublisher::IssuerKeys>,
        f: impl FnOnce(&mut KeyPublisher, &mut HashMapStorageProvider, B256) -> eyre::Result<()>,
    ) -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, || {
            let mut publisher = KeyPublisher::new();
            let id = publisher.create_publisher(
                CREATOR,
                IKeyPublisher::createPublisherCall {
                    salt: B256::repeat_byte(1),
                    owner: OWNER,
                    initialKeys: initial,
                },
            )?;
            Ok::<_, TempoPrecompileError>((publisher, id))
        })
        .map_err(|e| eyre::eyre!("{e:?}"))
        .and_then(|(mut publisher, id)| f(&mut publisher, &mut storage, id))
    }

    fn assert_error(result: Result<impl core::fmt::Debug>, expected: KeyPublisherError) {
        match result {
            Err(TempoPrecompileError::KeyPublisherError(err)) => assert_eq!(err, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }

    #[test]
    fn publisher_id_matches_abi_encoding() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || {
            let publisher = KeyPublisher::new();
            let salt = B256::repeat_byte(7);
            let id = publisher.publisher_id(CREATOR, salt)?;
            assert_eq!(id, compute_publisher_id(CREATOR, salt));
            let mut preimage = [0u8; 64];
            preimage[12..32].copy_from_slice(CREATOR.as_slice());
            preimage[32..].copy_from_slice(salt.as_slice());
            assert_eq!(id, alloy::primitives::keccak256(preimage));
            Ok::<_, TempoPrecompileError>(())
        })?;
        Ok(())
    }

    #[test]
    fn create_lists_initial_keys_and_rejects_duplicates() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        storage.set_timestamp(U256::from(NOW));
        StorageCtx::enter(&mut storage, || {
            let mut publisher = KeyPublisher::new();
            let call = |owner, initial_keys| IKeyPublisher::createPublisherCall {
                salt: B256::ZERO,
                owner,
                initialKeys: initial_keys,
            };
            assert_error(
                publisher.create_publisher(CREATOR, call(Address::ZERO, vec![])),
                KeyPublisherError::zero_address(),
            );
            assert_error(
                publisher.create_publisher(
                    CREATOR,
                    call(
                        OWNER,
                        vec![
                            IKeyPublisher::IssuerKeys {
                                issuer: key(2),
                                keyHashes: vec![key(1)],
                            },
                            IKeyPublisher::IssuerKeys {
                                issuer: key(2),
                                keyHashes: vec![key(3)],
                            },
                        ],
                    ),
                ),
                KeyPublisherError::issuers_not_sorted(),
            );
            assert_error(
                publisher.create_publisher(
                    CREATOR,
                    call(
                        OWNER,
                        vec![IKeyPublisher::IssuerKeys {
                            issuer: key(2),
                            keyHashes: vec![key(3), key(1)],
                        }],
                    ),
                ),
                KeyPublisherError::keys_not_sorted(),
            );

            let initial = vec![
                IKeyPublisher::IssuerKeys {
                    issuer: key(1),
                    keyHashes: vec![key(10), key(11)],
                },
                IKeyPublisher::IssuerKeys {
                    issuer: key(2),
                    keyHashes: vec![],
                },
            ];
            let id = publisher.create_publisher(CREATOR, call(OWNER, initial.clone()))?;
            assert_eq!(id, compute_publisher_id(CREATOR, B256::ZERO));
            assert_eq!(publisher.owner(id)?, OWNER);
            assert_eq!(publisher.active_keys(id, key(1))?, vec![key(10), key(11)]);
            assert_eq!(publisher.key_valid_until(id, key(1), key(10))?, ACTIVE);
            assert!(publisher.is_key_active(id, key(1), key(11))?);
            publisher.assert_emitted_events(vec![
                KeyPublisherEvent::publisher_created(id, CREATOR, OWNER),
                KeyPublisherEvent::keys_set(
                    id,
                    key(1),
                    vec![key(10), key(11)],
                    NOW + KEY_GRACE_PERIOD,
                ),
                KeyPublisherEvent::keys_set(id, key(2), vec![], NOW + KEY_GRACE_PERIOD),
            ]);

            assert_error(
                publisher.create_publisher(CREATOR, call(OWNER, initial)),
                KeyPublisherError::publisher_exists(),
            );
            // Another creator with the same salt gets a different ID.
            let other = publisher.create_publisher(OWNER, call(OWNER, vec![]))?;
            assert_ne!(other, id);
            Ok::<_, TempoPrecompileError>(())
        })?;
        Ok(())
    }

    #[test]
    fn rotation_keeps_dropped_keys_for_the_grace_period() -> eyre::Result<()> {
        let initial = vec![IKeyPublisher::IssuerKeys {
            issuer: key(1),
            keyHashes: vec![key(10), key(11)],
        }];
        with_publisher(initial, |publisher, storage, id| {
            let set = |keys| IKeyPublisher::setKeysCall {
                publisherId: id,
                issuer: key(1),
                keyHashes: keys,
            };
            StorageCtx::enter(storage, || {
                publisher.set_keys(OWNER, set(vec![key(11), key(12)]))?;
                Ok::<_, TempoPrecompileError>(())
            })?;
            let grace_until = NOW + KEY_GRACE_PERIOD;
            for (timestamp, active) in [
                (grace_until - 1, true),
                (grace_until, true),
                (grace_until + 1, false),
            ] {
                storage.set_timestamp(U256::from(timestamp));
                StorageCtx::enter(storage, || {
                    assert_eq!(publisher.key_valid_until(id, key(1), key(10))?, grace_until);
                    assert_eq!(publisher.is_key_active(id, key(1), key(10))?, active);
                    assert!(publisher.is_key_active(id, key(1), key(12))?);
                    Ok::<_, TempoPrecompileError>(())
                })?;
            }

            // Re-listing a key in its grace period makes it active again.
            StorageCtx::enter(storage, || {
                publisher.set_keys(OWNER, set(vec![key(10), key(11), key(12)]))?;
                assert_eq!(publisher.key_valid_until(id, key(1), key(10))?, ACTIVE);
                // Repeating the call changes nothing.
                publisher.set_keys(OWNER, set(vec![key(10), key(11), key(12)]))?;
                assert_eq!(
                    publisher.active_keys(id, key(1))?,
                    vec![key(10), key(11), key(12)]
                );
                // An empty list drops every key.
                publisher.set_keys(OWNER, set(vec![]))?;
                assert!(publisher.active_keys(id, key(1))?.is_empty());
                assert_ne!(publisher.key_valid_until(id, key(1), key(12))?, ACTIVE);
                Ok::<_, TempoPrecompileError>(())
            })?;
            Ok(())
        })
    }

    #[test]
    fn revoke_is_immediate_and_relisting_restores() -> eyre::Result<()> {
        let initial = vec![IKeyPublisher::IssuerKeys {
            issuer: key(1),
            keyHashes: vec![key(10), key(11), key(12)],
        }];
        with_publisher(initial, |publisher, storage, id| {
            StorageCtx::enter(storage, || {
                let revoke = |key_hash| IKeyPublisher::revokeKeyCall {
                    publisherId: id,
                    issuer: key(1),
                    keyHash: key_hash,
                };
                publisher.clear_emitted_events();
                publisher.revoke_key(OWNER, revoke(key(11)))?;
                assert_eq!(publisher.key_valid_until(id, key(1), key(11))?, 0);
                assert!(!publisher.is_key_active(id, key(1), key(11))?);
                assert_eq!(publisher.active_keys(id, key(1))?, vec![key(10), key(12)]);
                // Revoking an inactive key succeeds.
                publisher.revoke_key(OWNER, revoke(key(99)))?;
                publisher.assert_emitted_events(vec![
                    KeyPublisherEvent::key_revoked(id, key(1), key(11)),
                    KeyPublisherEvent::key_revoked(id, key(1), key(99)),
                ]);
                // Re-listing a revoked key restores it.
                publisher.set_keys(
                    OWNER,
                    IKeyPublisher::setKeysCall {
                        publisherId: id,
                        issuer: key(1),
                        keyHashes: vec![key(10), key(11), key(12)],
                    },
                )?;
                assert_eq!(publisher.key_valid_until(id, key(1), key(11))?, ACTIVE);
                Ok::<_, TempoPrecompileError>(())
            })?;
            Ok(())
        })
    }

    #[test]
    fn rejects_invalid_arguments_and_callers() -> eyre::Result<()> {
        with_publisher(vec![], |publisher, storage, id| {
            StorageCtx::enter(storage, || {
                let set = |publisher_id, issuer, keys| IKeyPublisher::setKeysCall {
                    publisherId: publisher_id,
                    issuer,
                    keyHashes: keys,
                };
                let r = B256::from(BN254_SCALAR_FIELD.to_be_bytes::<32>());
                assert_error(
                    publisher.set_keys(OWNER, set(B256::ZERO, key(1), vec![])),
                    KeyPublisherError::unknown_publisher(),
                );
                assert_error(
                    publisher.set_keys(CREATOR, set(id, key(1), vec![])),
                    KeyPublisherError::unauthorized(),
                );
                for bad in [B256::ZERO, r] {
                    assert_error(
                        publisher.set_keys(OWNER, set(id, bad, vec![])),
                        KeyPublisherError::invalid_field_element(),
                    );
                    assert_error(
                        publisher.set_keys(OWNER, set(id, key(1), vec![bad])),
                        KeyPublisherError::invalid_field_element(),
                    );
                }
                assert_error(
                    publisher.set_keys(OWNER, set(id, key(1), vec![key(2), key(2)])),
                    KeyPublisherError::keys_not_sorted(),
                );
                assert_error(
                    publisher.set_keys(OWNER, set(id, key(1), (1..=17).map(key).collect())),
                    KeyPublisherError::too_many_keys(),
                );
                publisher.set_keys(OWNER, set(id, key(1), (1..=16).map(key).collect()))?;

                // Ownership transfer.
                let transfer = |new_owner| IKeyPublisher::transferOwnershipCall {
                    publisherId: id,
                    newOwner: new_owner,
                };
                assert_error(
                    publisher.transfer_ownership(OWNER, transfer(Address::ZERO)),
                    KeyPublisherError::zero_address(),
                );
                publisher.clear_emitted_events();
                publisher.transfer_ownership(OWNER, transfer(CREATOR))?;
                publisher.assert_emitted_events(vec![KeyPublisherEvent::ownership_transferred(
                    id, OWNER, CREATOR,
                )]);
                assert_error(
                    publisher.set_keys(OWNER, set(id, key(1), vec![])),
                    KeyPublisherError::unauthorized(),
                );
                publisher.set_keys(CREATOR, set(id, key(1), vec![]))?;
                Ok::<_, TempoPrecompileError>(())
            })?;
            Ok(())
        })
    }

    #[test]
    fn node_slot_matches_storage() -> eyre::Result<()> {
        let initial = vec![IKeyPublisher::IssuerKeys {
            issuer: key(1),
            keyHashes: vec![key(10)],
        }];
        with_publisher(initial, |_, storage, id| {
            // keccak256(key_hash . keccak256(issuer . keccak256(publisher_id . uint256(2))))
            let level = |key: B256, slot: B256| {
                alloy::primitives::keccak256([key.as_slice(), slot.as_slice()].concat())
            };
            let expected = level(
                key(10),
                level(
                    key(1),
                    level(id, B256::from(U256::from(2).to_be_bytes::<32>())),
                ),
            );
            let slot = key_valid_until_slot(id, key(1), key(10));
            assert_eq!(B256::from(slot.to_be_bytes::<32>()), expected);
            let value = storage.sload(KEY_PUBLISHER_ADDRESS, slot)?;
            assert_eq!(value, U256::from(ACTIVE));
            assert!(is_key_active_at(value.saturating_to(), NOW));
            assert!(!is_key_active_at(0, NOW));
            Ok(())
        })
    }
}
