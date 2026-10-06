//! Provider key publication and rotation for TIP-1132.

use crate::{
    error::Result,
    storage::{Handler, Mapping},
};
use alloy::{
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use tempo_contracts::precompiles::{IKeyPublisher, KeyPublisherError};
use tempo_precompiles_macros::contract;

pub use tempo_contracts::precompiles::KEY_PUBLISHER_ADDRESS;

pub mod dispatch;

#[cfg(test)]
mod tests;

pub const KEY_GRACE_PERIOD: u64 = 3_600;
pub const MAX_KEYS_PER_ISSUER: usize = 16;
pub const ACTIVE: u64 = u64::MAX;
pub const BN254_SCALAR_FIELD: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

#[contract(addr = KEY_PUBLISHER_ADDRESS)]
pub struct KeyPublisher {
    owners: Mapping<B256, Address>,
    active_key_sets: Mapping<B256, Mapping<B256, Vec<B256>>>,
    key_valid_until: Mapping<B256, Mapping<B256, Mapping<B256, u64>>>,
}

impl KeyPublisher {
    pub fn compute_publisher_id(creator: Address, salt: B256) -> B256 {
        keccak256((creator, salt).abi_encode())
    }

    pub fn owner(&self, publisher_id: B256) -> Result<Address> {
        self.owners[publisher_id].read()
    }

    pub fn active_keys(&self, publisher_id: B256, issuer: B256) -> Result<Vec<B256>> {
        self.active_key_sets[publisher_id][issuer].read()
    }

    pub fn key_valid_until(&self, publisher_id: B256, issuer: B256, key_hash: B256) -> Result<u64> {
        self.key_valid_until[publisher_id][issuer][key_hash].read()
    }

    pub fn is_key_active(&self, publisher_id: B256, issuer: B256, key_hash: B256) -> Result<bool> {
        let value = self.key_valid_until(publisher_id, issuer, key_hash)?;
        Ok(value != 0 && self.storage.timestamp() <= U256::from(value))
    }

    pub fn create_publisher(
        &mut self,
        sender: Address,
        call: IKeyPublisher::createPublisherCall,
    ) -> Result<B256> {
        if call.owner.is_zero() {
            return Err(KeyPublisherError::zero_address().into());
        }
        let publisher_id = Self::compute_publisher_id(sender, call.salt);
        if !self.owner(publisher_id)?.is_zero() {
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
            Self::validate_keys(entry.issuer, &entry.keyHashes)?;
        }
        if self.storage.account_code(self.address)?.1.is_empty() {
            self.__initialize()?;
        }
        self.owners[publisher_id].write(call.owner)?;
        self.emit_event(IKeyPublisher::PublisherCreated {
            publisherId: publisher_id,
            creator: sender,
            owner: call.owner,
        })?;
        for entry in call.initialKeys {
            self.replace_keys(publisher_id, entry.issuer, entry.keyHashes)?;
        }
        Ok(publisher_id)
    }

    pub fn transfer_ownership(
        &mut self,
        sender: Address,
        call: IKeyPublisher::transferOwnershipCall,
    ) -> Result<()> {
        self.require_owner(sender, call.publisherId)?;
        if call.newOwner.is_zero() {
            return Err(KeyPublisherError::zero_address().into());
        }
        self.owners[call.publisherId].write(call.newOwner)?;
        self.emit_event(IKeyPublisher::OwnershipTransferred {
            publisherId: call.publisherId,
            previousOwner: sender,
            newOwner: call.newOwner,
        })
    }

    pub fn set_keys(&mut self, sender: Address, call: IKeyPublisher::setKeysCall) -> Result<()> {
        self.require_owner(sender, call.publisherId)?;
        Self::validate_keys(call.issuer, &call.keyHashes)?;
        self.replace_keys(call.publisherId, call.issuer, call.keyHashes)
    }

    pub fn revoke_key(
        &mut self,
        sender: Address,
        call: IKeyPublisher::revokeKeyCall,
    ) -> Result<()> {
        self.require_owner(sender, call.publisherId)?;
        Self::validate_field(call.issuer)?;
        Self::validate_field(call.keyHash)?;
        let mut keys = self.active_keys(call.publisherId, call.issuer)?;
        if let Ok(index) = keys.binary_search(&call.keyHash) {
            keys.remove(index);
            self.active_key_sets[call.publisherId][call.issuer].write(keys)?;
        }
        self.key_valid_until[call.publisherId][call.issuer][call.keyHash].write(0)?;
        self.emit_event(IKeyPublisher::KeyRevoked {
            publisherId: call.publisherId,
            issuer: call.issuer,
            keyHash: call.keyHash,
        })
    }

    fn require_owner(&self, sender: Address, publisher_id: B256) -> Result<()> {
        let owner = self.owner(publisher_id)?;
        if owner.is_zero() {
            return Err(KeyPublisherError::unknown_publisher().into());
        }
        if sender != owner {
            return Err(KeyPublisherError::unauthorized().into());
        }
        Ok(())
    }

    fn validate_field(value: B256) -> Result<()> {
        if value.is_zero() || U256::from_be_bytes(value.0) >= BN254_SCALAR_FIELD {
            return Err(KeyPublisherError::invalid_field_element().into());
        }
        Ok(())
    }

    fn validate_keys(issuer: B256, keys: &[B256]) -> Result<()> {
        Self::validate_field(issuer)?;
        if keys.len() > MAX_KEYS_PER_ISSUER {
            return Err(KeyPublisherError::too_many_keys().into());
        }
        for key in keys {
            Self::validate_field(*key)?;
        }
        if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(KeyPublisherError::keys_not_sorted().into());
        }
        Ok(())
    }

    fn replace_keys(&mut self, publisher_id: B256, issuer: B256, keys: Vec<B256>) -> Result<()> {
        let grace_until = self
            .storage
            .timestamp()
            .checked_add(U256::from(KEY_GRACE_PERIOD))
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(crate::error::TempoPrecompileError::under_overflow)?;
        for key in self.active_keys(publisher_id, issuer)? {
            if keys.binary_search(&key).is_err() {
                self.key_valid_until[publisher_id][issuer][key].write(grace_until)?;
            }
        }
        for key in &keys {
            self.key_valid_until[publisher_id][issuer][*key].write(ACTIVE)?;
        }
        self.active_key_sets[publisher_id][issuer].write(keys.clone())?;
        self.emit_event(IKeyPublisher::KeysSet {
            publisherId: publisher_id,
            issuer,
            keyHashes: keys,
            graceUntil: grace_until,
        })
    }
}
