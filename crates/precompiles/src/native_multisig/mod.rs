//! Native multisig account precompile.

pub mod auth;
pub mod dispatch;

pub use auth::NativeMultisigAuthError;
pub use tempo_contracts::precompiles::INativeMultisig;

use crate::{
    account_keychain::{AccountKeychain, getTransactionKeyCall},
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, StorageCtx},
};
use alloy::primitives::{Address, B256, TxKind, U256};
use tempo_contracts::precompiles::{
    NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{MultisigConfig, MultisigConfigError};

use crate::is_valid_multisig_account;

/// Native multisig account storage.
#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    /// Latest nonzero configuration commitment. Zero means no update has occurred.
    config_commitments: Mapping<Address, B256>,

    // WARNING: transient storage slots must remain after persistent storage fields until the
    // `contract` macro supports independent persistent/transient layouts.
    tx_origin: Address,
    directly_authorized_account: Address,
}

impl NativeMultisig {
    /// Initializes the precompile storage layout.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the persistent commitment slot for `account`.
    pub fn config_commitment_storage_slot(account: Address) -> U256 {
        Self::new().config_commitments[account].slot()
    }

    /// Seeds the enclosing transaction origin.
    pub fn set_tx_origin(&mut self, origin: Address) -> Result<()> {
        self.tx_origin.t_write(origin)
    }

    /// Records the account directly authorized by the outer multisig signature.
    pub fn set_directly_authorized_account(&mut self, account: Address) -> Result<()> {
        self.directly_authorized_account.t_write(account)
    }

    /// Derives an account from an initial configuration without reading persistent state.
    pub fn derive_account(
        &self,
        salt: B256,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<Address> {
        self.derive_account_from_config(&MultisigConfig {
            salt,
            version: 0,
            threshold,
            owners: owners.into_iter().map(Into::into).collect(),
        })
    }

    /// Returns the persisted configuration commitment, including zero before the first update.
    pub fn get_config_commitment(&self, account: Address) -> Result<B256> {
        self.config_commitments[account].read()
    }

    /// Commits to the caller's next owner configuration.
    pub fn update_multisig_config(
        &mut self,
        msg_sender: Address,
        current: INativeMultisig::MultisigConfig,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<()> {
        self.ensure_update_authorized(msg_sender)?;

        let current = MultisigConfig::from(current);
        current
            .validate_for_account(msg_sender)
            .map_err(map_multisig_config_error)?;
        let stored = self.get_config_commitment(msg_sender)?;
        if current.version == 0 {
            if !stored.is_zero() || self.derive_account_from_config(&current)? != msg_sender {
                return Err(NativeMultisigError::invalid_config().into());
            }
        } else if stored.is_zero() || self.hash_config_commitment(&current)? != stored {
            return Err(NativeMultisigError::invalid_config().into());
        }

        let version = current
            .version
            .checked_add(1)
            .ok_or_else(NativeMultisigError::invalid_config)?;
        let event_owners = owners.clone();
        let next = MultisigConfig {
            salt: current.salt,
            version,
            threshold,
            owners: owners.into_iter().map(Into::into).collect(),
        };
        next.validate_for_account(msg_sender)
            .map_err(map_multisig_config_error)?;
        let commitment = self.hash_config_commitment(&next)?;
        if commitment.is_zero() {
            return Err(NativeMultisigError::invalid_config().into());
        }

        self.config_commitments[msg_sender].write(commitment)?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            msg_sender,
            next.salt,
            next.version,
            next.threshold,
            event_owners,
        ))
    }

    fn ensure_update_authorized(&self, msg_sender: Address) -> Result<()> {
        if StorageCtx.tx_kind() != Some(TxKind::Call(NATIVE_MULTISIG_ADDRESS))
            || self.tx_origin.t_read()? != msg_sender
            || self.directly_authorized_account.t_read()? != msg_sender
        {
            return Err(NativeMultisigError::unauthorized_multisig_caller().into());
        }

        let transaction_key =
            AccountKeychain::new().get_transaction_key(getTransactionKeyCall {}, msg_sender)?;
        if !transaction_key.is_zero() {
            return Err(NativeMultisigError::unauthorized_multisig_caller().into());
        }
        Ok(())
    }

    fn derive_account_from_config(&self, config: &MultisigConfig) -> Result<Address> {
        config.validate().map_err(map_multisig_config_error)?;
        let preimage = config
            .account_derivation_preimage()
            .map_err(map_multisig_config_error)?;
        let hash = self.storage.keccak256(&preimage)?;
        let account = Address::from_slice(&hash[12..]);
        if config.owner_weight(account).is_some() {
            return Err(NativeMultisigError::invalid_multisig_owner().into());
        }
        if !is_valid_multisig_account(account, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        Ok(account)
    }

    fn hash_config_commitment(&self, config: &MultisigConfig) -> Result<B256> {
        let preimage = config
            .commitment_preimage()
            .map_err(map_multisig_config_error)?;
        self.storage.keccak256(&preimage)
    }
}

fn map_multisig_config_error(err: MultisigConfigError) -> TempoPrecompileError {
    match err {
        MultisigConfigError::EmptyOwners
        | MultisigConfigError::ZeroOwner
        | MultisigConfigError::AccountIsOwner => {
            NativeMultisigError::invalid_multisig_owner().into()
        }
        MultisigConfigError::TooManyOwners => NativeMultisigError::too_many_owners().into(),
        MultisigConfigError::ZeroThreshold | MultisigConfigError::ThresholdExceedsWeight => {
            NativeMultisigError::invalid_threshold().into()
        }
        MultisigConfigError::ZeroWeight | MultisigConfigError::TotalWeightExceedsMax => {
            NativeMultisigError::invalid_weight().into()
        }
        MultisigConfigError::DuplicateOwner => NativeMultisigError::duplicate_owner().into(),
        MultisigConfigError::OwnersNotAscending => {
            NativeMultisigError::invalid_owner_order().into()
        }
        MultisigConfigError::DerivedAccountZero => NativeMultisigError::invalid_account().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::address;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::MultisigOwner;

    fn initial_config() -> MultisigConfig {
        MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: address!("0000000000000000000000000000000000000011"),
                weight: 1,
            }],
        }
    }

    fn abi_config(config: &MultisigConfig) -> INativeMultisig::MultisigConfig {
        config.clone().into()
    }

    fn abi_owners(owner: Address) -> Vec<INativeMultisig::MultisigOwner> {
        vec![INativeMultisig::MultisigOwner { owner, weight: 1 }]
    }

    #[test]
    fn derive_account_is_stateless_and_meters_hashing() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let config = initial_config();
        let expected = config.derive_account().unwrap();

        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                NativeMultisig::new().derive_account(
                    config.salt,
                    config.threshold,
                    config.owners.clone().into_iter().map(Into::into).collect(),
                )?,
                expected
            );
            Ok::<_, TempoPrecompileError>(())
        })?;

        assert_eq!(storage.counter_sload(), 0);
        assert_eq!(storage.counter_sstore(), 0);
        Ok(())
    }

    #[test]
    fn initial_and_current_updates_replace_one_commitment() -> eyre::Result<()> {
        let config = initial_config();
        let account = config.derive_account().unwrap();
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12)
            .with_tx_kind(TxKind::Call(NATIVE_MULTISIG_ADDRESS));

        StorageCtx::enter(&mut storage, || NativeMultisig::new().initialize())?;
        storage.reset_counters();

        let first_owner = address!("0000000000000000000000000000000000000022");
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            multisig.set_directly_authorized_account(account)?;
            multisig.update_multisig_config(
                account,
                abi_config(&config),
                1,
                abi_owners(first_owner),
            )?;
            Ok::<_, TempoPrecompileError>(())
        })?;

        assert_eq!(storage.counter_sstore(), 1);
        let current = MultisigConfig {
            salt: config.salt,
            version: 1,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: first_owner,
                weight: 1,
            }],
        };
        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                NativeMultisig::new().get_config_commitment(account)?,
                current.commitment().unwrap()
            );
            Ok::<_, TempoPrecompileError>(())
        })?;

        storage.clear_transient();
        let second_owner = address!("0000000000000000000000000000000000000033");
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            multisig.set_directly_authorized_account(account)?;
            multisig.update_multisig_config(
                account,
                abi_config(&current),
                1,
                abi_owners(second_owner),
            )
        })?;

        let next = MultisigConfig {
            owners: vec![MultisigOwner {
                owner: second_owner,
                weight: 1,
            }],
            version: 2,
            ..current
        };
        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                NativeMultisig::new().get_config_commitment(account)?,
                next.commitment().unwrap()
            );
            Ok::<_, TempoPrecompileError>(())
        })?;
        Ok(())
    }

    #[test]
    fn update_requires_direct_outer_authorization() -> eyre::Result<()> {
        let config = initial_config();
        let account = config.derive_account().unwrap();
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12)
            .with_tx_kind(TxKind::Call(NATIVE_MULTISIG_ADDRESS));

        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(account)?;
            assert!(matches!(
                multisig.update_multisig_config(
                    account,
                    abi_config(&config),
                    1,
                    abi_owners(Address::repeat_byte(0x22)),
                ),
                Err(TempoPrecompileError::NativeMultisigError(
                    NativeMultisigError::UnauthorizedMultisigCaller(_)
                ))
            ));
            Ok::<_, TempoPrecompileError>(())
        })?;
        Ok(())
    }
}
