//! Journaled native account configuration updates.
pub mod dispatch;
#[cfg(test)]
mod migration_tests;
#[cfg(test)]
mod tests;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{ConfigCommitmentWriteGas, Handler, StorageCtx},
};
use alloy::primitives::{Address, B256};
pub use tempo_chainspec::is_valid_native_account as valid_account;
use tempo_contracts::precompiles::{
    INativeMultisig, NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::{
    account::decode_config_commitment,
    transaction::{
        MultisigConfig, MultisigConfigError, MultisigOwner,
        multisig::MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN,
    },
};

#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    tx_origin: Address,
    directly_authorized_account: Address,
    migration_root: Address,
    migration_only_call: bool,
}

impl NativeMultisig {
    /// Seeds only the direct outer owner-quorum authority, never a delegate or sponsor.
    pub fn set_authority(&mut self, origin: Address, directly_authorized: Address) -> Result<()> {
        self.tx_origin.t_write(origin)?;
        self.directly_authorized_account
            .t_write(directly_authorized)
    }

    pub fn derive_account(
        &self,
        salt: B256,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<Address> {
        let factory = self.factory()?;
        let config = config(salt, 0, threshold, owners);
        config.validate().map_err(map_config_error)?;
        self.storage
            .deduct_gas(initial_account_proof_gas(&config))?;
        let account = config.derive_account(factory).map_err(map_config_error)?;
        if !valid_account(account, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        Ok(account)
    }

    pub fn get_config_commitment(&self, account: Address) -> Result<B256> {
        self.storage.config_commitment(account)
    }

    pub fn update_config(
        &mut self,
        sender: Address,
        current: INativeMultisig::MultisigConfig,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<()> {
        // The wrapper rejects delegatecall; a validated native origin cannot have code.
        // Together these conditions restrict authority to protocol-created batch calls.
        if sender.is_zero()
            || self.tx_origin.t_read()? != sender
            || self.directly_authorized_account.t_read()? != sender
        {
            return Err(NativeMultisigError::unauthorized_multisig_caller().into());
        }
        self.factory()?;
        let current = config(
            current.salt,
            current.version,
            current.threshold,
            current.owners,
        );
        current
            .validate_for_account(sender)
            .map_err(map_config_error)?;
        let stored = self.get_config_commitment(sender)?;
        let hash = self
            .storage
            .keccak256(&current.commitment_preimage().map_err(map_config_error)?)?;
        if stored.is_zero() || stored != hash {
            return Err(NativeMultisigError::invalid_config().into());
        }
        let version = current
            .version
            .checked_add(1)
            .ok_or_else(NativeMultisigError::invalid_config)?;
        let next = config(current.salt, version, threshold, owners.clone());
        next.validate_for_account(sender)
            .map_err(map_config_error)?;
        let hash = self
            .storage
            .keccak256(&next.commitment_preimage().map_err(map_config_error)?)?;
        if hash.is_zero() {
            return Err(NativeMultisigError::invalid_config().into());
        }
        self.storage
            .set_config_commitment(sender, hash, ConfigCommitmentWriteGas::Precompile)?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            sender, next.salt, version, threshold, owners,
        ))
    }

    fn factory(&self) -> Result<Address> {
        self.storage
            .with_block_env(|block| block.multisig_recovery_factory)
            .filter(|factory| !factory.is_zero())
            .ok_or_else(|| NativeMultisigError::invalid_config().into())
    }

    /// Handler-only transaction context; all fields are reset before each execution.
    pub fn set_migration_authority(&mut self, root: Address, only_call: bool) -> Result<()> {
        self.migration_root.t_write(root)?;
        self.migration_only_call.t_write(only_call)
    }

    /// Journaled in-place migration authorized only by a direct primitive root.
    pub fn upgrade_account(
        &mut self,
        sender: Address,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<B256> {
        if !self.storage.spec().is_t14()
            || !self
                .storage
                .with_block_env(|block| block.account_migration_enabled)
        {
            return Err(NativeMultisigError::migration_not_active().into());
        }
        if sender.is_zero()
            || self.tx_origin.t_read()? != sender
            || self.migration_root.t_read()? != sender
        {
            return Err(NativeMultisigError::primitive_root_required().into());
        }
        if !self.migration_only_call.t_read()? {
            return Err(NativeMultisigError::upgrade_must_be_only_call().into());
        }
        if !valid_account(sender, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        let (has_code, commitment) = self.storage.with_account_info(sender, |info| {
            Ok((
                !info.is_empty_code_hash(),
                decode_config_commitment(&info.extension, true)
                    .map_err(|error| TempoPrecompileError::Fatal(error.to_string()))?,
            ))
        })?;
        if has_code {
            return Err(NativeMultisigError::account_has_code().into());
        }
        if !commitment.is_zero() {
            return Err(NativeMultisigError::account_already_configurable().into());
        }
        self.factory()?;
        let salt = self
            .storage
            .keccak256(&[b"tempo:multisig:upgrade".as_slice(), sender.as_slice()].concat())?;
        // Positive versions permit the old root as an explicitly weighted owner and
        // validate against the stored leaf rather than re-deriving the account address.
        let next = config(salt, 1, threshold, owners.clone());
        next.validate_for_account(sender)
            .map_err(|_| NativeMultisigError::invalid_config())?;
        let hash = self.storage.keccak256(
            &next
                .commitment_preimage()
                .map_err(|_| NativeMultisigError::invalid_config())?,
        )?;
        if hash.is_zero() {
            return Err(NativeMultisigError::invalid_config().into());
        }
        self.storage
            .set_config_commitment(sender, hash, ConfigCommitmentWriteGas::Migration)?;
        self.emit_event(NativeMultisigEvent::account_upgraded(
            sender, hash, salt, threshold, owners,
        ))?;
        Ok(hash)
    }
}

pub const fn keccak_cost(bytes: usize) -> u64 {
    30 + 6 * bytes.div_ceil(32) as u64
}

/// Hashing cost of deriving an unregistered account from its initial configuration.
pub fn initial_account_proof_gas(config: &MultisigConfig) -> u64 {
    keccak_cost(config.account_salt_preimage_len())
        + keccak_cost(MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN)
}

fn config(
    salt: B256,
    version: u64,
    threshold: u8,
    owners: Vec<INativeMultisig::MultisigOwner>,
) -> MultisigConfig {
    MultisigConfig {
        salt,
        version,
        threshold,
        owners: owners
            .into_iter()
            .map(|owner| MultisigOwner {
                owner: owner.owner,
                weight: owner.weight,
            })
            .collect(),
    }
}

fn map_config_error(error: MultisigConfigError) -> TempoPrecompileError {
    match error {
        MultisigConfigError::EmptyOwners
        | MultisigConfigError::ZeroOwner
        | MultisigConfigError::AccountIsOwner => NativeMultisigError::invalid_multisig_owner(),
        MultisigConfigError::TooManyOwners => NativeMultisigError::too_many_owners(),
        MultisigConfigError::ZeroThreshold | MultisigConfigError::ThresholdExceedsWeight => {
            NativeMultisigError::invalid_threshold()
        }
        MultisigConfigError::ZeroWeight | MultisigConfigError::TotalWeightExceedsMax => {
            NativeMultisigError::invalid_weight()
        }
        MultisigConfigError::DuplicateOwner => NativeMultisigError::duplicate_owner(),
        MultisigConfigError::OwnersNotAscending => NativeMultisigError::invalid_owner_order(),
        MultisigConfigError::DerivedAccountZero => NativeMultisigError::invalid_account(),
    }
    .into()
}

/// Protocol authority check, not a pure signature recovery check.
pub fn root_key_retired(account: Address) -> Result<bool> {
    if !StorageCtx.spec().is_t14()
        || !StorageCtx.with_block_env(|block| block.account_migration_enabled)
    {
        return Ok(false);
    }
    Ok(!StorageCtx.config_commitment(account)?.is_zero())
}

/// Rejects independently acting primitive keys after migration activation.
pub fn ensure_root_key_active(account: Address) -> Result<()> {
    if root_key_retired(account)? {
        return Err(NativeMultisigError::root_key_retired(account).into());
    }
    Ok(())
}
