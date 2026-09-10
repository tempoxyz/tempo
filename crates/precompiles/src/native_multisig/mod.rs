//! Journaled native account configuration updates.
pub mod dispatch;
#[cfg(test)]
mod tests;

use crate::{
    error::Result,
    storage::{ConfigCommitmentWriteGas, Handler},
};
use alloy::primitives::{Address, B256};
use tempo_contracts::precompiles::{
    INativeMultisig, NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::{
    TempoAddressExt,
    transaction::{
        MultisigConfig, MultisigConfigError, MultisigOwner,
        multisig::MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN,
    },
};

#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    tx_origin: Address,
    directly_authorized_account: Address,
}

impl NativeMultisig {
    /// Seeds only the direct outer owner-quorum authority, never a delegate or sponsor.
    pub fn set_authority(&mut self, origin: Address, directly_authorized: Address) -> Result<()> {
        self.tx_origin.t_write(origin)?;
        self.directly_authorized_account
            .t_write(directly_authorized)
    }

    pub fn derive_account(
        &mut self,
        salt: B256,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<Address> {
        let factory = self.factory()?;
        let config = config(salt, 0, threshold, owners);
        config.validate().map_err(map_config_error)?;
        self.storage.deduct_gas(
            keccak_cost(config.account_salt_preimage_len())
                + keccak_cost(MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN),
        )?;
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
}

pub fn valid_account(account: Address, spec: tempo_chainspec::hardfork::TempoHardfork) -> bool {
    !account.is_zero()
        && !account.is_virtual()
        && !account.is_precompile(spec)
        && !revm::precompile::Precompiles::new(revm::precompile::PrecompileSpecId::from_spec_id(
            spec.into(),
        ))
        .contains(&account)
        && account.zone_portal_id().is_none()
}

pub const fn keccak_cost(bytes: usize) -> u64 {
    30 + 6 * bytes.div_ceil(32) as u64
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

fn map_config_error(error: MultisigConfigError) -> crate::error::TempoPrecompileError {
    match error {
        MultisigConfigError::EmptyOwners
        | MultisigConfigError::ZeroOwner
        | MultisigConfigError::AccountIsOwner => NativeMultisigError::invalid_multisig_owner(),
        MultisigConfigError::TooManyOwners => NativeMultisigError::too_many_owners(),
        MultisigConfigError::ZeroThreshold
        | MultisigConfigError::ThresholdExceedsMax
        | MultisigConfigError::ThresholdExceedsWeight => NativeMultisigError::invalid_threshold(),
        MultisigConfigError::ZeroWeight | MultisigConfigError::TotalWeightExceedsMax => {
            NativeMultisigError::invalid_weight()
        }
        MultisigConfigError::DuplicateOwner => NativeMultisigError::duplicate_owner(),
        MultisigConfigError::OwnersNotAscending => NativeMultisigError::invalid_owner_order(),
        MultisigConfigError::DerivedAccountZero => NativeMultisigError::invalid_account(),
    }
    .into()
}
