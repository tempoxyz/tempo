//! Native multisig account precompile.

pub mod dispatch;
mod error;

#[cfg(test)]
mod tests;

pub use error::{
    NativeMultisigAuthError, NativeMultisigAuthorizationError, NativeMultisigStateError,
};
pub use tempo_contracts::precompiles::INativeMultisig;

use crate::{
    account_keychain::{AccountKeychain, getTransactionKeyCall},
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping, StorageCtx},
};
use alloy::primitives::{Address, B256, TxKind, U256};
use revm::interpreter::gas::{KECCAK256, KECCAK256WORD};
use tempo_contracts::precompiles::{
    NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{
    MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN, MultisigConfig, MultisigConfigError,
    MultisigQuorumError, MultisigSignature, MultisigWeightAccumulator, TempoSignature,
    multisig_account_address,
};

use crate::is_valid_multisig_account;

/// Gas for hashing the fixed-length native multisig CREATE2 preimage.
pub const MULTISIG_ACCOUNT_CREATE2_GAS: u64 =
    KECCAK256 + KECCAK256WORD * MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN.div_ceil(32) as u64;

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
            if !stored.is_zero()
                || self.derive_account_from_validated_config(&current)? != msg_sender
            {
                return Err(NativeMultisigError::invalid_config().into());
            }
        } else if stored.is_zero() || self.hash_validated_config_commitment(&current)? != stored {
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
        let commitment = self.hash_validated_config_commitment(&next)?;
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

    /// Validates every configuration witness against its account's current commitment.
    pub fn validate_authorization_state(
        &self,
        signature: &MultisigSignature,
    ) -> std::result::Result<(), NativeMultisigAuthError> {
        self.validate_authorization_state_inner(signature)
    }

    fn validate_authorization_state_inner(
        &self,
        signature: &MultisigSignature,
    ) -> std::result::Result<(), NativeMultisigAuthError> {
        if !is_valid_multisig_account(signature.account(), self.storage.spec()) {
            return Err(NativeMultisigAuthorizationError::InvalidAccount {
                account: signature.account(),
            }
            .into());
        }

        let stored = self
            .get_config_commitment(signature.account())
            .map_err(NativeMultisigAuthError::from_state_access_error)?;
        let config = signature.config();
        let (valid, expected, actual) = if config.version == 0 {
            (stored.is_zero(), B256::ZERO, stored)
        } else {
            let actual = signature.config_commitment();
            (!stored.is_zero() && actual == stored, stored, actual)
        };
        if !valid {
            return Err(NativeMultisigStateError::ConfigurationCommitmentMismatch {
                expected,
                actual,
            }
            .into());
        }

        for approval in signature.signatures() {
            let TempoSignature::Multisig(nested) = approval else {
                continue;
            };
            self.validate_authorization_state_inner(nested)?;
        }
        Ok(())
    }

    /// Verifies owner membership, ordering, signatures, and quorum for a validated witness tree.
    pub fn verify_authorization_quorum(
        inner_digest: B256,
        signature: &MultisigSignature,
    ) -> std::result::Result<(), NativeMultisigAuthError> {
        let digest = signature.digest(inner_digest);
        let config = signature.config();
        let mut weight = MultisigWeightAccumulator::new(config.threshold)
            .map_err(NativeMultisigAuthorizationError::Quorum)?;

        for (index, approval) in signature.signatures().iter().enumerate() {
            let owner = match approval {
                TempoSignature::Primitive(primitive) => {
                    primitive.recover_signer(&digest).map_err(|_| {
                        NativeMultisigAuthorizationError::OwnerSignatureRecoveryFailed {
                            approval_index: index,
                        }
                    })?
                }
                TempoSignature::Multisig(nested) => {
                    Self::verify_authorization_quorum(digest, nested)?;
                    nested.account()
                }
                TempoSignature::Keychain(_) => {
                    return Err(NativeMultisigAuthorizationError::KeychainOwnerSignature {
                        approval_index: index,
                    }
                    .into());
                }
            };

            let owner_weight =
                config
                    .owner_weight(owner)
                    .ok_or(NativeMultisigAuthorizationError::Quorum(
                        MultisigQuorumError::SignerNotOwner,
                    ))?;
            weight
                .record_owner(owner, owner_weight)
                .map_err(NativeMultisigAuthorizationError::Quorum)?;
            if weight.has_quorum() {
                if index + 1 != signature.signatures().len() {
                    return Err(NativeMultisigAuthorizationError::Quorum(
                        MultisigQuorumError::ExcessSignatures,
                    )
                    .into());
                }
                return weight
                    .finish()
                    .map_err(NativeMultisigAuthorizationError::Quorum)
                    .map_err(Into::into);
            }
        }

        weight
            .finish()
            .map_err(NativeMultisigAuthorizationError::Quorum)
            .map_err(Into::into)
    }

    fn ensure_update_authorized(&self, msg_sender: Address) -> Result<()> {
        if msg_sender.is_zero()
            || StorageCtx.tx_kind() != Some(TxKind::Call(NATIVE_MULTISIG_ADDRESS))
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
        self.derive_account_from_validated_config(config)
    }

    fn derive_account_from_validated_config(&self, config: &MultisigConfig) -> Result<Address> {
        let preimage = config
            .account_salt_preimage()
            .expect("validated multisig config has an encodable owner count");
        let account_salt = self.storage.keccak256(&preimage)?;
        self.storage.deduct_gas(MULTISIG_ACCOUNT_CREATE2_GAS)?;
        let account = multisig_account_address(account_salt);
        if config.owner_weight(account).is_some() {
            return Err(NativeMultisigError::invalid_multisig_owner().into());
        }
        if !is_valid_multisig_account(account, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        Ok(account)
    }

    fn hash_validated_config_commitment(&self, config: &MultisigConfig) -> Result<B256> {
        let preimage = config
            .commitment_preimage()
            .expect("validated multisig config has an encodable owner count");
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
