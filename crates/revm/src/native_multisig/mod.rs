//! Bounded native authorization shared by execution, pool validation, and simulation.
use crate::{ExecutionContext, TempoInvalidTransaction, TempoTxEnv};
use alloy_primitives::{Address, B256};
use revm::{
    context::{JournalTr, result::EVMError},
    context_interface::cfg::GasParams,
};
use tempo_precompiles::native_multisig::{keccak_cost, valid_account};
use tempo_primitives::{
    TempoBlockEnv,
    transaction::{
        KeychainSignature, MultisigQuorumError, MultisigSignature, MultisigWeightAccumulator,
        SignatureType, TempoSignature, multisig::MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum NativeMultisigError {
    #[error("native multisig is unavailable in this execution context")]
    UnsupportedContext,
    #[error("native multisig recovery factory is not configured")]
    FactoryNotConfigured,
    #[error("invalid multisig account {account}")]
    InvalidAccount { account: Address },
    #[error("multisig signer account mismatch: expected {expected}, actual {actual}")]
    AccountMismatch { expected: Address, actual: Address },
    #[error("multisig configuration commitment mismatch: expected {expected}, actual {actual}")]
    ConfigurationCommitmentMismatch { expected: B256, actual: B256 },
    #[error("invalid multisig owner signature at approval {approval_index}")]
    OwnerSignatureRecoveryFailed { approval_index: usize },
    #[error("{0}")]
    Quorum(MultisigQuorumError),
}

/// An independently signed role. Repeated accounts still require both role digests.
pub struct NativeAuthorization<'a> {
    pub signature: &'a MultisigSignature,
    /// Role digest before native multisig domain separation.
    pub inner_digest: B256,
}

impl NativeAuthorization<'_> {
    /// Verifies owner signatures and quorum against the supplied configuration.
    /// Does not check account state, eligibility, or gas affordability; see [`validate_state`].
    pub fn verify(&self) -> Result<(), NativeMultisigError> {
        let digest = self.signature.digest(self.inner_digest);
        let config = self.signature.config();
        let mut weight = MultisigWeightAccumulator::new(config.threshold)
            .map_err(NativeMultisigError::Quorum)?;
        for (approval_index, primitive) in self.signature.signatures().iter().enumerate() {
            let owner = primitive.recover_signer(&digest).map_err(|_| {
                NativeMultisigError::OwnerSignatureRecoveryFailed { approval_index }
            })?;
            let owner_weight = config
                .owner_weight(owner)
                .ok_or(NativeMultisigError::Quorum(
                    MultisigQuorumError::SignerNotOwner,
                ))?;
            weight
                .record_owner(owner, owner_weight)
                .map_err(NativeMultisigError::Quorum)?;
            if weight.has_quorum() && approval_index + 1 != self.signature.signatures().len() {
                return Err(NativeMultisigError::Quorum(
                    MultisigQuorumError::ExcessSignatures,
                ));
            }
        }
        weight.finish().map_err(NativeMultisigError::Quorum)
    }
}

/// Outer (direct or delegated) role, then inline grant role; either slot may be absent.
pub fn authorizations(tx: &TempoTxEnv) -> [Option<NativeAuthorization<'_>>; 2] {
    let Some(aa) = tx.tempo_tx_env.as_ref() else {
        return [None, None];
    };
    let outer = match &aa.signature {
        TempoSignature::Multisig(signature) => Some(NativeAuthorization {
            signature,
            inner_digest: aa.signature_hash,
        }),
        TempoSignature::Keychain(keychain) => {
            keychain
                .signature
                .as_multisig()
                .map(|signature| NativeAuthorization {
                    signature,
                    inner_digest: KeychainSignature::signing_hash(
                        aa.signature_hash,
                        keychain.user_address,
                    ),
                })
        }
        TempoSignature::Primitive(_) => None,
    };
    let grant = aa.key_authorization.as_ref().and_then(|auth| {
        Some(NativeAuthorization {
            signature: auth.signature.as_multisig()?,
            inner_digest: auth.signature_hash(),
        })
    });
    [outer, grant]
}

/// Includes a separately named grant recipient, which need not sign this transaction.
pub(crate) fn has_account_access(tx: &TempoTxEnv) -> bool {
    tx.tempo_tx_env.as_ref().is_some_and(|aa| {
        // A direct or keychain-wrapped native quorum has no primitive signature type.
        aa.signature.signature_type().is_none()
            || aa.key_authorization.as_ref().is_some_and(|auth| {
                auth.signature.as_multisig().is_some() || auth.key_type == SignatureType::Multisig
            })
    })
}

fn grant_delegate(tx: &TempoTxEnv) -> Option<Address> {
    tx.tempo_tx_env
        .as_ref()?
        .key_authorization
        .as_ref()
        .filter(|auth| auth.key_type == SignatureType::Multisig)
        .map(|auth| auth.key_id)
}

fn account_access_gas(gas: &GasParams, is_cold: bool) -> u64 {
    gas.warm_storage_read_cost()
        + if is_cold {
            gas.cold_account_additional_cost()
        } else {
            0
        }
}

/// The inline grant's code check runs with intrinsic-only metering. Charge its account load
/// here, unless caller loading or a native signing role already accounts for that address.
/// Merely naming a recipient neither validates an owner witness nor registers a commitment.
fn grant_delegate_access_gas<J: JournalTr>(
    journal: &mut J,
    tx: &TempoTxEnv,
    spec: tempo_chainspec::hardfork::TempoHardfork,
    gas: &GasParams,
    signers: &[Address],
) -> Result<u64, EVMError<<J::Database as revm::Database>::Error, TempoInvalidTransaction>> {
    if spec.is_t12()
        && let Some(delegate) = grant_delegate(tx)
        && delegate != tx.caller
        && !signers.contains(&delegate)
    {
        let loaded = journal.load_account(delegate)?;
        return Ok(account_access_gas(gas, loaded.is_cold));
    }
    Ok(0)
}

/// Validates all native actors without cryptography, and returns state-dependent intrinsic gas.
/// Loads and warms accounts, but does not register commitments.
/// Caller must charge the returned amount and check fee affordability before `verify`.
/// Transaction access-list and beneficiary warmth must be initialized before these account loads.
pub fn validate_state<J: JournalTr>(
    journal: &mut J,
    tx: &TempoTxEnv,
    block: &TempoBlockEnv,
    spec: tempo_chainspec::hardfork::TempoHardfork,
    gas: &GasParams,
) -> Result<u64, EVMError<<J::Database as revm::Database>::Error, TempoInvalidTransaction>> {
    let roles = authorizations(tx);
    if spec.is_t12()
        && tx
            .tempo_tx_env
            .as_ref()
            .is_some_and(|aa| aa.signature.is_keychain())
    {
        let caller = journal.load_account(tx.caller)?;
        let commitment =
            tempo_primitives::account::decode_config_commitment(&caller.data.info.extension, true)
                .map_err(|error| EVMError::Custom(error.to_string()))?;
        if !commitment.is_zero() && !caller.data.info.is_empty_code_hash() {
            return Err(EVMError::Transaction(
                TempoInvalidTransaction::NativeMultisig(NativeMultisigError::InvalidAccount {
                    account: tx.caller,
                }),
            ));
        }
    }
    if roles.iter().all(Option::is_none) {
        return grant_delegate_access_gas(journal, tx, spec, gas, &[]);
    }
    let invalid = |error| EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(error));
    let factory = block
        .multisig_recovery_factory
        .filter(|factory| !factory.is_zero())
        .ok_or_else(|| invalid(NativeMultisigError::FactoryNotConfigured))?;
    let aa = tx.tempo_tx_env.as_ref().expect("roles require AA");
    if !spec.is_t12()
        || aa.subblock_transaction
        || matches!(tx.execution_context, ExecutionContext::Unspecified)
        || aa
            .signature
            .as_keychain()
            .is_some_and(|key| key.is_legacy())
    {
        return Err(invalid(NativeMultisigError::UnsupportedContext));
    }
    for signature in [
        aa.signature.as_multisig(),
        aa.key_authorization
            .as_ref()
            .and_then(|auth| auth.signature.as_multisig()),
    ]
    .into_iter()
    .flatten()
    {
        if signature.account() != tx.caller {
            return Err(invalid(NativeMultisigError::AccountMismatch {
                expected: tx.caller,
                actual: signature.account(),
            }));
        }
    }
    let mut accounts = Vec::with_capacity(2);
    let mut extra_gas = 0;
    for role in roles.into_iter().flatten() {
        let signature = role.signature;
        let address = signature.account();
        if !valid_account(address, spec) {
            return Err(invalid(NativeMultisigError::InvalidAccount {
                account: address,
            }));
        }
        let loaded = journal.load_account(address)?;
        let info = &loaded.data.info;
        if !info.is_empty_code_hash() {
            return Err(invalid(NativeMultisigError::InvalidAccount {
                account: address,
            }));
        }
        let commitment = tempo_primitives::account::decode_config_commitment(&info.extension, true)
            .map_err(|error| EVMError::Custom(error.to_string()))?;
        let first = !accounts.contains(&address);
        if first && address != tx.caller {
            extra_gas += account_access_gas(gas, loaded.is_cold);
        }
        accounts.push(address);
        let actual = signature.config_commitment();
        if actual.is_zero() || (!commitment.is_zero() && commitment != actual) {
            return Err(invalid(
                NativeMultisigError::ConfigurationCommitmentMismatch {
                    expected: commitment,
                    actual,
                },
            ));
        }
        if commitment.is_zero() {
            if signature.config().version != 0
                || signature.config().derive_account(factory).ok() != Some(address)
            {
                return Err(invalid(NativeMultisigError::InvalidAccount {
                    account: address,
                }));
            }
            extra_gas += keccak_cost(signature.config().account_salt_preimage_len())
                + keccak_cost(MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN);
            if first {
                extra_gas += 20_000;
            }
        }
    }
    Ok(extra_gas + grant_delegate_access_gas(journal, tx, spec, gas, &accounts)?)
}

/// Verifies each signed role separately. RPC simulation must validate the claimed owner quorum
/// before constructing its mock witness; this function skips quorum recovery only in that mode.
pub fn verify(tx: &TempoTxEnv) -> Result<(), TempoInvalidTransaction> {
    let roles = authorizations(tx);
    if roles.iter().all(Option::is_none) {
        return Ok(());
    }
    match tx.execution_context {
        ExecutionContext::Transaction { .. } => {
            for role in roles.into_iter().flatten() {
                role.verify()?;
            }
        }
        ExecutionContext::Simulation => {}
        ExecutionContext::Unspecified => return Err(NativeMultisigError::UnsupportedContext.into()),
    }
    let aa = tx.tempo_tx_env.as_ref().expect("native roles require AA");
    if let Some(auth) = &aa.key_authorization {
        let signer = auth
            .recover_account()
            .map_err(|_| TempoInvalidTransaction::KeyAuthorizationSignatureRecoveryFailed)?;
        let reject = |reason: &str| TempoInvalidTransaction::KeychainValidationFailed {
            reason: reason.to_owned(),
        };
        let keychain = aa.signature.as_keychain();
        let key_id = keychain
            .map(|key| {
                if matches!(tx.execution_context, ExecutionContext::Simulation)
                    && let Some(key_id) = aa.override_key_id
                {
                    return Ok(key_id);
                }
                key.key_id(&aa.signature_hash)
                    .map_err(|_| TempoInvalidTransaction::AccessKeyRecoveryFailed)
            })
            .transpose()?;
        if signer == tx.caller {
            if keychain.is_some() && key_id != Some(auth.key_id) {
                return Err(reject(
                    "root-signed key authorization must use root transaction signature",
                ));
            }
        } else if auth.account.is_none()
            || key_id != Some(signer)
            || keychain
                .is_none_or(|key| key.signature.signature_type() != auth.signature.signature_type())
        {
            return Err(reject(
                "admin-signed key authorization must match transaction key and parent account",
            ));
        }
        if key_id == Some(auth.key_id)
            && keychain.is_some_and(|key| {
                key.signature
                    .signature_type()
                    .unwrap_or(tempo_primitives::transaction::SignatureType::Multisig)
                    != auth.key_type
            })
        {
            return Err(reject(
                "key authorization key_type does not match the keychain signature type",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
