use alloy_primitives::{Address, U256};
use reth_evm::EvmInternals;
use revm::{
    Database, Journal,
    context::{
        Cfg, CfgEnv, JournalTr, Transaction,
        result::{EVMError, InvalidTransaction},
    },
    handler::pre_execution::calculate_caller_fee,
    interpreter::InitialAndFloorGas,
};
use std::fmt::Debug;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    is_valid_multisig_account,
    native_multisig::{NativeMultisig, NativeMultisigAuthError, NativeMultisigAuthorizationError},
    storage::{
        PrecompileStorageProvider, StorageActions, StorageCtx, evm::EvmPrecompileStorageProvider,
    },
};
use tempo_primitives::transaction::{MultisigSignature, TempoSignature};

use crate::{
    ExecutionContext, NativeMultisigInvalidReason, NativeMultisigValidationReason, TempoBlockEnv,
    TempoInvalidTransaction, TempoTxEnv,
};

pub(super) fn validate_state<DB: Database + Debug>(
    journal: &mut Journal<DB>,
    block: &TempoBlockEnv,
    cfg: &CfgEnv<TempoHardfork>,
    tx: &TempoTxEnv,
    actions: StorageActions,
    init_gas: &mut InitialAndFloorGas,
    account_balance: U256,
) -> Result<Option<U256>, EVMError<DB::Error, TempoInvalidTransaction>> {
    if !cfg.spec().is_t12() {
        return Ok(None);
    }

    let inputs = MultisigValidationInputs::from_tx(tx);

    // Reject an unfunded worst-case quorum before owner verification. Subblock fee failures
    // must remain after nonce consumption and use the normal path below.
    let early_multisig_balance = if !tx.is_subblock_transaction() && inputs.has_multisig_signature()
    {
        Some(calculate_caller_fee(account_balance, tx, block, cfg)?)
    } else {
        None
    };

    // The order below is observable through error precedence and gas accounting.
    let validates_caller_multisig = inputs.outer_signature.is_some()
        || inputs
            .key_authorization_signature
            .is_some_and(|signature| signature.account() == tx.caller());
    let caller_has_code = if validates_caller_multisig || inputs.outer_is_keychain {
        !journal
            .load_account(tx.caller())?
            .data
            .info
            .is_empty_code_hash()
    } else {
        false
    };
    let keychain_caller_has_code = inputs.outer_is_keychain && caller_has_code;
    let requires_state_validation = inputs.has_multisig_signature()
        || inputs.key_authorization_key_id.is_some()
        || keychain_caller_has_code;

    if !requires_state_validation {
        return Ok(early_multisig_balance);
    }

    if validates_caller_multisig && caller_has_code {
        return Err(TempoInvalidTransaction::NativeMultisigValidationFailed(
            NativeMultisigValidationReason::AccountHasCodeOrDelegation {
                account: tx.caller(),
            },
        )
        .into());
    }

    validate_nested_multisig_account_code(journal, &inputs)?;

    let role_validation_gas = validate_multisig_role_conflicts(
        journal,
        block,
        cfg,
        tx,
        &actions,
        &inputs,
        keychain_caller_has_code,
    )?;
    init_gas.initial_regular_gas = init_gas
        .initial_regular_gas
        .saturating_add(role_validation_gas);
    validate_gas_after_multisig_reads::<DB>(cfg, tx, init_gas)?;

    validate_multisig_config_state(journal, block, cfg, tx, actions, &inputs)?;

    if tx.execution_context() != ExecutionContext::Simulation {
        verify_authorization_quorums::<DB>(tx, &inputs)?;
    }

    Ok(early_multisig_balance)
}

/// Multisig-specific views of the AA envelope, computed once for all validation phases.
struct MultisigValidationInputs<'a> {
    outer_signature: Option<&'a MultisigSignature>,
    key_authorization_signature: Option<&'a MultisigSignature>,
    key_authorization_key_id: Option<Address>,
    outer_is_keychain: bool,
}

impl<'a> MultisigValidationInputs<'a> {
    fn from_tx(tx: &'a TempoTxEnv) -> Self {
        let tempo_tx_env = tx.tempo_tx_env.as_deref();
        let outer_signature = tempo_tx_env.and_then(|aa| aa.signature.as_multisig());
        let key_authorization_signature = tempo_tx_env
            .and_then(|aa| aa.key_authorization.as_ref())
            .and_then(|key_auth| key_auth.signature.as_multisig());
        let key_authorization_key_id = tempo_tx_env
            .and_then(|aa| aa.key_authorization.as_ref())
            .map(|key_auth| key_auth.key_id);
        let outer_is_keychain = tempo_tx_env.is_some_and(|aa| aa.signature.is_keychain());

        Self {
            outer_signature,
            key_authorization_signature,
            key_authorization_key_id,
            outer_is_keychain,
        }
    }

    fn signatures(&self) -> impl Iterator<Item = &'a MultisigSignature> + '_ {
        [self.outer_signature, self.key_authorization_signature]
            .into_iter()
            .flatten()
    }

    fn has_multisig_signature(&self) -> bool {
        self.outer_signature.is_some() || self.key_authorization_signature.is_some()
    }
}

fn validate_nested_multisig_account_code<DB: Database + Debug>(
    journal: &mut Journal<DB>,
    inputs: &MultisigValidationInputs<'_>,
) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
    let mut nested_accounts = Vec::new();
    for signature in inputs.signatures() {
        collect_nested_multisig_accounts(signature, &mut nested_accounts);
    }
    for account in nested_accounts {
        if !journal
            .load_account(account)?
            .data
            .info
            .is_empty_code_hash()
        {
            return Err(TempoInvalidTransaction::NativeMultisigValidationFailed(
                NativeMultisigValidationReason::AccountHasCodeOrDelegation { account },
            )
            .into());
        }
    }

    Ok(())
}

/// Rejects a code-bearing keychain caller or access key with a stored multisig commitment.
/// Returns gas spent reading their stored commitments.
fn validate_multisig_role_conflicts<DB: Database + Debug>(
    journal: &mut Journal<DB>,
    block: &TempoBlockEnv,
    cfg: &CfgEnv<TempoHardfork>,
    tx: &TempoTxEnv,
    actions: &StorageActions,
    inputs: &MultisigValidationInputs<'_>,
    keychain_caller_has_code: bool,
) -> Result<u64, EVMError<DB::Error, TempoInvalidTransaction>> {
    if inputs.key_authorization_key_id.is_none() && !keychain_caller_has_code {
        return Ok(0);
    }

    let internals = EvmInternals::new(journal, block, cfg, tx);
    let mut provider =
        EvmPrecompileStorageProvider::new_max_gas(internals, cfg).with_actions(actions.clone());
    provider.set_tip1060_storage_credits(false);
    let validation = StorageCtx::enter(&mut provider, || {
        let multisig = NativeMultisig::new();

        if keychain_caller_has_code
            && !multisig
                .get_config_commitment(tx.caller())
                .map_err(NativeMultisigAuthError::from_state_access_error)
                .map_err(map_native_multisig_error::<DB>)?
                .is_zero()
        {
            return Err(TempoInvalidTransaction::NativeMultisigValidationFailed(
                NativeMultisigValidationReason::AccountHasCodeOrDelegation {
                    account: tx.caller(),
                },
            )
            .into());
        }

        if let Some(key_id) = inputs.key_authorization_key_id
            && !multisig
                .get_config_commitment(key_id)
                .map_err(NativeMultisigAuthError::from_state_access_error)
                .map_err(map_native_multisig_error::<DB>)?
                .is_zero()
        {
            return Err(TempoInvalidTransaction::NativeMultisigValidationFailed(
                NativeMultisigValidationReason::AccountCannotBeAccessKey { account: key_id },
            )
            .into());
        }

        Ok::<(), EVMError<DB::Error, TempoInvalidTransaction>>(())
    });
    let gas_used = provider.gas_used();
    validation?;
    Ok(gas_used)
}

/// Rechecks transaction gas limits after charging multisig commitment reads.
fn validate_gas_after_multisig_reads<DB: Database>(
    cfg: &CfgEnv<TempoHardfork>,
    tx: &TempoTxEnv,
    init_gas: &InitialAndFloorGas,
) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
    if tx.gas_limit() < init_gas.initial_total_gas() {
        return Err(InvalidTransaction::CallGasCostMoreThanGasLimit {
            gas_limit: tx.gas_limit(),
            initial_gas: init_gas.initial_total_gas(),
        }
        .into());
    }

    if cfg.is_amsterdam_eip8037_enabled()
        && init_gas.initial_regular_gas().max(init_gas.floor_gas) > cfg.tx_gas_limit_cap()
    {
        return Err(InvalidTransaction::GasFloorMoreThanGasLimit {
            gas_floor: init_gas.initial_regular_gas(),
            gas_limit: cfg.tx_gas_limit_cap(),
        }
        .into());
    }

    Ok(())
}

/// Checks initial and current configuration witnesses against stored commitments.
fn validate_multisig_config_state<DB: Database + Debug>(
    journal: &mut Journal<DB>,
    block: &TempoBlockEnv,
    cfg: &CfgEnv<TempoHardfork>,
    tx: &TempoTxEnv,
    actions: StorageActions,
    inputs: &MultisigValidationInputs<'_>,
) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
    if inputs.has_multisig_signature() {
        StorageCtx::enter_precompile(
            journal,
            block,
            cfg,
            tx,
            actions,
            |multisig: NativeMultisig| -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
                for signature in inputs.signatures() {
                    multisig
                        .validate_authorization_state(signature)
                        .map_err(map_native_multisig_error::<DB>)?;
                }
                Ok(())
            },
        )?;
    }

    Ok(())
}

fn verify_authorization_quorums<DB: Database>(
    tx: &TempoTxEnv,
    inputs: &MultisigValidationInputs<'_>,
) -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
    if let Some(signature) = inputs.outer_signature {
        let tempo_tx_env = tx
            .tempo_tx_env
            .as_deref()
            .expect("outer multisig signature is derived from tempo_tx_env");
        NativeMultisig::verify_authorization_quorum(tempo_tx_env.signature_hash, signature)
            .map_err(map_native_multisig_error::<DB>)?;
    }
    if let Some(signature) = inputs.key_authorization_signature {
        let key_auth = tx
            .tempo_tx_env
            .as_deref()
            .and_then(|aa| aa.key_authorization.as_ref())
            .expect("multisig signature is derived from key authorization");
        NativeMultisig::verify_authorization_quorum(
            key_auth.authorization.signature_hash(),
            signature,
        )
        .map_err(map_native_multisig_error::<DB>)?;
    }

    Ok(())
}

pub(super) fn validate_native_multisig_signature_account(
    signature: &MultisigSignature,
    expected_account: Address,
    spec: TempoHardfork,
) -> Result<Address, NativeMultisigInvalidReason> {
    let account = signature.account();
    if account != expected_account {
        return Err(NativeMultisigInvalidReason::SignatureAccountMismatch {
            expected: expected_account,
            actual: account,
        });
    }
    if !is_valid_multisig_account(account, spec) {
        return Err(NativeMultisigInvalidReason::Authorization(
            NativeMultisigAuthorizationError::InvalidAccount { account },
        ));
    }
    Ok(account)
}

fn collect_nested_multisig_accounts(signature: &MultisigSignature, accounts: &mut Vec<Address>) {
    for approval in signature.signatures() {
        let TempoSignature::Multisig(nested) = approval else {
            continue;
        };
        accounts.push(nested.account());
        collect_nested_multisig_accounts(nested, accounts);
    }
}

pub(super) fn map_native_multisig_error<DB: Database>(
    error: NativeMultisigAuthError,
) -> EVMError<DB::Error, TempoInvalidTransaction> {
    match error {
        NativeMultisigAuthError::Fatal(error) => EVMError::Custom(error),
        NativeMultisigAuthError::Invalid(error) => map_native_multisig_invalid_reason::<DB>(
            NativeMultisigInvalidReason::Authorization(error),
        ),
        NativeMultisigAuthError::State(error) => {
            TempoInvalidTransaction::NativeMultisigValidationFailed(
                NativeMultisigValidationReason::AuthorizationState(error),
            )
            .into()
        }
    }
}

pub(super) fn map_native_multisig_invalid_reason<DB: Database>(
    reason: NativeMultisigInvalidReason,
) -> EVMError<DB::Error, TempoInvalidTransaction> {
    TempoInvalidTransaction::NativeMultisigInvalidTransaction(reason).into()
}
