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
    native_multisig::{NativeMultisig, auth::NativeMultisigAuthError},
    storage::{
        PrecompileStorageProvider, StorageActions, StorageCtx, evm::EvmPrecompileStorageProvider,
    },
};
use tempo_primitives::transaction::{MultisigSignature, TempoSignature};

use crate::{ExecutionContext, TempoBlockEnv, TempoInvalidTransaction, TempoTxEnv};

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

    let tempo_tx_env = tx.tempo_tx_env.as_deref();
    let outer_multisig_signature = tempo_tx_env.and_then(|aa| aa.signature.as_multisig());
    let key_authorization_multisig_signature = tempo_tx_env
        .and_then(|aa| aa.key_authorization.as_ref())
        .and_then(|key_auth| key_auth.signature.as_multisig());
    let has_multisig_signature =
        outer_multisig_signature.is_some() || key_authorization_multisig_signature.is_some();

    // Reject an unfunded worst-case quorum before owner verification. Subblock fee failures
    // must remain after nonce consumption and use the normal path below.
    let early_multisig_balance = if !tx.is_subblock_transaction() && has_multisig_signature {
        Some(calculate_caller_fee(account_balance, tx, block, cfg)?)
    } else {
        None
    };

    let key_authorization_key_id = tempo_tx_env
        .and_then(|aa| aa.key_authorization.as_ref())
        .map(|key_auth| key_auth.key_id);
    let outer_keychain_signature = tempo_tx_env.is_some_and(|aa| aa.signature.is_keychain());
    let validates_caller_multisig = outer_multisig_signature.is_some()
        || key_authorization_multisig_signature
            .is_some_and(|signature| signature.account() == tx.caller());
    let caller_has_code = if validates_caller_multisig || outer_keychain_signature {
        !journal
            .load_account(tx.caller())?
            .data
            .info
            .is_empty_code_hash()
    } else {
        false
    };
    let keychain_caller_has_code = outer_keychain_signature && caller_has_code;
    let requires_native_multisig_state =
        has_multisig_signature || key_authorization_key_id.is_some() || keychain_caller_has_code;

    if !requires_native_multisig_state {
        return Ok(early_multisig_balance);
    }

    if validates_caller_multisig && caller_has_code {
        return Err(TempoInvalidTransaction::NativeMultisigValidationFailed {
            reason: "native multisig account cannot have code or EIP-7702 delegation".to_string(),
        }
        .into());
    }

    let mut nested_accounts = Vec::new();
    for signature in [
        outer_multisig_signature,
        key_authorization_multisig_signature,
    ]
    .into_iter()
    .flatten()
    {
        collect_nested_multisig_accounts(signature, &mut nested_accounts);
    }
    for account in nested_accounts {
        if !journal
            .load_account(account)?
            .data
            .info
            .is_empty_code_hash()
        {
            return Err(TempoInvalidTransaction::NativeMultisigValidationFailed {
                reason: format!(
                    "native multisig owner account {account} cannot have code or EIP-7702 delegation"
                ),
            }
            .into());
        }
    }

    let commitment_gating_gas = if key_authorization_key_id.is_some() || keychain_caller_has_code {
        let internals = EvmInternals::new(journal, block, cfg, tx);
        let mut provider =
            EvmPrecompileStorageProvider::new_max_gas(internals, cfg).with_actions(actions.clone());
        let validation = StorageCtx::enter(&mut provider, || {
            let multisig = NativeMultisig::new();

            if keychain_caller_has_code
                && !multisig
                    .get_config_commitment(tx.caller())
                    .map_err(NativeMultisigAuthError::from)
                    .map_err(map_native_multisig_error::<DB>)?
                    .is_zero()
            {
                return Err(TempoInvalidTransaction::NativeMultisigValidationFailed {
                    reason: "native multisig account cannot have code or EIP-7702 delegation"
                        .to_string(),
                }
                .into());
            }

            if let Some(key_id) = key_authorization_key_id
                && !multisig
                    .get_config_commitment(key_id)
                    .map_err(NativeMultisigAuthError::from)
                    .map_err(map_native_multisig_error::<DB>)?
                    .is_zero()
            {
                return Err(TempoInvalidTransaction::NativeMultisigValidationFailed {
                    reason: format!(
                        "native multisig account {key_id} cannot be used as an access key"
                    ),
                }
                .into());
            }

            Ok::<(), EVMError<DB::Error, TempoInvalidTransaction>>(())
        });
        let gas_used = provider.gas_used();
        validation?;
        gas_used
    } else {
        0
    };

    init_gas.initial_regular_gas = init_gas
        .initial_regular_gas
        .saturating_add(commitment_gating_gas);

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

    if has_multisig_signature {
        StorageCtx::enter_precompile(
            journal,
            block,
            cfg,
            tx,
            actions,
            |multisig: NativeMultisig| -> Result<(), EVMError<DB::Error, TempoInvalidTransaction>> {
                for signature in [
                    outer_multisig_signature,
                    key_authorization_multisig_signature,
                ]
                .into_iter()
                .flatten()
                {
                    multisig
                        .validate_authorization_state(signature)
                        .map_err(map_native_multisig_error::<DB>)?;
                }
                Ok(())
            },
        )?;
    }

    if tx.execution_context() != ExecutionContext::Simulation {
        if let Some(signature) = outer_multisig_signature {
            NativeMultisig::verify_authorization_quorum(
                tempo_tx_env
                    .expect("outer multisig signature is derived from tempo_tx_env")
                    .signature_hash,
                signature,
            )
            .map_err(map_native_multisig_error::<DB>)?;
        }
        if let Some(signature) = key_authorization_multisig_signature {
            let key_auth = tempo_tx_env
                .and_then(|aa| aa.key_authorization.as_ref())
                .expect("multisig signature is derived from key authorization");
            NativeMultisig::verify_authorization_quorum(
                key_auth.authorization.signature_hash(),
                signature,
            )
            .map_err(map_native_multisig_error::<DB>)?;
        }
    }

    Ok(early_multisig_balance)
}

pub(super) fn validate_native_multisig_signature_account(
    signature: &MultisigSignature,
    expected_account: Address,
    spec: TempoHardfork,
    account_mismatch_reason: &'static str,
) -> Result<Address, TempoInvalidTransaction> {
    let account = signature.account();
    if account != expected_account {
        return Err(TempoInvalidTransaction::NativeMultisigInvalidTransaction {
            reason: account_mismatch_reason.to_string(),
        });
    }
    if !is_valid_multisig_account(account, spec) {
        return Err(TempoInvalidTransaction::NativeMultisigInvalidTransaction {
            reason: "multisig signature names a reserved account address".to_string(),
        });
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

fn map_native_multisig_error<DB: Database>(
    error: NativeMultisigAuthError,
) -> EVMError<DB::Error, TempoInvalidTransaction> {
    match error {
        NativeMultisigAuthError::Fatal(error) => EVMError::Custom(error),
        NativeMultisigAuthError::InvalidTransaction(reason) => {
            TempoInvalidTransaction::NativeMultisigInvalidTransaction { reason }.into()
        }
        NativeMultisigAuthError::ValidationFailed(reason) => {
            TempoInvalidTransaction::NativeMultisigValidationFailed { reason }.into()
        }
    }
}
