//! The ConfigurableAccount keychain key type through the account keychain ABI.

use alloy::{
    primitives::{Address, B256, Bytes},
    sol_types::{SolCall, SolInterface},
};
use evm2::{
    BaseEvmConfigSelector, Evm, EvmTypesHost, ExecutionConfig, SpecId,
    evm::{InMemoryDB, precompile::NoPrecompiles},
    precompiles::{PrecompileError, PrecompileResult},
    registry::TxRegistry,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    AccountKeychainError,
    IAccountKeychain::{
        KeyRestrictions, SignatureType, authorizeAdminKeyCall, authorizeKey_0Call,
        authorizeKey_1Call, authorizeKey_2Call, getKeyCall,
    },
};
use tempo_precompiles::{
    Precompile,
    account_keychain::AccountKeychain,
    storage::{StorageCtx, evm::EvmPrecompileStorageProvider, hashmap::HashMapStorageProvider},
};
use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

struct TestTypes;

impl EvmTypesHost for TestTypes {
    type ConfigSelector = BaseEvmConfigSelector;
    type SpecId = SpecId;
    type Tx = ();
    type EvmExt = ();
    type MessageExt = ();
    type MessageResultExt = ();
    type TxEnvExt = ();
    type TxResultExt = ();
    type BlockEnvExt = TempoBlockExt;
    type Host<'a> = Evm<'a, Self>;
}

const PARENT: Address = Address::repeat_byte(0x11);
const DELEGATE: Address = Address::repeat_byte(0x22);

fn restrictions(expiry: u64) -> KeyRestrictions {
    KeyRestrictions {
        expiry,
        enforceLimits: false,
        limits: vec![],
        allowAnyCalls: true,
        allowedCalls: vec![],
    }
}

/// The revert output of `result`, or `None` when the call succeeded. Any other failure fails
/// the test: keychain calls only succeed or revert.
#[track_caller]
fn revert_output(result: &PrecompileResult) -> Option<&Bytes> {
    match result {
        Ok(_) => None,
        Err(PrecompileError::Revert(bytes)) => Some(bytes),
        Err(error) => panic!("keychain calls never fail the frame: {error:?}"),
    }
}

/// Runs `calldata` from `PARENT` as both the sender and the transaction origin, in the entered
/// storage context.
fn keychain_call_as_parent(calldata: &[u8]) -> PrecompileResult {
    let mut keychain = AccountKeychain::new();
    keychain.set_tx_origin(PARENT).unwrap();
    keychain.call(calldata, PARENT)
}

/// Runs `calldata` from `PARENT` as both the sender and the transaction origin.
fn call_as_parent(storage: &mut HashMapStorageProvider, calldata: &[u8]) -> PrecompileResult {
    StorageCtx::enter(storage, || keychain_call_as_parent(calldata))
}

/// Runs `calldata` from `PARENT` as both the sender and the transaction origin, on an EVM at
/// `spec` with mainnet gas parameters. Returns the result and the gas the call charged.
fn call_as_parent_in_evm(spec: TempoHardfork, calldata: &[u8]) -> (PrecompileResult, u64) {
    let version = tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, false);
    let mut evm = Evm::<TestTypes>::new_with_execution_config(
        ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
        SpecId::OSAKA,
        TempoBlockEnv::default(),
        TxRegistry::new(),
        InMemoryDB::default(),
        NoPrecompiles::default(),
    );
    let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
    StorageCtx::enter(&mut storage, || {
        let result = keychain_call_as_parent(calldata);
        (result, StorageCtx.gas_used())
    })
}

/// The signature and calldata of each authorization entrypoint that carries a `signatureType`.
fn authorization_calls(
    key_id: Address,
    signature_type: SignatureType,
    expiry: u64,
) -> [(&'static str, Vec<u8>); 4] {
    [
        (
            authorizeKey_0Call::SIGNATURE,
            authorizeKey_0Call {
                keyId: key_id,
                signatureType: signature_type,
                expiry,
                enforceLimits: false,
                limits: vec![],
            }
            .abi_encode(),
        ),
        (
            authorizeKey_1Call::SIGNATURE,
            authorizeKey_1Call {
                keyId: key_id,
                signatureType: signature_type,
                config: restrictions(expiry),
            }
            .abi_encode(),
        ),
        (
            authorizeKey_2Call::SIGNATURE,
            authorizeKey_2Call {
                keyId: key_id,
                signatureType: signature_type,
                config: restrictions(expiry),
                witness: B256::ZERO,
            }
            .abi_encode(),
        ),
        (
            authorizeAdminKeyCall::SIGNATURE,
            authorizeAdminKeyCall {
                keyId: key_id,
                signatureType: signature_type,
                witness: B256::ZERO,
            }
            .abi_encode(),
        ),
    ]
}

fn key_expiry(storage: &mut HashMapStorageProvider, key_id: Address) -> u64 {
    StorageCtx::enter(storage, || {
        AccountKeychain::new()
            .get_key(getKeyCall {
                account: PARENT,
                keyId: key_id,
            })
            .unwrap()
            .expiry
    })
}

/// Before T14, key type 3 reverts exactly like an unknown key type (4) on every
/// authorization entrypoint: same status, bytes and gas.
#[test]
fn key_type_reverts_like_an_unknown_type_before_t14() {
    let configurable_type = SignatureType::ConfigurableAccount as u8;
    let unknown_type = configurable_type + 1;
    for spec in TempoHardfork::VARIANTS
        .iter()
        .copied()
        .filter(|spec| !spec.is_t14())
    {
        for key_id in [Address::ZERO, PARENT, DELEGATE] {
            for expiry in [0, u64::MAX] {
                let calls = authorization_calls(key_id, SignatureType::ConfigurableAccount, expiry);
                for (entrypoint, mut calldata) in calls {
                    let case = format!("{spec}, {entrypoint}, key {key_id}, expiry {expiry}");
                    // The `signatureType` word follows the `keyId` word, after the selector.
                    assert_eq!(calldata[67], configurable_type, "{case}");
                    let mut run = |signature_type: u8| {
                        calldata[67] = signature_type;
                        call_as_parent_in_evm(spec, &calldata)
                    };
                    let (configurable, configurable_gas) = run(configurable_type);
                    let (unknown, unknown_gas) = run(unknown_type);
                    assert!(revert_output(&unknown).is_some(), "{case}");
                    assert!(unknown_gas > 0, "{case}");
                    assert_eq!(
                        revert_output(&configurable),
                        revert_output(&unknown),
                        "{case}"
                    );
                    assert_eq!(configurable_gas, unknown_gas, "{case}");
                }
            }
        }
    }
}

/// Between T11 and T14, authorization calldata that ends right after the key type word reverts
/// with empty output, whether the type is 3 or an unknown 4: it fails the regular ABI decode.
#[test]
fn truncated_authorization_reverts_empty_between_t11_and_t14() {
    let configurable_type = SignatureType::ConfigurableAccount as u8;
    let unknown_type = configurable_type + 1;
    for spec in TempoHardfork::VARIANTS
        .iter()
        .copied()
        .filter(|spec| spec.is_t11() && !spec.is_t14())
    {
        let calls = authorization_calls(DELEGATE, SignatureType::ConfigurableAccount, u64::MAX);
        for (entrypoint, calldata) in calls {
            // Selector, `keyId` word and `signatureType` word.
            let mut truncated = calldata[..68].to_vec();
            let case = format!("{spec}, {entrypoint}");
            let mut run = |signature_type: u8| {
                truncated[67] = signature_type;
                call_as_parent_in_evm(spec, &truncated)
            };
            let (configurable, configurable_gas) = run(configurable_type);
            let (unknown, unknown_gas) = run(unknown_type);
            assert_eq!(revert_output(&configurable), Some(&Bytes::new()), "{case}");
            assert_eq!(
                revert_output(&configurable),
                revert_output(&unknown),
                "{case}"
            );
            assert_eq!(configurable_gas, unknown_gas, "{case}");
        }
    }
}

/// The code of an EIP-7702 delegation to `target`.
fn eip7702_delegation(target: Address) -> Bytes {
    [&[0xef, 0x01, 0x00], target.as_slice()].concat().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DelegateCase {
    CodeFree,
    SelfGrant,
    Bytecode,
    Delegation,
}

/// A grant to a ConfigurableAccount key is accepted from T14 only, and only for a code-free
/// delegate other than the granting account.
#[test]
fn delegate_grants_are_guarded_from_t14() {
    for spec in TempoHardfork::VARIANTS.iter().copied() {
        for case in [
            DelegateCase::CodeFree,
            DelegateCase::SelfGrant,
            DelegateCase::Bytecode,
            DelegateCase::Delegation,
        ] {
            let delegate = if case == DelegateCase::SelfGrant {
                PARENT
            } else {
                DELEGATE
            };
            let calls = authorization_calls(delegate, SignatureType::ConfigurableAccount, u64::MAX);
            // Every fork since T3 rejects the legacy `authorizeKey` selector outright.
            for (entrypoint, calldata) in calls
                .iter()
                .filter(|(_, calldata)| !calldata.starts_with(&authorizeKey_0Call::SELECTOR))
            {
                let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
                match case {
                    DelegateCase::Bytecode => StorageCtx::enter(&mut storage, || {
                        StorageCtx
                            .set_code(delegate, Bytes::from_static(&[0x60, 0x00]))
                            .unwrap()
                    }),
                    DelegateCase::Delegation => StorageCtx::enter(&mut storage, || {
                        StorageCtx
                            .set_code(delegate, eip7702_delegation(Address::repeat_byte(0x33)))
                            .unwrap()
                    }),
                    DelegateCase::CodeFree | DelegateCase::SelfGrant => {}
                }

                let output = call_as_parent(&mut storage, calldata);
                let granted = spec.is_t14() && case == DelegateCase::CodeFree;
                assert_eq!(
                    revert_output(&output).is_none(),
                    granted,
                    "{spec}, {entrypoint}, {case:?}"
                );
                if !granted {
                    if spec.is_t14() {
                        assert_eq!(
                            AccountKeychainError::abi_decode(revert_output(&output).unwrap())
                                .unwrap(),
                            AccountKeychainError::invalid_key_id(),
                            "{spec}, {entrypoint}, {case:?}"
                        );
                    }
                    assert_eq!(
                        key_expiry(&mut storage, delegate),
                        0,
                        "{spec}, {entrypoint}, {case:?}"
                    );
                }
            }
        }
    }
}

/// A stored ConfigurableAccount key is only usable from T14, and only when the signature
/// declares the same type.
#[test]
fn stored_key_type_is_checked_on_use() {
    let configurable_type = SignatureType::ConfigurableAccount as u8;
    let secp256k1_type = SignatureType::Secp256k1 as u8;
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    let grant = authorizeKey_1Call {
        keyId: DELEGATE,
        signatureType: SignatureType::ConfigurableAccount,
        config: restrictions(u64::MAX),
    }
    .abi_encode();
    assert!(revert_output(&call_as_parent(&mut storage, &grant)).is_none());

    let validate = |storage: &mut HashMapStorageProvider, expected_sig_type| {
        StorageCtx::enter(storage, || {
            AccountKeychain::new()
                .validate_keychain_authorization(PARENT, DELEGATE, 0, expected_sig_type)
                .is_ok()
        })
    };
    for spec in TempoHardfork::VARIANTS
        .iter()
        .copied()
        .filter(|spec| spec.is_t14())
    {
        storage.set_spec(spec);
        assert!(validate(&mut storage, None), "{spec}");
        assert!(validate(&mut storage, Some(configurable_type)), "{spec}");
        assert!(!validate(&mut storage, Some(secp256k1_type)), "{spec}");
    }
    storage.set_spec(TempoHardfork::T13);
    for expected_sig_type in [None, Some(secp256k1_type), Some(configurable_type)] {
        assert!(
            !validate(&mut storage, expected_sig_type),
            "{expected_sig_type:?}"
        );
    }
}
