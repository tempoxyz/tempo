//! The ConfigurableAccount keychain key type through the account keychain ABI.

use alloy::{
    primitives::{Address, B256, Bytes, address},
    sol_types::{SolCall, SolInterface},
};
use alloy_evm::EvmEnv;
use revm::{context::CfgEnv, database::InMemoryDB, precompile::PrecompileOutput, state::Bytecode};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    AccountKeychainError,
    IAccountKeychain::{
        KeyRestrictions, SignatureType, authorizeAdminKeyCall, authorizeKey_0Call,
        authorizeKey_1Call, authorizeKey_2Call, getKeyCall,
    },
};
use tempo_evm::{TempoBlockEnv, evm::TempoEvm};
use tempo_precompiles::{
    Precompile,
    account_keychain::AccountKeychain,
    storage::{StorageActions, StorageCtx, hashmap::HashMapStorageProvider},
};
use tempo_primitives::{MasterId, TempoAddressExt, UserTag};

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

/// Runs `calldata` from `PARENT` as both the sender and the transaction origin, in the entered
/// storage context.
fn keychain_call_as_parent(calldata: &[u8]) -> PrecompileOutput {
    let mut keychain = AccountKeychain::new();
    keychain.set_tx_origin(PARENT).unwrap();
    keychain
        .call(calldata, PARENT)
        .expect("keychain calls never fail the frame")
}

/// Runs `calldata` from `PARENT` as both the sender and the transaction origin.
fn call_as_parent(storage: &mut HashMapStorageProvider, calldata: &[u8]) -> PrecompileOutput {
    StorageCtx::enter(storage, || keychain_call_as_parent(calldata))
}

/// Runs `calldata` from `PARENT` as both the sender and the transaction origin, on an EVM at
/// `spec` with mainnet gas parameters, so the output carries the gas a node would charge.
fn call_as_parent_in_evm(spec: TempoHardfork, calldata: &[u8]) -> PrecompileOutput {
    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.set_spec_and_mainnet_gas_params(spec);
    let mut evm = TempoEvm::new(
        InMemoryDB::default(),
        EvmEnv {
            cfg_env: cfg,
            block_env: TempoBlockEnv::default(),
        },
    );
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        keychain_call_as_parent(calldata)
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
                    let configurable = run(configurable_type);
                    let unknown = run(unknown_type);
                    assert!(unknown.is_revert(), "{case}");
                    assert!(unknown.gas_used > 0, "{case}");
                    assert_eq!(configurable, unknown, "{case}");
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
            let configurable = run(configurable_type);
            let unknown = run(unknown_type);
            assert!(configurable.is_revert(), "{case}");
            assert!(configurable.bytes.is_empty(), "{case}");
            assert_eq!(configurable, unknown, "{case}");
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DelegateCase {
    CodeFree,
    SelfGrant,
    Bytecode,
    Delegation,
    Reserved(Address),
}

/// A grant to a ConfigurableAccount key is accepted from T14 only, and only for a code-free
/// delegate other than the granting account that is not in a reserved address range.
#[test]
fn delegate_grants_are_guarded_from_t14() {
    for spec in TempoHardfork::VARIANTS.iter().copied() {
        for case in [
            DelegateCase::CodeFree,
            DelegateCase::SelfGrant,
            DelegateCase::Bytecode,
            DelegateCase::Delegation,
            // An Ethereum precompile, an uncreated TIP-20, a virtual and a zone portal address
            // carry no code.
            DelegateCase::Reserved(Address::with_last_byte(1)),
            DelegateCase::Reserved(Address::new_tip20(1)),
            DelegateCase::Reserved(Address::new_virtual(MasterId::ZERO, UserTag::ZERO)),
            DelegateCase::Reserved(address!("5ad0000000000000000000000000000000000001")),
        ] {
            let delegate = match case {
                DelegateCase::SelfGrant => PARENT,
                DelegateCase::Reserved(address) => address,
                DelegateCase::CodeFree | DelegateCase::Bytecode | DelegateCase::Delegation => {
                    DELEGATE
                }
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
                            .set_code(
                                delegate,
                                Bytecode::new_raw(Bytes::from_static(&[0x60, 0x00])),
                            )
                            .unwrap()
                    }),
                    DelegateCase::Delegation => StorageCtx::enter(&mut storage, || {
                        StorageCtx
                            .set_code(delegate, Bytecode::new_eip7702(Address::repeat_byte(0x33)))
                            .unwrap()
                    }),
                    DelegateCase::CodeFree
                    | DelegateCase::SelfGrant
                    | DelegateCase::Reserved(_) => {}
                }

                let output = call_as_parent(&mut storage, calldata);
                let granted = spec.is_t14() && case == DelegateCase::CodeFree;
                assert_eq!(
                    !output.is_revert(),
                    granted,
                    "{spec}, {entrypoint}, {case:?}"
                );
                if granted {
                    let get_key = getKeyCall {
                        account: PARENT,
                        keyId: delegate,
                    }
                    .abi_encode();
                    let output = call_as_parent(&mut storage, &get_key);
                    assert!(!output.is_revert(), "{spec}, {entrypoint}");
                    let key = getKeyCall::abi_decode_returns(&output.bytes).unwrap();
                    assert_eq!(
                        key.signatureType,
                        SignatureType::ConfigurableAccount,
                        "{spec}, {entrypoint}"
                    );
                } else {
                    if spec.is_t14() {
                        assert_eq!(
                            AccountKeychainError::abi_decode(&output.bytes).unwrap(),
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

/// A stored ConfigurableAccount key is only usable when the signature declares the same type.
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
    assert!(!call_as_parent(&mut storage, &grant).is_revert());

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
}

/// From T6, an admin grant naming the granting account reverts with `InvalidKeyId` and stores
/// no key, whatever its key type.
#[test]
fn admin_self_grants_are_rejected() {
    for spec in TempoHardfork::VARIANTS
        .iter()
        .copied()
        .filter(|spec| spec.is_t6())
    {
        for signature_type in [
            SignatureType::Secp256k1,
            SignatureType::P256,
            SignatureType::WebAuthn,
        ] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
            let grant = authorizeAdminKeyCall {
                keyId: PARENT,
                signatureType: signature_type,
                witness: B256::ZERO,
            }
            .abi_encode();
            let output = call_as_parent(&mut storage, &grant);
            assert!(output.is_revert(), "{spec}, {signature_type:?}");
            assert_eq!(
                AccountKeychainError::abi_decode(&output.bytes).unwrap(),
                AccountKeychainError::invalid_key_id(),
                "{spec}, {signature_type:?}"
            );
            assert_eq!(
                key_expiry(&mut storage, PARENT),
                0,
                "{spec}, {signature_type:?}"
            );
        }
    }
}
