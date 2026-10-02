//! Registered Earn payment execution through one paid EVM2 delegate frame.

use crate::{
    error::{Result, TempoPrecompileError},
    input_cost,
    native_call::{
        NativeCallBudget, NativeCallExt, NativeCallLimits, native_delegate_call, verify_native_code,
    },
    storage::{StorageActions, StorageCtx, evm::EvmPrecompileStorageProvider},
    storage_credits::NonCreditableSlots,
    tip20::{ISSUER_ROLE, TIP20Token},
};
use alloy::primitives::{Address, B256, Bytes, U256};
use evm2::{
    Evm, EvmTypes,
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
};
use std::{cell::RefCell, rc::Rc};
use tempo_contracts::TempoHardfork;
use tempo_contracts::earn::{
    EARN_IMPLEMENTATION_SLOT, EarnPaymentKind, EarnRegistrationField,
    NATIVE_EARN_DISPATCHER_V1_HASH, NATIVE_EARN_DISPATCHER_V1_RUNTIME,
    NATIVE_EARN_REGISTRY_ADDRESS, earn_payment_kind, earn_registration_preimage,
};
use tempo_primitives::TempoBlockExt;

struct EarnRegistration {
    pair: Address,
    implementation: Address,
    implementation_hash: B256,
    asset: Address,
    earn_share: Address,
    engine_hash: B256,
}

fn word_address(word: U256) -> Address {
    let bytes = word.to_be_bytes::<32>();
    Address::from_slice(&bytes[12..])
}

fn charged_registration_slot(account: Address, field: EarnRegistrationField) -> Result<U256> {
    Ok(U256::from_be_bytes(
        StorageCtx
            .keccak256(&earn_registration_preimage(account, field))?
            .0,
    ))
}

fn registration(address: Address, kind: EarnPaymentKind) -> Result<EarnRegistration> {
    let storage = StorageCtx;
    let read = |field| {
        storage.sload(
            NATIVE_EARN_REGISTRY_ADDRESS,
            charged_registration_slot(address, field)?,
        )
    };
    let expected_kind = match kind {
        EarnPaymentKind::Vault => 1,
        EarnPaymentKind::Fees => 2,
    };
    if read(EarnRegistrationField::Kind)? != U256::from(expected_kind) {
        return Err(TempoPrecompileError::OutOfGas);
    }
    Ok(EarnRegistration {
        pair: word_address(read(EarnRegistrationField::Pair)?),
        implementation: word_address(read(EarnRegistrationField::Implementation)?),
        implementation_hash: B256::from(
            read(EarnRegistrationField::ImplementationHash)?.to_be_bytes::<32>(),
        ),
        asset: word_address(read(EarnRegistrationField::Asset)?),
        earn_share: word_address(read(EarnRegistrationField::EarnShare)?),
        engine_hash: B256::from(read(EarnRegistrationField::EngineHash)?.to_be_bytes::<32>()),
    })
}

/// Bounded native dispatch profile selected by the T16 fork.
pub struct NativeEarnExecution<'a> {
    pub spec: TempoHardfork,
    pub actions: StorageActions,
    pub non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    pub budget: &'a NativeCallBudget,
}

impl NativeEarnExecution<'_> {
    pub fn execute<T: EvmTypes<BlockEnvExt = TempoBlockExt>>(
        &self,
        evm: &mut Evm<'_, T>,
        message: &Message<T>,
        gas: &mut GasTracker,
    ) -> PrecompileResult
    where
        T::EvmExt: NativeCallExt,
    {
        if message.kind != MessageKind::Call
            || message.destination != message.code_address
            || message.caller_is_static
            || !message.value.is_zero()
            || message.code.original_byte_slice() != NATIVE_EARN_DISPATCHER_V1_RUNTIME
        {
            return Err(PrecompileError::Revert(Bytes::new()));
        }
        let Some(selector_kind) = earn_payment_kind(&message.input) else {
            return Err(PrecompileHalt::OutOfGas.into());
        };
        let mut storage = EvmPrecompileStorageProvider::new(evm, gas, self.spec, false)
            .with_actions(self.actions.clone())
            .with_non_creditable_slots(self.non_creditable_slots.clone());
        let prepared = StorageCtx::enter(&mut storage, || {
            let storage = StorageCtx;
            storage.deduct_gas(input_cost(self.spec, message.input.len())?)?;
            let kind = match storage.sload(
                NATIVE_EARN_REGISTRY_ADDRESS,
                charged_registration_slot(message.destination, EarnRegistrationField::Kind)?,
            )? {
                value if value == U256::from(1) => EarnPaymentKind::Vault,
                value if value == U256::from(2) => EarnPaymentKind::Fees,
                _ => return Err(TempoPrecompileError::OutOfGas),
            };
            let registered = registration(message.destination, kind)?;
            let fee_checkpoint = kind == EarnPaymentKind::Fees
                && selector_kind == EarnPaymentKind::Vault
                && message.input.starts_with(&[0x37, 0xa4, 0xe8, 0x34])
                && message.caller == registered.pair;
            if selector_kind != kind && !fee_checkpoint {
                return Err(TempoPrecompileError::OutOfGas);
            }
            let implementation = U256::from_be_slice(registered.implementation.as_slice());
            if storage.sload(message.destination, EARN_IMPLEMENTATION_SLOT)? != implementation {
                return Err(TempoPrecompileError::OutOfGas);
            }
            let expected_pair_kind = match kind {
                EarnPaymentKind::Vault => EarnPaymentKind::Fees,
                EarnPaymentKind::Fees => EarnPaymentKind::Vault,
            };
            let pair = registration(registered.pair, expected_pair_kind)?;
            if pair.pair != message.destination
                || pair.asset != registered.asset
                || pair.earn_share != registered.earn_share
            {
                return Err(TempoPrecompileError::OutOfGas);
            }
            let read_address = |address, slot| -> Result<Address> {
                Ok(word_address(storage.sload(address, U256::from(slot))?))
            };
            match kind {
                EarnPaymentKind::Vault => {
                    if read_address(message.destination, 0)? == Address::ZERO
                        || read_address(message.destination, 1)? != registered.asset
                        || read_address(message.destination, 2)? != registered.earn_share
                        || read_address(message.destination, 3)? != registered.pair
                        || read_address(registered.pair, 0)? != message.destination
                        || read_address(registered.pair, 1)? != registered.earn_share
                    {
                        return Err(TempoPrecompileError::OutOfGas);
                    }
                }
                EarnPaymentKind::Fees => {
                    if read_address(message.destination, 0)? != registered.pair
                        || read_address(message.destination, 1)? != registered.earn_share
                        || read_address(registered.pair, 1)? != registered.asset
                        || read_address(registered.pair, 2)? != registered.earn_share
                        || read_address(registered.pair, 3)? != message.destination
                    {
                        return Err(TempoPrecompileError::OutOfGas);
                    }
                }
            }
            let vault = match kind {
                EarnPaymentKind::Vault => message.destination,
                EarnPaymentKind::Fees => registered.pair,
            };
            if !TIP20Token::from_address(registered.earn_share)?
                .has_role_internal(vault, ISSUER_ROLE)?
            {
                return Err(TempoPrecompileError::OutOfGas);
            }
            Ok((registered, pair, kind, fee_checkpoint))
        });
        let (registered, pair, kind, fee_checkpoint) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return error.into_precompile_result(),
        };
        verify_native_code(
            evm,
            gas,
            registered.implementation,
            registered.implementation_hash,
        )?;
        verify_native_code(evm, gas, registered.pair, NATIVE_EARN_DISPATCHER_V1_HASH)?;
        verify_native_code(evm, gas, pair.implementation, pair.implementation_hash)?;
        if kind == EarnPaymentKind::Vault {
            let engine = {
                let mut storage = EvmPrecompileStorageProvider::new(evm, gas, self.spec, false)
                    .with_actions(self.actions.clone())
                    .with_non_creditable_slots(self.non_creditable_slots.clone());
                StorageCtx::enter(&mut storage, || {
                    StorageCtx
                        .sload(message.destination, U256::ZERO)
                        .map(word_address)
                })
            };
            let engine = match engine {
                Ok(engine) => engine,
                Err(error) => return error.into_precompile_result(),
            };
            verify_native_code(evm, gas, engine, registered.engine_hash)?;
            if message.input.starts_with(&[0xfb, 0x3a, 0xc8, 0xb8]) && message.caller != engine {
                return Err(PrecompileError::Revert(Bytes::new()));
            }
        }
        if message.depth == 0 && !fee_checkpoint {
            evm.ext()
                .native_call_context()
                .record_verified_earn_payment();
        }
        let (execution_gas, state_gas) = match kind {
            EarnPaymentKind::Vault => (8_000_000, 4_000_000),
            EarnPaymentKind::Fees => (2_000_000, 1_000_000),
        };
        native_delegate_call(
            evm,
            message,
            gas,
            self.budget,
            registered.implementation,
            message.input.clone(),
            NativeCallLimits {
                execution_gas,
                state_gas,
                input_bytes: 8_192,
                output_bytes: 4_096,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TempoPrecompiles, storage::StorageCtx};
    use evm2::{
        BaseEvmConfigSelector, ExecutionConfig, SpecId, bytecode::Bytecode, env::TxEnv,
        evm::InMemoryDB, interpreter::Host, registry::TxRegistry,
    };
    use tempo_contracts::earn::earn_registration_slot;
    use tempo_primitives::TempoBlockEnv;

    struct Types;

    impl evm2::EvmTypesHost for Types {
        type ConfigSelector = BaseEvmConfigSelector;
        type SpecId = SpecId;
        type Tx = ();
        type EvmExt = crate::native_call::NativeCallContext;
        type MessageExt = ();
        type MessageResultExt = ();
        type TxEnvExt = ();
        type TxResultExt = ();
        type BlockEnvExt = TempoBlockExt;
        type Host<'a> = Evm<'a, Self>;
    }

    const VAULT: Address = Address::with_last_byte(0x91);
    const FEES: Address = Address::with_last_byte(0x92);
    const VAULT_IMPL: Address = Address::with_last_byte(0x93);
    const FEES_IMPL: Address = Address::with_last_byte(0x94);
    const ENGINE: Address = Address::with_last_byte(0x95);
    const ASSET: Address = Address::with_last_byte(0x96);
    const SHARE: Address =
        alloy::primitives::address!("0x20c0000000000000000000000000000000000097");

    fn setup(registered: bool, nested_fee_call: bool, issuer: bool) -> Evm<'static, Types> {
        let spec = TempoHardfork::T16;
        let version = tempo_chainspec::gas_params::version(SpecId::OSAKA, spec, false);
        let slots = Rc::new(RefCell::new(NonCreditableSlots::empty()));
        let provider = TempoPrecompiles::new(spec, StorageActions::disabled(), slots);
        let mut evm = Evm::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
            SpecId::OSAKA,
            TempoBlockEnv::default(),
            TxRegistry::new(),
            InMemoryDB::default(),
            provider,
        );
        let vault_impl_code = if nested_fee_call {
            let mut code = vec![
                0x63, 0x37, 0xa4, 0xe8, 0x34, 0x60, 0xe0, 0x1b, 0x60, 0x00, 0x52, 0x60, 0x00, 0x60,
                0x00, 0x60, 0x04, 0x60, 0x00, 0x60, 0x00, 0x73,
            ];
            code.extend_from_slice(FEES.as_slice());
            code.extend_from_slice(&[0x62, 0x1e, 0x84, 0x80, 0xf1, 0x60, 0x2b, 0x55, 0x00]);
            Bytes::from(code)
        } else {
            Bytes::from_static(&[0x60, 0x2a, 0x60, 0x2a, 0x55, 0x00])
        };
        let fees_impl_code = Bytes::from_static(&[0x00]);
        let engine_code = Bytes::from_static(&[0x00]);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut s = StorageCtx;
            for account in [VAULT, FEES] {
                s.set_code(
                    account,
                    Bytes::copy_from_slice(NATIVE_EARN_DISPATCHER_V1_RUNTIME),
                )?;
            }
            s.set_code(VAULT_IMPL, vault_impl_code.clone())?;
            s.set_code(FEES_IMPL, fees_impl_code.clone())?;
            s.set_code(ENGINE, engine_code.clone())?;
            if issuer {
                TIP20Token::from_address(SHARE)?.grant_role_internal(VAULT, ISSUER_ROLE)?;
            }
            let address_word = |address: Address| U256::from_be_slice(address.as_slice());
            for (address, slot, value) in [
                (VAULT, EARN_IMPLEMENTATION_SLOT, address_word(VAULT_IMPL)),
                (VAULT, U256::ZERO, address_word(ENGINE)),
                (VAULT, U256::from(1), address_word(ASSET)),
                (VAULT, U256::from(2), address_word(SHARE)),
                (VAULT, U256::from(3), address_word(FEES)),
                (FEES, EARN_IMPLEMENTATION_SLOT, address_word(FEES_IMPL)),
                (FEES, U256::ZERO, address_word(VAULT)),
                (FEES, U256::from(1), address_word(SHARE)),
            ] {
                s.sstore(address, slot, value)?;
            }
            if registered {
                for (account, values) in [
                    (
                        VAULT,
                        [
                            U256::from(1),
                            address_word(FEES),
                            address_word(VAULT_IMPL),
                            U256::from_be_slice(
                                alloy::primitives::keccak256(&vault_impl_code).as_slice(),
                            ),
                            address_word(ASSET),
                            address_word(SHARE),
                            U256::from_be_slice(
                                alloy::primitives::keccak256(&engine_code).as_slice(),
                            ),
                        ],
                    ),
                    (
                        FEES,
                        [
                            U256::from(2),
                            address_word(VAULT),
                            address_word(FEES_IMPL),
                            U256::from_be_slice(
                                alloy::primitives::keccak256(&fees_impl_code).as_slice(),
                            ),
                            address_word(ASSET),
                            address_word(SHARE),
                            U256::ZERO,
                        ],
                    ),
                ] {
                    for (field, value) in [
                        EarnRegistrationField::Kind,
                        EarnRegistrationField::Pair,
                        EarnRegistrationField::Implementation,
                        EarnRegistrationField::ImplementationHash,
                        EarnRegistrationField::Asset,
                        EarnRegistrationField::EarnShare,
                        EarnRegistrationField::EngineHash,
                    ]
                    .into_iter()
                    .zip(values)
                    {
                        s.sstore(
                            NATIVE_EARN_REGISTRY_ADDRESS,
                            earn_registration_slot(account, field),
                            value,
                        )?;
                    }
                }
            }
            Ok(())
        })
        .unwrap();
        evm
    }

    fn call(
        evm: &mut Evm<'static, Types>,
        destination: Address,
        caller: Address,
        depth: u16,
    ) -> evm2::interpreter::MessageResult<Types> {
        let mut message = Message::<Types> {
            kind: MessageKind::Call,
            depth,
            gas_limit: 15_000_000,
            destination,
            call_target: destination,
            caller,
            input: Bytes::from_static(&[0x37, 0xa4, 0xe8, 0x34]),
            code: Bytecode::new_legacy(Bytes::copy_from_slice(NATIVE_EARN_DISPATCHER_V1_RUNTIME)),
            code_address: destination,
            ..Default::default()
        };
        Host::execute_message(evm, &TxEnv::<Types>::default(), &mut message).unwrap()
    }

    #[test]
    fn native_vault_delegate_frame_writes_vault_storage_and_marks_payment() {
        let mut evm = setup(true, false, true);
        let result = call(&mut evm, VAULT, Address::with_last_byte(0xaa), 0);
        assert!(result.stop.is_success());
        assert!(evm.ext().native_call_context().verified_earn_payment());
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        let stored =
            StorageCtx::enter(&mut storage, || StorageCtx.sload(VAULT, U256::from(42))).unwrap();
        assert_eq!(stored, U256::from(42));
    }

    #[test]
    fn unregistered_dispatcher_cannot_mark_a_payment() {
        let mut evm = setup(false, false, true);
        let result = call(&mut evm, VAULT, Address::with_last_byte(0xaa), 0);
        assert!(!result.stop.is_success());
        assert!(!evm.ext().native_call_context().verified_earn_payment());
    }

    #[test]
    fn fee_checkpoint_from_vault_uses_registered_fee_implementation() {
        let mut evm = setup(true, false, true);
        let result = call(&mut evm, FEES, VAULT, 1);
        assert!(result.stop.is_success());
        assert!(!evm.ext().native_call_context().verified_earn_payment());
    }

    #[test]
    fn vault_and_fee_checkpoint_share_one_bounded_native_budget() {
        let mut evm = setup(true, true, true);
        let result = call(&mut evm, VAULT, Address::with_last_byte(0xaa), 0);
        assert!(result.stop.is_success());
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        let child_succeeded =
            StorageCtx::enter(&mut storage, || StorageCtx.sload(VAULT, U256::from(43))).unwrap();
        assert_eq!(child_succeeded, U256::from(1));
        assert!(evm.ext().native_call_context().verified_earn_payment());
    }

    #[test]
    fn registered_vault_without_share_issuer_role_cannot_mark_payment() {
        let mut evm = setup(true, false, false);
        let result = call(&mut evm, VAULT, Address::with_last_byte(0xaa), 0);
        assert!(!result.stop.is_success());
        assert!(!evm.ext().native_call_context().verified_earn_payment());
    }
}
