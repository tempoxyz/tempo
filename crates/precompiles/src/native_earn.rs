//! Registered Earn payment execution through one paid EVM2 delegate frame.

use crate::{
    Precompile, charge_input_cost, dispatch,
    error::{Result, TempoPrecompileError},
    input_cost, mutate,
    native_call::{
        NativeCallBudget, NativeCallExt, NativeCallLimits, native_delegate_call, verify_native_code,
    },
    storage::{StorageActions, StorageCtx, evm::EvmPrecompileStorageProvider},
    storage_credits::NonCreditableSlots,
    tip20::{ISSUER_ROLE, TIP20Token},
};
use alloy::primitives::{Address, B256, Bytes, IntoLogData, U256};
use evm2::{
    Evm, EvmTypes,
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
};
use std::{cell::RefCell, rc::Rc};
use tempo_contracts::{
    TempoHardfork,
    earn::{
        EARN_IMPLEMENTATION_SLOT, EarnPaymentKind, EarnRegistrationField, INativeEarnRegistrar,
        NATIVE_EARN_DISPATCHER_V1_HASH, NATIVE_EARN_DISPATCHER_V1_RUNTIME,
        NATIVE_EARN_REGISTRY_ADDRESS, NativeEarnRegistered, NativeEarnSettlementRegistered,
        earn_engine_approval_preimage, earn_fees_clone_runtime, earn_forwarder_snapshot_preimage,
        earn_payment_kind, earn_registration_preimage, earn_settlement_input, factory_slots,
    },
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
        EarnPaymentKind::SettlementForwarder => 3,
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

/// Factory-only T16 admission for new stacks, called before deployment returns.
#[derive(Debug, Default)]
pub struct NativeEarnRegistrar {
    storage: StorageCtx,
}

impl NativeEarnRegistrar {
    pub fn new() -> Self {
        Self::default()
    }

    fn require_governor(&self, sender: Address) -> Result<()> {
        if sender == Address::ZERO
            || sender
                != word_address(
                    self.storage
                        .sload(NATIVE_EARN_REGISTRY_ADDRESS, factory_slots::GOVERNOR)?,
                )
        {
            return Err(TempoPrecompileError::OutOfGas);
        }
        Ok(())
    }

    fn engine_approval_slot(&self, engine: Address) -> Result<U256> {
        Ok(U256::from_be_bytes(
            self.storage
                .keccak256(&earn_engine_approval_preimage(engine))?
                .0,
        ))
    }

    fn approved_engine_hash(&self, engine: Address) -> Result<B256> {
        Ok(B256::from(
            self.storage
                .sload(
                    NATIVE_EARN_REGISTRY_ADDRESS,
                    self.engine_approval_slot(engine)?,
                )?
                .to_be_bytes::<32>(),
        ))
    }

    fn approve_engine(&mut self, sender: Address, engine: Address) -> Result<()> {
        self.require_governor(sender)?;
        if engine == Address::ZERO {
            return Err(TempoPrecompileError::OutOfGas);
        }
        let hash = self.storage.account_code(engine)?.0;
        if hash == B256::ZERO || hash == alloy::primitives::KECCAK256_EMPTY {
            return Err(TempoPrecompileError::OutOfGas);
        }
        let slot = self.engine_approval_slot(engine)?;
        self.storage.sstore(
            NATIVE_EARN_REGISTRY_ADDRESS,
            slot,
            U256::from_be_slice(hash.as_slice()),
        )
    }

    fn revoke_engine(&mut self, sender: Address, engine: Address) -> Result<()> {
        self.require_governor(sender)?;
        self.storage.sstore(
            NATIVE_EARN_REGISTRY_ADDRESS,
            self.engine_approval_slot(engine)?,
            U256::ZERO,
        )
    }

    fn update_vault_engine(
        &mut self,
        sender: Address,
        vault: Address,
        engine: Address,
    ) -> Result<()> {
        self.require_governor(sender)?;
        if vault == Address::ZERO
            || self.storage.sload(
                NATIVE_EARN_REGISTRY_ADDRESS,
                charged_registration_slot(vault, EarnRegistrationField::Kind)?,
            )? != U256::ONE
            || self.storage.sload(vault, U256::ZERO)? != U256::from_be_slice(engine.as_slice())
            || self.storage.account_code(vault)?.0 != NATIVE_EARN_DISPATCHER_V1_HASH
        {
            return Err(TempoPrecompileError::OutOfGas);
        }
        let hash = self.approved_engine_hash(engine)?;
        if hash == B256::ZERO || self.storage.account_code(engine)?.0 != hash {
            return Err(TempoPrecompileError::OutOfGas);
        }
        self.storage.sstore(
            NATIVE_EARN_REGISTRY_ADDRESS,
            charged_registration_slot(vault, EarnRegistrationField::EngineHash)?,
            U256::from_be_slice(hash.as_slice()),
        )
    }

    fn register(
        &mut self,
        sender: Address,
        call: INativeEarnRegistrar::registerCall,
    ) -> Result<()> {
        let registry = NATIVE_EARN_REGISTRY_ADDRESS;
        let read = |slot| self.storage.sload(registry, slot);
        if sender == Address::ZERO
            || sender != word_address(read(factory_slots::ADDRESS)?)
            || call.vault == Address::ZERO
            || call.fees == Address::ZERO
            || call.vault == call.fees
            || call.asset == call.earnShare
            || TIP20Token::from_address(call.asset).is_err()
            || TIP20Token::from_address(call.earnShare).is_err()
        {
            return Err(TempoPrecompileError::OutOfGas);
        }
        let hash_word = |slot| -> Result<B256> { Ok(B256::from(read(slot)?.to_be_bytes::<32>())) };
        let check_code = |address: Address, expected: B256| -> Result<()> {
            if expected == B256::ZERO || self.storage.account_code(address)?.0 != expected {
                return Err(TempoPrecompileError::OutOfGas);
            }
            Ok(())
        };
        check_code(sender, hash_word(factory_slots::CODE_HASH)?)?;
        let vault_implementation = word_address(read(factory_slots::VAULT_IMPLEMENTATION)?);
        let fees_implementation = word_address(read(factory_slots::FEES_IMPLEMENTATION)?);
        let vault_implementation_hash = hash_word(factory_slots::VAULT_IMPLEMENTATION_HASH)?;
        let fees_implementation_hash = hash_word(factory_slots::FEES_IMPLEMENTATION_HASH)?;
        check_code(call.vault, hash_word(factory_slots::VAULT_RUNTIME_HASH)?)?;
        check_code(vault_implementation, vault_implementation_hash)?;
        check_code(fees_implementation, fees_implementation_hash)?;
        let fees_clone_hash = self
            .storage
            .keccak256(&earn_fees_clone_runtime(fees_implementation))?;
        check_code(call.fees, fees_clone_hash)?;
        let engine_hash = self.approved_engine_hash(call.engine)?;
        check_code(call.engine, engine_hash)?;
        let address_word = |address: Address| U256::from_be_slice(address.as_slice());
        for (address, slot, expected) in [
            (
                call.vault,
                EARN_IMPLEMENTATION_SLOT,
                address_word(vault_implementation),
            ),
            (call.vault, U256::ZERO, address_word(call.engine)),
            (call.vault, U256::from(1), address_word(call.asset)),
            (call.vault, U256::from(2), address_word(call.earnShare)),
            (call.vault, U256::from(3), address_word(call.fees)),
            (call.fees, U256::ZERO, address_word(call.vault)),
            (call.fees, U256::from(1), address_word(call.earnShare)),
        ] {
            if self.storage.sload(address, slot)? != expected {
                return Err(TempoPrecompileError::OutOfGas);
            }
        }
        if self.storage.sload(call.fees, EARN_IMPLEMENTATION_SLOT)? != U256::ZERO
            || !TIP20Token::from_address(call.earnShare)?
                .has_role_internal(call.vault, ISSUER_ROLE)?
        {
            return Err(TempoPrecompileError::OutOfGas);
        }
        for account in [call.vault, call.fees] {
            if self.storage.sload(
                registry,
                charged_registration_slot(account, EarnRegistrationField::Kind)?,
            )? != U256::ZERO
            {
                return Err(TempoPrecompileError::OutOfGas);
            }
        }
        for (account, values) in [
            (
                call.vault,
                [
                    U256::ONE,
                    address_word(call.fees),
                    address_word(vault_implementation),
                    U256::from_be_slice(vault_implementation_hash.as_slice()),
                    address_word(call.asset),
                    address_word(call.earnShare),
                    U256::from_be_slice(engine_hash.as_slice()),
                ],
            ),
            (
                call.fees,
                [
                    U256::from(2),
                    address_word(call.vault),
                    address_word(fees_implementation),
                    U256::from_be_slice(fees_implementation_hash.as_slice()),
                    address_word(call.asset),
                    address_word(call.earnShare),
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
                self.storage
                    .sstore(registry, charged_registration_slot(account, field)?, value)?;
            }
        }
        self.storage.sstore(
            call.fees,
            EARN_IMPLEMENTATION_SLOT,
            address_word(fees_implementation),
        )?;
        let runtime = Bytes::copy_from_slice(NATIVE_EARN_DISPATCHER_V1_RUNTIME);
        self.storage.set_code(call.vault, runtime.clone())?;
        self.storage.set_code(call.fees, runtime)?;
        self.storage.emit_event(
            registry,
            NativeEarnRegistered {
                vault: call.vault,
                asset: call.asset,
                earnShare: call.earnShare,
                fees: call.fees,
                engine: call.engine,
                engineCodeHash: engine_hash,
            }
            .into_log_data(),
        )
    }

    fn register_settlement_forwarder(
        &mut self,
        sender: Address,
        call: INativeEarnRegistrar::registerSettlementForwarderCall,
    ) -> Result<()> {
        self.require_governor(sender)?;
        if call.forwarder == Address::ZERO
            || call.vault == Address::ZERO
            || call.engine == Address::ZERO
            || call.forwarder == call.vault
            || call.forwarder == call.engine
            || call.forwarderCodeHash == B256::ZERO
            || call.forwarderCodeHash == alloy::primitives::KECCAK256_EMPTY
            || self.storage.account_code(call.forwarder)?.0 != call.forwarderCodeHash
            || self.storage.account_code(call.vault)?.0 != NATIVE_EARN_DISPATCHER_V1_HASH
            || self.storage.sload(
                NATIVE_EARN_REGISTRY_ADDRESS,
                charged_registration_slot(call.forwarder, EarnRegistrationField::Kind)?,
            )? != U256::ZERO
            || self
                .storage
                .sload(call.forwarder, EARN_IMPLEMENTATION_SLOT)?
                != U256::ZERO
            || self.storage.sload(call.vault, U256::ZERO)?
                != U256::from_be_slice(call.engine.as_slice())
        {
            return Err(TempoPrecompileError::OutOfGas);
        }
        let vault = registration(call.vault, EarnPaymentKind::Vault)?;
        let engine_hash = self.approved_engine_hash(call.engine)?;
        if engine_hash == B256::ZERO
            || engine_hash != vault.engine_hash
            || self.storage.account_code(call.engine)?.0 != engine_hash
        {
            return Err(TempoPrecompileError::OutOfGas);
        }
        let snapshot_hash = self
            .storage
            .keccak256(&earn_forwarder_snapshot_preimage(call.forwarder))?;
        let mut snapshot_bytes = [0u8; 20];
        snapshot_bytes[..4].copy_from_slice(&[0x5a, 0xec, 0x00, 0x01]);
        snapshot_bytes[4..].copy_from_slice(&snapshot_hash[16..]);
        let snapshot = Address::from(snapshot_bytes);
        if !self
            .storage
            .with_account_info(snapshot, |info| Ok(info.is_empty()))?
        {
            return Err(TempoPrecompileError::OutOfGas);
        }
        if self.storage.copy_runtime(call.forwarder, snapshot)? != Some(call.forwarderCodeHash) {
            return Err(TempoPrecompileError::OutOfGas);
        }
        self.storage.sstore(
            call.forwarder,
            EARN_IMPLEMENTATION_SLOT,
            U256::from_be_slice(snapshot.as_slice()),
        )?;
        self.storage.set_code(
            call.forwarder,
            Bytes::copy_from_slice(NATIVE_EARN_DISPATCHER_V1_RUNTIME),
        )?;
        for (field, value) in [
            (EarnRegistrationField::Kind, U256::from(3)),
            (
                EarnRegistrationField::Pair,
                U256::from_be_slice(call.vault.as_slice()),
            ),
            (
                EarnRegistrationField::Implementation,
                U256::from_be_slice(snapshot.as_slice()),
            ),
            (
                EarnRegistrationField::ImplementationHash,
                U256::from_be_slice(call.forwarderCodeHash.as_slice()),
            ),
            (
                EarnRegistrationField::Asset,
                U256::from_be_slice(vault.asset.as_slice()),
            ),
            (
                EarnRegistrationField::EarnShare,
                U256::from_be_slice(vault.earn_share.as_slice()),
            ),
            (
                EarnRegistrationField::EngineHash,
                U256::from_be_slice(engine_hash.as_slice()),
            ),
        ] {
            self.storage.sstore(
                NATIVE_EARN_REGISTRY_ADDRESS,
                charged_registration_slot(call.forwarder, field)?,
                value,
            )?;
        }
        self.storage.emit_event(
            NATIVE_EARN_REGISTRY_ADDRESS,
            NativeEarnSettlementRegistered {
                forwarder: call.forwarder,
                vault: call.vault,
                engine: call.engine,
                snapshot,
                forwarderCodeHash: call.forwarderCodeHash,
            }
            .into_log_data(),
        )
    }
}

impl Precompile for NativeEarnRegistrar {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut self.storage, calldata) {
            return error;
        }
        dispatch!(calldata, |call| match call {
            INativeEarnRegistrar::INativeEarnRegistrarCalls {
                register(call) => mutate(call, msg_sender, |sender, call| self.register(sender, call)),
                registerSettlementForwarder(call) => mutate(call, msg_sender, |sender, call| self.register_settlement_forwarder(sender, call)),
                approveEngine(call) => mutate(call, msg_sender, |sender, call| self.approve_engine(sender, call.engine)),
                revokeEngine(call) => mutate(call, msg_sender, |sender, call| self.revoke_engine(sender, call.engine)),
                updateVaultEngine(call) => mutate(call, msg_sender, |sender, call| self.update_vault_engine(sender, call.vault, call.engine)),
            }
        })
    }
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
                EarnPaymentKind::SettlementForwarder => return Err(TempoPrecompileError::OutOfGas),
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
                EarnPaymentKind::SettlementForwarder => return Err(TempoPrecompileError::OutOfGas),
            }
            let vault = match kind {
                EarnPaymentKind::Vault => message.destination,
                EarnPaymentKind::Fees => registered.pair,
                EarnPaymentKind::SettlementForwarder => return Err(TempoPrecompileError::OutOfGas),
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
            let approved = {
                let mut storage = EvmPrecompileStorageProvider::new(evm, gas, self.spec, false)
                    .with_actions(self.actions.clone())
                    .with_non_creditable_slots(self.non_creditable_slots.clone());
                StorageCtx::enter(&mut storage, || {
                    let storage = StorageCtx;
                    let slot = U256::from_be_bytes(
                        storage.keccak256(&earn_engine_approval_preimage(engine))?.0,
                    );
                    storage.sload(NATIVE_EARN_REGISTRY_ADDRESS, slot)
                })
            };
            match approved {
                Ok(value) if value == U256::from_be_slice(registered.engine_hash.as_slice()) => {}
                Ok(_) => return Err(PrecompileHalt::OutOfGas.into()),
                Err(error) => return error.into_precompile_result(),
            }
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
            EarnPaymentKind::SettlementForwarder => return Err(PrecompileHalt::OutOfGas.into()),
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

/// Registered forwarding-solver admission for a bounded async solve and
/// vault claim finalization in one payment transaction.
pub struct NativeEarnSettlementExecution<'a> {
    pub spec: TempoHardfork,
    pub actions: StorageActions,
    pub non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    pub budget: &'a NativeCallBudget,
}

impl NativeEarnSettlementExecution<'_> {
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
            || message.depth != 0
            || message.destination != message.code_address
            || message.caller_is_static
            || !message.value.is_zero()
            || message.code.original_byte_slice() != NATIVE_EARN_DISPATCHER_V1_RUNTIME
            || !earn_settlement_input(&message.input)
        {
            return Err(PrecompileError::Revert(Bytes::new()));
        }
        let mut storage = EvmPrecompileStorageProvider::new(evm, gas, self.spec, false)
            .with_actions(self.actions.clone())
            .with_non_creditable_slots(self.non_creditable_slots.clone());
        let prepared = StorageCtx::enter(&mut storage, || {
            let storage = StorageCtx;
            storage.deduct_gas(input_cost(self.spec, message.input.len())?)?;
            let registered =
                registration(message.destination, EarnPaymentKind::SettlementForwarder)?;
            if storage.sload(message.destination, EARN_IMPLEMENTATION_SLOT)?
                != U256::from_be_slice(registered.implementation.as_slice())
            {
                return Err(TempoPrecompileError::OutOfGas);
            }
            let vault = registration(registered.pair, EarnPaymentKind::Vault)?;
            let fees = registration(vault.pair, EarnPaymentKind::Fees)?;
            if vault.asset != registered.asset
                || vault.earn_share != registered.earn_share
                || vault.engine_hash != registered.engine_hash
                || fees.pair != registered.pair
                || fees.asset != registered.asset
                || fees.earn_share != registered.earn_share
                || storage.account_code(registered.pair)?.0 != NATIVE_EARN_DISPATCHER_V1_HASH
                || storage.account_code(vault.pair)?.0 != NATIVE_EARN_DISPATCHER_V1_HASH
                || storage.sload(registered.pair, EARN_IMPLEMENTATION_SLOT)?
                    != U256::from_be_slice(vault.implementation.as_slice())
                || storage.sload(vault.pair, EARN_IMPLEMENTATION_SLOT)?
                    != U256::from_be_slice(fees.implementation.as_slice())
                || word_address(storage.sload(registered.pair, U256::from(1))?) != vault.asset
                || word_address(storage.sload(registered.pair, U256::from(2))?) != vault.earn_share
                || word_address(storage.sload(registered.pair, U256::from(3))?) != vault.pair
                || word_address(storage.sload(vault.pair, U256::ZERO)?) != registered.pair
                || word_address(storage.sload(vault.pair, U256::from(1))?) != vault.earn_share
            {
                return Err(TempoPrecompileError::OutOfGas);
            }
            let engine = word_address(storage.sload(registered.pair, U256::ZERO)?);
            let approval_slot =
                U256::from_be_bytes(storage.keccak256(&earn_engine_approval_preimage(engine))?.0);
            if engine == Address::ZERO
                || storage.sload(NATIVE_EARN_REGISTRY_ADDRESS, approval_slot)?
                    != U256::from_be_slice(registered.engine_hash.as_slice())
                || !TIP20Token::from_address(vault.earn_share)?
                    .has_role_internal(registered.pair, ISSUER_ROLE)?
            {
                return Err(TempoPrecompileError::OutOfGas);
            }
            Ok((registered, vault, fees, engine))
        });
        let (registered, vault, fees, engine) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return error.into_precompile_result(),
        };
        verify_native_code(
            evm,
            gas,
            registered.implementation,
            registered.implementation_hash,
        )?;
        verify_native_code(evm, gas, vault.implementation, vault.implementation_hash)?;
        verify_native_code(evm, gas, fees.implementation, fees.implementation_hash)?;
        verify_native_code(evm, gas, engine, registered.engine_hash)?;
        // The solver's immutable engine getter must name the registered vault
        // engine before the transaction can enter the payment lane.
        let returned = native_delegate_call(
            evm,
            message,
            gas,
            self.budget,
            registered.implementation,
            Bytes::from_static(&[0xc9, 0xd4, 0x62, 0x3f]),
            NativeCallLimits {
                execution_gas: 100_000,
                state_gas: 100_000,
                input_bytes: 4,
                output_bytes: 32,
            },
        )?;
        if returned.bytes().len() != 32
            || word_address(U256::from_be_slice(returned.bytes())) != engine
        {
            return Err(PrecompileHalt::OutOfGas.into());
        }
        let mut authorization = vec![0xcd, 0xa4, 0x85, 0x0d];
        authorization
            .extend_from_slice(&U256::from_be_slice(message.caller.as_slice()).to_be_bytes::<32>());
        let authorized = native_delegate_call(
            evm,
            message,
            gas,
            self.budget,
            registered.implementation,
            Bytes::from(authorization),
            NativeCallLimits {
                execution_gas: 100_000,
                state_gas: 100_000,
                input_bytes: 36,
                output_bytes: 32,
            },
        )?;
        if authorized.bytes().len() != 32 || U256::from_be_slice(authorized.bytes()) != U256::ONE {
            return Err(PrecompileHalt::OutOfGas.into());
        }
        evm.ext()
            .native_call_context()
            .record_verified_earn_payment();
        native_delegate_call(
            evm,
            message,
            gas,
            self.budget,
            registered.implementation,
            message.input.clone(),
            NativeCallLimits {
                execution_gas: 11_000_000,
                state_gas: 4_000_000,
                input_bytes: 356,
                output_bytes: 4_096,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TempoPrecompiles, storage::StorageCtx};
    use alloy::{primitives::keccak256, sol_types::SolCall};
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
    const FORWARDER: Address = Address::with_last_byte(0x9b);
    const NEW_ENGINE: Address = Address::with_last_byte(0x9a);
    const ASSET: Address =
        alloy::primitives::address!("0x20c0000000000000000000000000000000000096");
    const FACTORY: Address = Address::with_last_byte(0x98);
    const GOVERNOR: Address = Address::with_last_byte(0x99);
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
                s.sstore(
                    NATIVE_EARN_REGISTRY_ADDRESS,
                    tempo_contracts::earn::earn_engine_approval_slot(ENGINE),
                    U256::from_be_slice(alloy::primitives::keccak256(&engine_code).as_slice()),
                )?;
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
        call_with_input(
            evm,
            destination,
            caller,
            depth,
            Bytes::from_static(&[0x37, 0xa4, 0xe8, 0x34]),
        )
    }

    fn call_with_input(
        evm: &mut Evm<'static, Types>,
        destination: Address,
        caller: Address,
        depth: u16,
        input: Bytes,
    ) -> evm2::interpreter::MessageResult<Types> {
        let mut message = Message::<Types> {
            kind: MessageKind::Call,
            depth,
            gas_limit: 50_000_000,
            destination,
            call_target: destination,
            caller,
            input,
            code: Bytecode::new_legacy(Bytes::copy_from_slice(NATIVE_EARN_DISPATCHER_V1_RUNTIME)),
            code_address: destination,
            ..Default::default()
        };
        Host::execute_message(evm, &TxEnv::<Types>::default(), &mut message).unwrap()
    }

    fn setup_registrar(approve_engine: bool) -> Evm<'static, Types> {
        let mut evm = setup(false, false, true);
        let proxy_code = Bytes::from_static(&[0x60, 0x00, 0x56]);
        let factory_code = Bytes::from_static(&[0x60, 0x00, 0x00]);
        let fee_clone = earn_fees_clone_runtime(FEES_IMPL);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut s = StorageCtx;
            s.set_code(VAULT, proxy_code.clone())?;
            s.set_code(FEES, Bytes::copy_from_slice(&fee_clone))?;
            s.set_code(FACTORY, factory_code.clone())?;
            s.sstore(FEES, EARN_IMPLEMENTATION_SLOT, U256::ZERO)?;
            for (slot, value) in [
                (
                    factory_slots::ADDRESS,
                    U256::from_be_slice(FACTORY.as_slice()),
                ),
                (
                    factory_slots::GOVERNOR,
                    U256::from_be_slice(GOVERNOR.as_slice()),
                ),
                (
                    factory_slots::CODE_HASH,
                    U256::from_be_slice(keccak256(&factory_code).as_slice()),
                ),
                (
                    factory_slots::VAULT_RUNTIME_HASH,
                    U256::from_be_slice(keccak256(&proxy_code).as_slice()),
                ),
                (
                    factory_slots::VAULT_IMPLEMENTATION,
                    U256::from_be_slice(VAULT_IMPL.as_slice()),
                ),
                (
                    factory_slots::VAULT_IMPLEMENTATION_HASH,
                    U256::from_be_slice(keccak256([0x60, 0x2a, 0x60, 0x2a, 0x55, 0x00]).as_slice()),
                ),
                (
                    factory_slots::FEES_IMPLEMENTATION,
                    U256::from_be_slice(FEES_IMPL.as_slice()),
                ),
                (
                    factory_slots::FEES_IMPLEMENTATION_HASH,
                    U256::from_be_slice(keccak256([0x00]).as_slice()),
                ),
            ] {
                s.sstore(NATIVE_EARN_REGISTRY_ADDRESS, slot, value)?;
            }
            if approve_engine {
                s.sstore(
                    NATIVE_EARN_REGISTRY_ADDRESS,
                    tempo_contracts::earn::earn_engine_approval_slot(ENGINE),
                    U256::from_be_slice(keccak256([0x00]).as_slice()),
                )?;
            }
            Ok(())
        })
        .unwrap();
        evm
    }

    fn mock_forwarder_code(authorized: bool) -> Bytes {
        let mut code = vec![
            0x36, 0x60, 0x04, 0x14, 0x60, 0x18, 0x57, 0x36, 0x60, 0x24, 0x14, 0x60, 0x36, 0x57,
            0x33, 0x60, 0x2b, 0x55, 0x60, 0x2a, 0x60, 0x2a, 0x55, 0x00, 0x5b, 0x73,
        ];
        code.extend_from_slice(ENGINE.as_slice());
        code.extend_from_slice(&[
            0x60,
            0x00,
            0x52,
            0x60,
            0x20,
            0x60,
            0x00,
            0xf3,
            0x5b,
            0x60,
            u8::from(authorized),
            0x60,
            0x00,
            0x52,
            0x60,
            0x20,
            0x60,
            0x00,
            0xf3,
        ]);
        Bytes::from(code)
    }

    fn settlement_input() -> Bytes {
        let mut input = vec![0xbf, 0x8d, 0x3f, 0x22];
        input.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
        input.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
        input.extend_from_slice(&U256::ONE.to_be_bytes::<32>());
        input.extend_from_slice(&[0x11; 32]);
        Bytes::from(input)
    }

    #[test]
    fn registered_settlement_forwarder_executes_in_payment_lane() {
        let mut evm = setup_registrar(true);
        assert!(register_call(&mut evm, FACTORY).stop.is_success());
        let code = mock_forwarder_code(true);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        StorageCtx::enter(&mut storage, || {
            StorageCtx.set_code(FORWARDER, code.clone())
        })
        .unwrap();
        let input = INativeEarnRegistrar::registerSettlementForwarderCall {
            forwarder: FORWARDER,
            vault: VAULT,
            engine: ENGINE,
            forwarderCodeHash: keccak256(&code),
        }
        .abi_encode();
        let result = registrar_call(&mut evm, GOVERNOR, input);
        assert!(result.stop.is_success(), "{result:?}");
        assert_eq!(evm.logs().len(), 2);
        assert_eq!(evm.logs()[1].address, NATIVE_EARN_REGISTRY_ADDRESS);
        let snapshot = tempo_contracts::earn::earn_forwarder_snapshot_address(FORWARDER);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            assert_eq!(StorageCtx.account_code(snapshot)?.0, keccak256(&code));
            assert_eq!(
                StorageCtx.account_code(FORWARDER)?.0,
                NATIVE_EARN_DISPATCHER_V1_HASH
            );
            assert_eq!(
                StorageCtx.sload(FORWARDER, EARN_IMPLEMENTATION_SLOT)?,
                U256::from_be_slice(snapshot.as_slice())
            );
            Ok(())
        })
        .unwrap();
        let result = call_with_input(
            &mut evm,
            FORWARDER,
            Address::with_last_byte(0xaa),
            0,
            settlement_input(),
        );
        assert!(result.stop.is_success(), "{result:?}");
        assert!(evm.ext().native_call_context().verified_earn_payment());
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        let marker =
            StorageCtx::enter(&mut storage, || StorageCtx.sload(FORWARDER, U256::from(42)))
                .unwrap();
        assert_eq!(marker, U256::from(42));
        let caller =
            StorageCtx::enter(&mut storage, || StorageCtx.sload(FORWARDER, U256::from(43)))
                .unwrap();
        assert_eq!(caller, U256::from(0xaa));
    }

    #[test]
    fn settlement_forwarder_rejects_unregistered_or_unauthorized_calls() {
        let mut evm = setup_registrar(true);
        assert!(register_call(&mut evm, FACTORY).stop.is_success());
        let unregistered = call_with_input(
            &mut evm,
            FORWARDER,
            Address::with_last_byte(0xaa),
            0,
            settlement_input(),
        );
        assert!(!unregistered.stop.is_success());
        assert!(!evm.ext().native_call_context().verified_earn_payment());

        let code = mock_forwarder_code(false);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        StorageCtx::enter(&mut storage, || {
            StorageCtx.set_code(FORWARDER, code.clone())
        })
        .unwrap();
        let input = INativeEarnRegistrar::registerSettlementForwarderCall {
            forwarder: FORWARDER,
            vault: VAULT,
            engine: ENGINE,
            forwarderCodeHash: keccak256(&code),
        }
        .abi_encode();
        assert!(registrar_call(&mut evm, GOVERNOR, input).stop.is_success());
        let unauthorized = call_with_input(
            &mut evm,
            FORWARDER,
            Address::with_last_byte(0xaa),
            0,
            settlement_input(),
        );
        assert!(!unauthorized.stop.is_success());
        assert!(!evm.ext().native_call_context().verified_earn_payment());
    }

    fn register_call(
        evm: &mut Evm<'static, Types>,
        caller: Address,
    ) -> evm2::interpreter::MessageResult<Types> {
        let input = INativeEarnRegistrar::registerCall {
            vault: VAULT,
            fees: FEES,
            asset: ASSET,
            earnShare: SHARE,
            engine: ENGINE,
        }
        .abi_encode();
        call_with_input(
            evm,
            NATIVE_EARN_REGISTRY_ADDRESS,
            caller,
            0,
            Bytes::from(input),
        )
    }

    fn registrar_call(
        evm: &mut Evm<'static, Types>,
        caller: Address,
        input: Vec<u8>,
    ) -> evm2::interpreter::MessageResult<Types> {
        call_with_input(
            evm,
            NATIVE_EARN_REGISTRY_ADDRESS,
            caller,
            0,
            Bytes::from(input),
        )
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

    #[test]
    fn async_request_and_cancel_use_registered_payment_frame() {
        let mut evm = setup(true, false, true);
        // requestRedeem(uint256,bytes,address): three head words and an
        // empty dynamic bytes tail at the canonical offset.
        let mut request = vec![0x9f, 0xed, 0x97, 0xfb];
        request.extend_from_slice(&U256::from(4).to_be_bytes::<32>());
        request.extend_from_slice(&U256::from(96).to_be_bytes::<32>());
        request.extend_from_slice(&U256::from(0xaa).to_be_bytes::<32>());
        request.extend_from_slice(&[0u8; 32]);
        let result = call_with_input(
            &mut evm,
            VAULT,
            Address::with_last_byte(0xaa),
            0,
            Bytes::from(request),
        );
        assert!(result.stop.is_success());
        assert!(evm.ext().native_call_context().verified_earn_payment());

        let mut evm = setup(true, false, true);
        // cancelRedeem(bytes32,uint256) has two fixed-size arguments.
        let mut cancel = vec![0x2f, 0xa4, 0x62, 0x97];
        cancel.extend_from_slice(&[0x11; 32]);
        cancel.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        let result = call_with_input(
            &mut evm,
            VAULT,
            Address::with_last_byte(0xaa),
            0,
            Bytes::from(cancel),
        );
        assert!(result.stop.is_success());
        assert!(evm.ext().native_call_context().verified_earn_payment());
    }

    #[test]
    fn async_finalize_requires_the_registered_engine() {
        let mut finalize = vec![0xfb, 0x3a, 0xc8, 0xb8];
        finalize.extend_from_slice(&[0x11; 32]);
        finalize.extend_from_slice(&U256::from_be_slice(ASSET.as_slice()).to_be_bytes::<32>());
        finalize.extend_from_slice(&U256::from(4).to_be_bytes::<32>());
        let mut evm = setup(true, false, true);
        let rejected = call_with_input(
            &mut evm,
            VAULT,
            Address::with_last_byte(0xaa),
            0,
            Bytes::from(finalize.clone()),
        );
        assert!(!rejected.stop.is_success());
        assert!(!evm.ext().native_call_context().verified_earn_payment());
        let accepted = call_with_input(&mut evm, VAULT, ENGINE, 0, Bytes::from(finalize));
        assert!(accepted.stop.is_success());
        assert!(evm.ext().native_call_context().verified_earn_payment());
    }

    #[test]
    fn approved_factory_registers_new_stack_and_installs_dispatcher() {
        let mut evm = setup_registrar(true);
        let result = register_call(&mut evm, FACTORY);
        assert!(result.stop.is_success(), "{result:?}");
        assert_eq!(evm.logs().len(), 1);
        assert_eq!(evm.logs()[0].address, NATIVE_EARN_REGISTRY_ADDRESS);
        assert_eq!(
            evm.logs()[0].data,
            NativeEarnRegistered {
                vault: VAULT,
                asset: ASSET,
                earnShare: SHARE,
                fees: FEES,
                engine: ENGINE,
                engineCodeHash: keccak256([0x00]),
            }
            .into_log_data()
        );
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            assert_eq!(
                StorageCtx.account_code(VAULT)?.0,
                NATIVE_EARN_DISPATCHER_V1_HASH
            );
            assert_eq!(
                StorageCtx.account_code(FEES)?.0,
                NATIVE_EARN_DISPATCHER_V1_HASH
            );
            assert_eq!(
                StorageCtx.sload(FEES, EARN_IMPLEMENTATION_SLOT)?,
                U256::from_be_slice(FEES_IMPL.as_slice())
            );
            assert_eq!(
                StorageCtx.sload(
                    NATIVE_EARN_REGISTRY_ADDRESS,
                    tempo_contracts::earn::earn_registration_slot(
                        VAULT,
                        EarnRegistrationField::Kind
                    )
                )?,
                U256::ONE
            );
            Ok(())
        })
        .unwrap();
        assert!(!register_call(&mut evm, FACTORY).stop.is_success());
        assert!(
            call(&mut evm, VAULT, Address::with_last_byte(0xaa), 0)
                .stop
                .is_success()
        );
        assert!(evm.ext().native_call_context().verified_earn_payment());
    }

    #[test]
    fn registrar_rejects_forged_factory_and_unapproved_engine() {
        let mut evm = setup_registrar(true);
        assert!(
            !register_call(&mut evm, Address::with_last_byte(0xaa))
                .stop
                .is_success()
        );
        let mut evm = setup_registrar(false);
        assert!(!register_call(&mut evm, FACTORY).stop.is_success());
    }

    #[test]
    fn registrar_rejects_changed_factory_and_proxy_code() {
        let mut evm = setup_registrar(true);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        StorageCtx::enter(&mut storage, || {
            StorageCtx.set_code(FACTORY, Bytes::from_static(&[0x60, 0x01, 0x00]))
        })
        .unwrap();
        assert!(!register_call(&mut evm, FACTORY).stop.is_success());

        let mut evm = setup_registrar(true);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        StorageCtx::enter(&mut storage, || {
            StorageCtx.set_code(VAULT, Bytes::from_static(&[0x60, 0x01, 0x00]))
        })
        .unwrap();
        assert!(!register_call(&mut evm, FACTORY).stop.is_success());
    }

    #[test]
    fn governor_can_approve_revoke_and_refresh_migrated_engine() {
        let mut evm = setup_registrar(false);
        let approve = INativeEarnRegistrar::approveEngineCall { engine: ENGINE }.abi_encode();
        assert!(
            !registrar_call(&mut evm, FACTORY, approve.clone())
                .stop
                .is_success()
        );
        assert!(
            registrar_call(&mut evm, GOVERNOR, approve)
                .stop
                .is_success()
        );
        assert!(register_call(&mut evm, FACTORY).stop.is_success());
        let revoke = INativeEarnRegistrar::revokeEngineCall { engine: ENGINE }.abi_encode();
        assert!(registrar_call(&mut evm, GOVERNOR, revoke).stop.is_success());
        assert!(
            !call(&mut evm, VAULT, Address::with_last_byte(0xaa), 0)
                .stop
                .is_success()
        );

        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T16);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut s = StorageCtx;
            s.set_code(NEW_ENGINE, Bytes::from_static(&[0x60, 0x01, 0x00]))?;
            s.sstore(
                VAULT,
                U256::ZERO,
                U256::from_be_slice(NEW_ENGINE.as_slice()),
            )
        })
        .unwrap();
        let approve_new =
            INativeEarnRegistrar::approveEngineCall { engine: NEW_ENGINE }.abi_encode();
        assert!(
            registrar_call(&mut evm, GOVERNOR, approve_new)
                .stop
                .is_success()
        );
        assert!(
            !call(&mut evm, VAULT, Address::with_last_byte(0xaa), 0)
                .stop
                .is_success()
        );
        let refresh = INativeEarnRegistrar::updateVaultEngineCall {
            vault: VAULT,
            engine: NEW_ENGINE,
        }
        .abi_encode();
        assert!(
            registrar_call(&mut evm, GOVERNOR, refresh)
                .stop
                .is_success()
        );
        assert!(
            call(&mut evm, VAULT, Address::with_last_byte(0xaa), 0)
                .stop
                .is_success()
        );
    }
}
