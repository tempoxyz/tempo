//! Native portal execution using one journal and bounded paid dependency calls.
//!
//! The runtime selects the fork and transaction-wide budget before dispatch.

use super::{ZONE_PORTAL_PROXY_RUNTIME, ZonePortalStorage};
use crate::{
    DelegateCallNotAllowed,
    error::{Result, TempoPrecompileError},
    input_cost,
    native_call::{
        NativeCallBudget, NativeCallExt, NativeCallLimits, native_call, native_delegate_call,
        verify_native_code,
    },
    storage::{Handler, StorageActions, StorageCtx, evm::EvmPrecompileStorageProvider},
    storage_credits::NonCreditableSlots,
    zone_factory::ZoneFactory,
};
use alloy::{
    primitives::{Bytes, U256, keccak256},
    sol_types::{SolCall, SolError, SolValue},
};
use evm2::{
    Evm, EvmTypes,
    evm::precompile::PrecompileOutput,
    interpreter::{GasTracker, Message, MessageKind},
    precompiles::{PrecompileError, PrecompileHalt, PrecompileResult},
};
use std::{cell::RefCell, rc::Rc, sync::LazyLock};
use tempo_contracts::{
    TempoHardfork,
    precompiles::{
        ITIP20, ZONE_PORTAL_IMPL_ADDRESS,
        zone_portal::{ZonePortal, ZonePortalError},
    },
    zones::T13_ZONE_PORTAL_RUNTIME,
};
use tempo_primitives::TempoBlockExt;

/// Canonical encoding of either deposit selector with exactly 64 ciphertext bytes.
const DEPOSIT_CALL_BYTES: usize = 420;

static PORTAL_IMPLEMENTATION_HASH: LazyLock<alloy::primitives::B256> =
    LazyLock::new(|| keccak256(&T13_ZONE_PORTAL_RUNTIME));

/// Runtime-selected storage policy and paid dependency limits for one native call.
pub struct NativePortalExecution<'a> {
    /// Active protocol fork.
    pub spec: TempoHardfork,
    /// Shared action recording/replay mode.
    pub actions: StorageActions,
    /// Shared storage-credit exclusions.
    pub non_creditable_slots: Rc<RefCell<NonCreditableSlots>>,
    /// Reservation object shared with every other native root in the transaction.
    pub budget: &'a NativeCallBudget,
    /// Protocol-selected TIP-20 child frame limits, independent of calldata.
    pub dependency_limits: NativeCallLimits,
}

impl NativePortalExecution<'_> {
    fn with_storage<T: EvmTypes<BlockEnvExt = TempoBlockExt>, R>(
        &self,
        evm: &mut Evm<'_, T>,
        message: &Message<T>,
        gas: &mut GasTracker,
        action: impl FnOnce(&mut ZonePortalStorage) -> Result<R>,
    ) -> Result<R> {
        let mut storage = EvmPrecompileStorageProvider::new(
            evm,
            gas,
            self.spec,
            message.caller_is_static || message.kind == MessageKind::StaticCall,
        )
        .with_actions(self.actions.clone())
        .with_non_creditable_slots(self.non_creditable_slots.clone());
        StorageCtx::enter(&mut storage, || {
            action(&mut ZonePortalStorage::new(message.destination))
        })
    }

    /// Executes a deposit through paid TIP-20 calls and commits its queue entry.
    ///
    /// The surrounding EVM native frame owns rollback. This function must not be
    /// called with a live `StorageCtx` borrow: preparation and commit each enter
    /// their own scope, while dependencies run between those scopes.
    pub fn deposit<T: EvmTypes<BlockEnvExt = TempoBlockExt>>(
        &self,
        evm: &mut Evm<'_, T>,
        message: &Message<T>,
        gas: &mut GasTracker,
    ) -> PrecompileResult
    where
        T::EvmExt: NativeCallExt,
    {
        if message.destination != message.code_address {
            return Err(PrecompileError::Revert(
                DelegateCallNotAllowed {}.abi_encode().into(),
            ));
        }
        if !message.value.is_zero() {
            return Err(PrecompileError::Revert(Bytes::new()));
        }
        if message.input.len() > DEPOSIT_CALL_BYTES {
            return Err(PrecompileHalt::OutOfGas.into());
        }
        let prepared = self.with_storage(evm, message, gas, |portal| {
            portal
                .storage
                .deduct_gas(input_cost(self.spec, message.input.len())?)?;
            if portal.storage.is_static() {
                return Err(TempoPrecompileError::StaticCallNotAllowed);
            }
            if !ZoneFactory::new().is_zone_portal(message.destination)?
                || !portal.initialized.read()?
                || message.code.original_byte_slice() != ZONE_PORTAL_PROXY_RUNTIME
            {
                return Err(ZonePortalError::PortalNotRegistered(
                    ZonePortal::PortalNotRegistered {},
                )
                .into());
            }
            let config = crate::dispatch::abi_decoder_config_for_spec(self.spec);
            let call = if message
                .input
                .starts_with(&ZonePortal::depositCall::SELECTOR)
            {
                let call = ZonePortal::depositCall::abi_decode_with_config(&message.input, config)
                    .map_err(|_| TempoPrecompileError::OutOfGas)?;
                if call.abi_encode().as_slice() != message.input.as_ref() {
                    return Err(TempoPrecompileError::OutOfGas);
                }
                call
            } else if message
                .input
                .starts_with(&ZonePortal::depositEncryptedCall::SELECTOR)
            {
                let call = ZonePortal::depositEncryptedCall::abi_decode_with_config(
                    &message.input,
                    config,
                )
                .map_err(|_| TempoPrecompileError::OutOfGas)?;
                if call.abi_encode().as_slice() != message.input.as_ref() {
                    return Err(TempoPrecompileError::OutOfGas);
                }
                ZonePortal::depositCall {
                    token: call.token,
                    amount: call.amount,
                    keyIndex: call.keyIndex,
                    encrypted: call.encrypted,
                    tempoRefundRecipient: call.tempoRefundRecipient,
                }
            } else {
                let mut selector = [0; 4];
                if message.input.len() >= 4 {
                    selector.copy_from_slice(&message.input[..4]);
                }
                return Err(TempoPrecompileError::UnknownFunctionSelector(selector));
            };
            portal.prepare_deposit(message.caller, call)
        });
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return error.into_precompile_result(),
        };
        if message.depth == 0 {
            evm.ext()
                .native_call_context()
                .record_verified_portal_deposit();
        }
        let token = prepared.token();
        native_call(
            evm,
            message,
            gas,
            self.budget,
            token,
            Bytes::from(
                ITIP20::transferFromCall {
                    from: message.caller,
                    to: message.destination,
                    amount: U256::from(prepared.amount()),
                }
                .abi_encode(),
            ),
            false,
            self.dependency_limits,
        )?;
        if prepared.fee() != 0 {
            native_call(
                evm,
                message,
                gas,
                self.budget,
                token,
                Bytes::from(
                    ITIP20::transferCall {
                        to: prepared.admin(),
                        amount: U256::from(prepared.fee()),
                    }
                    .abi_encode(),
                ),
                false,
                self.dependency_limits,
            )?;
        }
        match self.with_storage(evm, message, gas, |portal| portal.commit_deposit(prepared)) {
            Ok(hash) => Ok(PrecompileOutput::new(hash.abi_encode().into())),
            Err(error) => error.into_precompile_result(),
        }
    }

    /// Executes a registered sequencer's bounded batch through the canonical
    /// protocol implementation in the portal's existing storage context.
    ///
    /// This retains the historical verifier, signature, queue, and event rules
    /// while every nested call consumes the one paid delegate frame.
    pub fn submit_batch<T: EvmTypes<BlockEnvExt = TempoBlockExt>>(
        &self,
        evm: &mut Evm<'_, T>,
        message: &Message<T>,
        gas: &mut GasTracker,
    ) -> PrecompileResult
    where
        T::EvmExt: NativeCallExt,
    {
        if message.destination != message.code_address {
            return Err(PrecompileError::Revert(
                DelegateCallNotAllowed {}.abi_encode().into(),
            ));
        }
        if !message.value.is_zero() {
            return Err(PrecompileError::Revert(Bytes::new()));
        }
        if message.input.len() > 65_536 {
            return Err(PrecompileHalt::OutOfGas.into());
        }
        let prepared = self.with_storage(evm, message, gas, |portal| {
            portal
                .storage
                .deduct_gas(input_cost(self.spec, message.input.len())?)?;
            if portal.storage.is_static() {
                return Err(TempoPrecompileError::StaticCallNotAllowed);
            }
            if !ZoneFactory::new().is_zone_portal(message.destination)?
                || !portal.initialized.read()?
                || message.code.original_byte_slice() != ZONE_PORTAL_PROXY_RUNTIME
            {
                return Err(ZonePortalError::PortalNotRegistered(
                    ZonePortal::PortalNotRegistered {},
                )
                .into());
            }
            if portal.role[message.caller].read()? != 1 {
                return Err(ZonePortalError::NotSequencer(ZonePortal::NotSequencer {}).into());
            }
            let config = crate::dispatch::abi_decoder_config_for_spec(self.spec);
            if message
                .input
                .starts_with(&ZonePortal::submitBatch_0Call::SELECTOR)
            {
                let call =
                    ZonePortal::submitBatch_0Call::abi_decode_with_config(&message.input, config)
                        .map_err(|_| TempoPrecompileError::OutOfGas)?;
                if call.abi_encode().as_slice() != message.input.as_ref()
                    || call.verifierConfig.len() > 1_024
                    || call.proof.len() > 32_768
                    || call.signatures.len() > 16
                    || call.signatures.iter().any(|sig| sig.len() > 256)
                {
                    return Err(TempoPrecompileError::OutOfGas);
                }
            } else if message
                .input
                .starts_with(&ZonePortal::submitBatch_1Call::SELECTOR)
            {
                let call =
                    ZonePortal::submitBatch_1Call::abi_decode_with_config(&message.input, config)
                        .map_err(|_| TempoPrecompileError::OutOfGas)?;
                if call.abi_encode().as_slice() != message.input.as_ref()
                    || call.verifierConfig.len() > 1_024
                    || call.proof.len() > 32_768
                    || call.signatures.len() > 16
                    || call.signatures.iter().any(|sig| sig.len() > 256)
                {
                    return Err(TempoPrecompileError::OutOfGas);
                }
            } else {
                return Err(TempoPrecompileError::OutOfGas);
            }
            Ok(())
        });
        if let Err(error) = prepared {
            return error.into_precompile_result();
        }
        verify_native_code(
            evm,
            gas,
            ZONE_PORTAL_IMPL_ADDRESS,
            *PORTAL_IMPLEMENTATION_HASH,
        )?;
        if message.depth == 0 {
            evm.ext()
                .native_call_context()
                .record_verified_portal_settlement();
        }
        native_delegate_call(
            evm,
            message,
            gas,
            self.budget,
            ZONE_PORTAL_IMPL_ADDRESS,
            message.input.clone(),
            self.dependency_limits,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{PortalEncryptionKeyEntry, PortalTokenConfig},
        *,
    };
    use crate::{
        PATH_USD_ADDRESS, TempoPrecompiles, storage::Handler, tip20::TIP20Token,
        zone_factory::portal::deposit::tests::baseline_call,
    };
    use alloy::primitives::{Address, B256};
    use evm2::{
        BaseEvmConfigSelector, ExecutionConfig, SpecId, bytecode::Bytecode, env::TxEnv,
        evm::InMemoryDB, interpreter::Host, registry::TxRegistry,
    };
    use tempo_contracts::precompiles::ITIP20;
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

    const PORTAL: Address = Address::new([
        0x5a, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    const ADMIN: Address = Address::with_last_byte(0x55);

    fn setup_evm(approve: bool, queue_full: bool) -> (Evm<'static, Types>, Address) {
        let (sender, call) = baseline_call();
        let spec = TempoHardfork::T15;
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
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, spec);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut setup = crate::test_util::TIP20Setup::path_usd(sender)
                .with_issuer(sender)
                .with_mint(sender, U256::from(2_000_000));
            if approve {
                setup = setup.with_approval(sender, PORTAL, U256::from(2_000_000));
            }
            setup.apply()?;
            ZoneFactory::new().next_zone_id.write(2)?;
            let mut portal = ZonePortalStorage::new(PORTAL);
            portal
                .storage
                .set_code(PORTAL, Bytes::from_static(&ZONE_PORTAL_PROXY_RUNTIME))?;
            portal.initialized.write(true)?;
            portal.zone_id.write(1)?;
            portal.admin.write(ADMIN)?;
            portal.zone_gas_rate.write(1)?;
            portal.token_configs[PATH_USD_ADDRESS].write(PortalTokenConfig {
                enabled: true,
                deposits_active: true,
            })?;
            portal
                .encryption_keys
                .write(vec![PortalEncryptionKeyEntry {
                    x: call.encrypted.ephemeralPubkeyX,
                    y_parity: 2,
                    activation_block: 0,
                }])?;
            if queue_full {
                portal.deposit_count.write(210)?;
            }
            Ok(())
        })
        .unwrap();
        (evm, sender)
    }

    fn run_deposit(
        evm: &mut Evm<'static, Types>,
        sender: Address,
    ) -> evm2::interpreter::MessageResult<Types> {
        let (_, call) = baseline_call();
        let mut message = Message::<Types> {
            kind: MessageKind::Call,
            gas_limit: 30_000_000,
            destination: PORTAL,
            call_target: PORTAL,
            caller: sender,
            input: call.abi_encode().into(),
            code: Bytecode::new_legacy(Bytes::from_static(&ZONE_PORTAL_PROXY_RUNTIME)),
            code_address: PORTAL,
            ..Default::default()
        };
        Host::execute_message(evm, &TxEnv::<Types>::default(), &mut message).unwrap()
    }

    fn empty_batch() -> ZonePortal::submitBatch_1Call {
        ZonePortal::submitBatch_1Call {
            tempoBlockNumber: 1,
            recentTempoBlockNumber: 1,
            blockTransition: ZonePortal::BlockTransition {
                prevBlockHash: B256::ZERO,
                nextBlockHash: B256::ZERO,
            },
            depositQueueTransition: ZonePortal::DepositQueueTransition {
                prevProcessedHash: B256::ZERO,
                nextProcessedHash: B256::ZERO,
                prevDepositNumber: 0,
                nextDepositNumber: 0,
            },
            tokenEnablementTransition: ZonePortal::TokenEnablementTransition {
                prevProcessedTokenCount: 0,
                nextProcessedTokenCount: 0,
            },
            withdrawalQueueHash: B256::ZERO,
            verifierConfig: Bytes::new(),
            proof: Bytes::new(),
            nextZoneHeight: U256::from(1),
            signatures: vec![],
        }
    }

    #[test]
    fn native_batch_rejects_missing_implementation_before_payment_admission() {
        let (mut evm, sequencer) = setup_evm(false, false);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            ZonePortalStorage::new(PORTAL).role[sequencer].write(1)
        })
        .unwrap();
        let mut message = Message::<Types> {
            kind: MessageKind::Call,
            gas_limit: 30_000_000,
            destination: PORTAL,
            call_target: PORTAL,
            caller: sequencer,
            input: empty_batch().abi_encode().into(),
            code: Bytecode::new_legacy(Bytes::from_static(&ZONE_PORTAL_PROXY_RUNTIME)),
            code_address: PORTAL,
            ..Default::default()
        };
        let result =
            Host::execute_message(&mut evm, &TxEnv::<Types>::default(), &mut message).unwrap();
        assert!(result.stop.is_revert());
        assert!(!evm.ext().native_call_context().verified_portal_settlement());
    }

    #[test]
    fn native_batch_enters_canonical_implementation_with_paid_child_work() {
        let (mut evm, sequencer) = setup_evm(false, false);
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(&mut evm, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut portal = ZonePortalStorage::new(PORTAL);
            portal.role[sequencer].write(1)?;
            portal
                .storage
                .set_code(ZONE_PORTAL_IMPL_ADDRESS, T13_ZONE_PORTAL_RUNTIME)?;
            Ok(())
        })
        .unwrap();
        let mut message = Message::<Types> {
            kind: MessageKind::Call,
            gas_limit: 30_000_000,
            destination: PORTAL,
            call_target: PORTAL,
            caller: sequencer,
            input: empty_batch().abi_encode().into(),
            code: Bytecode::new_legacy(Bytes::from_static(&ZONE_PORTAL_PROXY_RUNTIME)),
            code_address: PORTAL,
            ..Default::default()
        };
        let result =
            Host::execute_message(&mut evm, &TxEnv::<Types>::default(), &mut message).unwrap();
        // This synthetic batch has no valid proof or signatures, so Solidity
        // rejects it after the authenticated, charged delegate frame enters.
        assert!(result.stop.is_revert());
        assert!(evm.ext().native_call_context().verified_portal_settlement());
        assert!(result.gas.spent() > 2_600);
    }

    fn balances(
        evm: &mut Evm<'static, Types>,
        sender: Address,
    ) -> (U256, U256, U256, U256, U256, u64, B256) {
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(evm, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || -> Result<_> {
            let token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            let portal = ZonePortalStorage::new(PORTAL);
            Ok((
                token.balance_of(ITIP20::balanceOfCall { account: sender })?,
                token.balance_of(ITIP20::balanceOfCall { account: PORTAL })?,
                token.balance_of(ITIP20::balanceOfCall { account: ADMIN })?,
                token.total_supply()?,
                token.allowance(ITIP20::allowanceCall {
                    owner: sender,
                    spender: PORTAL,
                })?,
                portal.deposit_count.read()?,
                portal.current_deposit_queue_hash.read()?,
            ))
        })
        .unwrap()
    }

    #[test]
    fn paid_native_deposit_calls_tip20_and_commits_net_backing() {
        let (mut evm, sender) = setup_evm(true, false);
        let logs_before = evm.logs().len();
        let result = run_deposit(&mut evm, sender);
        assert!(result.stop.is_success(), "{:?}", result.stop);
        assert!(evm.ext().verified_portal_deposit());
        assert!(result.gas.used() > 0);
        let (sender_balance, portal_balance, fee_balance, supply, allowance, count, hash) =
            balances(&mut evm, sender);
        assert_eq!(
            (sender_balance, portal_balance, fee_balance),
            (
                U256::from(1_000_000),
                U256::from(900_000),
                U256::from(100_000)
            )
        );
        assert_eq!(count, 1);
        assert_eq!(sender_balance + portal_balance + fee_balance, supply);
        assert_eq!(supply, U256::from(2_000_000));
        assert_eq!(allowance, U256::from(1_000_000));
        assert_eq!(result.output.as_ref(), hash.abi_encode().as_slice());
        assert_eq!(evm.logs().len() - logs_before, 3);
    }

    #[test]
    fn exhausted_queue_rolls_back_both_paid_tip20_transfers() {
        let (mut evm, sender) = setup_evm(true, true);
        let before = balances(&mut evm, sender);
        let logs_before = evm.logs().len();
        let result = run_deposit(&mut evm, sender);
        assert!(evm.ext().verified_portal_deposit());
        assert!(result.stop.is_revert(), "{:?}", result.stop);
        assert_eq!(balances(&mut evm, sender), before);
        assert_eq!(evm.logs().len(), logs_before);
        assert!(result.gas.used() > 0);
    }

    #[test]
    fn missing_allowance_reverts_without_portal_or_fee_balance() {
        let (mut evm, sender) = setup_evm(false, false);
        let before = balances(&mut evm, sender);
        let logs_before = evm.logs().len();
        let result = run_deposit(&mut evm, sender);
        assert!(evm.ext().verified_portal_deposit());
        assert!(result.stop.is_revert(), "{:?}", result.stop);
        assert_eq!(balances(&mut evm, sender), before);
        assert_eq!(evm.logs().len(), logs_before);
    }
}
