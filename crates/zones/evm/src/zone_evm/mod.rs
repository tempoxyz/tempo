//! Zone runtime EVM and its private execution policies.

#[cfg(test)]
mod cold_access;
pub(crate) mod contract_creation;
mod validation;

pub(crate) use contract_creation::zone_execution_config;
pub use validation::validate_transaction;

use alloy_consensus::transaction::Recovered;
use alloy_primitives::B256;
use evm2::{
    AnyError, TxResult,
    registry::{AnyTxHandler, HandlerError, HandlerResult, TxHandler, TxRegistry, TxRequest},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{ExecutionContext, TempoEvmTypes, TempoTxEnv, tempo_tx_registry};
use zone_precompiles::{
    L1State, L1StorageReader, tempo_state::TEMPO_BLOCK_NUMBER_SLOT, tx_context,
};
use zone_primitives::constants::{CONTRACT_DEPLOYER_ALLOWLIST, TEMPO_STATE_ADDRESS};

use crate::database::validate_journal;

/// Wraps Tempo's handlers with Zone transaction validation and transaction-local L1 context.
pub(crate) fn zone_tx_registry<L1: L1StorageReader>(
    spec: TempoHardfork,
    l1: L1State<L1>,
) -> TxRegistry<TempoEvmTypes, TxResult<TempoEvmTypes>> {
    let tempo = tempo_tx_registry(spec.into());
    let mut zone = TxRegistry::new();

    for type_id in [0, 1, 2, 4, 0x76] {
        let Some(handler) = tempo.get_by_type(type_id) else {
            continue;
        };
        zone.register(
            type_id,
            |tx: &TempoTxEnv| Some(tx),
            ZoneTxHandler {
                inner: handler,
                l1: l1.clone(),
            },
        );
    }

    zone
}

/// Applies Zone policies and context around either phase of a Tempo handler.
struct ZoneTxHandler<L1> {
    inner: AnyTxHandler<TempoEvmTypes, TxResult<TempoEvmTypes>>,
    l1: L1State<L1>,
}

impl<L1: L1StorageReader> ZoneTxHandler<L1> {
    fn enter(
        &self,
        request: &mut TxRequest<'_, '_, TempoEvmTypes, TempoTxEnv>,
    ) -> HandlerResult<ZoneTxContext<L1>> {
        self.l1.reset_transaction_state();
        crate::validate_transaction(request.envelope, CONTRACT_DEPLOYER_ALLOWLIST)?;

        // The accepted EVM overlay sits above L1OverlayDB. Snapshot its checkpoint
        // here so mirrored reads cannot fall back to the backing database's old value.
        let initial_anchor = request
            .host
            .state_mut()
            .storage_slot_untracked(&TEMPO_STATE_ADDRESS, &TEMPO_BLOCK_NUMBER_SLOT)?;
        // The accepted cache keys mirrored slots without their anchor. That is sound because a
        // Zone EVM executes one block, whose committed opening advanceTempo is its only anchor change.
        self.l1.begin_transaction(initial_anchor);

        let tx_hash = match request.envelope.execution_context() {
            ExecutionContext::Transaction { tx_hash } => tx_hash,
            ExecutionContext::Simulation => B256::repeat_byte(0xff),
        };
        let fee_payer = request
            .envelope
            .fee_payer()
            .unwrap_or_else(|_| request.tx.signer());
        Ok(ZoneTxContext {
            l1: self.l1.clone(),
            _transaction: tx_context::set_current_transaction(tx_hash, fee_payer),
        })
    }
}

impl<L1: L1StorageReader> TxHandler<TempoEvmTypes, TempoTxEnv, TxResult<TempoEvmTypes>>
    for ZoneTxHandler<L1>
{
    fn validate(
        &self,
        mut request: TxRequest<'_, '_, TempoEvmTypes, TempoTxEnv>,
    ) -> HandlerResult<()> {
        let _context = self.enter(&mut request)?;
        let transaction = Recovered::new_unchecked(request.envelope, request.tx.signer());
        self.inner.validate(transaction, request.host)
    }

    fn execute(
        &self,
        mut request: TxRequest<'_, '_, TempoEvmTypes, TempoTxEnv>,
    ) -> HandlerResult<TxResult<TempoEvmTypes>> {
        let _context = self.enter(&mut request)?;
        let transaction = Recovered::new_unchecked(request.envelope, request.tx.signer());
        let result = self.inner.execute(transaction, request.host)?;
        validate_journal(request.host.state())
            .map_err(|error| HandlerError::Fatal(AnyError::new(error)))?;
        Ok(result)
    }
}

struct ZoneTxContext<L1: L1StorageReader> {
    l1: L1State<L1>,
    _transaction: tx_context::TransactionContextGuard,
}

impl<L1: L1StorageReader> Drop for ZoneTxContext<L1> {
    fn drop(&mut self) {
        self.l1.reset_transaction_state();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{ZoneBlockExecutor, ZoneDbError, ZoneEvm, ZoneEvmConfig};
    use alloy_consensus::{SignableTransaction, TxEip7702, TxLegacy, transaction::Recovered};
    use alloy_primitives::{Address, B256, Signature, TxKind, U256};
    use alloy_sol_types::{SolCall, SolError};
    use evm2::{
        PendingState, TxResult,
        evm::{AccountInfo, InMemoryDB, precompile::NoPrecompiles},
        interpreter::InstrStop,
        registry::{HandlerError, TxRegistry, TxRequest, handler},
    };
    use reth_chainspec::EthChainSpec;
    use reth_evm::{BlockExecutor, BlockExecutorFactory, ConfigureEvm};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempo_chainspec::{hardfork::TempoHardfork, spec::DEV};
    use tempo_contracts::{
        precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount},
        zones::IZoneOutbox,
    };
    use tempo_evm::{
        ResolvedFeeToken, TempoEvmEnv, TempoEvmTypes, TempoInvalidTransaction, TempoTxEnv,
    };
    use tempo_precompiles::{TIP403_REGISTRY_ADDRESS, storage::StorageCtx};
    use tempo_primitives::{
        TempoEvmKind, TempoTxEnvelope,
        transaction::{
            Authorization, TempoSignature, TempoSignedAuthorization, TempoTransaction,
            envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
        },
    };
    use zone_chainspec::ZoneChainSpec;
    use zone_precompiles::{
        ADVANCE_TEMPO_SELECTOR, ZONE_FEE_MANAGER_ADDRESS, test_utils::MockL1Reader,
        zone_fee_manager,
    };
    use zone_primitives::constants::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, zone_chain_id};

    /// A dev Zone EVM config that reads Tempo through `l1`.
    pub(crate) fn config(l1: MockL1Reader) -> ZoneEvmConfig<MockL1Reader> {
        let mut genesis = DEV.genesis().clone();
        genesis.config.chain_id = zone_chain_id(DEV.chain_id(), 1).unwrap();
        ZoneEvmConfig::new(
            std::sync::Arc::new(ZoneChainSpec::from_genesis(genesis).unwrap()),
            l1,
            Address::ZERO,
        )
    }

    /// A zone environment at `spec` that charges no fees, with a 30M block gas limit.
    pub(crate) fn fee_free_env(spec: TempoHardfork) -> TempoEvmEnv {
        let mut env = TempoEvmEnv {
            spec,
            ..Default::default()
        };
        env.version = tempo_chainspec::gas_params::version(evm2::SpecId::from(spec), spec, false);
        tempo_chainspec::gas_params::apply_zone(&mut env.version, spec);
        env.version.features.remove(evm2::EvmFeatures::FEE_CHARGE);
        env.block.gas_limit = U256::from(30_000_000);
        env
    }

    /// A zone database whose fee manager defaults to pathUSD, holding `sender` at nonce 1.
    pub(crate) fn sender_db(sender: Address) -> InMemoryDB {
        let mut db = InMemoryDB::default();
        db.insert_account_info(&ZONE_FEE_MANAGER_ADDRESS, AccountInfo::default());
        db.insert_account_storage(
            &ZONE_FEE_MANAGER_ADDRESS,
            &zone_fee_manager::slots::DEFAULT_FEE_TOKEN,
            &U256::from_be_slice(tempo_precompiles::DEFAULT_FEE_TOKEN.as_slice()),
        );
        db.insert_account_info(&sender, AccountInfo::default().with_nonce(1));
        db
    }

    pub(super) fn test_evm(db: InMemoryDB) -> ZoneEvm<'static> {
        let spec = TempoHardfork::T7;
        let mut env = TempoEvmEnv {
            spec,
            ..Default::default()
        };
        env.version = tempo_chainspec::gas_params::version(evm2::SpecId::OSAKA, spec, false);
        env.block.gas_limit = U256::from(30_000_000);
        BlockExecutorFactory::evm_with_env(&config(MockL1Reader::default()), db, env)
    }

    pub(super) fn transaction(
        caller: Address,
        envelope: impl Into<TempoTxEnvelope>,
    ) -> Recovered<TempoTxEnv> {
        Recovered::new_unchecked(
            Recovered::new_unchecked(envelope.into(), caller).into(),
            caller,
        )
    }

    fn registry_write() -> PendingState {
        let mut state = PendingState::default();
        state.insert_account(
            TIP403_REGISTRY_ADDRESS,
            Some(AccountInfo::default()),
            Some(AccountInfo::default()),
        );
        state.insert_storage(TIP403_REGISTRY_ADDRESS, U256::ZERO, U256::ZERO, U256::ONE);
        state
    }

    fn transactions_with_authorization_lists() -> [Recovered<TempoTxEnv>; 2] {
        let authorization = Authorization {
            chain_id: U256::ZERO,
            address: Address::ZERO,
            nonce: 0,
        };
        let eip7702 = TempoTxEnvelope::Eip7702(
            TxEip7702 {
                authorization_list: vec![
                    authorization
                        .clone()
                        .into_signed(Signature::test_signature()),
                ],
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );
        let tempo = TempoTxEnvelope::AA(
            TempoTransaction {
                tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                    authorization,
                    TempoSignature::default(),
                )],
                ..Default::default()
            }
            .into_signed(TempoSignature::default()),
        );
        [
            transaction(Address::ZERO, eip7702),
            transaction(Address::ZERO, tempo),
        ]
    }

    /// The handler's own storage contexts over a zone EVM follow zone rules too, not only zone
    /// precompile calls.
    #[test]
    fn handler_storage_contexts_follow_zone_rules() {
        let mut evm = BlockExecutorFactory::evm_with_env(
            &config(MockL1Reader::default()),
            InMemoryDB::default(),
            TempoEvmEnv::default(),
        );
        assert_eq!(
            StorageCtx::enter_evm(&mut evm, || StorageCtx::default().kind()),
            TempoEvmKind::Zone
        );
    }

    #[test]
    fn pool_validation_rejects_authorization_lists() {
        for tx in transactions_with_authorization_lists() {
            let result = test_evm(InMemoryDB::default())
                .validate_tx(&tx)
                .unwrap_err();
            assert!(matches!(
                result.external_ref::<TempoInvalidTransaction>(),
                Some(TempoInvalidTransaction::CallsValidation(
                    "authorization lists are not supported"
                ))
            ));
        }
    }

    #[test]
    fn block_execution_rejects_authorization_lists() {
        for tx in transactions_with_authorization_lists() {
            let mut evm = test_evm(InMemoryDB::default());
            let err = evm
                .transact(&tx)
                .expect_err("authorization list must be rejected before execution");
            assert!(matches!(
                err.external_ref::<TempoInvalidTransaction>(),
                Some(TempoInvalidTransaction::CallsValidation(
                    "authorization lists are not supported"
                ))
            ));
        }
    }

    #[test]
    fn sanitizes_all_completed_execution_results() {
        for stop in [InstrStop::Stop, InstrStop::Revert, InstrStop::NotActivated] {
            let mut evm = test_evm(InMemoryDB::default());
            let mut registry = TxRegistry::new();
            // Inject completed execution state, retaining the production block-executor guard.
            registry.register(
                0,
                |tx: &TempoTxEnv| Some(tx),
                handler(
                    |_: &mut TxRequest<'_, '_, TempoEvmTypes, TempoTxEnv>| Ok(()),
                    move |request: TxRequest<'_, '_, TempoEvmTypes, TempoTxEnv>, ()| {
                        request.host.state_mut().set_pending_state(registry_write());
                        Ok(TxResult::<TempoEvmTypes> {
                            status: stop == InstrStop::Stop,
                            stop,
                            ..Default::default()
                        })
                    },
                ),
            );
            evm.set_execution_config(
                super::zone_execution_config(TempoHardfork::T7, *evm.version()),
                TempoHardfork::T7,
                registry,
                NoPrecompiles::default(),
            );
            let config = config(MockL1Reader::default());
            let block = Default::default();
            let ctx = config.context_for_block(&block).unwrap();
            let mut executor = ZoneBlockExecutor::new(evm, ctx, config.chain_spec());
            let tx = Recovered::new_unchecked(
                TempoTxEnvelope::Legacy(
                    TxLegacy {
                        to: ZONE_INBOX_ADDRESS.into(),
                        input: (&ADVANCE_TEMPO_SELECTOR).into(),
                        ..Default::default()
                    }
                    .into_signed(TEMPO_SYSTEM_TX_SIGNATURE),
                ),
                TEMPO_SYSTEM_TX_SENDER,
            );
            let result = executor.execute_transaction_without_commit(tx).unwrap_err();
            assert!(matches!(
                result
                    .as_internal()
                    .and_then(|error| error.downcast_other::<ZoneDbError>()),
                Some(ZoneDbError::L1Write {
                    address: TIP403_REGISTRY_ADDRESS,
                    slot: U256::ZERO
                })
            ));
        }
    }
    #[test]
    fn validation_sets_and_clears_l1_context() {
        let spec = TempoHardfork::T7;
        let mut db = InMemoryDB::default();
        db.insert_account_storage(
            &TEMPO_STATE_ADDRESS,
            &TEMPO_BLOCK_NUMBER_SLOT,
            &U256::from(42),
        );
        let mut evm = test_evm(db);
        let l1 = evm
            .database_as::<crate::L1OverlayDB<InMemoryDB, MockL1Reader>>()
            .unwrap()
            .l1_state()
            .clone();
        let preparations = Arc::new(AtomicUsize::new(0));
        let mut inner = TxRegistry::new();
        let observed_l1 = l1.clone();
        let observed_preparations = preparations.clone();
        inner.register(
            0,
            |tx: &TempoTxEnv| Some(tx),
            handler(
                move |request: &mut TxRequest<'_, '_, TempoEvmTypes, TempoTxEnv>| {
                    assert_eq!(observed_l1.initial_anchor(), Some(U256::from(42)));
                    request.host.ext_mut().resolved_fee_token =
                        Some(ResolvedFeeToken::Selected(Address::ZERO));
                    if observed_preparations.fetch_add(1, Ordering::SeqCst) == 1 {
                        return Err(HandlerError::Fatal("injected preparation failure".into()));
                    }
                    Ok(())
                },
                |_, ()| -> HandlerResult<TxResult<TempoEvmTypes>> {
                    panic!("pool validation must not execute user calls")
                },
            ),
        );
        let mut registry = TxRegistry::new();
        registry.register(
            0,
            |tx: &TempoTxEnv| Some(tx),
            ZoneTxHandler {
                inner: inner.get_by_type(0).unwrap(),
                l1: l1.clone(),
            },
        );
        evm.set_execution_config(
            super::zone_execution_config(spec, *evm.version()),
            spec,
            registry,
            NoPrecompiles::default(),
        );
        let tx = transaction(
            Address::repeat_byte(0xab),
            TxLegacy {
                to: Address::ZERO.into(),
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );
        for fails in [false, true, false] {
            let result = evm.validate_tx(&tx);
            assert_eq!(result.is_err(), fails);
            assert_eq!(l1.initial_anchor(), None);
            assert_eq!(l1.get_anchor(), None);
        }
        assert_eq!(preparations.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn l1_read_gas_is_independent_of_discarded_attempt() {
        let sender = Address::repeat_byte(0x01);
        let tx = transaction(
            sender,
            TxLegacy {
                nonce: 1,
                gas_limit: 1_000_000,
                to: TxKind::Call(ZONE_OUTBOX_ADDRESS),
                input: IZoneOutbox::pendingWithdrawalsCountCall {}
                    .abi_encode()
                    .into(),
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );

        for (spec, expected_gas) in [
            (TempoHardfork::T13, 27_394),
            (TempoHardfork::T14, 37_894),
            (TempoHardfork::T15, 37_894),
        ] {
            let l1 = MockL1Reader::default();
            l1.seed_active_sequencer(Address::ZERO, 0, sender);
            let make_evm = || {
                BlockExecutorFactory::evm_with_env(
                    &config(l1.clone()),
                    sender_db(sender),
                    fee_free_env(spec),
                )
            };
            let mut builder = make_evm();
            let mut replay = make_evm();

            // Discarding leaves the account cache populated but resets the selected L1 anchor.
            let discarded = builder.transact(&tx).unwrap().discard();
            let commitment_reads = l1.commitment_requests();
            let built = builder.transact(&tx).unwrap().discard();
            assert_eq!(l1.commitment_requests(), commitment_reads);
            let replayed = replay.transact(&tx).unwrap().discard();

            for result in [&discarded, &built, &replayed] {
                assert!(result.status, "{spec:?}: {result:?}");
                assert_eq!(
                    IZoneOutbox::pendingWithdrawalsCountCall::abi_decode_returns(&result.output)
                        .unwrap(),
                    U256::ZERO,
                );
            }
            assert_eq!(discarded.tx_gas_used(), expected_gas, "{spec:?}");
            assert_eq!(replayed.tx_gas_used(), expected_gas, "{spec:?}");
            assert_eq!(built.tx_gas_used(), replayed.tx_gas_used(), "{spec:?}");
            for evm in [&mut builder, &mut replay] {
                assert_eq!(
                    evm.state_mut()
                        .account_info_untracked(&sender)
                        .unwrap()
                        .unwrap()
                        .nonce,
                    1,
                    "discarded attempts must not change the sender nonce at {spec:?}",
                );
            }
        }
    }

    #[test]
    fn configurable_account_precompile_reads_tempo_and_rejects_writes() {
        let (sender, account) = (Address::repeat_byte(0x01), Address::repeat_byte(0x04));
        let commitment = B256::repeat_byte(7);
        let l1 = MockL1Reader::default();
        l1.insert_commitment(account, 0, commitment);
        let mut evm = BlockExecutorFactory::evm_with_env(
            &config(l1),
            sender_db(sender),
            fee_free_env(TempoHardfork::T14),
        );
        let mut call = |input: Vec<u8>| {
            let tx = TxLegacy {
                nonce: 1,
                gas_limit: 1_000_000,
                to: TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS),
                input: input.into(),
                ..Default::default()
            };
            evm.transact(&transaction(
                sender,
                tx.into_signed(Signature::test_signature()),
            ))
            .unwrap()
            .discard()
        };

        let read = call(IConfigurableAccount::getConfigCommitmentCall { account }.abi_encode());
        assert!(read.status, "{read:?}");
        assert_eq!(read.output[..], commitment[..]);

        for input in [
            IConfigurableAccount::updateConfigCall {
                current: IConfigurableAccount::ConfigurableAccountConfig {
                    salt: B256::ZERO,
                    version: 0,
                    threshold: 1,
                    owners: vec![],
                },
                threshold: 1,
                owners: vec![],
            }
            .abi_encode(),
            IConfigurableAccount::upgradeAccountCall {
                threshold: 1,
                owners: vec![],
            }
            .abi_encode(),
        ] {
            let rejected = call(input);
            assert_eq!(rejected.stop, InstrStop::Revert);
            assert_eq!(
                rejected.output,
                IConfigurableAccount::UnsupportedOnZone {}.abi_encode()
            );
        }
    }
}
