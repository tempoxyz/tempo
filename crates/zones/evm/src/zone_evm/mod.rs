//! Zone runtime EVM and its private execution policies.

pub(crate) mod contract_creation;
mod validation;

pub(crate) use contract_creation::zone_execution_config;
pub use validation::validate_transaction;

use crate::executor::ZoneTransactionKind;
use alloy_consensus::transaction::Recovered;
use alloy_primitives::B256;
use evm2::{
    AnyError, TxResult,
    registry::{AnyTxHandler, HandlerError, HandlerResult, TxHandler, TxRegistry, TxRequest},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{ExecutionContext, TempoEvmTypes, TempoTxEnv, tempo_tx_registry};
use zone_precompiles::{
    L1State, L1StorageReader, TIP403_REGISTRY_ADDRESS, tempo_state::TEMPO_BLOCK_NUMBER_SLOT,
    tx_context,
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

        // Mirrored registry values depend on the anchor, but the accepted cache is keyed by slot
        // only. Keep its entries only while they were loaded at this transaction's anchor.
        // Anchor-changing transactions switch anchors mid-transaction, and a cache hit skips
        // `L1OverlayDB`, which would hide the switch: they always start from an empty cache.
        let changes_anchor = matches!(
            ZoneTransactionKind::classify(request.envelope.evm_tx().is_system_tx(), || {
                request.envelope.evm_tx().calls()
            }),
            ZoneTransactionKind::AdvanceTempo | ZoneTransactionKind::AdvanceTempoHeaders
        );
        if self.l1.select_registry_cache_anchor(initial_anchor) || changes_anchor {
            request
                .host
                .state_mut()
                .overlay_db_mut()
                .cache
                .storage
                .remove(&TIP403_REGISTRY_ADDRESS);
        }
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
    use alloy_primitives::{Address, Signature, U256};
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
    use tempo_evm::{
        ResolvedFeeToken, TempoEvmEnv, TempoEvmTypes, TempoInvalidTransaction, TempoTxEnv,
    };
    use tempo_precompiles::TIP403_REGISTRY_ADDRESS;
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{
            Authorization, TempoSignature, TempoSignedAuthorization, TempoTransaction,
            envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
        },
    };
    use zone_chainspec::ZoneChainSpec;
    use zone_precompiles::{ADVANCE_TEMPO_SELECTOR, test_utils::MockL1Reader};
    use zone_primitives::constants::{ZONE_INBOX_ADDRESS, zone_chain_id};

    pub(crate) fn config() -> ZoneEvmConfig<MockL1Reader> {
        let mut genesis = DEV.genesis().clone();
        genesis.config.chain_id = zone_chain_id(DEV.chain_id(), 1).unwrap();
        ZoneEvmConfig::new(
            std::sync::Arc::new(ZoneChainSpec::from_genesis(genesis).unwrap()),
            MockL1Reader::default(),
            Address::ZERO,
        )
    }

    pub(super) fn test_evm(db: InMemoryDB) -> ZoneEvm<'static> {
        let spec = TempoHardfork::T7;
        let mut env = TempoEvmEnv {
            spec,
            ..Default::default()
        };
        env.version = tempo_chainspec::gas_params::version(evm2::SpecId::OSAKA, spec, false);
        env.block.gas_limit = U256::from(30_000_000);
        BlockExecutorFactory::evm_with_env(&config(), db, env)
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
            let config = config();
            let block = Default::default();
            let ctx = config.context_for_block(&block).unwrap();
            let mut executor = ZoneBlockExecutor::new(evm, ctx, config.chain_spec());
            let tx = Recovered::new_unchecked(
                TempoTxEnvelope::Legacy(
                    TxLegacy {
                        to: ZONE_INBOX_ADDRESS.into(),
                        input: ADVANCE_TEMPO_SELECTOR.to_vec().into(),
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
}
