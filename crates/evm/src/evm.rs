use crate::{ProtocolFeeManager, TempoEvmExt, TempoEvmTypes, TempoFeeManager};
use std::sync::Arc;

/// Tempo's EVM is EVM2 with the Tempo type family.
pub type TempoEvm<'a> = evm2::Evm<'a, TempoEvmTypes>;

/// Total gas Tempo system calls are allowed to use.
pub const SYSTEM_CALL_GAS_LIMIT: u64 = 250_000_000;

/// Configuration copied into each Tempo EVM instance.
#[derive(Clone, Debug)]
pub struct TempoEvmFactory {
    fee_manager: Arc<dyn ProtocolFeeManager>,
}

impl Default for TempoEvmFactory {
    fn default() -> Self {
        Self {
            fee_manager: Arc::new(TempoFeeManager::new()),
        }
    }
}

impl TempoEvmFactory {
    /// Uses a custom protocol fee implementation for subsequently created EVMs.
    pub fn with_fee_manager(mut self, fee_manager: impl ProtocolFeeManager + 'static) -> Self {
        self.fee_manager = Arc::new(fee_manager);
        self
    }

    pub(crate) fn evm_ext(&self, mut ext: TempoEvmExt) -> TempoEvmExt {
        ext.fee_manager = self.fee_manager.clone();
        ext
    }
}

impl reth_evm_ethereum::EvmFactory for TempoEvmFactory {
    type Types = TempoEvmTypes;
    type SpecId = tempo_chainspec::hardfork::TempoHardfork;

    fn spec_id(&self, spec: evm2::SpecId) -> Self::SpecId {
        spec.into()
    }

    fn execution_config(
        &self,
        spec: Self::SpecId,
        version: evm2::Version,
    ) -> evm2::ExecutionConfig<Self::Types> {
        evm2::ExecutionConfig::for_spec_and_version(spec, version)
    }

    fn tx_registry(
        &self,
        spec: Self::SpecId,
    ) -> evm2::registry::TxRegistry<Self::Types, evm2::TxResult<Self::Types>> {
        crate::tempo_tx_registry(spec.into())
    }

    fn configure_evm(&self, evm: &mut TempoEvm<'_>) {
        let spec = evm.config_spec_id();
        let mut ext = core::mem::take(evm.ext_mut());
        ext.fee_manager = self.fee_manager.clone();
        let precompiles = tempo_precompiles::TempoPrecompiles::new(
            spec,
            ext.actions.clone(),
            ext.non_creditable_slots.clone(),
        );
        *evm.ext_mut() = ext;
        evm.set_precompiles(precompiles);
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod runtime_tests {
    use super::{
        tests::{TestEvmExt, configured_evm, create_evm, legacy_tx_env},
        *,
    };
    use crate::{TempoBlockEnv, TempoInvalidTransaction, TempoTxEnv};
    use alloy_consensus::{Signed, TxLegacy, transaction::Recovered};
    use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
    use alloy_sol_types::{SolCall, SolError, SolValue};
    use evm2::{
        bytecode::Bytecode,
        evm::{
            AccountInfo, DynDatabase, InMemoryDB, PendingState, StateChangeSink, StateChangeSource,
            StorageChange, SystemTx,
        },
        interpreter::{InstrStop, op as opcode},
    };
    use indexmap::IndexMap;
    use std::collections::BTreeMap;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::{
        precompiles::{
            IZoneFactory, IZoneVerifier, ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS,
            ZONE_PORTAL_IMPL_ADDRESS, ZONE_VERIFIER_ADDRESS,
        },
        zones::{T13_ZONE_VERIFIER_RUNTIME, ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME},
    };
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, STORAGE_CREDITS_ADDRESS,
        TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageAction, StorageCtx, StorageKey},
        storage_credits::StorageCredits,
        test_util::TIP20Setup,
        tip_fee_manager::{
            IFeeManager, TipFeeManager,
            amm::{Pool, PoolKey, compute_amount_out},
            slots as fee_manager_slots,
        },
        tip20::{
            ITIP20, rewards::__packing_user_reward_info as user_reward_info_slots,
            slots as tip20_slots,
        },
        tip403_registry::slots as tip403_registry_slots,
        zone_factory::{ZONE_CREATION_GAS, ZoneFactory, portal_address},
    };
    use tempo_primitives::{
        AASigned, TempoAddressExt, TempoTransaction, TempoTxEnvelope,
        transaction::{Call, PrimitiveSignature, TempoSignature},
    };

    alloy_sol_types::sol! {
        enum TestZonePortalRole {
            None,
            Sequencer,
            Account,
            CallbackGateway,
            PauseGuardian
        }

        enum TestZonePortalCapability {
            PausePortal,
            AccessPolicy
        }

        struct TestBlockTransition {
            bytes32 prevBlockHash;
            bytes32 nextBlockHash;
        }

        struct TestDepositQueueTransition {
            bytes32 prevProcessedHash;
            bytes32 nextProcessedHash;
            uint64 prevDepositNumber;
            uint64 nextDepositNumber;
        }

        interface TestZonePortal {
            error InvalidProof();

            function enableToken(address token) external;
            function tokenEnablementHash() external view returns (bytes32);
            function hasRole(address account, TestZonePortalRole role) external view returns (bool);
            function isSequencer(address account) external view returns (bool);
            function setAllowedAccount(address account, bool allowed) external;
            function paused() external view returns (bool);
            function pauseExpiry() external view returns (uint64);
            function abdicationEffectiveAt(TestZonePortalCapability capability)
                external
                view
                returns (uint64);
            function pause() external;
            function resume() external;
            function submitBatch(
                uint64 tempoBlockNumber,
                uint64 recentTempoBlockNumber,
                TestBlockTransition calldata blockTransition,
                TestDepositQueueTransition calldata depositQueueTransition,
                bytes32 withdrawalQueueHash,
                bytes calldata verifierConfig,
                bytes calldata proof,
                uint256 nextZoneHeight,
                bytes[] calldata signatures
            ) external;
        }

        interface TestZoneMessenger {
            function relayMessage(
                uint32 zoneId,
                address token,
                bytes32 senderTag,
                address target,
                uint128 amount,
                uint64 gasLimit,
                bytes calldata data
            ) external;
        }

        interface TestWithdrawalReceiver {
            function onWithdrawalReceived(
                uint32 zoneId,
                address portal,
                bytes32 senderTag,
                address token,
                uint128 amount,
                bytes calldata data
            ) external returns (bytes4);
        }
    }

    fn runtime_returning_selector(selector: [u8; 4]) -> Bytecode {
        const SELECTOR_SHIFT_BITS: u8 = 224;
        const ABI_WORD_BYTES: u8 = 32;

        let mut code = vec![opcode::PUSH4];
        code.extend_from_slice(&selector);
        code.extend_from_slice(&[
            opcode::PUSH1,
            SELECTOR_SHIFT_BITS,
            opcode::SHL,
            opcode::PUSH0,
            opcode::MSTORE,
            opcode::PUSH1,
            ABI_WORD_BYTES,
            opcode::PUSH0,
            opcode::RETURN,
        ]);
        Bytecode::new_raw(code.into())
    }

    fn initialize_zone_factory(db: &mut InMemoryDB, owner: Address) {
        db.insert_account_info(
            &ZONE_FACTORY_ADDRESS,
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[0xef]))),
        );
        let factory_config = U256::from(1) | (U256::from_be_slice(owner.as_slice()) << u32::BITS);
        db.insert_account_storage(&ZONE_FACTORY_ADDRESS, &U256::ZERO, &factory_config);
    }

    fn system_tx_env(to: TxKind, input: Bytes) -> TempoTxEnv {
        let tx = TxLegacy {
            chain_id: Some(1),
            to,
            input,
            ..Default::default()
        };
        let tx = Signed::new_unhashed(
            tx,
            tempo_primitives::transaction::envelope::TEMPO_SYSTEM_TX_SIGNATURE,
        );
        Recovered::new_unchecked(TempoTxEnvelope::Legacy(tx), Address::ZERO).into()
    }

    #[test]
    fn can_execute_system_tx() {
        let mut evm = create_evm();
        let result = evm
            .transact_detach(system_tx_env(TxKind::Call(Address::ZERO), Bytes::new()))
            .unwrap();

        assert!(result.result.status);
    }

    #[test]
    fn test_transact_raw() {
        let mut evm = create_evm();

        let tx = legacy_tx_env(
            Address::repeat_byte(0x01),
            0,
            TxKind::Call(Address::repeat_byte(0x02)),
            Bytes::new(),
            21_000,
        );

        let result = evm.transact_detach(tx);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.status);
        assert_eq!(result.result.tx_gas_used(), 21_000);
    }

    #[test]
    fn test_transact_raw_system_tx() {
        let mut evm = create_evm();

        // System transaction
        let tx = system_tx_env(TxKind::Call(Address::repeat_byte(0x01)), Bytes::new());

        let result = evm.transact_detach(tx);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.result.status);
        // System transactions should not consume gas
        assert_eq!(result.result.tx_gas_used(), 0);
    }

    #[test]
    fn test_transact_raw_system_tx_must_be_call() {
        let mut evm = create_evm();

        // System transaction with Create kind
        let tx = system_tx_env(TxKind::Create, Bytes::new());

        let result = evm.transact_detach(tx);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::SystemTransactionMustBeCall)
        ));
    }

    #[test]
    fn test_transact_raw_system_tx_failed() {
        let contract_addr = Address::repeat_byte(0xaa);
        let mut evm = create_evm();
        // Deploy a contract that always reverts: PUSH1 0x00 PUSH1 0x00 REVERT (0x60006000fd)
        let revert_code = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xfd]);
        evm.overlay_db_mut().insert_account_info(
            &contract_addr,
            AccountInfo::default().with_code(Bytecode::new_raw(revert_code)),
        );

        // System transaction that will fail with call to contract that reverts
        let tx = system_tx_env(TxKind::Call(contract_addr), Bytes::new());

        let result = evm.transact_detach(tx);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::SystemTransactionFailed(_))
        ));
    }

    #[test]
    fn test_transact_system_call() {
        let mut evm = create_evm();

        let caller = Address::repeat_byte(0x01);
        let contract = Address::repeat_byte(0x02);
        let data = Bytes::from_static(&[0x01, 0x02, 0x03]);

        let result = evm.system_call(SystemTx::new(contract, data).with_caller(caller));
        assert!(result.is_ok());

        let result = result.unwrap().discard();
        assert!(result.status);
    }

    #[test]
    fn zone_factory_created_portal_executes_deployed_runtime() {
        let owner = Address::repeat_byte(0x11);
        let admin = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        // Returns 42 for every call. The portal proxy should delegate to this deployed runtime.
        let logic_runtime = Bytecode::new_raw(Bytes::from_static(&[
            0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ]));
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &ZONE_PORTAL_IMPL_ADDRESS,
            AccountInfo::default().with_code(logic_runtime),
        );
        initialize_zone_factory(&mut db, owner);
        let mut evm = configured_evm(TempoHardfork::T10, 0, false, db);

        StorageCtx::enter_evm(&mut evm, || TIP20Setup::path_usd(admin).apply()).unwrap();

        let result = evm
            .system_call(
                SystemTx::new(
                    ZONE_FACTORY_ADDRESS,
                    IZoneFactory::createZoneCall {
                        params: IZoneFactory::CreateZoneParams {
                            initialToken: PATH_USD_ADDRESS,
                            accessMode: true,
                            gatewayMode: true,
                            allowedAccounts: vec![admin],
                            zoneGateways: vec![Address::repeat_byte(0x44)],
                            admin,
                            sequencers: vec![sequencer],
                            threshold: 1,
                            rpcUrl: "https://zone.example".to_string(),
                        },
                    }
                    .abi_encode()
                    .into(),
                )
                .with_caller(owner),
            )
            .unwrap()
            .commit();
        assert!(result.status, "createZone failed: {result:?}");
        assert!(result.tx_gas_used() >= ZONE_CREATION_GAS);
        assert!(result.execution_gas_spent() >= ZONE_CREATION_GAS);
        let created = IZoneFactory::createZoneCall::abi_decode_returns(&result.output).unwrap();

        let result = evm
            .system_call(SystemTx::new(created.portal, Bytes::new()).with_caller(Address::ZERO))
            .unwrap()
            .discard();
        assert!(result.status, "portal call failed: {result:?}");
        assert_eq!(U256::from_be_slice(&result.output), U256::from(42));
    }

    #[test]
    fn test_zone_verifier_runtime_is_shadowed_at_t13() {
        let calldata = IZoneVerifier::verifyCall {
            zoneId: 1,
            tempoBlockNumber: 1,
            anchorBlockNumber: 1,
            anchorBlockHash: B256::ZERO,
            expectedWithdrawalBatchIndex: 0,
            nextZoneHeight: U256::ZERO,
            blockTransition: IZoneVerifier::BlockTransition {
                prevBlockHash: B256::ZERO,
                nextBlockHash: B256::ZERO,
            },
            depositQueueTransition: IZoneVerifier::DepositQueueTransition {
                prevProcessedHash: B256::ZERO,
                nextProcessedHash: B256::ZERO,
                prevDepositNumber: 0,
                nextDepositNumber: 0,
            },
            tokenEnablementTransition: IZoneVerifier::TokenEnablementTransition {
                prevProcessedTokenCount: 0,
                nextProcessedTokenCount: 0,
            },
            withdrawalQueueHash: B256::ZERO,
            verifierConfig: Bytes::new(),
            proof: Bytes::new(),
        }
        .abi_encode();

        let execute = |spec| {
            let mut db = InMemoryDB::default();
            db.insert_account_info(
                &ZONE_VERIFIER_ADDRESS,
                AccountInfo::default().with_code(Bytecode::new_legacy(T13_ZONE_VERIFIER_RUNTIME)),
            );
            let mut evm = configured_evm(spec, 0, false, db);
            let result = evm
                .system_call(SystemTx::new(
                    ZONE_VERIFIER_ADDRESS,
                    calldata.clone().into(),
                ))
                .unwrap()
                .discard();
            assert!(result.status, "Zone verifier call failed: {result:?}");
            IZoneVerifier::verifyCall::abi_decode_returns(&result.output).unwrap()
        };

        assert!(execute(TempoHardfork::T10));
        assert!(execute(TempoHardfork::T11));
        assert!(execute(TempoHardfork::T12));
        assert!(!execute(TempoHardfork::T13));
    }

    #[test]
    fn zone_portal_runtime_commits_subsequent_token_enablements() {
        let owner = Address::repeat_byte(0x11);
        let admin = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        let portal_runtime = Bytecode::new_raw(ZONE_PORTAL_RUNTIME);
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &ZONE_PORTAL_IMPL_ADDRESS,
            AccountInfo::default().with_code(portal_runtime),
        );
        initialize_zone_factory(&mut db, owner);
        let mut evm = configured_evm(TempoHardfork::T10, 0, false, db);

        let second_token =
            StorageCtx::enter_evm(&mut evm, || -> Result<_, TempoPrecompileError> {
                TIP20Setup::path_usd(admin).apply()?;
                Ok(TIP20Setup::create("Second Token", "SECOND", admin)
                    .apply()?
                    .address())
            })
            .unwrap();

        let create = evm
            .system_call(
                SystemTx::new(
                    ZONE_FACTORY_ADDRESS,
                    IZoneFactory::createZoneCall {
                        params: IZoneFactory::CreateZoneParams {
                            initialToken: PATH_USD_ADDRESS,
                            accessMode: true,
                            gatewayMode: true,
                            allowedAccounts: vec![],
                            zoneGateways: vec![],
                            admin,
                            sequencers: vec![sequencer],
                            threshold: 1,
                            rpcUrl: "https://zone.example".to_string(),
                        },
                    }
                    .abi_encode()
                    .into(),
                )
                .with_caller(owner),
            )
            .unwrap()
            .commit();
        assert!(create.status, "createZone failed: {create:?}");
        let created = IZoneFactory::createZoneCall::abi_decode_returns(&create.output).unwrap();

        let sequencer_status = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::isSequencerCall { account: sequencer }
                        .abi_encode()
                        .into(),
                )
                .with_caller(Address::ZERO),
            )
            .unwrap()
            .discard();
        assert!(
            sequencer_status.status,
            "isSequencer failed: {sequencer_status:?}"
        );
        assert!(
            TestZonePortal::isSequencerCall::abi_decode_returns(&sequencer_status.output).unwrap()
        );

        let account = Address::repeat_byte(0x55);
        let set_account = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::setAllowedAccountCall {
                        account,
                        allowed: true,
                    }
                    .abi_encode()
                    .into(),
                )
                .with_caller(admin),
            )
            .unwrap()
            .commit();
        assert!(
            set_account.status,
            "setAllowedAccount failed: {set_account:?}"
        );

        let account_role = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::hasRoleCall {
                        account,
                        role: TestZonePortalRole::Account,
                    }
                    .abi_encode()
                    .into(),
                )
                .with_caller(Address::ZERO),
            )
            .unwrap()
            .discard();
        assert!(account_role.status, "hasRole failed: {account_role:?}");
        assert!(TestZonePortal::hasRoleCall::abi_decode_returns(&account_role.output).unwrap());

        for call in [
            TestZonePortal::pausedCall {}.abi_encode(),
            TestZonePortal::pauseExpiryCall {}.abi_encode(),
            TestZonePortal::abdicationEffectiveAtCall {
                capability: TestZonePortalCapability::PausePortal,
            }
            .abi_encode(),
        ] {
            let result = evm
                .system_call(SystemTx::new(created.portal, call.into()).with_caller(Address::ZERO))
                .unwrap()
                .discard();
            assert!(result.status, "pause ABI call failed: {result:?}");
            assert_eq!(U256::from_be_slice(&result.output), U256::ZERO);
        }

        let pause = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::pauseCall {}.abi_encode().into(),
                )
                .with_caller(sequencer),
            )
            .unwrap()
            .commit();
        assert!(pause.status, "pause failed: {pause:?}");

        let submit = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::submitBatchCall {
                        tempoBlockNumber: 0,
                        recentTempoBlockNumber: 0,
                        blockTransition: TestBlockTransition {
                            prevBlockHash: B256::repeat_byte(1),
                            nextBlockHash: B256::ZERO,
                        },
                        depositQueueTransition: TestDepositQueueTransition {
                            prevProcessedHash: B256::ZERO,
                            nextProcessedHash: B256::ZERO,
                            prevDepositNumber: 0,
                            nextDepositNumber: 0,
                        },
                        withdrawalQueueHash: B256::ZERO,
                        verifierConfig: Bytes::new(),
                        proof: Bytes::new(),
                        nextZoneHeight: U256::ZERO,
                        signatures: Vec::new(),
                    }
                    .abi_encode()
                    .into(),
                )
                .with_caller(sequencer),
            )
            .unwrap()
            .discard();
        assert_eq!(submit.stop, InstrStop::Revert);
        assert_eq!(
            submit.output.as_ref(),
            TestZonePortal::InvalidProof::SELECTOR
        );

        let resume = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::resumeCall {}.abi_encode().into(),
                )
                .with_caller(admin),
            )
            .unwrap()
            .commit();
        assert!(resume.status, "resume failed: {resume:?}");

        let paused = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::pausedCall {}.abi_encode().into(),
                )
                .with_caller(Address::ZERO),
            )
            .unwrap()
            .discard();
        assert!(paused.status, "paused failed after resume: {paused:?}");
        assert_eq!(U256::from_be_slice(&paused.output), U256::ZERO);

        let enable = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::enableTokenCall {
                        token: second_token,
                    }
                    .abi_encode()
                    .into(),
                )
                .with_caller(admin),
            )
            .unwrap()
            .commit();
        assert!(enable.status, "enableToken failed: {enable:?}");

        let commitment = evm
            .system_call(
                SystemTx::new(
                    created.portal,
                    TestZonePortal::tokenEnablementHashCall {}
                        .abi_encode()
                        .into(),
                )
                .with_caller(Address::ZERO),
            )
            .unwrap()
            .discard();
        assert!(
            commitment.status,
            "tokenEnablementHash failed: {commitment:?}"
        );
        let actual =
            TestZonePortal::tokenEnablementHashCall::abi_decode_returns(&commitment.output)
                .unwrap();
        let initial = keccak256(
            (B256::ZERO, PATH_USD_ADDRESS, "pathUSD", "pathUSD", "USD").abi_encode_params(),
        );
        let expected =
            keccak256((initial, second_token, "Second Token", "SECOND", "USD").abi_encode_params());
        assert_eq!(actual, expected);
    }

    #[test]
    fn zone_messenger_runtime_authorizes_registered_callback_gateway() {
        let owner = Address::repeat_byte(0x11);
        let admin = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        let gateway = Address::repeat_byte(0x44);
        let mut db = InMemoryDB::default();
        for (address, runtime) in [
            (ZONE_PORTAL_IMPL_ADDRESS, ZONE_PORTAL_RUNTIME),
            (ZONE_MESSENGER_ADDRESS, ZONE_MESSENGER_RUNTIME),
        ] {
            db.insert_account_info(
                &address,
                AccountInfo::default().with_code(Bytecode::new_raw(runtime)),
            );
        }
        let callback_runtime =
            runtime_returning_selector(TestWithdrawalReceiver::onWithdrawalReceivedCall::SELECTOR);
        db.insert_account_info(&gateway, AccountInfo::default().with_code(callback_runtime));
        initialize_zone_factory(&mut db, owner);
        let mut evm = configured_evm(TempoHardfork::T10, 0, false, db);

        StorageCtx::enter_evm(&mut evm, || {
            TIP20Setup::path_usd(admin)
                .with_issuer(admin)
                .with_mint(ZONE_MESSENGER_ADDRESS, U256::from(100))
                .apply()
        })
        .unwrap();

        let create = evm
            .system_call(
                SystemTx::new(
                    ZONE_FACTORY_ADDRESS,
                    IZoneFactory::createZoneCall {
                        params: IZoneFactory::CreateZoneParams {
                            initialToken: PATH_USD_ADDRESS,
                            accessMode: false,
                            gatewayMode: true,
                            allowedAccounts: vec![],
                            zoneGateways: vec![gateway],
                            admin,
                            sequencers: vec![sequencer],
                            threshold: 1,
                            rpcUrl: "https://zone.example".to_string(),
                        },
                    }
                    .abi_encode()
                    .into(),
                )
                .with_caller(owner),
            )
            .unwrap()
            .commit();
        assert!(create.status, "createZone failed: {create:?}");
        let created = IZoneFactory::createZoneCall::abi_decode_returns(&create.output).unwrap();

        let relay = evm
            .system_call(
                SystemTx::new(
                    ZONE_MESSENGER_ADDRESS,
                    TestZoneMessenger::relayMessageCall {
                        zoneId: created.zoneId,
                        token: PATH_USD_ADDRESS,
                        senderTag: B256::ZERO,
                        target: gateway,
                        amount: 1,
                        gasLimit: 100_000,
                        data: Bytes::new(),
                    }
                    .abi_encode()
                    .into(),
                )
                .with_caller(created.portal),
            )
            .unwrap()
            .discard();
        assert!(
            relay.status,
            "registered gateway callback failed: {relay:?}"
        );
    }

    #[test]
    fn zone_factory_creation_oog_below_minimum_reverts_state() {
        let owner = Address::repeat_byte(0x11);
        let admin = Address::repeat_byte(0x22);
        let sequencer = Address::repeat_byte(0x33);
        let mut db = InMemoryDB::default();
        initialize_zone_factory(&mut db, owner);
        let mut evm = configured_evm(TempoHardfork::T10, 0, false, db);

        StorageCtx::enter_evm(&mut evm, || TIP20Setup::path_usd(admin).apply()).unwrap();

        let input = IZoneFactory::createZoneCall {
            params: IZoneFactory::CreateZoneParams {
                initialToken: PATH_USD_ADDRESS,
                accessMode: true,
                gatewayMode: true,
                allowedAccounts: vec![admin],
                zoneGateways: vec![Address::repeat_byte(0x44)],
                admin,
                sequencers: vec![sequencer],
                threshold: 1,
                rpcUrl: "https://zone.example".to_string(),
            },
        }
        .abi_encode();

        let result = evm
            .transact_commit(legacy_tx_env(
                owner,
                0,
                TxKind::Call(ZONE_FACTORY_ADDRESS),
                input.into(),
                ZONE_CREATION_GAS - 1,
            ))
            .unwrap();
        assert!(result.stop.is_out_of_gas(), "expected OOG, got: {result:?}");
        assert_eq!(result.tx_gas_used(), ZONE_CREATION_GAS - 1);

        StorageCtx::enter_evm(&mut evm, || {
            let factory = ZoneFactory::new();
            assert_eq!(factory.next_zone_id()?, 1);
            assert!(!factory.is_zone_portal(portal_address(1))?);
            Ok::<_, TempoPrecompileError>(())
        })
        .unwrap();
    }

    #[derive(Default)]
    struct StorageState {
        reconstructed: BTreeMap<(Address, U256), U256>,
        first_loads: BTreeMap<(Address, U256), U256>,
    }

    impl StorageState {
        fn apply_sload_value(
            &mut self,
            key: (Address, U256),
            value: U256,
            action: &str,
            hardfork: TempoHardfork,
        ) -> U256 {
            match self.reconstructed.get(&key) {
                Some(current) => {
                    let (address, slot) = key;
                    assert_eq!(
                        *current, value,
                        "{action} SLOAD value must match reconstructed current value for {address:?}:{slot:?} on {hardfork:?}",
                    );
                    *current
                }
                None => {
                    self.first_loads.insert(key, value);
                    self.reconstructed.insert(key, value);
                    value
                }
            }
        }
    }

    fn assert_storage_actions_reconstruct_evm_state(
        actions: &[StorageAction],
        state: &PendingState,
        hardfork: TempoHardfork,
    ) {
        let mut storage_state = StorageState::default();

        for action in actions {
            match *action {
                StorageAction::Sload(address, slot, value) => {
                    let key = (address, slot);
                    storage_state.apply_sload_value(key, value, "SLOAD", hardfork);
                }
                StorageAction::Sstore(address, slot, sload_value, value) => {
                    let key = (address, slot);
                    storage_state.apply_sload_value(key, sload_value, "SSTORE", hardfork);
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::Sinc(address, slot, sload_value, delta) => {
                    let key = (address, slot);
                    let current =
                        storage_state.apply_sload_value(key, sload_value, "SINC", hardfork);
                    let value = current.checked_add(delta).unwrap_or_else(|| {
                        panic!("SINC overflow for {address:?}:{slot:?} on {hardfork:?}")
                    });
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::Sdec(address, slot, sload_value, delta) => {
                    let key = (address, slot);
                    let current =
                        storage_state.apply_sload_value(key, sload_value, "SDEC", hardfork);
                    let value = current.checked_sub(delta).unwrap_or_else(|| {
                        panic!("SDEC underflow for {address:?}:{slot:?} on {hardfork:?}")
                    });
                    storage_state.reconstructed.insert(key, value);
                }
                StorageAction::FeeAmmSwap(slot, sload_value, amount_in) => {
                    let key = (action.address(), slot);
                    let current =
                        storage_state.apply_sload_value(key, sload_value, "FeeAmmSwap", hardfork);
                    let mut pool = Pool::decode_from_slot(current);
                    pool.apply_swap(
                        amount_in,
                        compute_amount_out(amount_in).expect("compute_amount_out should not fail"),
                    )
                    .unwrap_or_else(|err| {
                        panic!(
                            "FeeAmmSwap invalid for {:?}:{slot:?} on {hardfork:?}: {err}",
                            action.address()
                        )
                    });
                    storage_state
                        .reconstructed
                        .insert(key, pool.encode_to_slot().unwrap());
                }
                StorageAction::FeeAmmLiquidityCheck(
                    slot,
                    sload_value,
                    amount_out,
                    has_enough_liquidity,
                ) => {
                    let key = (action.address(), slot);
                    let current = storage_state.apply_sload_value(
                        key,
                        sload_value,
                        "FeeAmmLiquidityCheck",
                        hardfork,
                    );
                    let pool = Pool::decode_from_slot(current);
                    assert_eq!(
                        pool.has_enough_reserve_validator_token(amount_out),
                        has_enough_liquidity,
                        "FeeAmmLiquidityCheck mismatch for {:?}:{slot:?} on {hardfork:?}",
                        action.address(),
                    );
                }
            }
        }

        #[derive(Default)]
        struct StorageChanges(Vec<StorageChange>);

        impl StateChangeSink for StorageChanges {
            type Error = core::convert::Infallible;

            fn storage(&mut self, change: StorageChange) -> Result<(), Self::Error> {
                self.0.push(change);
                Ok(())
            }

            fn storage_read(
                &mut self,
                address: Address,
                key: U256,
                value: U256,
            ) -> Result<(), Self::Error> {
                self.0.push(StorageChange {
                    address,
                    key,
                    original: value,
                    current: value,
                });
                Ok(())
            }
        }

        let mut state_changes = StorageChanges::default();
        state.visit(&mut state_changes).unwrap();
        for storage_slot in state_changes.0 {
            let address = storage_slot.address;
            let slot = storage_slot.key;
            let key = (address, slot);
            let original_value = storage_state.first_loads.get(&key).unwrap_or_else(|| {
                        panic!(
                            "EVM output storage cell {address:?}:{slot:?} was not loaded in StorageActions on {hardfork:?}",
                        )
                    });
            assert_eq!(
                *original_value, storage_slot.original,
                "reconstructed original value mismatch for {address:?}:{slot:?} on {hardfork:?}",
            );

            let reconstructed_value = storage_state.reconstructed.get(&key).unwrap_or_else(|| {
                        panic!(
                            "EVM output storage cell {address:?}:{slot:?} was not reconstructed from StorageActions on {hardfork:?}",
                        )
                    });
            assert_eq!(
                *reconstructed_value, storage_slot.current,
                "reconstructed present value mismatch for {address:?}:{slot:?} on {hardfork:?}",
            );
        }
    }

    struct StorageActionSnapshotLabels {
        addresses: BTreeMap<Address, &'static str>,
        slots: BTreeMap<(Address, U256), &'static str>,
        tip20_slots: BTreeMap<U256, &'static str>,
    }

    fn snapshot_storage_actions(
        actions: &[StorageAction],
        labels: &StorageActionSnapshotLabels,
    ) -> Vec<String> {
        actions
            .iter()
            .map(|action| match *action {
                StorageAction::Sload(address, slot, value) => {
                    format!(
                        "Sload({}, {}, {value})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sstore(address, slot, sload_value, value) => {
                    format!(
                        "Sstore({}, {}, {sload_value}, {value})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sinc(address, slot, sload_value, delta) => {
                    format!(
                        "Sinc({}, {}, {sload_value}, {delta})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::Sdec(address, slot, sload_value, delta) => {
                    format!(
                        "Sdec({}, {}, {sload_value}, {delta})",
                        labels.address(address),
                        labels.slot(address, slot)
                    )
                }
                StorageAction::FeeAmmSwap(slot, sload_value, amount_in) => {
                    format!(
                        "FeeAmmSwap({}, {}, {sload_value}, {amount_in})",
                        labels.address(action.address()),
                        labels.slot(action.address(), slot),
                    )
                }
                StorageAction::FeeAmmLiquidityCheck(
                    slot,
                    slot_value,
                    amount_out,
                    has_enough_liquidity,
                ) => {
                    format!(
                        "FeeAmmLiquidityCheck({}, {}, {slot_value}, {amount_out}, {has_enough_liquidity})",
                        labels.address(action.address()),
                        labels.slot(action.address(), slot),
                    )
                }
            })
            .collect()
    }

    impl StorageActionSnapshotLabels {
        fn address(&self, address: Address) -> String {
            self.addresses
                .get(&address)
                .copied()
                .map(str::to_string)
                .unwrap_or_else(|| format!("{address:?}"))
        }

        fn slot(&self, address: Address, slot: U256) -> String {
            if address.is_tip20() {
                self.tip20_slots.get(&slot)
            } else {
                self.slots.get(&(address, slot))
            }
            .copied()
            .map(str::to_string)
            .unwrap_or_else(|| slot.to_string())
        }
    }

    #[test]
    fn test_tip20_full_evm_storage_actions() {
        for hardfork in TempoHardfork::VARIANTS {
            // skip pre-T5 hardforks to avoid clutter
            if !hardfork.is_t5() {
                continue;
            }

            let sender = Address::repeat_byte(0x01);
            let recipient = Address::repeat_byte(0x02);
            let beneficiary = Address::repeat_byte(0x03);
            let starting_balance = U256::from(1_000_000);
            let transfer_amount = U256::from(100);
            let gas_limit = 1_000_000;
            let gas_price = 1_000_000_000u64;
            let amm_liquidity_reserve = 500_000u128;
            let amm_liquidity = U256::from(amm_liquidity_reserve);

            let mut evm = configured_evm(*hardfork, 0, false, InMemoryDB::default());
            evm.set_block(TempoBlockEnv {
                beneficiary,
                basefee: U256::from(gas_price),
                gas_limit: U256::from(30_000_000),
                ..Default::default()
            });

            let (fee_token, two_hop_fee_token) =
                StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
                    TIP20Setup::path_usd(sender)
                        .with_issuer(sender)
                        .with_mint(sender, starting_balance)
                        .apply()?;
                    let fee_token = TIP20Setup::create("FeeToken", "FEE", sender)
                        .with_salt(B256::ZERO)
                        .with_issuer(sender)
                        .with_mint(sender, starting_balance)
                        .with_mint(recipient, starting_balance)
                        .apply()?;
                    let two_hop_fee_token = TIP20Setup::create("TwoHopFeeToken", "2HOP", sender)
                        .with_salt(B256::repeat_byte(0x01))
                        .quote_token(fee_token.address())
                        .with_issuer(sender)
                        .with_mint(sender, starting_balance)
                        .apply()?;

                    let mut fee_manager = TipFeeManager::new();
                    fee_manager.set_user_token(
                        sender,
                        IFeeManager::setUserTokenCall {
                            token: fee_token.address(),
                        },
                    )?;
                    fee_manager.mint(
                        sender,
                        fee_token.address(),
                        PATH_USD_ADDRESS,
                        amm_liquidity,
                        sender,
                    )?;
                    let two_hop_first_pool_id =
                        PoolKey::new(two_hop_fee_token.address(), fee_token.address()).get_id();
                    let two_hop_first_pool_slot =
                        U256::from_be_bytes::<32>(two_hop_first_pool_id.into())
                            .mapping_slot(fee_manager_slots::POOLS);
                    StorageCtx.sstore(
                        TIP_FEE_MANAGER_ADDRESS,
                        two_hop_first_pool_slot,
                        Pool {
                            reserve_user_token: 0,
                            reserve_validator_token: amm_liquidity_reserve,
                        }
                        .encode_to_slot()?,
                    )?;

                    Ok::<(Address, Address), tempo_precompiles::error::TempoPrecompileError>((
                        fee_token.address(),
                        two_hop_fee_token.address(),
                    ))
                })
                .expect("TIP20 setup should succeed");
            evm.state_mut().commit_transaction();
            evm.state_mut().clear_transaction_state();
            evm.ext_mut().actions.enable();
            reth_evm_ethereum::EvmFactory::configure_evm(&TempoEvmFactory::default(), &mut evm);
            let actions = evm.ext().actions.clone();
            assert_eq!(actions.take(), Some(vec![]));

            let sender_balance_slot = sender.mapping_slot(tip20_slots::BALANCES);
            let fee_manager_balance_slot =
                TIP_FEE_MANAGER_ADDRESS.mapping_slot(tip20_slots::BALANCES);
            let recipient_balance_slot = recipient.mapping_slot(tip20_slots::BALANCES);
            let sender_reward_info_slot = sender.mapping_slot(tip20_slots::USER_REWARD_INFO);
            let recipient_reward_info_slot = recipient.mapping_slot(tip20_slots::USER_REWARD_INFO);
            let validator_token_slot =
                beneficiary.mapping_slot(fee_manager_slots::VALIDATOR_TOKENS);
            let user_token_slot = sender.mapping_slot(fee_manager_slots::USER_TOKENS);
            let collected_fees_slot = PATH_USD_ADDRESS
                .mapping_slot(beneficiary.mapping_slot(fee_manager_slots::COLLECTED_FEES));
            let pool_id = PoolKey::new(fee_token, PATH_USD_ADDRESS).get_id();
            let pool_slot =
                U256::from_be_bytes::<32>(pool_id.into()).mapping_slot(fee_manager_slots::POOLS);
            let pending_pool_reservation_slot = U256::from_be_bytes::<32>(pool_id.into())
                .mapping_slot(fee_manager_slots::PENDING_FEE_SWAP_RESERVATION);
            let two_hop_direct_pool_id = PoolKey::new(two_hop_fee_token, PATH_USD_ADDRESS).get_id();
            let two_hop_direct_pool_slot = U256::from_be_bytes::<32>(two_hop_direct_pool_id.into())
                .mapping_slot(fee_manager_slots::POOLS);
            let two_hop_first_pool_id = PoolKey::new(two_hop_fee_token, fee_token).get_id();
            let two_hop_first_pool_slot = U256::from_be_bytes::<32>(two_hop_first_pool_id.into())
                .mapping_slot(fee_manager_slots::POOLS);
            let two_hop_first_pending_pool_reservation_slot =
                U256::from_be_bytes::<32>(two_hop_first_pool_id.into())
                    .mapping_slot(fee_manager_slots::PENDING_FEE_SWAP_RESERVATION);
            let receive_policy_config_slot =
                recipient.mapping_slot(tip403_registry_slots::RECEIVE_POLICIES);
            let nonce_key = U256::from(42);
            let sender_nonce_key_slot = nonce_key
                .mapping_slot(sender.mapping_slot(tempo_precompiles::nonce::slots::NONCES));

            #[rustfmt::skip]
            let labels = StorageActionSnapshotLabels {
                addresses: BTreeMap::from([
                    (PATH_USD_ADDRESS, "PATH_USD"),
                    (fee_token, "FEE_TOKEN"),
                    (two_hop_fee_token, "TWO_HOP_FEE_TOKEN"),
                    (TIP_FEE_MANAGER_ADDRESS, "TIP_FEE_MANAGER"),
                    (TIP403_REGISTRY_ADDRESS, "TIP403_REGISTRY"),
                    (STORAGE_CREDITS_ADDRESS, "STORAGE_CREDITS"),
                    (NONCE_PRECOMPILE_ADDRESS, "NONCE_MANAGER"),
                ]),
                slots: BTreeMap::from([
                    ((TIP_FEE_MANAGER_ADDRESS, validator_token_slot), "validatorTokens[beneficiary]"),
                    ((TIP_FEE_MANAGER_ADDRESS, user_token_slot), "userTokens[sender]"),
                    ((TIP_FEE_MANAGER_ADDRESS, collected_fees_slot), "collectedFees[beneficiary][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, pool_slot), "pools[FEE_TOKEN][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, pending_pool_reservation_slot), "pendingFeeSwapReservation[FEE_TOKEN][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, two_hop_direct_pool_slot), "pools[TWO_HOP_FEE_TOKEN][PATH_USD]"),
                    ((TIP_FEE_MANAGER_ADDRESS, two_hop_first_pool_slot), "pools[TWO_HOP_FEE_TOKEN][FEE_TOKEN]"),
                    ((TIP_FEE_MANAGER_ADDRESS, two_hop_first_pending_pool_reservation_slot), "pendingFeeSwapReservation[TWO_HOP_FEE_TOKEN][FEE_TOKEN]"),
                    ((TIP403_REGISTRY_ADDRESS, receive_policy_config_slot), "receivePolicies[recipient]"),
                    ((STORAGE_CREDITS_ADDRESS, StorageCredits::slot(PATH_USD_ADDRESS)), "storageCredits[PATH_USD]"),
                    ((STORAGE_CREDITS_ADDRESS, StorageCredits::slot(fee_token)), "storageCredits[FEE_TOKEN]"),
                    ((STORAGE_CREDITS_ADDRESS, StorageCredits::slot(two_hop_fee_token)), "storageCredits[TWO_HOP_FEE_TOKEN]"),
                    ((NONCE_PRECOMPILE_ADDRESS, sender_nonce_key_slot), "nonces[sender][42]"),
                ]),
                tip20_slots: BTreeMap::from([
                    (tip20_slots::CURRENCY, "currency"),
                    (tip20_slots::QUOTE_TOKEN, "quoteToken"),
                    (tip20_slots::TRANSFER_POLICY_ID, "transferPolicyId"),
                    (tip20_slots::PAUSED, "paused"),
                    (tip20_slots::GLOBAL_REWARD_PER_TOKEN, "globalRewardPerToken"),
                    (sender_balance_slot, "balances[sender]"),
                    (fee_manager_balance_slot, "balances[FeeManager]"),
                    (recipient_balance_slot, "balances[recipient]"),
                    (sender_reward_info_slot + user_reward_info_slots::REWARD_RECIPIENT, "userRewardInfo[sender].rewardRecipient"),
                    (sender_reward_info_slot + user_reward_info_slots::REWARD_PER_TOKEN, "userRewardInfo[sender].rewardPerToken"),
                    (sender_reward_info_slot + user_reward_info_slots::REWARD_BALANCE, "userRewardInfo[sender].rewardBalance"),
                    (recipient_reward_info_slot + user_reward_info_slots::REWARD_RECIPIENT, "userRewardInfo[recipient].rewardRecipient"),
                    (recipient_reward_info_slot + user_reward_info_slots::REWARD_PER_TOKEN, "userRewardInfo[recipient].rewardPerToken"),
                    (recipient_reward_info_slot + user_reward_info_slots::REWARD_BALANCE, "userRewardInfo[recipient].rewardBalance"),
                ]),
            };

            let run_transfer = |evm: &mut TempoEvm<'_>,
                                caller: Address,
                                to: Address,
                                amount: U256,
                                nonce: u64,
                                nonce_key: U256,
                                fee_token: Address|
             -> eyre::Result<Vec<String>> {
                let calldata: Bytes = ITIP20::transferCall { to, amount }.abi_encode().into();
                let tx: TempoTxEnv = Recovered::new_unchecked(
                    TempoTxEnvelope::AA(AASigned::new_unhashed(
                        TempoTransaction {
                            chain_id: 1,
                            fee_token: Some(fee_token),
                            max_priority_fee_per_gas: u128::from(gas_price),
                            max_fee_per_gas: u128::from(gas_price),
                            gas_limit,
                            calls: vec![Call {
                                to: TxKind::Call(PATH_USD_ADDRESS),
                                value: U256::ZERO,
                                input: calldata,
                            }],
                            nonce_key,
                            nonce,
                            ..Default::default()
                        },
                        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                            alloy_primitives::Signature::test_signature(),
                        )),
                    )),
                    caller,
                )
                .into();
                let result = evm
                    .transact(&Recovered::new_unchecked(tx, caller))?
                    .detach();
                assert!(result.result.status, "hardfork: {hardfork:?}");
                let actions = actions
                    .take()
                    .expect("storage action recording should be enabled");
                assert_storage_actions_reconstruct_evm_state(
                    &actions,
                    &result.pending_state,
                    *hardfork,
                );
                evm.commit_source(&result.pending_state);
                Ok(snapshot_storage_actions(&actions, &labels))
            };

            let snapshot = IndexMap::from([
                // TIP-20 transfer with sequential protocol nonce and a fee token that requires going through feeAMM to pay fees.
                (
                    "direct_first_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        0,
                        U256::ZERO,
                        fee_token,
                    )
                    .unwrap(),
                ),
                // Same as first transfer. Now we expect a lot of storage actions to change from SLOAD+SSTORE into SINC/SDEC, because recipient
                // and fee balances are no longer zero.
                (
                    "direct_second_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        1,
                        U256::ZERO,
                        fee_token,
                    )
                    .unwrap(),
                ),
                // Same as second transfer, but different fee token that requires a two-hop path.
                (
                    "twohop_first_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        2,
                        U256::ZERO,
                        two_hop_fee_token,
                    )
                    .unwrap(),
                ),
                // Same as third transfer.
                (
                    "twohop_second_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        3,
                        U256::ZERO,
                        two_hop_fee_token,
                    )
                    .unwrap(),
                ),
                // TIP-20 transfer with a 2D nonce.
                (
                    "2d_nonce_first_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        0,
                        nonce_key,
                        fee_token,
                    )
                    .unwrap(),
                ),
                (
                    "2d_nonce_second_transfer",
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        transfer_amount,
                        1,
                        nonce_key,
                        fee_token,
                    )
                    .unwrap(),
                ),
                // Clear sender balance, minting a storage credit for PATH_USD.
                ("clear_balance_transfer", {
                    let sender_balance = evm
                        .overlay_db_mut()
                        .get_storage(&PATH_USD_ADDRESS, &sender_balance_slot)
                        .expect("sender balance slot should be available");
                    run_transfer(
                        &mut evm,
                        sender,
                        recipient,
                        sender_balance,
                        4,
                        U256::ZERO,
                        fee_token,
                    )
                    .unwrap()
                }),
                // Recreate sender balance, consuming the PATH_USD storage credit through an SSTORE.
                (
                    "recreate_balance_transfer",
                    run_transfer(
                        &mut evm,
                        recipient,
                        sender,
                        transfer_amount,
                        0,
                        U256::ZERO,
                        fee_token,
                    )
                    .unwrap(),
                ),
            ]);
            insta::with_settings!({
                snapshot_path => "snapshots",
                prepend_module_to_snapshot => false,
            }, {
                insta::assert_yaml_snapshot!(
                    format!(
                        "tempo_evm__evm__tests__tip20_full_evm_storage_actions_{}",
                        hardfork.name()
                    ),
                    snapshot
                );
            });
        }
    }

    // ==================== TIP-1000 EVM Configuration Tests ====================

    /// Test that TempoEvm applies custom gas params through the production EVM factory.
    /// This verifies the [TIP-1000] gas parameter override mechanism.
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
    #[test]
    fn test_tempo_evm_applies_gas_params() {
        // Create EVM with T1 hardfork to get TIP-1000 gas params
        let evm = configured_evm(TempoHardfork::T1, 0, false, InMemoryDB::default());

        // Verify gas params were applied (check a known T1 override)
        // T1 has tx_eip7702_per_empty_account_cost = 12,500
        let gas_params = &evm.version().gas_params;
        assert_eq!(
            gas_params.get(evm2::version::GasId::TxEip7702PerEmptyAccountCost),
            12_500,
            "T1 should have EIP-7702 per empty account cost of 12,500"
        );
    }

    /// The factory must preserve the resolved environment's nondefault gas cap.
    #[test]
    fn test_tempo_evm_respects_gas_cap() {
        use reth_evm::BlockExecutorFactory;

        let spec = TempoHardfork::T1A;
        let mut version = *crate::tempo_execution_config(spec, 1).version();
        let cap = spec.tx_gas_limit_cap().unwrap();
        assert_ne!(version.tx_gas_limit_cap, cap);
        version.tx_gas_limit_cap = cap;
        let evm = crate::TempoEvmConfig::moderato().evm_with_env(
            InMemoryDB::default(),
            crate::TempoEvmEnv {
                spec,
                version,
                block: TempoBlockEnv::default(),
            },
        );
        assert_eq!(evm.version().tx_gas_limit_cap, cap);
    }

    /// Test that gas params differ between T0 and T1 hardforks.
    #[test]
    fn test_tempo_evm_gas_params_differ_t0_vs_t1() {
        // Create T0 and T1 EVMs
        let t0 = configured_evm(TempoHardfork::T0, 0, false, InMemoryDB::default());
        let t1 = configured_evm(TempoHardfork::T1, 0, false, InMemoryDB::default());

        // T0 should have default EIP-7702 cost (25,000)
        // T1 should have reduced cost (12,500)
        let t0_eip7702_cost = t0
            .version()
            .gas_params
            .get(evm2::version::GasId::TxEip7702PerEmptyAccountCost);
        let t1_eip7702_cost = t1
            .version()
            .gas_params
            .get(evm2::version::GasId::TxEip7702PerEmptyAccountCost);

        assert_eq!(t0_eip7702_cost, 25_000, "T0 should have default 25,000");
        assert_eq!(t1_eip7702_cost, 12_500, "T1 should have reduced 12,500");
        assert_ne!(
            t0_eip7702_cost, t1_eip7702_cost,
            "Gas params should differ between T0 and T1"
        );
    }

    /// Test that T1 has significantly higher state creation costs.
    #[test]
    fn test_tempo_evm_t1_state_creation_costs() {
        use evm2::version::GasId;

        let evm = configured_evm(TempoHardfork::T1, 0, false, InMemoryDB::default());
        let gas_params = &evm.version().gas_params;

        // Verify TIP-1000 state creation cost increases
        assert_eq!(
            gas_params.get(GasId::SstoreSetWithoutLoadCost),
            250_000,
            "T1 SSTORE set cost should be 250,000"
        );
        assert_eq!(
            gas_params.get(GasId::TxCreateCost),
            500_000,
            "T1 TX create cost should be 500,000"
        );
        assert_eq!(
            gas_params.get(GasId::Create),
            500_000,
            "T1 CREATE opcode cost should be 500,000"
        );
        assert_eq!(
            gas_params.get(GasId::NewAccountCost),
            250_000,
            "T1 new account cost should be 250,000"
        );
        assert_eq!(
            gas_params.get(GasId::CodeDepositCost),
            1_000,
            "T1 code deposit cost should be 1,000 per byte"
        );
    }
}
