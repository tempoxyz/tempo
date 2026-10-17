//! Contract creation runtime enforcement.

use alloy_primitives::Address;
use evm2::{
    EvmConfig, ExecutionConfig, OpcodeConfig, SpecId, Version,
    interpreter::{
        InstrStop, InterpreterState, Pc, Result, StackMut,
        instructions::create as CreateInstruction, op, private::Instruction,
    },
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoEvmTypes, tempo_opcode_config};
use zone_primitives::constants::CONTRACT_DEPLOYER_ALLOWLIST;

/// Zone opcode configuration over Tempo and an inherited Ethereum specification.
pub(crate) struct ZoneConfig<const BASE_SPEC_ID: u32>(());

impl<const BASE_SPEC_ID: u32> EvmConfig<TempoEvmTypes> for ZoneConfig<BASE_SPEC_ID> {
    const BASE_SPEC_ID: SpecId =
        SpecId::try_from_u32(BASE_SPEC_ID).expect("invalid Zone base spec id");
    const OPCODE_CONFIG: &'static OpcodeConfig<TempoEvmTypes> =
        &zone_opcode_config::<BASE_SPEC_ID>();
}

/// Selects the Zone opcode table for the active Tempo specification.
pub(crate) fn zone_execution_config(
    spec: TempoHardfork,
    version: Version,
) -> ExecutionConfig<TempoEvmTypes> {
    let base_spec = SpecId::from(spec);
    evm2::spec_to_generic!(base_spec, |BASE_SPEC_ID| ExecutionConfig::for_config::<
        ZoneConfig<BASE_SPEC_ID>,
    >()
    .with_version(version))
}

const fn zone_opcode_config<const BASE_SPEC_ID: u32>() -> OpcodeConfig<TempoEvmTypes> {
    let mut config = tempo_opcode_config::<BASE_SPEC_ID>();
    config.set_instruction::<ZoneCreate<false>>(op::CREATE, 0);
    config.set_instruction::<ZoneCreate<true>>(op::CREATE2, 0);
    config
}

struct ZoneCreate<const IS_CREATE2: bool>;

impl<const IS_CREATE2: bool> Instruction<TempoEvmTypes> for ZoneCreate<IS_CREATE2> {
    const DYNAMIC_GAS: bool = true;

    fn execute(
        pc: &mut Pc,
        stack: StackMut<'_>,
        state: &mut InterpreterState<'_, '_, TempoEvmTypes>,
    ) -> Result {
        create::<IS_CREATE2>(pc, stack, state, CONTRACT_DEPLOYER_ALLOWLIST)
    }
}

fn create<const IS_CREATE2: bool>(
    pc: &mut Pc,
    stack: StackMut<'_>,
    state: &mut InterpreterState<'_, '_, TempoEvmTypes>,
    allowlist: &[Address],
) -> Result {
    if !allowlist.contains(&state.message().destination) {
        return Err(InstrStop::NotActivated);
    }
    CreateInstruction::<TempoEvmTypes, IS_CREATE2>::execute(pc, stack, state)
}

#[cfg(test)]
mod tests {
    use super::{
        super::tests::{test_evm, transaction},
        *,
    };
    use crate::{L1OverlayDB, ZoneEvm, validate_transaction, zone_evm::zone_tx_registry};
    use alloy_consensus::{SignableTransaction, TxLegacy, transaction::Recovered};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256, bytes};
    use evm2::{
        bytecode::Bytecode,
        evm::{AccountInfo, InMemoryDB},
    };
    use tempo_evm::{TempoInvalidTransaction, TempoTxEnv};
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{Call, TempoSignature, TempoTransaction},
    };
    use zone_precompiles::{
        ZONE_FEE_MANAGER_ADDRESS, ZonePrecompiles, test_utils::MockL1Reader as TestL1,
        zone_fee_manager,
    };

    const TEST_DEPLOYER: Address = Address::repeat_byte(0x42);

    struct TestCreate<const IS_CREATE2: bool>;
    impl<const IS_CREATE2: bool> Instruction<TempoEvmTypes> for TestCreate<IS_CREATE2> {
        const DYNAMIC_GAS: bool = true;
        fn execute(
            pc: &mut Pc,
            stack: StackMut<'_>,
            state: &mut InterpreterState<'_, '_, TempoEvmTypes>,
        ) -> Result {
            create::<IS_CREATE2>(pc, stack, state, &[TEST_DEPLOYER])
        }
    }

    struct TestConfig;
    impl EvmConfig<TempoEvmTypes> for TestConfig {
        const BASE_SPEC_ID: SpecId = SpecId::OSAKA;
        const OPCODE_CONFIG: &'static OpcodeConfig<TempoEvmTypes> = &{
            let mut config = zone_opcode_config::<{ SpecId::OSAKA as u32 }>();
            config.set_instruction::<TestCreate<false>>(op::CREATE, 0);
            config.set_instruction::<TestCreate<true>>(op::CREATE2, 0);
            config
        };
    }

    fn enable_test_deployer(evm: &mut ZoneEvm<'static>) {
        let l1 = evm
            .database_as::<L1OverlayDB<InMemoryDB, TestL1>>()
            .unwrap()
            .l1_state()
            .clone();
        let spec = tempo_chainspec::hardfork::TempoHardfork::T7;
        let precompiles = ZonePrecompiles::new(
            spec,
            evm.ext().actions.clone(),
            evm.ext().non_creditable_slots.clone(),
            l1.clone(),
        );
        evm.set_execution_config(
            ExecutionConfig::for_config::<TestConfig>().with_version(*evm.version()),
            spec,
            zone_tx_registry(spec, l1),
            precompiles,
        );
    }

    fn test_db(contracts: impl IntoIterator<Item = (Address, Bytes)>) -> InMemoryDB {
        let mut db = InMemoryDB::default();
        db.insert_account_info(&ZONE_FEE_MANAGER_ADDRESS, AccountInfo::default());
        db.insert_account_storage(
            &ZONE_FEE_MANAGER_ADDRESS,
            &zone_fee_manager::slots::DEFAULT_FEE_TOKEN,
            &U256::from_be_slice(tempo_precompiles::DEFAULT_FEE_TOKEN.as_slice()),
        );
        for (address, code) in contracts {
            db.insert_account_info(
                &address,
                AccountInfo {
                    nonce: 1,
                    ..Default::default()
                }
                .with_code(Bytecode::new_raw(code)),
            );
        }
        db
    }

    fn evm_with_contract(addr: Address, code: &[u8]) -> ZoneEvm<'static> {
        test_evm(test_db([(addr, Bytes::copy_from_slice(code))]))
    }

    fn call_tx(caller: Address, contract: Address) -> Recovered<TempoTxEnv> {
        transaction(
            caller,
            TxLegacy {
                gas_limit: 1_000_000,
                to: TxKind::Call(contract),
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        )
    }

    #[test]
    fn top_level_create_transaction_is_rejected() {
        let mut evm = evm_with_contract(Address::ZERO, &[]);
        let tx = transaction(
            Address::repeat_byte(0x01),
            TxLegacy {
                gas_limit: 1_000_000,
                to: TxKind::Create,
                input: Bytes::from_static(&[0x00]),
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );
        let err = evm
            .transact(&tx)
            .expect_err("top-level create must be rejected");
        assert!(matches!(
            err.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::CallsValidation(
                "contract creation is not supported"
            ))
        ));
    }

    #[test]
    fn pool_validation_rejects_top_level_create_before_tempo_checks() {
        let mut evm = evm_with_contract(Address::ZERO, &[]);
        let tx = transaction(
            Address::repeat_byte(0x01),
            TxLegacy {
                to: TxKind::Create,
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );
        let result = evm.validate_tx(&tx).unwrap_err();
        assert!(matches!(
            result.external_ref::<TempoInvalidTransaction>(),
            Some(TempoInvalidTransaction::CallsValidation(
                "contract creation is not supported"
            ))
        ));
    }

    #[test]
    fn top_level_create_respects_allowlist() {
        let caller = Address::repeat_byte(0x01);
        let tx = transaction(
            caller,
            TxLegacy {
                to: TxKind::Create,
                ..Default::default()
            }
            .into_signed(Signature::test_signature()),
        );
        assert!(validate_transaction(tx.inner(), &[]).is_err());
        assert!(validate_transaction(tx.inner(), &[caller]).is_ok());
    }

    #[test]
    fn runtime_create_opcodes_are_disabled_for_unlisted_deployers() {
        let (contract, caller) = (Address::repeat_byte(0x10), Address::repeat_byte(0x20));
        for bytecode in [
            // PUSH0 PUSH0 PUSH0 CREATE STOP
            bytes!("0x5f5f5ff000"),
            // PUSH0 PUSH0 PUSH0 PUSH0 CREATE2 STOP
            bytes!("0x5f5f5f5ff500"),
        ] {
            let mut evm = evm_with_contract(contract, &bytecode);
            let result = evm
                .transact(&call_tx(caller, contract))
                .expect("transaction should execute")
                .discard();
            assert_eq!(result.stop, InstrStop::NotActivated);
        }
    }

    #[test]
    fn allowlisted_deployer_can_execute_create_and_create2() {
        let caller = Address::repeat_byte(0x20);
        for bytecode in [
            // CREATE, then return the created address.
            bytes!("0x5f5f5ff05f5260205ff3"),
            // CREATE2, then return the created address.
            bytes!("0x5f5f5f5ff55f5260205ff3"),
        ] {
            let mut evm = evm_with_contract(TEST_DEPLOYER, &bytecode);
            enable_test_deployer(&mut evm);
            let result = evm
                .transact(&call_tx(caller, TEST_DEPLOYER))
                .expect("allowlisted deployment should execute")
                .detach();
            assert!(
                result.result.status,
                "allowlisted deployment should succeed"
            );
            let created = Address::from_slice(&result.result.output[12..]);
            assert_ne!(created, Address::ZERO);
            assert!(result.pending_state.account_info(&created).is_some());
        }
    }

    #[test]
    fn delegatecall_does_not_borrow_deployer_privilege() {
        let caller = Address::repeat_byte(0x20);
        let proxy = Address::repeat_byte(0x30);

        // DELEGATECALL the allowlisted deployer with empty calldata, then return its success flag.
        let mut proxy_code = vec![0x5f, 0x5f, 0x5f, 0x5f, 0x73];
        proxy_code.extend_from_slice(TEST_DEPLOYER.as_slice());
        proxy_code.extend_from_slice(&[0x61, 0xff, 0xff, 0xf4, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);

        let mut evm = test_evm(test_db([
            (proxy, Bytes::from(proxy_code)),
            (TEST_DEPLOYER, bytes!("0x5f5f5ff000")),
        ]));
        enable_test_deployer(&mut evm);
        let result = evm
            .transact(&call_tx(caller, proxy))
            .expect("proxy call should execute")
            .discard();
        assert!(result.status, "proxy should handle the failed delegatecall");
        assert_eq!(result.output[31], 0);
    }

    #[test]
    fn aa_calls_without_creation_are_allowed() {
        let tx = aa_tx(
            Address::repeat_byte(0x11),
            TxKind::Call(Address::repeat_byte(0x22)),
        );
        assert!(validate_transaction(tx.inner(), CONTRACT_DEPLOYER_ALLOWLIST).is_ok());
    }

    #[test]
    fn aa_create_respects_allowlist() {
        let caller = Address::repeat_byte(0x11);
        let tx = aa_tx(caller, TxKind::Create);
        assert!(validate_transaction(tx.inner(), &[]).is_err());
        assert!(validate_transaction(tx.inner(), &[caller]).is_ok());
    }

    fn aa_tx(caller: Address, to: TxKind) -> Recovered<TempoTxEnv> {
        transaction(
            caller,
            TempoTxEnvelope::AA(
                TempoTransaction {
                    calls: vec![Call {
                        to,
                        value: U256::ZERO,
                        input: Bytes::new(),
                    }],
                    ..Default::default()
                }
                .into_signed(TempoSignature::default()),
            ),
        )
    }
}
