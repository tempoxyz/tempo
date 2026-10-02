use super::*;
use alloy_primitives::{Bytes, TxKind};
use revm::{
    DatabaseCommit, ExecuteEvm, MainContext,
    context::{ContextTr, JournalTr, TxEnv},
    database::{CacheDB, EmptyDB},
    state::{AccountInfo, Bytecode},
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    storage::{StorageActions, StorageCtx, access, fee_updates},
    test_util::TIP20Setup,
};

type TestDB = CacheDB<EmptyDB>;

fn evm(db: TestDB, spec: TempoHardfork) -> TempoEvm<TestDB, ()> {
    TempoEvm::new(
        Context::mainnet()
            .with_db(db)
            .with_block(TempoBlockEnv {
                inner: revm::context::BlockEnv {
                    basefee: 0,
                    gas_limit: 30_000_000,
                    ..Default::default()
                },
                ..Default::default()
            })
            .with_cfg(CfgEnv::new_with_spec_and_gas_params(
                spec,
                crate::gas_params::tempo_gas_params(spec),
            ))
            .with_tx(TempoTxEnv::default()),
        (),
    )
}

fn tx(target: Address, gas_price: u128) -> TempoTxEnv {
    TempoTxEnv {
        inner: TxEnv {
            caller: Address::with_last_byte(101),
            kind: TxKind::Call(target),
            gas_limit: 1_000_000,
            gas_price,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn contract(db: &mut TestDB, address: Address, code: &[u8]) {
    db.insert_account_info(
        address,
        AccountInfo::default().with_code(Bytecode::new_raw(Bytes::copy_from_slice(code))),
    );
}

#[test]
fn opcode_recording_observes_cached_and_reverted_storage_without_changing_execution() {
    let target = Address::with_last_byte(100);
    for spec in [TempoHardfork::T0, TempoHardfork::T7, TempoHardfork::T14] {
        for revert in [false, true] {
            // Read one cached slot and write another. A database wrapper cannot
            // observe either access because both are already in the journal.
            let mut code = vec![0x60, 5, 0x54, 0x50, 0x60, 8, 0x60, 6, 0x55];
            code.extend_from_slice(if revert {
                &[0x60, 0, 0x60, 0, 0xfd]
            } else {
                &[0]
            });
            let mut db = TestDB::default();
            contract(&mut db, target, &code);
            for slot in [5, 6] {
                db.insert_account_storage(target, U256::from(slot), U256::from(7))
                    .unwrap();
            }
            let mut canonical = evm(db.clone(), spec);
            let mut recorded = evm(db, spec);
            for current in [&mut canonical, &mut recorded] {
                current.ctx.journaled_state.load_account(target).unwrap();
                for slot in [5, 6] {
                    current
                        .ctx
                        .journaled_state
                        .sload(target, U256::from(slot))
                        .unwrap();
                }
            }
            recorded.enable_storage_access_recording();
            let expected = canonical.transact(tx(target, 0)).unwrap();
            let (actual, accesses) = access::record(|| recorded.transact(tx(target, 0)));
            assert_eq!(actual.unwrap(), expected, "{spec:?}, revert={revert}");
            assert!(accesses.slots.contains(&(target, U256::from(5))));
            assert!(accesses.slots.contains(&(target, U256::from(6))));
            assert!(!accesses.unsupported);
            assert!(recorded.take_recorded_body().is_none());
        }
    }
}

#[test]
fn nested_creation_and_selfdestruct_disable_fee_rebasing_without_changing_execution() {
    let target = Address::with_last_byte(100);
    let caller = tx(target, 1).inner.caller;
    let mut setup = evm(TestDB::default(), TempoHardfork::T0);
    StorageCtx::enter_ctx(&mut setup.ctx, StorageActions::disabled(), || {
        TIP20Setup::path_usd(caller)
            .with_issuer(caller)
            .with_mint(caller, U256::from(1_000_000_000u64))
            .apply()
            .unwrap();
    });
    let state = setup.ctx.journaled_state.finalize();
    setup.ctx.db_mut().commit(state);
    let mut funded = setup.inner.ctx.journaled_state.database;
    contract(&mut funded, TIP_FEE_MANAGER_ADDRESS, &[0]);
    for spec in [TempoHardfork::T0, TempoHardfork::T7, TempoHardfork::T14] {
        for code in [
            // A CALL transaction can still execute CREATE/CREATE2 internally.
            &[0x60, 0, 0x60, 0, 0x60, 0, 0xf0, 0x50, 0][..],
            &[0x60, 0, 0x60, 0, 0x60, 0, 0x60, 0, 0xf5, 0x50, 0][..],
            &[0x60, 102, 0xff][..],
        ] {
            let mut db = funded.clone();
            contract(&mut db, target, code);
            let mut canonical = evm(db.clone(), spec);
            let mut recorded = evm(db, spec);
            let (expected, unchecked_updates) =
                fee_updates::record(|| canonical.transact(tx(target, 1)));
            let expected = expected.unwrap();
            assert!(expected.result.is_success(), "{spec:?}, {code:?}");
            assert!(!unchecked_updates.is_empty(), "{spec:?}, {code:?}");
            recorded.enable_storage_access_recording();
            let ((actual, checked_updates), accesses) =
                access::record(|| fee_updates::record(|| recorded.transact(tx(target, 1))));
            assert_eq!(actual.unwrap(), expected, "{spec:?}, {code:?}");
            assert!(accesses.unsupported);
            assert!(checked_updates.is_empty());
            assert!(recorded.take_recorded_body().is_none());
        }
    }
}
