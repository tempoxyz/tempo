use super::*;
use alloy_primitives::{Bytes, TxKind};
use revm::{
    context::{CfgEnv, TxEnv},
    database::{CacheDB, EmptyDB},
};

#[test]
fn prewarmed_results_preserve_components_after_context_configuration_changes() {
    let target = Address::with_last_byte(100);
    let caller = Address::with_last_byte(101);
    let mut db = CacheDB::<EmptyDB>::default();
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[
            0x60, 1, 0x60, 0, 0x55, 0,
        ]))),
    );
    let original_env = Env {
        cfg_env: CfgEnv::new_with_spec_and_gas_params(
            TempoHardfork::T0,
            tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T0),
        ),
        block_env: TempoBlockEnv {
            inner: revm::context::BlockEnv {
                basefee: 0,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let mut changed_env = original_env.clone();
    changed_env.cfg_env = CfgEnv::new_with_spec_and_gas_params(
        TempoHardfork::T7,
        tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T7),
    );
    let tx = TempoTxEnv {
        inner: TxEnv {
            caller,
            kind: TxKind::Call(target),
            gas_limit: 1_000_000,
            gas_price: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    for mutate_before_injection in [true, false] {
        let mut canonical = TempoEvm::new(db.clone(), original_env.clone());
        canonical.ctx_mut().cfg = changed_env.cfg_env.clone();
        let expected = canonical.transact_raw(tx.clone()).unwrap();
        // T7 installs an SSTORE storage-credit hook at construction. Merely
        // changing ctx.cfg on the original T0 EVM does not install that hook.
        let mut rebuilt = TempoEvm::new(db.clone(), changed_env.clone());
        assert_ne!(rebuilt.transact_raw(tx.clone()).unwrap(), expected);

        let mut recorder = PrewarmingExecutor::new(db.clone(), changed_env.clone());
        let candidate = recorder.execute(tx.clone(), None).unwrap();
        let mut parallel = TempoEvm::new(db.clone(), original_env.clone());
        let pool = SpeculativeExecutor::new(1, 1).unwrap();
        parallel.set_speculative_executor(Some(pool.clone()));
        if mutate_before_injection {
            parallel.ctx_mut().cfg = changed_env.cfg_env.clone();
        }
        parallel.set_preexecuted_transaction(candidate);
        parallel.ctx_mut().cfg = changed_env.cfg_env.clone();
        assert_eq!(parallel.transact_raw(tx.clone()).unwrap(), expected);
        assert_eq!(pool.prewarmed_reuses(), 0);
    }
}
