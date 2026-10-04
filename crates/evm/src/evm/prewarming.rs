//! Retain a strict recording EVM on each Engine prewarming worker for one block.

use super::*;
use reth_evm::{BoxedPrewarmRunner, EvmPrewarmRunner, PrewarmRunner};
use std::sync::Arc;

impl TempoEvmFactory {
    pub(crate) fn prewarm_runner<DB: Database + 'static>(
        &self,
        db: DB,
        env: EvmEnv<TempoHardfork, TempoBlockEnv>,
    ) -> BoxedPrewarmRunner<crate::TempoEvmConfig, DB> {
        let session = self.engine_prewarming.as_ref().and_then(|cache| {
            if !env.cfg_env.disable_nonce_check
                || !env.cfg_env.disable_balance_check
                || env.cfg_env.disable_base_fee
            {
                return None;
            }
            let mut canonical = env.clone();
            canonical.cfg_env.disable_nonce_check = false;
            canonical.cfg_env.disable_balance_check = false;
            cache.session(&canonical)
        });
        let Some(session) = session else {
            return Box::new(EvmPrewarmRunner::new(self.create_evm(db, env)));
        };
        let executor =
            PrewarmingExecutor::new(db, session.env().clone()).with_state(session.prefix());
        Box::new(EnginePrewarmRunner {
            mode: Some(RunnerMode::Strict(Box::new(CaptureState {
                executor,
                session,
                relaxed_env: env,
            }))),
        })
    }
}

struct CaptureState<DB: Database> {
    executor: PrewarmingExecutor<DB>,
    session: Arc<EnginePrewarmingSession>,
    relaxed_env: EvmEnv<TempoHardfork, TempoBlockEnv>,
}

impl<DB: Database> CaptureState<DB> {
    fn transact(
        &mut self,
        tx: TempoTxEnv,
    ) -> Result<ResultAndState<HaltReason>, EVMError<DB::Error, TempoInvalidTransaction>> {
        let _worker = self.session.worker_entry();
        // The runner owns an immutable environment and a private standard EVM.
        // Inspection, journal/context mutation and custom fee hooks cannot enter
        // this interface; precompile mutation permanently selects Legacy below.
        if self.relaxed_env.cfg_env.disable_fee_charge {
            self.session.capture_event(CaptureEvent::GuardRejected);
        } else if self.session.can_capture(&tx) {
            self.session.capture_event(CaptureEvent::StrictAttempts);
            let mut strict_tx = tx.clone();
            let offset = strict_tx
                .tempo_tx_env
                .as_mut()
                .and_then(|aa| aa.expiring_nonce_idx.take());
            match self.executor.execute(strict_tx, offset) {
                Ok(candidate) => {
                    self.session.capture_event(CaptureEvent::StrictSucceeded);
                    let hint = candidate.prewarming_result();
                    self.session.publish(candidate);
                    return Ok(hint);
                }
                Err(_) => self.session.capture_event(CaptureEvent::StrictFailed),
            }
        }
        drop(_worker);
        // Keep the original transaction and its parent-relative AA offset on
        // misses and strict failures. No reference to this parent survives the
        // call, and neither executor commits its speculative writes.
        TempoEvm::new(self.executor.parent_db_mut(), self.relaxed_env.clone()).transact(tx)
    }

    fn into_legacy(self) -> TempoEvm<DB> {
        let mut evm = TempoEvm::new(self.executor.into_db(), self.relaxed_env);
        // Preserve the original session and capture diagnostics. The caller
        // immediately exposes precompiles, which disables capture permanently.
        evm.engine_session = Some(self.session);
        evm.engine_capture = Some(|db, env, prefix, tx, offset| {
            PrewarmingExecutor::new(db, env)
                .with_state(prefix)
                .execute(tx, offset)
        });
        evm
    }
}

enum RunnerMode<DB: Database> {
    Strict(Box<CaptureState<DB>>),
    Legacy(Box<TempoEvm<DB>>),
}

struct EnginePrewarmRunner<DB: Database> {
    // Take ownership while executing so unwinding drops the possibly dirty EVM
    // and parent. Even a caller that catches a panic cannot reuse its journal.
    mode: Option<RunnerMode<DB>>,
}

impl<DB: Database> PrewarmRunner for EnginePrewarmRunner<DB> {
    type Tx = TempoTxEnv;
    type Error = EVMError<DB::Error, TempoInvalidTransaction>;
    type HaltReason = HaltReason;

    fn transact(&mut self, tx: Self::Tx) -> Result<ResultAndState<HaltReason>, Self::Error> {
        let Some(mut mode) = self.mode.take() else {
            return Err(EVMError::Custom("prewarming worker panicked".into()));
        };
        let result = match &mut mode {
            RunnerMode::Strict(state) => state.transact(tx),
            RunnerMode::Legacy(evm) => evm.transact(tx),
        };
        self.mode = Some(mode);
        result
    }

    fn precompiles_mut(&mut self) -> &mut PrecompilesMap {
        let mode = self.mode.take().expect("prewarming worker panicked");
        self.mode = Some(match mode {
            RunnerMode::Strict(state) => RunnerMode::Legacy(Box::new(state.into_legacy())),
            legacy => legacy,
        });
        let Some(RunnerMode::Legacy(evm)) = self.mode.as_mut() else {
            unreachable!()
        };
        evm.precompiles_mut()
    }
}
