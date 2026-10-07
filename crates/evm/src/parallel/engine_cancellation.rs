//! Stop strict Engine work that ordered execution can no longer consume.

use super::{
    EnginePrewarmingSession, Env, PreexecutedTransaction, PrewarmingExecutor, PrewarmingState,
};
use alloy_evm::Database;
use alloy_primitives::{Address, B256, U256};
use reth_revm::{
    database_interface::DBErrorMarker,
    state::{AccountInfo, Bytecode},
};
use std::cell::Cell;
use tempo_revm::TempoTxEnv;

pub(crate) enum EngineCaptureFailure {
    Execution,
    Stale,
}

pub(crate) fn capture_engine_transaction<DB: Database>(
    db: &mut DB,
    env: Env,
    prefix: PrewarmingState,
    session: &EnginePrewarmingSession,
    tx: TempoTxEnv,
    offset: Option<usize>,
) -> Result<PreexecutedTransaction, EngineCaptureFailure> {
    let index = session.index(&tx).ok_or(EngineCaptureFailure::Execution)?;
    let cancelled = Cell::new(false);
    let db = CancellableDatabase {
        db,
        session,
        index,
        cancelled: &cancelled,
    };
    let result = PrewarmingExecutor::new(db, env)
        .with_state(prefix)
        .execute(tx, offset);
    // Native precompiles may turn a provider error into a fatal string. Keep
    // cancellation identity out of that conversion, and never publish partial
    // work even if a caller handled an error internally.
    if cancelled.get() {
        Err(EngineCaptureFailure::Stale)
    } else {
        result.map_err(|_| EngineCaptureFailure::Execution)
    }
}

#[derive(Debug, thiserror::Error)]
enum CaptureDatabaseError<E> {
    #[error("stale Engine prewarming")]
    Stale,
    #[error(transparent)]
    Database(E),
}

impl<E: DBErrorMarker> DBErrorMarker for CaptureDatabaseError<E> {
    fn is_fatal(&self) -> bool {
        match self {
            Self::Stale => true,
            Self::Database(error) => error.is_fatal(),
        }
    }
}

struct CancellableDatabase<'a, DB> {
    db: DB,
    session: &'a EnginePrewarmingSession,
    index: usize,
    cancelled: &'a Cell<bool>,
}

impl<DB: Database> CancellableDatabase<'_, DB> {
    #[inline]
    fn check(&self) -> Result<(), CaptureDatabaseError<DB::Error>> {
        if self.session.capture_is_stale(self.index) {
            self.cancelled.set(true);
            Err(CaptureDatabaseError::Stale)
        } else {
            Ok(())
        }
    }
}

// The wrapper owns no state and is used only beneath the strict recorder. It
// cannot commit. Prefix hits and computation without provider reads do not
// poll; publication still rejects work that finishes after its ordered take.
impl<DB: Database> Database for CancellableDatabase<'_, DB> {
    type Error = CaptureDatabaseError<DB::Error>;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.check()?;
        self.db
            .basic(address)
            .map_err(CaptureDatabaseError::Database)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.check()?;
        self.db
            .storage(address, slot)
            .map_err(CaptureDatabaseError::Database)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.check()?;
        self.db
            .code_by_hash(hash)
            .map_err(CaptureDatabaseError::Database)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.check()?;
        self.db
            .block_hash(number)
            .map_err(CaptureDatabaseError::Database)
    }
}
