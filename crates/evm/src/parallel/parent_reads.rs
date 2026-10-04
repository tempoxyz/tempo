//! Typed lifetime adaptation for one borrowed Engine parent-read capture.

use super::*;
use reth_evm::parent_reads::CaptureParentReads;

/// Captures one execution without retaining the provider in its sealed witness.
pub(crate) fn capture_with_parent_reads<DB: Database>(
    db: &mut DB,
    env: Env,
    prefix: PrewarmingState,
    tx: TempoTxEnv,
    expiring_nonce_offset: Option<usize>,
    hooks: CaptureParentReads<DB>,
) -> Result<PreexecutedTransaction, EVMError<DB::Error, TempoInvalidTransaction>> {
    let proxy = CaptureDatabase {
        db,
        hooks,
        active: false,
    };
    PrewarmingExecutor::new(proxy, env)
        .with_state(prefix)
        .with_parent_reads(CaptureDatabase::<DB>::hooks())
        .execute(tx, expiring_nonce_offset)
}

/// Carries the original typed callbacks through the shorter database borrow.
/// Ordinary Database reads delegate directly, including nonce prediction loads.
#[derive(Debug)]
struct CaptureDatabase<'a, DB: Database> {
    db: &'a mut DB,
    hooks: CaptureParentReads<DB>,
    active: bool,
}

impl<DB: Database> CaptureDatabase<'_, DB> {
    fn hooks() -> CaptureParentReads<Self> {
        CaptureParentReads {
            begin: |proxy| {
                // Arm before calling into the provider so unwind also discards.
                proxy.active = true;
                (proxy.hooks.begin)(proxy.db);
            },
            storage: |proxy, index, address, slot| {
                (proxy.hooks.storage)(proxy.db, index, address, slot)
            },
            finish: |proxy| {
                let batch = (proxy.hooks.finish)(proxy.db);
                proxy.active = false;
                batch
            },
            discard: |proxy| proxy.discard(),
        }
    }

    fn discard(&mut self) {
        if std::mem::take(&mut self.active) {
            (self.hooks.discard)(self.db);
        }
    }
}

impl<DB: Database> Drop for CaptureDatabase<'_, DB> {
    fn drop(&mut self) {
        self.discard();
    }
}

impl<DB: Database> reth_revm::Database for CaptureDatabase<'_, DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.db.basic(address)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.db.storage(address, slot)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.db.code_by_hash(hash)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.db.block_hash(number)
    }
}
