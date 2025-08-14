use alloy_primitives::{Address, Bytes};
use reth::revm::{
    Context, Inspector,
    context::{
        BlockEnv, CfgEnv, TxEnv,
        result::{EVMError, HaltReason, ResultAndState},
    },
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::InterpreterResult,
    primitives::hardfork::SpecId,
};
use reth_evm::{Database, EthEvm, Evm, EvmEnv};
use std::ops::{Deref, DerefMut};

/// The Tempo EVM context type.
pub type TempoEvmContext<DB> = Context<BlockEnv, TxEnv, CfgEnv, DB>;

/// Tempo EVM implementation.
///
/// This is a wrapper type around the `revm` ethereum evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// `RevmEvm` type.
#[expect(missing_debug_implementations)]
pub struct TempoEvm<DB: Database, I, PRECOMPILE = EthPrecompiles> {
    inner: EthEvm<DB, I, PRECOMPILE>,
    inspect: bool,
}

impl<DB: Database, I, PRECOMPILE> TempoEvm<DB, I, PRECOMPILE> {
    /// Creates a new Tempo EVM instance.
    ///
    /// The `inspect` argument determines whether the configured [`Inspector`] of the given
    /// `RevmEvm` should be invoked on [`Evm::transact`].
    pub const fn new(evm: EthEvm<DB, I, PRECOMPILE>, inspect: bool) -> Self {
        Self {
            inner: evm,
            inspect,
        }
    }

    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &TempoEvmContext<DB> {
        self.inner.ctx()
    }

    /// Provides a mutable reference to the EVM context.
    pub fn ctx_mut(&mut self) -> &mut TempoEvmContext<DB> {
        self.inner.ctx_mut()
    }
}

impl<DB: Database, I, PRECOMPILE> Deref for TempoEvm<DB, I, PRECOMPILE> {
    type Target = TempoEvmContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I, PRECOMPILE> DerefMut for TempoEvm<DB, I, PRECOMPILE> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I, PRECOMPILE> Evm for TempoEvm<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<TempoEvmContext<DB>>,
    PRECOMPILE: PrecompileProvider<TempoEvmContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type Precompiles = PRECOMPILE;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        &self.block
    }

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        // TODO: Check balance
        // self.transact_system_call();

        self.inner.transact_raw(tx)

        // TODO: decrement balance
        // self.transact_system_call();
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.transact_system_call(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        self.inner.finish()
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        self.inner.components()
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        self.inner.components_mut()
    }
}
