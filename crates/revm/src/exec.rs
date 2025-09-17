use crate::{
    TempoTxEnv,
    evm::{TempoContext, TempoEvm},
    handler::TempoEvmHandler,
};
use reth_evm::{
    Database,
    revm::{
        DatabaseCommit, ExecuteCommitEvm, ExecuteEvm,
        context::{
            BlockEnv, ContextSetters, TxEnv,
            result::{ExecResultAndState, HaltReason},
        },
        context_interface::{
            ContextTr, JournalTr,
            result::{EVMError, ExecutionResult},
        },
        handler::{Handler, SystemCallTx, system_call::SystemCallEvm},
        inspector::{
            InspectCommitEvm, InspectEvm, InspectSystemCallEvm, Inspector, InspectorHandler,
        },
        primitives::{Address, Bytes},
        state::EvmState,
    },
};

impl<DB, I> ExecuteEvm for TempoEvm<DB, I>
where
    DB: Database,
{
    type Tx = TempoTxEnv;
    type Block = BlockEnv;
    type State = EvmState;
    type Error = EVMError<DB::Error>;
    type ExecutionResult = ExecutionResult<HaltReason>;

    fn set_block(&mut self, block: Self::Block) {
        self.0.ctx.set_block(block);
    }

    fn transact_one(&mut self, tx: Self::Tx) -> Result<Self::ExecutionResult, Self::Error> {
        self.0.ctx.set_tx(tx);
        let mut h = TempoEvmHandler::new();
        h.run(self)
    }

    fn finalize(&mut self) -> Self::State {
        self.0.ctx.journal_mut().finalize()
    }

    fn replay(
        &mut self,
    ) -> Result<ExecResultAndState<Self::ExecutionResult, Self::State>, Self::Error> {
        let mut h = TempoEvmHandler::new();
        h.run(self).map(|result| {
            let state = self.finalize();
            ExecResultAndState::new(result, state)
        })
    }
}

impl<DB, I> ExecuteCommitEvm for TempoEvm<DB, I>
where
    DB: Database + DatabaseCommit,
{
    fn commit(&mut self, state: Self::State) {
        self.0.ctx.db_mut().commit(state);
    }
}

impl<DB, I> InspectEvm for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type Inspector = I;

    fn set_inspector(&mut self, inspector: Self::Inspector) {
        self.0.inspector = inspector;
    }

    fn inspect_one_tx(&mut self, tx: Self::Tx) -> Result<Self::ExecutionResult, Self::Error> {
        self.0.ctx.set_tx(tx);
        let mut h = TempoEvmHandler::new();
        h.inspect_run(self)
    }
}

impl<DB, I> InspectCommitEvm for TempoEvm<DB, I>
where
    DB: Database + DatabaseCommit,
    I: Inspector<TempoContext<DB>>,
{
}

impl<DB, I> SystemCallEvm for TempoEvm<DB, I>
where
    DB: Database,
{
    fn system_call_one_with_caller(
        &mut self,
        caller: Address,
        system_contract_address: Address,
        data: Bytes,
    ) -> Result<Self::ExecutionResult, Self::Error> {
        self.0
            .ctx
            .set_tx(TxEnv::new_system_tx_with_caller(caller, system_contract_address, data).into());
        let mut h = TempoEvmHandler::new();
        h.run_system_call(self)
    }
}

impl<DB, I> InspectSystemCallEvm for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    fn inspect_one_system_call_with_caller(
        &mut self,
        caller: Address,
        system_contract_address: Address,
        data: Bytes,
    ) -> Result<Self::ExecutionResult, Self::Error> {
        self.0
            .ctx
            .set_tx(TxEnv::new_system_tx_with_caller(caller, system_contract_address, data).into());
        let mut h = TempoEvmHandler::new();
        h.inspect_run_system_call(self)
    }
}
