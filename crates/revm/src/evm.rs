use reth_evm::{
    Database,
    precompiles::PrecompilesMap,
    revm::{
        Context, Inspector,
        context::{BlockEnv, CfgEnv, ContextError, ContextTr, Evm, FrameStack, TxEnv},
        handler::{
            EthFrame, EthPrecompiles, EvmTr, FrameInitOrResult, FrameTr, ItemOrResult,
            instructions::EthInstructions,
        },
        inspector::InspectorEvmTr,
        interpreter::interpreter::EthInterpreter,
        state::Bytecode,
    },
};
use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;

/// The Tempo EVM context type.
pub type TempoContext<DB> = Context<BlockEnv, TxEnv, CfgEnv, DB>;

/// TempoEvm extends the Evm with Tempo specific types and logic.
#[derive(Debug)]
#[expect(clippy::type_complexity)]
pub struct TempoEvm<DB: Database, I>(
    /// Inner EVM type.
    pub  Evm<
        TempoContext<DB>,
        I,
        EthInstructions<EthInterpreter, TempoContext<DB>>,
        PrecompilesMap,
        EthFrame<EthInterpreter>,
    >,
);

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Create a new Optimism EVM.
    pub fn new(ctx: TempoContext<DB>, inspector: I) -> Self {
        Self(Evm {
            ctx,
            inspector,
            instruction: EthInstructions::new_mainnet(),
            precompiles: PrecompilesMap::from_static(EthPrecompiles::default().precompiles),
            frame_stack: FrameStack::new(),
        })
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Consumed self and returns a new Evm type with given Inspector.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        TempoEvm(self.0.with_inspector(inspector))
    }

    /// Consumes self and returns a new Evm type with given Precompiles.
    pub fn with_precompiles(self, precompiles: PrecompilesMap) -> Self {
        Self(self.0.with_precompiles(precompiles))
    }

    /// Consumes self and returns the inner Inspector.
    pub fn into_inspector(self) -> I {
        self.0.into_inspector()
    }
}

impl<DB, I> EvmTr for TempoEvm<DB, I>
where
    DB: Database,
{
    type Context = TempoContext<DB>;
    type Instructions = EthInstructions<EthInterpreter, TempoContext<DB>>;
    type Precompiles = PrecompilesMap;
    type Frame = EthFrame<EthInterpreter>;

    fn ctx(&mut self) -> &mut Self::Context {
        &mut self.0.ctx
    }

    fn ctx_ref(&self) -> &Self::Context {
        &self.0.ctx
    }

    fn ctx_instructions(&mut self) -> (&mut Self::Context, &mut Self::Instructions) {
        (&mut self.0.ctx, &mut self.0.instruction)
    }

    fn ctx_precompiles(&mut self) -> (&mut Self::Context, &mut Self::Precompiles) {
        (&mut self.0.ctx, &mut self.0.precompiles)
    }

    fn frame_stack(&mut self) -> &mut FrameStack<Self::Frame> {
        &mut self.0.frame_stack
    }

    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<DB::Error>,
    > {
        let is_first_init = self.0.frame_stack.index().is_none();
        let new_frame = if is_first_init {
            self.0.frame_stack.start_init()
        } else {
            self.0.frame_stack.get_next()
        };

        let ctx = &mut self.0.ctx;

        // Auto delegate the the default 7702 account if this is the account's first tx
        if ctx.tx.nonce == 0 {
            let caller = ctx.tx.caller;
            let journal = ctx.journal_mut();
            let account = journal.account(caller);

            let account_code = account.info.code.to_owned().unwrap_or_default();
            if account_code.is_empty() {
                journal.set_code(caller, Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS));
            }
        }

        let precompiles = &mut self.0.precompiles;
        let res = Self::Frame::init_with_context(new_frame, ctx, precompiles, frame_input)?;

        Ok(res.map_frame(|token| {
            if is_first_init {
                self.0.frame_stack.end_init(token);
            } else {
                self.0.frame_stack.push(token);
            }
            self.0.frame_stack.get()
        }))
    }

    fn frame_run(&mut self) -> Result<FrameInitOrResult<Self::Frame>, ContextError<DB::Error>> {
        self.0.frame_run()
    }

    #[doc = " Returns the result of the frame to the caller. Frame is popped from the frame stack."]
    #[doc = " Consumes the frame result or returns it if there is more frames to run."]
    fn frame_return_result(
        &mut self,
        result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<Option<<Self::Frame as FrameTr>::FrameResult>, ContextError<DB::Error>> {
        self.0.frame_return_result(result)
    }
}

impl<DB, I> InspectorEvmTr for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type Inspector = I;

    fn inspector(&mut self) -> &mut Self::Inspector {
        &mut self.0.inspector
    }

    fn ctx_inspector(&mut self) -> (&mut Self::Context, &mut Self::Inspector) {
        (&mut self.0.ctx, &mut self.0.inspector)
    }

    fn ctx_inspector_frame(
        &mut self,
    ) -> (&mut Self::Context, &mut Self::Inspector, &mut Self::Frame) {
        (
            &mut self.0.ctx,
            &mut self.0.inspector,
            self.0.frame_stack.get(),
        )
    }

    fn ctx_inspector_frame_instructions(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Inspector,
        &mut Self::Frame,
        &mut Self::Instructions,
    ) {
        (
            &mut self.0.ctx,
            &mut self.0.inspector,
            self.0.frame_stack.get(),
            &mut self.0.instruction,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use reth_evm::revm::{
        ExecuteEvm,
        context::{BlockEnv, CfgEnv, TxEnv},
        database::{CacheDB, EmptyDB},
        primitives::hardfork::SpecId,
        state::Bytecode,
    };

    #[test]
    fn test_auto_7702_delegation() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let ctx = TempoContext::new(db, SpecId::default());
        let mut tempo_evm = TempoEvm::new(ctx, ());

        let caller = Address::random();
        let tx_env = TxEnv {
            caller,
            nonce: 0,
            ..Default::default()
        };
        let res = tempo_evm.transact_one(tx_env)?;
        assert!(res.is_success());

        let ctx = tempo_evm.ctx();
        let account = ctx.journal().account(caller).to_owned();
        assert_eq!(
            account.info.code.unwrap(),
            Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS),
        );
        Ok(())
    }
}
