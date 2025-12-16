use crate::{TempoBlockEnv, TempoTxEnv, instructions};
use alloy_evm::{Database, precompiles::PrecompilesMap};
use alloy_primitives::{Log, U256};
use revm::{
    Context, Inspector,
    context::{CfgEnv, ContextError, Evm, FrameStack},
    handler::{
        EthFrame, EthPrecompiles, EvmTr, FrameInitOrResult, FrameTr, ItemOrResult,
        instructions::EthInstructions,
    },
    inspector::InspectorEvmTr,
    interpreter::interpreter::EthInterpreter,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::extend_tempo_precompiles;

/// The Tempo EVM context type.
pub type TempoContext<DB> = Context<TempoBlockEnv, TempoTxEnv, CfgEnv<TempoHardfork>, DB>;

/// TempoEvm extends the Evm with Tempo specific types and logic.
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
#[expect(clippy::type_complexity)]
pub struct TempoEvm<DB: Database, I> {
    /// Inner EVM type.
    #[deref]
    #[deref_mut]
    pub inner: Evm<
        TempoContext<DB>,
        I,
        EthInstructions<EthInterpreter, TempoContext<DB>>,
        PrecompilesMap,
        EthFrame<EthInterpreter>,
    >,
    /// Preserved logs from the last transaction
    pub logs: Vec<Log>,
    /// The fee collected in `collectFeePreTx` call.
    pub(crate) collected_fee: U256,
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Create a new Tempo EVM.
    pub fn new(ctx: TempoContext<DB>, inspector: I) -> Self {
        let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::default().precompiles);
        extend_tempo_precompiles(&mut precompiles, &ctx.cfg);

        Self::new_inner(Evm {
            ctx,
            inspector,
            instruction: instructions::tempo_instructions(),
            precompiles,
            frame_stack: FrameStack::new(),
        })
    }

    /// Inner helper function to create a new Tempo EVM with empty logs.
    #[inline]
    #[expect(clippy::type_complexity)]
    fn new_inner(
        inner: Evm<
            TempoContext<DB>,
            I,
            EthInstructions<EthInterpreter, TempoContext<DB>>,
            PrecompilesMap,
            EthFrame<EthInterpreter>,
        >,
    ) -> Self {
        Self {
            inner,
            logs: Vec::new(),
            collected_fee: U256::ZERO,
        }
    }
}

impl<DB: Database, I> TempoEvm<DB, I> {
    /// Consumed self and returns a new Evm type with given Inspector.
    pub fn with_inspector<OINSP>(self, inspector: OINSP) -> TempoEvm<DB, OINSP> {
        TempoEvm::new_inner(self.inner.with_inspector(inspector))
    }

    /// Consumes self and returns a new Evm type with given Precompiles.
    pub fn with_precompiles(self, precompiles: PrecompilesMap) -> Self {
        Self::new_inner(self.inner.with_precompiles(precompiles))
    }

    /// Consumes self and returns the inner Inspector.
    pub fn into_inspector(self) -> I {
        self.inner.into_inspector()
    }

    /// Take logs from the EVM.
    #[inline]
    pub fn take_logs(&mut self) -> Vec<Log> {
        std::mem::take(&mut self.logs)
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

    fn all(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
    ) {
        self.inner.all()
    }

    fn all_mut(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
    ) {
        self.inner.all_mut()
    }

    fn frame_stack(&mut self) -> &mut FrameStack<Self::Frame> {
        &mut self.inner.frame_stack
    }

    fn frame_init(
        &mut self,
        frame_input: <Self::Frame as FrameTr>::FrameInit,
    ) -> Result<
        ItemOrResult<&mut Self::Frame, <Self::Frame as FrameTr>::FrameResult>,
        ContextError<DB::Error>,
    > {
        self.inner.frame_init(frame_input)
    }

    fn frame_run(&mut self) -> Result<FrameInitOrResult<Self::Frame>, ContextError<DB::Error>> {
        self.inner.frame_run()
    }

    #[doc = " Returns the result of the frame to the caller. Frame is popped from the frame stack."]
    #[doc = " Consumes the frame result or returns it if there is more frames to run."]
    fn frame_return_result(
        &mut self,
        result: <Self::Frame as FrameTr>::FrameResult,
    ) -> Result<Option<<Self::Frame as FrameTr>::FrameResult>, ContextError<DB::Error>> {
        self.inner.frame_return_result(result)
    }
}

impl<DB, I> InspectorEvmTr for TempoEvm<DB, I>
where
    DB: Database,
    I: Inspector<TempoContext<DB>>,
{
    type Inspector = I;

    fn all_inspector(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
        &Self::Inspector,
    ) {
        self.inner.all_inspector()
    }

    fn all_mut_inspector(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
        &mut Self::Inspector,
    ) {
        self.inner.all_mut_inspector()
    }
}

#[cfg(test)]
mod tests {
    use alloy_evm::{Evm, EvmFactory};
    use alloy_primitives::{Address, U256, bytes};
    use reth_evm::EvmInternals;
    use revm::{
        context::{ContextTr, TxEnv},
        database::{CacheDB, EmptyDB},
        state::{AccountInfo, Bytecode},
    };
    use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;
    use tempo_evm::TempoEvmFactory;
    use tempo_precompiles::{
        storage::{StorageCtx, evm::EvmPrecompileStorageProvider},
        test_util::TIP20Setup,
    };

    #[test]
    fn test_auto_7702_delegation() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut tempo_evm = TempoEvmFactory::default().create_evm(db, Default::default());

        // HACK: initialize default fee token and pathUSD so that fee token validation passes
        let ctx = tempo_evm.ctx_mut();
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(
            EvmInternals::new(&mut ctx.journaled_state, &ctx.block),
            &ctx.cfg,
        );
        StorageCtx::enter(&mut storage, || {
            TIP20Setup::create("USD", "USD", Address::ZERO)
                .apply()
                .unwrap();
        });
        drop(storage);

        let caller_0 = Address::random();
        let tx_env = TxEnv {
            caller: caller_0,
            nonce: 0,
            ..Default::default()
        };
        let mut res = tempo_evm.transact_raw(tx_env.into())?;
        assert!(res.result.is_success());

        let account = res.state.remove(&caller_0).unwrap();
        assert_eq!(
            account.info.code.unwrap(),
            Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS),
        );

        Ok(())
    }

    #[test]
    fn test_access_millis_timestamp() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut tempo_evm = TempoEvmFactory::default().create_evm(db, Default::default());
        let ctx = tempo_evm.ctx_mut();
        ctx.block.timestamp = U256::from(1000);
        ctx.block.timestamp_millis_part = 100;
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(
            EvmInternals::new(&mut ctx.journaled_state, &ctx.block),
            &ctx.cfg,
        );
        StorageCtx::enter(&mut storage, || {
            TIP20Setup::create("USD", "USD", Address::ZERO)
                .apply()
                .unwrap();
        });
        drop(storage);

        let contract = Address::random();

        // Create a simple contract that returns output of the opcode.
        ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                // MILLISTIMESTAMP PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN
                code: Some(Bytecode::new_raw(bytes!("0x4F5F5260205FF3"))),
                ..Default::default()
            },
        );

        let tx_env = TxEnv {
            kind: contract.into(),
            ..Default::default()
        };
        let res = tempo_evm.transact_raw(tx_env.into())?;
        assert!(res.result.is_success());
        assert_eq!(
            U256::from_be_slice(res.result.output().unwrap()),
            U256::from(1000100)
        );

        Ok(())
    }
}
