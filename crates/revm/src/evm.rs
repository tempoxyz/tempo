use crate::{TempoBlockEnv, TempoTxEnv, instructions};
use alloy_evm::{Database, precompiles::PrecompilesMap};
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
use tempo_precompiles::extend_tempo_precompiles;

/// The Tempo EVM context type.
pub type TempoContext<DB> = Context<TempoBlockEnv, TempoTxEnv, CfgEnv, DB>;

/// TempoEvm extends the Evm with Tempo specific types and logic.
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
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
    /// Create a new Tempo EVM.
    pub fn new(ctx: TempoContext<DB>, inspector: I) -> Self {
        let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::default().precompiles);
        extend_tempo_precompiles(&mut precompiles, ctx.cfg.chain_id);

        Self(Evm {
            ctx,
            inspector,
            instruction: instructions::tempo_instructions(),
            precompiles,
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

    fn all(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
    ) {
        self.0.all()
    }

    fn all_mut(
        &mut self,
    ) -> (
        &mut Self::Context,
        &mut Self::Instructions,
        &mut Self::Precompiles,
        &mut FrameStack<Self::Frame>,
    ) {
        self.0.all_mut()
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
        self.0.frame_init(frame_input)
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

    fn all_inspector(
        &self,
    ) -> (
        &Self::Context,
        &Self::Instructions,
        &Self::Precompiles,
        &FrameStack<Self::Frame>,
        &Self::Inspector,
    ) {
        self.0.all_inspector()
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
        self.0.all_mut_inspector()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256, bytes};
    use reth_evm::EvmInternals;
    use revm::{
        ExecuteEvm,
        context::{ContextTr, TxEnv},
        database::{CacheDB, EmptyDB},
        primitives::hardfork::SpecId,
        state::{AccountInfo, Bytecode},
    };
    use tempo_contracts::DEFAULT_7702_DELEGATE_ADDRESS;
    use tempo_precompiles::{
        LINKING_USD_ADDRESS, storage::evm::EvmPrecompileStorageProvider, tip20::TIP20Token,
    };

    #[test]
    fn test_auto_7702_delegation() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut ctx = TempoContext::new(db, SpecId::default());

        // HACK: initialize default fee token and linkingUSD so that fee token validation passes
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(
            EvmInternals::new(&mut ctx.journaled_state, &ctx.block),
            ctx.cfg.chain_id,
        );
        TIP20Token::new(0, &mut storage)
            .initialize("USD", "USD", "USD", Address::ZERO, Address::ZERO)
            .unwrap();
        TIP20Token::new(1, &mut storage)
            .initialize("USD", "USD", "USD", LINKING_USD_ADDRESS, Address::ZERO)
            .unwrap();
        drop(storage);

        let mut tempo_evm = TempoEvm::new(ctx, ());

        let caller_0 = Address::random();
        let tx_env = TxEnv {
            caller: caller_0,
            nonce: 0,
            ..Default::default()
        };
        let res = tempo_evm.transact_one(tx_env.into())?;
        assert!(res.is_success());

        let ctx = tempo_evm.ctx();
        let account = ctx.journal().account(caller_0).to_owned();
        assert_eq!(
            account.info.code.unwrap(),
            Bytecode::new_eip7702(DEFAULT_7702_DELEGATE_ADDRESS),
        );

        Ok(())
    }

    #[test]
    fn test_access_millis_timestamp() -> eyre::Result<()> {
        let db = CacheDB::new(EmptyDB::new());
        let mut ctx = TempoContext::new(db, SpecId::default()).modify_block_chained(|block| {
            block.timestamp = U256::from(1000);
            block.timestamp_millis_part = 100;
        });
        let contract = Address::random();

        // HACK: initialize default fee token and linkingUSD so that fee token validation passes
        let mut storage = EvmPrecompileStorageProvider::new_max_gas(
            EvmInternals::new(&mut ctx.journaled_state, &ctx.block),
            ctx.cfg.chain_id,
        );
        TIP20Token::new(0, &mut storage)
            .initialize("USD", "USD", "USD", Address::ZERO, Address::ZERO)
            .unwrap();
        TIP20Token::new(1, &mut storage)
            .initialize("USD", "USD", "USD", LINKING_USD_ADDRESS, Address::ZERO)
            .unwrap();
        drop(storage);

        // Create a simple contract that returns output of the opcode.
        ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                // MILLISTIMESTAMP PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN
                code: Some(Bytecode::new_raw(bytes!("0x4F5F5260205FF3"))),
                ..Default::default()
            },
        );
        let mut tempo_evm = TempoEvm::new(ctx, ());

        let tx_env = TxEnv {
            kind: contract.into(),
            ..Default::default()
        };
        let res = tempo_evm.transact_one(tx_env.into())?;
        assert!(res.is_success());
        assert_eq!(
            U256::from_be_slice(res.output().unwrap()),
            U256::from(1000100)
        );

        Ok(())
    }
}
