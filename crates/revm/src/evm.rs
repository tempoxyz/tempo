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
    /// 2D nonce gas cost calculated during validation.
    pub(crate) nonce_2d_gas: u64,
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
            nonce_2d_gas: 0,
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
    use alloy_primitives::{Address, TxKind, U256, bytes};
    use reth_evm::EvmInternals;
    use revm::{
        Context, InspectEvm, MainContext,
        bytecode::opcode,
        context::{ContextTr, TxEnv},
        database::{CacheDB, EmptyDB},
        inspector::CountInspector,
        state::{AccountInfo, Bytecode},
    };
    use tempo_evm::TempoEvmFactory;
    use tempo_precompiles::{
        TIP20_FACTORY_ADDRESS,
        storage::{StorageCtx, evm::EvmPrecompileStorageProvider},
        test_util::TIP20Setup,
        tip20::ITIP20,
    };

    use crate::TempoEvm;

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
            TIP20Setup::create("USD", "USD", Address::ZERO).apply()
        })?;
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

    #[test]
    fn test_inspector_calls() -> eyre::Result<()> {
        // This test calls TIP20 setSupplyCap which emits a SupplyCapUpdate log event
        use alloy_sol_types::SolCall;
        use tempo_precompiles::PATH_USD_ADDRESS;

        let caller = Address::repeat_byte(0x01);
        let contract = Address::repeat_byte(0x42);

        let input_bytes = ITIP20::setSupplyCapCall {
            newSupplyCap: U256::from(100),
        }
        .abi_encode();

        // Create bytecode that calls setSupplyCap(uint256 newSupplyCap) on PATH_USD
        // it is 36 bytes long
        let mut bytecode_bytes = vec![];

        for (i, &byte) in input_bytes.iter().enumerate() {
            bytecode_bytes.extend_from_slice(&[
                opcode::PUSH1,
                byte,
                opcode::PUSH1,
                i as u8,
                opcode::MSTORE8,
            ]);
        }

        // CALL to PATH_USD precompile
        // CALL(gas, addr, value, argsOffset, argsSize, retOffset, retSize)
        bytecode_bytes.extend_from_slice(&[
            opcode::PUSH1,
            0x00, // retSize
            opcode::PUSH1,
            0x00, // retOffset
            opcode::PUSH1,
            0x24, // argsSize (4 + 32 = 36 = 0x24)
            opcode::PUSH1,
            0x00, // argsOffset
            opcode::PUSH1,
            0x00, // value = 0
        ]);

        // PUSH20 PATH_USD_ADDRESS
        bytecode_bytes.push(opcode::PUSH20);
        bytecode_bytes.extend_from_slice(PATH_USD_ADDRESS.as_slice());

        bytecode_bytes.extend_from_slice(&[
            opcode::PUSH2,
            0xFF,
            0xFF, // gas
            opcode::CALL,
            opcode::POP, // pop success/failure
            opcode::STOP,
        ]);

        let bytecode = Bytecode::new_raw(bytecode_bytes.into());

        // Set up EVM with TIP20 infrastructure
        let db = CacheDB::new(EmptyDB::new());

        let ctx = Context::mainnet()
            .with_db(db)
            .with_block(Default::default())
            .with_cfg(Default::default())
            .with_tx(Default::default());

        let mut evm: TempoEvm<CacheDB<EmptyDB>, _> = TempoEvm::new(ctx, CountInspector::new());
        // Set up TIP20 using the storage context pattern
        {
            let ctx = &mut evm.ctx;
            let mut storage = EvmPrecompileStorageProvider::new_max_gas(
                EvmInternals::new(&mut ctx.journaled_state, &ctx.block),
                &ctx.cfg,
            );
            StorageCtx::enter(&mut storage, || {
                TIP20Setup::path_usd(caller)
                    .with_issuer(caller)
                    .with_admin(contract) // Grant admin role to contract so it can call setSupplyCap
                    .apply()
            })?;
        }

        // Deploy the contract bytecode
        evm.ctx.db_mut().insert_account_info(
            contract,
            AccountInfo {
                code: Some(bytecode),
                ..Default::default()
            },
        );

        // Execute a call to the contract
        let tx_env = TxEnv {
            caller,
            kind: TxKind::Call(contract),
            gas_price: 0,
            gas_limit: 1_000_000,
            ..Default::default()
        };
        let result = evm
            .inspect_tx(tx_env.into())
            .expect("execution should succeed");

        assert!(
            result.result.is_success(),
            "Transaction should succeed: {:?}",
            result.result
        );

        // Verify that a SupplyCapUpdate log was emitted by the TIP20 precompile
        assert_eq!(
            result.result.logs().len(),
            2,
            "Should have emitted 1 log, result: {:?}",
            result.result
        );
        assert_eq!(
            result.result.logs()[0].address,
            TIP20_FACTORY_ADDRESS,
            "Log should be from TIP20_FACTORY"
        );

        // Get the inspector and verify counts
        let inspector = &evm.inspector;

        // Verify CALL opcode was executed (the call to PATH_USD)
        assert_eq!(
            inspector.get_count(opcode::CALL),
            1,
            "Should have 1 CALL opcode"
        );
        assert_eq!(
            inspector.get_count(opcode::STOP),
            1,
            "Should have 1 STOP opcode"
        );

        // Verify log count
        assert_eq!(inspector.log_count(), 1, "Should have 1 log");

        // Verify call count (initial tx + CALL to PATH_USD)
        assert_eq!(
            inspector.call_count(),
            2,
            "Should have 2 calls (initial tx + CALL)"
        );

        assert_eq!(inspector.call_end_count(), 2, "Should have 2 call ends");

        Ok(())
    }
}
