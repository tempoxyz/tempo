use alloy::sol_types::SolCall;
use alloy_primitives::{Address, Bytes, U256};
use reth::revm::{
    Context, Inspector,
    context::{
        BlockEnv, CfgEnv, TxEnv,
        result::{EVMError, HaltReason, InvalidTransaction, ResultAndState},
    },
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::InterpreterResult,
    primitives::hardfork::SpecId,
};
use reth_evm::{Database, EthEvm, Evm, EvmEnv, EvmError};
use std::ops::{Deref, DerefMut};
use tempo_precompiles::{
    TEMPO_FEE_MANAGER_ADDRESS,
    contracts::{
        ITIP20,
        types::IFeeManager::{self, IFeeManagerCalls},
    },
};

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
    pub fn new(evm: EthEvm<DB, I, PRECOMPILE>, inspect: bool) -> Self {
        // TODO:
        // evm.ctx_mut().cfg.disable_nonce_check = true;
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

impl<DB, I, PRECOMPILE> TempoEvm<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<TempoEvmContext<DB>>,
    PRECOMPILE: PrecompileProvider<TempoEvmContext<DB>, Output = InterpreterResult>,
{
    pub fn get_fee_token_balance(
        &mut self,
        sender: Address,
    ) -> Result<(Address, u8, u64), EVMError<DB::Error>> {
        let call_data = IFeeManager::getFeeTokenBalanceCall { sender }
            .abi_encode()
            .into();

        let balance_result =
            self.inner
                .transact_system_call(Address::ZERO, TEMPO_FEE_MANAGER_ADDRESS, call_data)?;
        let output = balance_result.result.output().unwrap_or_default();

        let token_address = Address::from_slice(&output[12..32]);
        let decimals = output[63];
        let balance = U256::from_be_slice(&output[64..96]).to::<u64>();

        Ok((token_address, decimals, balance))
    }

    pub fn collect_fee(&mut self, sender: Address, amount: u64) -> Result<(), EVMError<DB::Error>> {
        let call_data = IFeeManager::collectFeeCall {
            user: sender,
            amount: U256::from(amount),
        }
        .abi_encode()
        .into();

        let exec_result =
            self.inner
                .transact_system_call(Address::ZERO, TEMPO_FEE_MANAGER_ADDRESS, call_data)?;

        // TODO: handle exec result

        Ok(())
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
        mut tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        let caller = tx.caller;
        // Check that the account has a sufficient balance
        let (_, token_decimals, balance) = self.get_fee_token_balance(caller)?;

        let adjusted_balance = if token_decimals < 9 {
            balance * (10 * (9 - token_decimals as u64))
        } else {
            balance / (10 * (token_decimals as u64 - 9))
        };

        if tx.gas_limit > adjusted_balance {
            return Err(EVMError::Transaction(
                InvalidTransaction::LackOfFundForMaxFee {
                    fee: Box::new(U256::from(tx.gas_limit)),
                    balance: Box::new(U256::from(adjusted_balance)),
                },
            ));
        }

        // TODO: collect fees before tx execution

        tx.gas_price = 1;
        let res = self.inner.transact_raw(tx)?;

        // TODO: refund unused gas
        let gas_spent = res.result.gas_used();
        self.collect_fee(caller, gas_spent)?;

        Ok(res)
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
