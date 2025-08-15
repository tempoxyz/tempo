use alloy::sol_types::SolCall;
use alloy_primitives::{Address, Bytes, U256};
use reth::revm::{
    Context, Inspector,
    context::{
        BlockEnv, Cfg, CfgEnv, TxEnv,
        result::{
            EVMError, ExecResultAndState, ExecutionResult, HaltReason, InvalidTransaction,
            ResultAndState,
        },
    },
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::InterpreterResult,
    primitives::hardfork::SpecId,
};
use reth_evm::{Database, EthEvm, Evm, EvmEnv, EvmError, precompiles::PrecompilesMap};
use std::ops::{Deref, DerefMut};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        ITIP20,
        types::IFeeManager::{self},
    },
    precompiles,
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
        // TODO: disable balance check
        // evm.ctx_mut().cfg.disable_balance_check = true;

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

impl<DB, I> TempoEvm<DB, I, PrecompilesMap>
where
    DB: Database,
    I: Inspector<TempoEvmContext<DB>>,
{
    pub fn with_tempo_precompiles(mut self) -> Self {
        let chain_id = self.chain_id();
        precompiles::extend_tempo_precompiles(self.inner.precompiles_mut(), chain_id);
        self
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
    ) -> Result<(Address, u64), EVMError<DB::Error>> {
        let call_data = IFeeManager::getFeeTokenBalanceCall { sender }
            .abi_encode()
            .into();

        let balance_result =
            self.inner
                .transact_system_call(Address::ZERO, TIP_FEE_MANAGER_ADDRESS, call_data)?;

        // TODO: handle failure
        let output = balance_result.result.output().unwrap_or_default();

        let token_address = Address::from_slice(&output[12..32]);
        let balance = U256::from_be_slice(&output[32..64]).to::<u64>();

        Ok((token_address, balance))
    }

    pub fn collect_fee(
        &mut self,
        caller: Address,
        coinbase: Address,
        amount: U256,
    ) -> Result<ExecResultAndState<ExecutionResult>, EVMError<DB::Error>> {
        let call_data = IFeeManager::collectFeeCall {
            user: caller,
            coinbase,
            amount,
        }
        .abi_encode()
        .into();

        let exec_result =
            self.inner
                .transact_system_call(Address::ZERO, TIP_FEE_MANAGER_ADDRESS, call_data)?;

        Ok(exec_result)
    }

    pub fn decrement_gas_fee(
        &mut self,
        caller: Address,
        fee_token: Address,
        gas_fee: U256,
    ) -> Result<ExecResultAndState<ExecutionResult>, EVMError<DB::Error>> {
        let call_data = ITIP20::transferCall {
            to: TIP_FEE_MANAGER_ADDRESS,
            amount: gas_fee,
        }
        .abi_encode()
        .into();

        let exec_result = self
            .inner
            .transact_system_call(caller, fee_token, call_data)?;

        Ok(exec_result)
    }

    pub fn increment_gas_fee(
        &mut self,
        caller: Address,
        fee_token: Address,
        gas_fee: U256,
    ) -> Result<ExecResultAndState<ExecutionResult>, EVMError<DB::Error>> {
        let call_data = ITIP20::transferCall {
            to: caller,
            amount: gas_fee,
        }
        .abi_encode()
        .into();
        let exec_result =
            self.inner
                .transact_system_call(TIP_FEE_MANAGER_ADDRESS, fee_token, call_data)?;

        Ok(exec_result)
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
        let caller = tx.caller;
        let (fee_token, balance) = self.get_fee_token_balance(caller)?;

        // Compute adjusted gas fee and ensure sufficient balance
        let gas_fee = tx.gas_limit * tx.gas_price as u64;
        let adjusted_fee = (gas_fee / 1000) + 1;

        if adjusted_fee > balance {
            return Err(EVMError::Transaction(
                InvalidTransaction::LackOfFundForMaxFee {
                    fee: Box::new(U256::from(adjusted_fee)),
                    balance: Box::new(U256::from(balance)),
                },
            ));
        }

        // Temporarily cache gas fees and execute tx
        let adjusted_fee = U256::from(adjusted_fee);
        self.decrement_gas_fee(caller, fee_token, adjusted_fee)?;
        let res = self.inner.transact_raw(tx)?;
        self.increment_gas_fee(caller, fee_token, adjusted_fee)?;

        // Adjust gas to 6 decimals and collect fees
        let adjusted_gas_spent = (res.result.gas_used() / 1000) - 1;
        let coinbase = self.inner.ctx().block.beneficiary;
        let exec_result = self.collect_fee(caller, coinbase, U256::from(adjusted_gas_spent))?;

        if !exec_result.result.is_success() {
            return Ok(exec_result);
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TempoEvmFactory;
    use alloy_primitives::{B256, U256};
    use rand::random;
    use reth::revm::{
        context::{BlockEnv, CfgEnv, ContextTr},
        db::{CacheDB, EmptyDB},
        inspector::NoOpInspector,
    };
    use reth_evm::{EthEvmFactory, EvmEnv, EvmFactory, precompiles::PrecompilesMap};
    use std::collections::HashMap;
    use tempo_precompiles::{
        TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
        contracts::{
            self, HashMapStorageProvider,
            ITIP20::ITIP20Calls,
            ITIP20Factory, TIP20Token, address_to_token_id_unchecked,
            storage::evm::EvmStorageProvider,
            tip_fee_manager::TipFeeManager,
            tip20::ISSUER_ROLE,
            types::{IFeeManager, ITIP20},
        },
        precompiles::extend_tempo_precompiles,
    };

    fn setup_tempo_evm() -> TempoEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap> {
        let db = CacheDB::default();
        let env = EvmEnv::default();
        let factory = TempoEvmFactory::default();
        factory.create_evm(db, env)
    }

    #[test]
    fn test_get_gas_fee_token_balance() -> eyre::Result<()> {
        let mut evm = setup_tempo_evm();

        // Create the fee token
        let admin = Address::random();
        let create_token_call = ITIP20Factory::createTokenCall {
            name: "TestUSD".into(),
            symbol: "T".into(),
            currency: "USD".into(),
            admin,
        };

        let result = evm.transact_system_call(
            admin,
            TIP20_FACTORY_ADDRESS,
            create_token_call.abi_encode().into(),
        )?;

        assert!(result.result.is_success(), "Token creation failed");

        let output = result.result.output().unwrap_or_default();
        let token_id = ITIP20Factory::createTokenCall::abi_decode_returns(output)?;
        let token_address = contracts::token_id_to_address(token_id.to::<u64>());

        // Assert that the fee token is not set
        let sender = Address::random();
        let (fee_token, balance) = evm.get_fee_token_balance(sender)?;

        assert_eq!(fee_token, Address::ZERO);
        assert_eq!(balance, 0);

        // Set fee token
        let set_fee_token_call = IFeeManager::setUserTokenCall {
            token: token_address,
        };

        let result = evm.transact_system_call(
            sender,
            TIP_FEE_MANAGER_ADDRESS,
            set_fee_token_call.abi_encode().into(),
        )?;
        assert!(result.result.is_success());

        let fee_balance = random::<u64>();
        let mint_call = ITIP20::mintCall {
            to: sender,
            amount: U256::from(fee_balance),
        };

        let result =
            evm.transact_system_call(admin, token_address, mint_call.abi_encode().into())?;
        assert!(result.result.is_success());

        let (fee_token, balance) = evm.get_fee_token_balance(sender)?;
        assert_eq!(fee_token, token_address);
        assert_eq!(balance, fee_balance);

        Ok(())
    }

    #[test]
    fn test_increment_gas_fee() {}

    #[test]
    fn test_decrement_gas_fee() {}

    #[test]
    fn test_transact_raw() {}

    #[test]
    fn test_transact_raw_insufficient_balance() {}
}
