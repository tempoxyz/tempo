use alloy::sol_types::SolCall;
use alloy_primitives::{Address, Bytes, U256};
use reth_evm::{Database, EthEvm, Evm, EvmEnv, precompiles::PrecompilesMap};
use reth_revm::{
    Context, Inspector,
    context::{
        BlockEnv, CfgEnv, ContextTr, JournalTr, Transaction, TxEnv,
        result::{
            EVMError, ExecResultAndState, ExecutionResult, HaltReason, InvalidTransaction,
            ResultAndState,
        },
    },
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::InterpreterResult,
    primitives::hardfork::SpecId,
    state::EvmState,
};
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

impl<DB: Database, I, PRECOMPILE> TempoEvm<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<TempoEvmContext<DB>>,
{
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
    /// Creates a new Tempo EVM instance.
    ///
    /// The `inspect` argument determines whether the configured [`Inspector`] of the given
    /// `RevmEvm` should be invoked on [`Evm::transact`].
    pub fn new(mut evm: EthEvm<DB, I, PrecompilesMap>, inspect: bool) -> Self {
        evm.cfg.disable_balance_check = true;
        let chain_id = evm.chain_id();
        precompiles::extend_tempo_precompiles(evm.precompiles_mut(), chain_id);

        Self {
            inner: evm,
            inspect,
        }
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

        // NOTE: transact_system_call clears the journal so we need to commit to journal state
        if balance_result.result.is_success() {
            self.journal_state(balance_result.state)?;
        }

        let output = balance_result.result.output().unwrap_or_default();
        let return_val = IFeeManager::getFeeTokenBalanceCall::abi_decode_returns(output)
            .map_err(|e| EVMError::Custom(format!("Failed to decode fee token balance: {e}")))?;

        Ok((return_val._0, return_val._1.to::<u64>()))
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

        if exec_result.result.is_success() {
            self.journal_state(exec_result.state.clone())?;
        }

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

        if exec_result.result.is_success() {
            self.journal_state(exec_result.state.clone())?;
        }

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

        if exec_result.result.is_success() {
            self.journal_state(exec_result.state.clone())?;
        }

        Ok(exec_result)
    }

    pub fn journal_state(&mut self, state: EvmState) -> Result<(), EVMError<DB::Error>> {
        let journal = self.inner.ctx_mut().journal_mut();
        for (address, account) in state.iter() {
            if !account.is_touched() {
                continue;
            }

            journal
                .load_account(*address)
                .map_err(|e| EVMError::Custom(format!("Failed to load account {address}: {e}")))?;
            journal.touch_account(*address);

            if account.is_selfdestructed() {
                // FIXME: Get `target` for self destruct
                //
                // NOTE: journal_state is only called after increment_gas_fee,
                // decrement_gas_fee and collect_fee. There should never be a self destruct but
                // it would be nice to have `journal_state` as a general fn.
                journal
                    .selfdestruct(*address, Address::ZERO)
                    .expect("Failed to selfdestruct account");
                continue;
            }

            if let Some(code) = &account.info.code {
                journal.set_code(*address, code.clone());
            }

            // TODO: we are not setting acct info atm

            for (key, value) in account.storage.iter() {
                journal
                    .sstore(*address, *key, value.present_value())
                    .map_err(|e| {
                        EVMError::Custom(format!("Failed to store value at {address}: {e}"))
                    })?;
            }
        }
        Ok(())
    }
}

impl<DB: Database, I, PRECOMPILE> Deref for TempoEvm<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<TempoEvmContext<DB>>,
{
    type Target = TempoEvmContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I, PRECOMPILE> DerefMut for TempoEvm<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<TempoEvmContext<DB>>,
{
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

        // All fee tokens are denominated in 6 decimals. Since gas is 9 decimals, the fee is
        // adjusted for decimals and rounded up.
        let gas_fee = tx.max_balance_spending()?;
        let adjusted_fee = gas_fee.div_ceil(U256::from(1000));

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
        if res.result.is_success() {
            self.journal_state(res.state.clone())?;
        } else {
            return Ok(res);
        }
        self.increment_gas_fee(caller, fee_token, adjusted_fee)?;

        // Adjust gas to 6 decimals and collect fees
        let adjusted_gas_spent = (res.result.gas_used() / 1000) + 1;
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
    use alloy_primitives::U256;

    use reth::revm::{
        context::ContextTr,
        db::{CacheDB, EmptyDB},
        inspector::NoOpInspector,
    };
    use reth_evm::{EvmEnv, EvmFactory, EvmInternals, precompiles::PrecompilesMap};
    use reth_revm::DatabaseCommit;
    use tempo_precompiles::{
        TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
        contracts::{
            ITIP20Factory, TIP20Token,
            storage::evm::EvmStorageProvider,
            tip20::ISSUER_ROLE,
            token_id_to_address,
            types::{IFeeManager, ITIP20},
        },
    };

    fn setup_tempo_evm() -> TempoEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap> {
        let db = CacheDB::default();
        let env = EvmEnv::default();
        let factory = TempoEvmFactory::default();
        factory.create_evm(db, env)
    }

    fn create_and_mint_token(
        symbol: String,
        name: String,
        currency: String,
        admin: Address,
        mint_amount: U256,
        evm: &mut TempoEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap>,
    ) -> eyre::Result<Address> {
        let create_token_call = ITIP20Factory::createTokenCall {
            name,
            symbol,
            currency,
            admin,
        };

        let result = evm.transact_system_call(
            admin,
            TIP20_FACTORY_ADDRESS,
            create_token_call.abi_encode().into(),
        )?;
        assert!(result.result.is_success(), "Token creation failed");
        evm.journal_state(result.state)?;

        let output = result.result.output().unwrap_or_default();
        let token_id = ITIP20Factory::createTokenCall::abi_decode_returns(output)?.to::<u64>();
        let token_address = token_id_to_address(token_id);

        let block = evm.block.clone();
        let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
        let mut provider = EvmStorageProvider::new(evm_internals, 1);

        let mut token = TIP20Token::new(token_id, &mut provider);
        token
            .get_roles_contract()
            .grant_role_internal(&admin, *ISSUER_ROLE);

        let result = token.set_supply_cap(
            &admin,
            ITIP20::setSupplyCapCall {
                newSupplyCap: U256::from(u64::MAX),
            },
        );
        assert!(result.is_ok());

        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: admin,
                    amount: mint_amount,
                },
            )
            .expect("Token minting failed");

        Ok(token_address)
    }

    fn balance_of_call(
        evm: &mut TempoEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap>,
        account: Address,
        token: Address,
    ) -> eyre::Result<u64> {
        let balance_call = ITIP20::balanceOfCall { account };
        let result = evm.transact_system_call(account, token, balance_call.abi_encode().into())?;
        evm.journal_state(result.state)
            .expect("Failed to journal state");

        let output = result.result.output().unwrap_or_default();
        let balance = ITIP20::balanceOfCall::abi_decode_returns(output)?;

        Ok(balance.to::<u64>())
    }

    fn transfer_tokens(
        evm: &mut TempoEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap>,
        from: Address,
        to: Address,
        token: Address,
        amount: U256,
    ) -> eyre::Result<()> {
        let result = evm.transact_system_call(
            from,
            token,
            ITIP20::transferCall { to, amount }.abi_encode().into(),
        )?;
        assert!(result.result.is_success(), "Token transfer failed");
        evm.journal_state(result.state)?;
        Ok(())
    }

    fn set_user_fee_token(
        evm: &mut TempoEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap>,
        user: Address,
        token: Address,
    ) -> eyre::Result<()> {
        let set_fee_token_call = IFeeManager::setUserTokenCall { token };
        let result = evm.transact_system_call(
            user,
            TIP_FEE_MANAGER_ADDRESS,
            set_fee_token_call.abi_encode().into(),
        )?;
        assert!(result.result.is_success(), "Setting user fee token failed");
        evm.journal_state(result.state)?;
        Ok(())
    }

    fn set_validator_fee_token(
        evm: &mut TempoEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap>,
        validator: Address,
        token: Address,
    ) -> eyre::Result<()> {
        let set_validator_fee_token_call = IFeeManager::setValidatorTokenCall { token };
        let result = evm.transact_system_call(
            validator,
            TIP_FEE_MANAGER_ADDRESS,
            set_validator_fee_token_call.abi_encode().into(),
        )?;
        assert!(
            result.result.is_success(),
            "Setting validator fee token failed"
        );
        evm.journal_state(result.state)?;
        Ok(())
    }

    fn approve_fee_manager(
        evm: &mut TempoEvm<CacheDB<EmptyDB>, NoOpInspector, PrecompilesMap>,
        user: Address,
        token: Address,
    ) -> eyre::Result<()> {
        let result = evm.transact_system_call(
            user,
            token,
            ITIP20::approveCall {
                spender: TIP_FEE_MANAGER_ADDRESS,
                amount: U256::MAX,
            }
            .abi_encode()
            .into(),
        )?;
        assert!(result.result.is_success(), "Fee manager approval failed");
        evm.journal_state(result.state)?;
        Ok(())
    }

    #[test]
    fn test_get_gas_fee_token_balance() -> eyre::Result<()> {
        let mut evm = setup_tempo_evm();
        let admin = Address::random();
        let fee_token = create_and_mint_token(
            "T".to_string(),
            "TestUSD".to_string(),
            "USD".to_string(),
            admin,
            U256::from(10000),
            &mut evm,
        )?;

        // Assert that the fee token is not set
        let sender = Address::random();
        let (user_fee_token, balance) = evm.get_fee_token_balance(sender)?;

        assert_eq!(user_fee_token, Address::ZERO);
        assert_eq!(balance, 0);

        set_user_fee_token(&mut evm, sender, fee_token)?;

        let fee_balance = 1000;
        transfer_tokens(&mut evm, admin, sender, fee_token, U256::from(fee_balance))?;

        let (token_address, balance) = evm.get_fee_token_balance(sender)?;
        assert_eq!(fee_token, token_address);
        assert_eq!(balance, fee_balance);

        Ok(())
    }

    #[test]
    fn test_decrement_increment_gas_fee() -> eyre::Result<()> {
        let mut evm = setup_tempo_evm();
        let admin = Address::random();
        let fee_token = create_and_mint_token(
            "T".to_string(),
            "TestUSD".to_string(),
            "USD".to_string(),
            admin,
            U256::from(10000),
            &mut evm,
        )?;

        let caller = Address::random();

        transfer_tokens(&mut evm, admin, caller, fee_token, U256::from(1000))?;
        let initial_balance = balance_of_call(&mut evm, caller, fee_token)?;

        // Decrement gas fee
        let gas_fee = U256::from(100);
        let result = evm.decrement_gas_fee(caller, fee_token, gas_fee)?;
        assert!(result.result.is_success());

        let decremented_balance = balance_of_call(&mut evm, caller, fee_token)?;
        assert_eq!(decremented_balance, initial_balance - gas_fee.to::<u64>());

        // Increment gas fee
        let result = evm.increment_gas_fee(caller, fee_token, gas_fee)?;
        assert!(result.result.is_success());

        let incremented_balance = balance_of_call(&mut evm, caller, fee_token)?;
        assert_eq!(incremented_balance, initial_balance);
        Ok(())
    }

    #[test]
    fn test_transact_raw() -> eyre::Result<()> {
        let mut evm = setup_tempo_evm();
        let validator = Address::random();
        let user = Address::random();
        let recipient = Address::random();

        // Create fee token and transfer token
        let mint_amount = U256::from(u64::MAX);
        let fee_token = create_and_mint_token(
            "F".to_string(),
            "FeeToken".to_string(),
            "USD".to_string(),
            validator,
            mint_amount,
            &mut evm,
        )?;

        let transfer_token = create_and_mint_token(
            "T".to_string(),
            "TransferToken".to_string(),
            "USD".to_string(),
            validator,
            mint_amount,
            &mut evm,
        )?;

        transfer_tokens(&mut evm, validator, user, fee_token, mint_amount)?;
        transfer_tokens(&mut evm, validator, user, transfer_token, mint_amount)?;
        set_user_fee_token(&mut evm, user, fee_token)?;
        set_validator_fee_token(&mut evm, validator, fee_token)?;
        approve_fee_manager(&mut evm, user, fee_token)?;

        // Check initial balances
        let initial_fee_balance = balance_of_call(&mut evm, user, fee_token)?;
        let initial_transfer_balance = balance_of_call(&mut evm, user, transfer_token)?;

        // Create transaction to transfer tokens
        let tx = TxEnv {
            caller: user,
            kind: transfer_token.into(),
            data: ITIP20::transferCall {
                to: recipient,
                amount: U256::ONE,
            }
            .abi_encode()
            .into(),
            gas_limit: 30000,
            gas_price: 1,
            value: U256::ZERO,
            ..Default::default()
        };

        // Execute transaction
        evm.ctx_mut().block.beneficiary = validator;
        let result = evm.transact_raw(tx)?;
        assert!(result.result.is_success(), "Transaction should succeed");
        evm.db_mut().commit(result.state);

        // Verify balances after transaction
        let final_transfer_balance = balance_of_call(&mut evm, user, transfer_token)?;
        let recipient_balance = balance_of_call(&mut evm, recipient, transfer_token)?;
        let final_fee_balance = balance_of_call(&mut evm, user, fee_token)?;

        assert_eq!(
            final_fee_balance,
            initial_fee_balance - result.result.gas_used().div_ceil(1000)
        );
        assert_eq!(final_transfer_balance, initial_transfer_balance - 1);
        assert_eq!(recipient_balance, 1);

        Ok(())
    }

    #[test]
    fn test_transact_raw_insufficient_balance() -> eyre::Result<()> {
        let mut evm = setup_tempo_evm();
        let admin = Address::random();
        let user = Address::random();
        let recipient = Address::random();

        // Create fee token with minimal mint amount
        let mint_amount = U256::from(1000);
        let fee_token = create_and_mint_token(
            "F".to_string(),
            "FeeToken".to_string(),
            "USD".to_string(),
            admin,
            mint_amount,
            &mut evm,
        )?;

        let transfer_token = create_and_mint_token(
            "T".to_string(),
            "TransferToken".to_string(),
            "USD".to_string(),
            admin,
            mint_amount,
            &mut evm,
        )?;

        transfer_tokens(&mut evm, admin, user, fee_token, U256::from(10))?;
        transfer_tokens(&mut evm, admin, user, transfer_token, mint_amount)?;
        set_user_fee_token(&mut evm, user, fee_token)?;

        // Create tx with gas limit higher than fee balance
        let gas_limit = 50000;
        let tx = TxEnv {
            caller: user,
            kind: transfer_token.into(),
            data: ITIP20::transferCall {
                to: recipient,
                amount: U256::ONE,
            }
            .abi_encode()
            .into(),
            gas_limit,
            gas_price: 1,
            value: U256::ZERO,
            ..Default::default()
        };

        let result = evm.transact_raw(tx);

        match result {
            Err(EVMError::Transaction(InvalidTransaction::LackOfFundForMaxFee {
                fee,
                balance,
            })) => {
                let expected_adjusted_fee = U256::from(gas_limit.div_ceil(1000));
                assert_eq!(*fee, expected_adjusted_fee);
                assert_eq!(*balance, U256::from(10));
            }
            _ => panic!("Expected LackOfFundForMaxFee error, got: {:?}", result),
        }

        Ok(())
    }

    #[test]
    fn test_transact_raw_overflow_payment() -> eyre::Result<()> {
        let mut evm = setup_tempo_evm();
        let admin = Address::random();
        let user = Address::random();

        let fee_token = create_and_mint_token(
            "F".to_string(),
            "FeeToken".to_string(),
            "USD".to_string(),
            admin,
            U256::from(u64::MAX),
            &mut evm,
        )?;

        transfer_tokens(&mut evm, admin, user, fee_token, U256::from(u64::MAX))?;
        set_user_fee_token(&mut evm, user, fee_token)?;

        // Create a transaction with values that would cause overflow in max_balance_spending calculation
        let tx = TxEnv {
            caller: user,
            kind: fee_token.into(),
            gas_limit: u64::MAX,
            gas_price: u128::MAX,
            value: U256::MAX,
            data: Bytes::default(),
            ..Default::default()
        };

        let result = evm.transact_raw(tx);
        assert!(matches!(
            result.err().unwrap(),
            EVMError::Transaction(InvalidTransaction::OverflowPaymentInTransaction)
        ));

        Ok(())
    }
}
