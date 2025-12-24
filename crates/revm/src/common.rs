use crate::TempoTxEnv;
use alloy_consensus::transaction::{Either, Recovered};
use alloy_primitives::{Address, Bytes, LogData, TxKind, U256};
use alloy_sol_types::SolCall;
use core::marker::PhantomData;
use revm::{
    Database,
    context::JournalTr,
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IFeeManager, IStablecoinExchange, ITIP403Registry,
    STABLECOIN_EXCHANGE_ADDRESS,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    error::{Result as TempoResult, TempoPrecompileError},
    storage::{Handler, PrecompileStorageProvider, StorageCtx},
    tip_fee_manager::TipFeeManager,
    tip20::{self, ITIP20, TIP20Token, is_tip20_prefix},
    tip403_registry::TIP403Registry,
};
use tempo_primitives::TempoTxEnvelope;

/// Returns true if the calldata is for a TIP-20 function that should trigger fee token inference.
/// Only `transfer`, `transferWithMemo`, and `distributeReward` qualify.
fn is_tip20_fee_inference_call(input: &[u8]) -> bool {
    input.first_chunk::<4>().is_some_and(|&s| {
        matches!(
            s,
            ITIP20::transferCall::SELECTOR
                | ITIP20::transferWithMemoCall::SELECTOR
                | ITIP20::distributeRewardCall::SELECTOR
        )
    })
}

/// Helper trait to abstract over different representations of Tempo transactions.
#[auto_impl::auto_impl(&)]
pub trait TempoTx {
    /// Returns the transaction's `feeToken` field, if configured.
    fn fee_token(&self) -> Option<Address>;

    /// Returns true if this is an AA transaction.
    fn is_aa(&self) -> bool;

    /// Returns an iterator over the transaction's calls.
    fn calls(&self) -> impl Iterator<Item = (TxKind, &Bytes)>;

    /// Returns the transaction's caller address.
    fn caller(&self) -> Address;
}

impl TempoTx for TempoTxEnv {
    fn fee_token(&self) -> Option<Address> {
        self.fee_token
    }

    fn is_aa(&self) -> bool {
        self.tempo_tx_env.is_some()
    }

    fn calls(&self) -> impl Iterator<Item = (TxKind, &Bytes)> {
        if let Some(aa) = self.tempo_tx_env.as_ref() {
            Either::Left(aa.aa_calls.iter().map(|call| (call.to, &call.input)))
        } else {
            Either::Right(core::iter::once((self.inner.kind, &self.inner.data)))
        }
    }

    fn caller(&self) -> Address {
        self.inner.caller
    }
}

impl TempoTx for Recovered<TempoTxEnvelope> {
    fn fee_token(&self) -> Option<Address> {
        self.inner().fee_token()
    }

    fn is_aa(&self) -> bool {
        self.inner().is_aa()
    }

    fn calls(&self) -> impl Iterator<Item = (TxKind, &Bytes)> {
        self.inner().calls()
    }

    fn caller(&self) -> Address {
        self.signer()
    }
}

/// Helper trait to perform Tempo-specific operations on top of different state providers.
///
/// We provide blanket implementations for revm database, journal and reth state provider.
///
/// The generic marker is used as a workaround to avoid conflicting implementations.
pub trait TempoStateAccess<M = ()> {
    /// Error type returned by storage operations.
    type Error: core::fmt::Display;

    /// Returns [`AccountInfo`] for the given address.
    fn basic(&mut self, address: Address) -> Result<AccountInfo, Self::Error>;

    /// Returns the storage value for the given address and key.
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error>;

    /// Returns a read-only storage provider for the given spec.
    fn with_read_only_storage_ctx<R>(&mut self, f: impl FnOnce() -> R) -> R
    where
        Self: Sized,
    {
        let spec = TempoHardfork::default();
        StorageCtx::enter(&mut ReadOnlyStorageProvider::new(self, spec), f)
    }

    /// Resolves user-level or transaction-level fee token preference.
    fn get_fee_token(&mut self, tx: impl TempoTx, fee_payer: Address) -> TempoResult<Address>
    where
        Self: Sized,
    {
        // If there is a fee token explicitly set on the tx type, use that.
        if let Some(fee_token) = tx.fee_token() {
            return Ok(fee_token);
        }

        // If the fee payer is also the msg.sender and the transaction is calling FeeManager to set a
        // new preference, the newly set preference should be used immediately instead of the
        // previously stored one
        if !tx.is_aa()
            && fee_payer == tx.caller()
            && let Some((kind, input)) = tx.calls().next()
            && kind.to() == Some(&TIP_FEE_MANAGER_ADDRESS)
            && let Ok(call) = IFeeManager::setUserTokenCall::abi_decode(input)
        {
            return Ok(call.token);
        }

        // Check stored user token preference
        let user_token = self.with_read_only_storage_ctx(|| {
            // ensure TIP_FEE_MANAGER_ADDRESS is loaded
            TipFeeManager::new().user_tokens.at(fee_payer).read()
        })?;

        if !user_token.is_zero() {
            return Ok(user_token);
        }

        // Check if the fee can be inferred from the TIP20 token being called
        if let Some(to) = tx.calls().next().and_then(|(kind, _)| kind.to().copied()) {
            let can_infer_tip20 =
                // AA txs only when fee_payer == tx.origin.
                if tx.is_aa() && fee_payer != tx.caller() {
                    false
                }
                // Otherwise, restricted to transfer/transferWithMemo/distributeReward,
                else {
                    tx.calls().all(|(kind, input)| {
                        kind.to() == Some(&to) && is_tip20_fee_inference_call(input)
                    })
                }
            ;

            if can_infer_tip20 && self.is_valid_fee_token(to)? {
                return Ok(to);
            }
        }

        // If calling swapExactAmountOut() or swapExactAmountIn() on the Stablecoin Exchange,
        // use the input token as the fee token (the token that will be pulled from the user).
        // For AA transactions, this only applies if there's exactly one call.
        let mut calls = tx.calls();
        if let Some((kind, input)) = calls.next()
            && kind.to() == Some(&STABLECOIN_EXCHANGE_ADDRESS)
            && (!tx.is_aa() || calls.next().is_none())
        {
            if let Ok(call) = IStablecoinExchange::swapExactAmountInCall::abi_decode(input)
                && self.is_valid_fee_token(call.tokenIn)?
            {
                return Ok(call.tokenIn);
            } else if let Ok(call) = IStablecoinExchange::swapExactAmountOutCall::abi_decode(input)
                && self.is_valid_fee_token(call.tokenIn)?
            {
                return Ok(call.tokenIn);
            }
        }

        // If no fee token is found, default to the first deployed TIP20
        Ok(DEFAULT_FEE_TOKEN)
    }

    /// Checks if the given token can be used as a fee token.
    fn is_valid_fee_token(&mut self, fee_token: Address) -> TempoResult<bool>
    where
        Self: Sized,
    {
        // Must have TIP20 prefix to be a valid fee token
        if !is_tip20_prefix(fee_token) {
            return Ok(false);
        }

        // Ensure the currency is USD
        // load fee token account to ensure that we can load storage for it.
        self.with_read_only_storage_ctx(|| {
            let token = TIP20Token::new(tip20::address_to_token_id_unchecked(fee_token));
            Ok(token.currency.len()? == 3 && token.currency.read()?.as_str() == "USD")
        })
    }

    /// Checks if the fee payer can transfer a given token (is not blacklisted).
    fn can_fee_payer_transfer(
        &mut self,
        fee_token: Address,
        fee_payer: Address,
    ) -> TempoResult<bool>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(|| {
            // Ensure the fee payer is not blacklisted
            let transfer_policy_id = TIP20Token::from_address(fee_token)?
                .transfer_policy_id
                .read()?;
            TIP403Registry::new().is_authorized(ITIP403Registry::isAuthorizedCall {
                policyId: transfer_policy_id,
                user: fee_payer,
            })
        })
    }

    /// Returns the balance of the given token for the given account.
    ///
    /// IMPORTANT: the caller must ensure `token` is a valid TIP20Token address.
    fn get_token_balance(&mut self, token: Address, account: Address) -> TempoResult<U256>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(|| {
            // Load the token balance for the given account.
            TIP20Token::from_address(token)?.balances.at(account).read()
        })
    }
}

impl<DB: Database> TempoStateAccess<()> for DB {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<AccountInfo, Self::Error> {
        self.basic(address).map(Option::unwrap_or_default)
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        self.storage(address, key)
    }
}

impl<T: JournalTr> TempoStateAccess<((), ())> for T {
    type Error = <T::Database as Database>::Error;

    fn basic(&mut self, address: Address) -> Result<AccountInfo, Self::Error> {
        self.load_account(address).map(|s| s.data.info.clone())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        JournalTr::sload(self, address, key).map(|s| s.data)
    }
}

#[cfg(feature = "reth")]
impl<T: reth_storage_api::StateProvider> TempoStateAccess<((), (), ())> for T {
    type Error = reth_evm::execute::ProviderError;

    fn basic(&mut self, address: Address) -> Result<AccountInfo, Self::Error> {
        self.basic_account(&address)
            .map(Option::unwrap_or_default)
            .map(Into::into)
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        self.storage(address, key.into())
            .map(Option::unwrap_or_default)
    }
}

/// Read-only storage provider that wraps a `TempoStateAccess`.
///
/// Implements `PrecompileStorageProvider` by delegating read operations to the backend
/// and returning errors for write operations.
///
/// The marker generic `M` selects which `TempoStateAccess<M>` impl to use for the backend.
struct ReadOnlyStorageProvider<'a, S, M = ()> {
    state: &'a mut S,
    spec: TempoHardfork,
    _marker: PhantomData<M>,
}

impl<'a, S, M> ReadOnlyStorageProvider<'a, S, M>
where
    S: TempoStateAccess<M>,
{
    /// Creates a new read-only storage provider.
    fn new(state: &'a mut S, spec: TempoHardfork) -> Self {
        Self {
            state,
            spec,
            _marker: PhantomData,
        }
    }
}

impl<S, M> PrecompileStorageProvider for ReadOnlyStorageProvider<'_, S, M>
where
    S: TempoStateAccess<M>,
{
    fn spec(&self) -> TempoHardfork {
        self.spec
    }

    fn is_static(&self) -> bool {
        // read-only operations should always be static
        true
    }

    fn sload(&mut self, address: Address, key: U256) -> TempoResult<U256> {
        let _ = self
            .state
            .basic(address)
            .map_err(|e| TempoPrecompileError::Fatal(e.to_string()))?;
        self.state
            .sload(address, key)
            .map_err(|e| TempoPrecompileError::Fatal(e.to_string()))
    }

    fn with_account_info(
        &mut self,
        address: Address,
        f: &mut dyn FnMut(&AccountInfo),
    ) -> TempoResult<()> {
        let info = self
            .state
            .basic(address)
            .map_err(|e| TempoPrecompileError::Fatal(e.to_string()))?;
        f(&info);
        Ok(())
    }

    // No-op methods are unimplemented in read-only context.
    fn chain_id(&self) -> u64 {
        unreachable!("'chain_id' not implemented in read-only context yet")
    }

    fn timestamp(&self) -> U256 {
        unreachable!("'timestamp' not implemented in read-only context yet")
    }

    fn beneficiary(&self) -> Address {
        unreachable!("'beneficiary' not implemented in read-only context yet")
    }

    fn tload(&mut self, _: Address, _: U256) -> TempoResult<U256> {
        unreachable!("'tload' not implemented in read-only context yet")
    }

    fn gas_used(&self) -> u64 {
        unreachable!("'gas_used' not implemented in read-only context yet")
    }

    fn gas_refunded(&self) -> i64 {
        unreachable!("'gas_refunded' not implemented in read-only context yet")
    }

    // Write operations are not supported in read-only context
    fn sstore(&mut self, _: Address, _: U256, _: U256) -> TempoResult<()> {
        unreachable!("'sstore' not supported in read-only context")
    }

    fn set_code(&mut self, _: Address, _: Bytecode) -> TempoResult<()> {
        unreachable!("'set_code' not supported in read-only context")
    }

    fn emit_event(&mut self, _: Address, _: LogData) -> TempoResult<()> {
        unreachable!("'emit_event' not supported in read-only context")
    }

    fn tstore(&mut self, _: Address, _: U256, _: U256) -> TempoResult<()> {
        unreachable!("'tstore' not supported in read-only context")
    }

    fn deduct_gas(&mut self, _: u64) -> TempoResult<()> {
        unreachable!("'deduct_gas' not supported in read-only context")
    }

    fn refund_gas(&mut self, _: i64) {
        unreachable!("'refund_gas' not supported in read-only context")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use revm::{context::TxEnv, database::EmptyDB, interpreter::instructions::utility::IntoU256};
    use tempo_precompiles::tip20;

    #[test]
    fn test_get_fee_token_fee_token_set() -> eyre::Result<()> {
        let caller = Address::random();
        let fee_token = Address::random();

        let tx_env = TxEnv {
            data: Bytes::new(),
            caller,
            ..Default::default()
        };
        let tx = TempoTxEnv {
            inner: tx_env,
            fee_token: Some(fee_token),
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let token = db.get_fee_token(tx, caller)?;
        assert_eq!(token, fee_token);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_fee_manager() -> eyre::Result<()> {
        let caller = Address::random();
        let token = Address::random();

        let call = IFeeManager::setUserTokenCall { token };
        let tx_env = TxEnv {
            data: call.abi_encode().into(),
            kind: TxKind::Call(TIP_FEE_MANAGER_ADDRESS),
            caller,
            ..Default::default()
        };
        let tx = TempoTxEnv {
            inner: tx_env,
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let result_token = db.get_fee_token(tx, caller)?;
        assert_eq!(result_token, token);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_user_token_set() -> eyre::Result<()> {
        let caller = Address::random();
        let user_token = Address::random();

        // Set user stored token preference in the FeeManager
        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let user_slot = TipFeeManager::new().user_tokens.at(caller).slot();
        db.insert_account_storage(TIP_FEE_MANAGER_ADDRESS, user_slot, user_token.into_u256())
            .unwrap();

        let result_token = db.get_fee_token(TempoTxEnv::default(), caller)?;
        assert_eq!(result_token, user_token);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_tip20() -> eyre::Result<()> {
        let caller = Address::random();
        let tip20_token = Address::random();

        let tx_env = TxEnv {
            data: Bytes::from_static(b"transfer_data"),
            kind: TxKind::Call(tip20_token),
            caller,
            ..Default::default()
        };
        let tx = TempoTxEnv {
            inner: tx_env,
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let result_token = db.get_fee_token(tx, caller)?;
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_fallback() -> eyre::Result<()> {
        let caller = Address::random();
        let tx_env = TxEnv {
            caller,
            ..Default::default()
        };
        let tx = TempoTxEnv {
            inner: tx_env,
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let result_token = db.get_fee_token(tx, caller)?;
        // Should fallback to DEFAULT_FEE_TOKEN when no preferences are found
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_stablecoin_exchange() -> eyre::Result<()> {
        let caller = Address::random();
        // Use PathUSD as token_in since it's a known valid USD fee token
        let token_in = DEFAULT_FEE_TOKEN;
        let token_out = address!("0x20C0000000000000000000000000000000000001");

        // Test swapExactAmountIn
        let call = IStablecoinExchange::swapExactAmountInCall {
            tokenIn: token_in,
            tokenOut: token_out,
            amountIn: 1000,
            minAmountOut: 900,
        };

        let tx_env = TxEnv {
            data: call.abi_encode().into(),
            kind: TxKind::Call(STABLECOIN_EXCHANGE_ADDRESS),
            caller,
            ..Default::default()
        };
        let tx = TempoTxEnv {
            inner: tx_env,
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        // Stablecoin exchange fee token inference requires Allegretto hardfork
        let token = db.get_fee_token(tx, caller)?;
        assert_eq!(token, token_in);

        // Test swapExactAmountOut
        let call = IStablecoinExchange::swapExactAmountOutCall {
            tokenIn: token_in,
            tokenOut: token_out,
            amountOut: 900,
            maxAmountIn: 1000,
        };

        let tx_env = TxEnv {
            data: call.abi_encode().into(),
            kind: TxKind::Call(STABLECOIN_EXCHANGE_ADDRESS),
            caller,
            ..Default::default()
        };

        let tx = TempoTxEnv {
            inner: tx_env,
            ..Default::default()
        };

        let token = db.get_fee_token(tx, caller)?;
        assert_eq!(token, token_in);

        Ok(())
    }

    #[test]
    fn test_read_token_balance_typed_storage() -> eyre::Result<()> {
        // Create a TIP-20 token address
        let token_id = 1u64;
        let token_address = tip20::token_id_to_address(token_id);
        let account = Address::random();
        let expected_balance = U256::from(1000u64);

        // Set up CacheDB with balance
        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let balance_slot = TIP20Token::new(token_id).balances.at(account).slot();
        db.insert_account_storage(token_address, balance_slot, expected_balance)?;

        // Read balance using typed storage
        let balance = db.get_token_balance(token_address, account)?;
        assert_eq!(balance, expected_balance);

        Ok(())
    }

    #[test]
    fn test_is_tip20_fee_inference_call() {
        use tempo_precompiles::tip20::{IRolesAuth::*, ITIP20::*};

        // Allowed selectors
        assert!(is_tip20_fee_inference_call(&transferCall::SELECTOR));
        assert!(is_tip20_fee_inference_call(&transferWithMemoCall::SELECTOR));
        assert!(is_tip20_fee_inference_call(&distributeRewardCall::SELECTOR));

        // Disallowed selectors
        assert!(!is_tip20_fee_inference_call(&grantRoleCall::SELECTOR));
        assert!(!is_tip20_fee_inference_call(&mintCall::SELECTOR));
        assert!(!is_tip20_fee_inference_call(&approveCall::SELECTOR));

        // Edge cases
        assert!(!is_tip20_fee_inference_call(&[]));
        assert!(!is_tip20_fee_inference_call(&[0x00, 0x01, 0x02]));
    }
}
