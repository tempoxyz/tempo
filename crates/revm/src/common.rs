use crate::{TempoBlockEnv, TempoInvalidTransaction, TempoTxEnv};
use alloy_consensus::transaction::{Either, Recovered};
use alloy_primitives::{Address, Bytes, LogData, TxKind, U256};
use alloy_sol_types::SolCall;
use core::marker::PhantomData;
use revm::{
    Database,
    context::{JournalTr, result::EVMError},
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, IFeeManager, IStablecoinDEX, STABLECOIN_DEX_ADDRESS,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    error::{Result as TempoResult, TempoPrecompileError},
    storage::{Handler, PrecompileStorageProvider, StorageAction, StorageActions, StorageCtx},
    tip_fee_manager::TipFeeManager,
    tip20::{ITIP20, TIP20Token},
};
use tempo_primitives::{TempoAddressExt, TempoTxEnvelope};

/// Returns true if the calldata is for a TIP-20 function that should trigger fee token inference.
/// `transfer` and `transferWithMemo` always qualify. `distributeReward` qualifies only before T7,
/// when the call still moves tokens.
fn is_tip20_fee_inference_call(spec: TempoHardfork, input: &[u8]) -> bool {
    input.first_chunk::<4>().is_some_and(|&s| {
        matches!(
            s,
            ITIP20::transferCall::SELECTOR | ITIP20::transferWithMemoCall::SELECTOR
        ) || (!spec.is_t7() && s == ITIP20::distributeRewardCall::SELECTOR)
    })
}

/// Helper trait to abstract over different representations of Tempo transactions.
#[auto_impl::auto_impl(&, Arc)]
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
    fn with_read_only_storage_ctx<R>(
        &mut self,
        spec: TempoHardfork,
        actions: StorageActions,
        f: impl FnOnce() -> R,
    ) -> R
    where
        Self: Sized,
    {
        StorageCtx::enter(
            &mut ReadOnlyStorageProvider::new(self, spec).with_actions(actions),
            f,
        )
    }

    /// Resolves user-level or transaction-level fee token preference.
    fn get_fee_token(
        &mut self,
        tx: impl TempoTx,
        fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address>
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
        let user_token = self.with_read_only_storage_ctx(spec, actions.clone(), || {
            // ensure TIP_FEE_MANAGER_ADDRESS is loaded
            TipFeeManager::new().user_tokens[fee_payer].read()
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
                // Otherwise, restricted to TIP-20 calls that move the called token.
                else {
                    tx.calls().all(|(kind, input)| {
                        kind.to() == Some(&to) && is_tip20_fee_inference_call(spec, input)
                    })
                }
            ;

            if can_infer_tip20 && self.is_valid_fee_token(spec, to, actions.clone())? {
                return Ok(to);
            }
        }

        // If calling swapExactAmountOut() or swapExactAmountIn() on the Stablecoin DEX,
        // use the input token as the fee token (the token that will be pulled from the user).
        // For AA transactions, this only applies if there's exactly one call.
        let mut calls = tx.calls();
        if let Some((kind, input)) = calls.next()
            && kind.to() == Some(&STABLECOIN_DEX_ADDRESS)
            && (!tx.is_aa() || calls.next().is_none())
        {
            if let Ok(call) = IStablecoinDEX::swapExactAmountInCall::abi_decode(input)
                && self.is_valid_fee_token(spec, call.tokenIn, actions.clone())?
            {
                return Ok(call.tokenIn);
            } else if let Ok(call) = IStablecoinDEX::swapExactAmountOutCall::abi_decode(input)
                && self.is_valid_fee_token(spec, call.tokenIn, actions)?
            {
                return Ok(call.tokenIn);
            }
        }

        // If no fee token is found, default to the first deployed TIP20
        Ok(DEFAULT_FEE_TOKEN)
    }

    /// Checks if the given TIP20 token has USD currency.
    ///
    /// IMPORTANT: Caller must ensure `fee_token` has a valid TIP20 prefix.
    fn is_tip20_usd(
        &mut self,
        spec: TempoHardfork,
        fee_token: Address,
        actions: StorageActions,
    ) -> TempoResult<bool>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(spec, actions, || {
            // SAFETY: caller must ensure prefix is already checked
            let token = TIP20Token::from_address_unchecked(fee_token);
            Ok(token.currency.len()? == 3 && token.currency.read()?.as_str() == "USD")
        })
    }

    /// Ensures the given TIP20 token uses USD currency.
    ///
    /// IMPORTANT: Caller must ensure `fee_token` has a valid TIP20 prefix.
    fn ensure_tip20_usd(
        &mut self,
        spec: TempoHardfork,
        fee_token: Address,
        actions: StorageActions,
    ) -> Result<(), EVMError<Self::Error, TempoInvalidTransaction>>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(spec, actions, || {
            // SAFETY: caller must ensure prefix is already checked
            let token = TIP20Token::from_address_unchecked(fee_token);
            let len = token.currency.len()?;

            let currency = if len > 31 {
                format!("<{len} bytes>")
            } else {
                token.currency.read()?
            };

            if currency.as_str() != "USD" {
                return Ok(Err(EVMError::Transaction(
                    TempoInvalidTransaction::FeeTokenNotUsdCurrency {
                        address: fee_token,
                        currency,
                    },
                )));
            }

            Ok(Ok(()))
        })
        .map_err(|err: TempoPrecompileError| EVMError::Custom(err.to_string()))?
    }

    /// Checks if the given token can be used as a fee token.
    fn is_valid_fee_token(
        &mut self,
        spec: TempoHardfork,
        fee_token: Address,
        actions: StorageActions,
    ) -> TempoResult<bool>
    where
        Self: Sized,
    {
        // Must have TIP20 prefix to be a valid fee token
        if !fee_token.is_tip20() {
            return Ok(false);
        }

        // Ensure the currency is USD
        self.is_tip20_usd(spec, fee_token, actions)
    }

    /// Checks if a fee token is paused.
    fn is_fee_token_paused(
        &mut self,
        spec: TempoHardfork,
        fee_token: Address,
        actions: StorageActions,
    ) -> TempoResult<bool>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(spec, actions, || {
            let token = TIP20Token::from_address(fee_token)?;
            token.paused()
        })
    }

    /// Returns the balance of the given token for the given account.
    ///
    /// IMPORTANT: the caller must ensure `token` is a valid TIP20Token address.
    fn get_token_balance(
        &mut self,
        token: Address,
        account: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<U256>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(spec, actions, || {
            // Load the token balance for the given account.
            TIP20Token::from_address(token)?.balances[account].read()
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
    actions: Option<StorageActions>,
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
            actions: None,
            _marker: PhantomData,
        }
    }

    fn with_actions(mut self, actions: StorageActions) -> Self {
        self.actions = Some(actions);
        self
    }
}

impl<S, M> PrecompileStorageProvider for ReadOnlyStorageProvider<'_, S, M>
where
    S: TempoStateAccess<M>,
{
    fn spec(&self) -> TempoHardfork {
        self.spec
    }

    fn amsterdam_eip8037_enabled(&self) -> bool {
        // Read-only context never executes TIP-1016 state gas paths (set_code, fill_state_gas);
        // the flag is not propagated through `with_read_only_storage_ctx`, so default to `false`.
        false
    }

    fn gas_limit(&self) -> u64 {
        0
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
        let value = self
            .state
            .sload(address, key)
            .map_err(|e| TempoPrecompileError::Fatal(e.to_string()))?;

        if let Some(actions) = &self.actions {
            actions.record(StorageAction::Sload(address, key, value));
        }

        Ok(value)
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

    fn block_env(&self) -> &TempoBlockEnv {
        unreachable!("'block_env' not implemented in read-only context yet")
    }

    fn tload(&mut self, _: Address, _: U256) -> TempoResult<U256> {
        unreachable!("'tload' not implemented in read-only context yet")
    }

    fn gas_used(&self) -> u64 {
        unreachable!("'gas_used' not implemented in read-only context yet")
    }

    fn state_gas_used(&self) -> u64 {
        unreachable!("'state_gas_used' not implemented in read-only context yet")
    }

    fn gas_refunded(&self) -> i64 {
        unreachable!("'gas_refunded' not implemented in read-only context yet")
    }

    fn reservoir(&self) -> u64 {
        unreachable!("'reservoir' not implemented in read-only context yet")
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

    fn checkpoint(&mut self) -> revm::context::journaled_state::JournalCheckpoint {
        unreachable!("'checkpoint' not supported in read-only context")
    }

    fn checkpoint_commit(&mut self, _: revm::context::journaled_state::JournalCheckpoint) {
        unreachable!("'checkpoint_commit' not supported in read-only context")
    }

    fn checkpoint_revert(&mut self, _: revm::context::journaled_state::JournalCheckpoint) {
        unreachable!("'checkpoint_revert' not supported in read-only context")
    }

    fn set_tip1060_storage_credits(&mut self, _enabled: bool) {
        // Read-only storage never runs TIP-1060 accounting.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, uint};
    use revm::{context::TxEnv, database::EmptyDB, interpreter::instructions::utility::IntoU256};
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        tip20::{IRolesAuth::*, ITIP20::*, TIP20Token, slots as tip20_slots},
    };

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
        let token = db.get_fee_token(
            tx,
            caller,
            TempoHardfork::Genesis,
            StorageActions::disabled(),
        )?;
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
        let result_token = db.get_fee_token(
            tx,
            caller,
            TempoHardfork::Genesis,
            StorageActions::disabled(),
        )?;
        assert_eq!(result_token, token);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_user_token_set() -> eyre::Result<()> {
        let caller = Address::random();
        let user_token = Address::random();

        // Set user stored token preference in the FeeManager
        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let user_slot = TipFeeManager::new().user_tokens[caller].slot();
        db.insert_account_storage(TIP_FEE_MANAGER_ADDRESS, user_slot, user_token.into_u256())
            .unwrap();

        let result_token = db.get_fee_token(
            TempoTxEnv::default(),
            caller,
            TempoHardfork::Genesis,
            StorageActions::disabled(),
        )?;
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
        let result_token = db.get_fee_token(
            tx,
            caller,
            TempoHardfork::Genesis,
            StorageActions::disabled(),
        )?;
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
        let result_token = db.get_fee_token(
            tx,
            caller,
            TempoHardfork::Genesis,
            StorageActions::disabled(),
        )?;
        // Should fallback to DEFAULT_FEE_TOKEN when no preferences are found
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_stablecoin_dex() -> eyre::Result<()> {
        let caller = Address::random();
        // Use pathUSD as token_in since it's a known valid USD fee token
        let token_in = DEFAULT_FEE_TOKEN;
        let token_out = address!("0x20C0000000000000000000000000000000000001");

        // Test swapExactAmountIn
        let call = IStablecoinDEX::swapExactAmountInCall {
            tokenIn: token_in,
            tokenOut: token_out,
            amountIn: 1000,
            minAmountOut: 900,
        };

        let tx_env = TxEnv {
            data: call.abi_encode().into(),
            kind: TxKind::Call(STABLECOIN_DEX_ADDRESS),
            caller,
            ..Default::default()
        };
        let tx = TempoTxEnv {
            inner: tx_env,
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let token = db.get_fee_token(
            tx,
            caller,
            TempoHardfork::Genesis,
            StorageActions::disabled(),
        )?;
        assert_eq!(token, token_in);

        // Test swapExactAmountOut
        let call = IStablecoinDEX::swapExactAmountOutCall {
            tokenIn: token_in,
            tokenOut: token_out,
            amountOut: 900,
            maxAmountIn: 1000,
        };

        let tx_env = TxEnv {
            data: call.abi_encode().into(),
            kind: TxKind::Call(STABLECOIN_DEX_ADDRESS),
            caller,
            ..Default::default()
        };

        let tx = TempoTxEnv {
            inner: tx_env,
            ..Default::default()
        };

        let token = db.get_fee_token(
            tx,
            caller,
            TempoHardfork::Genesis,
            StorageActions::disabled(),
        )?;
        assert_eq!(token, token_in);

        Ok(())
    }

    #[test]
    fn test_read_token_balance_typed_storage() -> eyre::Result<()> {
        let token_address = PATH_USD_ADDRESS;
        let account = Address::random();
        let expected_balance = U256::from(1000u64);

        // Set up CacheDB with balance
        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let balance_slot = TIP20Token::from_address(token_address)?.balances[account].slot();
        db.insert_account_storage(token_address, balance_slot, expected_balance)?;

        // Read balance using typed storage
        let balance = db.get_token_balance(
            token_address,
            account,
            TempoHardfork::Genesis,
            StorageActions::disabled(),
        )?;
        assert_eq!(balance, expected_balance);

        Ok(())
    }

    #[test]
    fn test_is_tip20_fee_inference_call() {
        for spec in [(TempoHardfork::T6), (TempoHardfork::T7)] {
            // Allowed selectors
            assert!(is_tip20_fee_inference_call(spec, &transferCall::SELECTOR));
            assert!(is_tip20_fee_inference_call(
                spec,
                &transferWithMemoCall::SELECTOR
            ));
            // Only allowed pre-T7
            assert_eq!(
                is_tip20_fee_inference_call(spec, &distributeRewardCall::SELECTOR),
                !spec.is_t7()
            );

            // Disallowed selectors
            assert!(!is_tip20_fee_inference_call(spec, &grantRoleCall::SELECTOR));
            assert!(!is_tip20_fee_inference_call(spec, &mintCall::SELECTOR));
            assert!(!is_tip20_fee_inference_call(spec, &approveCall::SELECTOR));

            // Edge cases
            assert!(!is_tip20_fee_inference_call(spec, &[]));
            assert!(!is_tip20_fee_inference_call(spec, &[0x00, 0x01, 0x02]));
        }
    }

    #[test]
    fn test_is_fee_token_paused() -> eyre::Result<()> {
        let token_address = PATH_USD_ADDRESS;
        let mut db = revm::database::CacheDB::new(EmptyDB::default());

        // Default (unpaused) returns false
        assert!(!db.is_fee_token_paused(
            TempoHardfork::Genesis,
            token_address,
            StorageActions::disabled()
        )?);

        // Set paused=true
        db.insert_account_storage(token_address, tip20_slots::PAUSED, U256::from(1))?;
        assert!(db.is_fee_token_paused(
            TempoHardfork::Genesis,
            token_address,
            StorageActions::disabled()
        )?);

        Ok(())
    }

    #[test]
    fn test_is_tip20_usd() -> eyre::Result<()> {
        let fee_token = PATH_USD_ADDRESS;

        // Short string encoding: left-aligned data + length*2 in LSB
        let cases: &[(U256, bool, &str)] = &[
            // "USD" = 0x555344, len=3, LSB=6 -> true
            (
                uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256),
                true,
                "USD",
            ),
            // "EUR" = 0x455552, len=3, LSB=6 -> false (wrong content)
            (
                uint!(0x4555520000000000000000000000000000000000000000000000000000000006_U256),
                false,
                "EUR",
            ),
            // "US" = 0x5553, len=2, LSB=4 -> false (wrong length)
            (
                uint!(0x5553000000000000000000000000000000000000000000000000000000000004_U256),
                false,
                "US",
            ),
            // empty -> false
            (U256::ZERO, false, "empty"),
        ];

        for (currency_value, expected, label) in cases {
            let mut db = revm::database::CacheDB::new(EmptyDB::default());
            db.insert_account_storage(fee_token, tip20_slots::CURRENCY, *currency_value)?;

            let is_usd = db.is_tip20_usd(
                TempoHardfork::Genesis,
                fee_token,
                StorageActions::disabled(),
            )?;
            assert_eq!(is_usd, *expected, "currency '{label}' failed");
        }

        Ok(())
    }

    #[test]
    fn test_tip20_currency_for_error_does_not_read_long_currency() -> eyre::Result<()> {
        let fee_token = PATH_USD_ADDRESS;
        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let len = 1024usize;

        db.insert_account_storage(fee_token, tip20_slots::CURRENCY, U256::from(len * 2 + 1))?;

        let err = db
            .ensure_tip20_usd(
                TempoHardfork::Genesis,
                fee_token,
                StorageActions::disabled(),
            )
            .expect_err("long non-USD currency returns an EVM error");
        assert!(matches!(
            err,
            EVMError::Transaction(
                TempoInvalidTransaction::FeeTokenNotUsdCurrency {
                    currency,
                    ..
                }
            ) if currency == "<1024 bytes>"
        ));

        Ok(())
    }
}
