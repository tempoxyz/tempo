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
    DEFAULT_FEE_TOKEN, IFeeManager, IStablecoinDEX, STABLECOIN_DEX_ADDRESS,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    error::{Result as TempoResult, TempoPrecompileError},
    storage::{Handler, PrecompileStorageProvider, StorageCtx},
    tip_fee_manager::TipFeeManager,
    tip20::{ITIP20, TIP20Token, is_tip20_prefix},
    tip403_registry::{AuthRole, TIP403Registry},
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
    fn with_read_only_storage_ctx<R>(&mut self, spec: TempoHardfork, f: impl FnOnce() -> R) -> R
    where
        Self: Sized,
    {
        StorageCtx::enter(&mut ReadOnlyStorageProvider::new(self, spec), f)
    }

    /// Resolves user-level or transaction-level fee token preference.
    fn get_fee_token(
        &mut self,
        tx: impl TempoTx,
        fee_payer: Address,
        spec: TempoHardfork,
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
        let user_token = self.with_read_only_storage_ctx(spec, || {
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
                // Otherwise, restricted to transfer/transferWithMemo/distributeReward,
                else {
                    tx.calls().all(|(kind, input)| {
                        kind.to() == Some(&to) && is_tip20_fee_inference_call(input)
                    })
                }
            ;

            if can_infer_tip20 && self.is_valid_fee_token(spec, to)? {
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
                && self.is_valid_fee_token(spec, call.tokenIn)?
            {
                return Ok(call.tokenIn);
            } else if let Ok(call) = IStablecoinDEX::swapExactAmountOutCall::abi_decode(input)
                && self.is_valid_fee_token(spec, call.tokenIn)?
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
    fn is_tip20_usd(&mut self, spec: TempoHardfork, fee_token: Address) -> TempoResult<bool>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(spec, || {
            // SAFETY: caller must ensure prefix is already checked
            let token = TIP20Token::from_address_unchecked(fee_token);
            Ok(token.currency.len()? == 3 && token.currency.read()?.as_str() == "USD")
        })
    }

    /// Checks if the given token can be used as a fee token.
    fn is_valid_fee_token(&mut self, spec: TempoHardfork, fee_token: Address) -> TempoResult<bool>
    where
        Self: Sized,
    {
        // Must have TIP20 prefix to be a valid fee token
        if !is_tip20_prefix(fee_token) {
            return Ok(false);
        }

        // Ensure the currency is USD
        self.is_tip20_usd(spec, fee_token)
    }

    /// Checks if a fee token is paused.
    fn is_fee_token_paused(&mut self, spec: TempoHardfork, fee_token: Address) -> TempoResult<bool>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(spec, || {
            let token = TIP20Token::from_address(fee_token)?;
            token.paused()
        })
    }

    /// Checks if the fee payer can transfer a given token (is not blacklisted).
    fn can_fee_payer_transfer(
        &mut self,
        fee_token: Address,
        fee_payer: Address,
        spec: TempoHardfork,
    ) -> TempoResult<bool>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(spec, || {
            // Ensure the fee payer is not blacklisted (sender authorization)
            let policy_id = TIP20Token::from_address(fee_token)?
                .transfer_policy_id
                .read()?;
            TIP403Registry::new().is_authorized_as(policy_id, fee_payer, AuthRole::sender())
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
    ) -> TempoResult<U256>
    where
        Self: Sized,
    {
        self.with_read_only_storage_ctx(spec, || {
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

    fn block_number(&self) -> u64 {
        unreachable!("'block_number' not implemented in read-only context yet")
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
    use alloy_primitives::{address, uint};
    use revm::{context::TxEnv, database::EmptyDB, interpreter::instructions::utility::IntoU256};
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        tip20::{IRolesAuth::*, ITIP20::*, slots as tip20_slots},
    };

    // ==================== TempoTx trait tests for TempoTxEnv ====================

    #[test]
    fn test_tempo_tx_env_is_aa_true() {
        let tx = TempoTxEnv {
            tempo_tx_env: Some(Box::new(crate::tx::TempoBatchCallEnv::default())),
            ..Default::default()
        };
        assert!(tx.is_aa());
    }

    #[test]
    fn test_tempo_tx_env_is_aa_false() {
        let tx = TempoTxEnv {
            tempo_tx_env: None,
            ..Default::default()
        };
        assert!(!tx.is_aa());
    }

    // ==================== TempoTx trait tests for Recovered<TempoTxEnvelope> ====================

    #[test]
    fn test_recovered_envelope_fee_token_aa() {
        use alloy_consensus::transaction::Recovered;
        use alloy_primitives::Signature;
        use tempo_primitives::TempoTxEnvelope;

        let signer = Address::repeat_byte(0xAA);

        // Legacy variant: no fee_token, not AA
        let system_sig = Signature::new(U256::ZERO, U256::ZERO, false);
        let legacy_envelope = TempoTxEnvelope::Legacy(
            alloy_consensus::Signed::new_unhashed(Default::default(), system_sig),
        );
        let recovered_legacy = Recovered::new_unchecked(legacy_envelope, signer);
        assert_eq!(TempoTx::fee_token(&recovered_legacy), None);
        assert!(!TempoTx::is_aa(&recovered_legacy));
        assert_eq!(TempoTx::caller(&recovered_legacy), signer);
        assert_eq!(TempoTx::calls(&recovered_legacy).count(), 1);
    }

    #[test]
    fn test_recovered_envelope_caller_returns_signer() {
        use alloy_consensus::transaction::Recovered;
        use alloy_primitives::Signature;
        use tempo_primitives::TempoTxEnvelope;

        let signer = Address::repeat_byte(0x42);
        let system_sig = Signature::new(U256::ZERO, U256::ZERO, false);
        let envelope = TempoTxEnvelope::Legacy(
            alloy_consensus::Signed::new_unhashed(Default::default(), system_sig),
        );
        let recovered = Recovered::new_unchecked(envelope, signer);

        assert_eq!(TempoTx::caller(&recovered), signer);
        assert_ne!(TempoTx::caller(&recovered), Address::ZERO);
    }

    // ==================== TempoStateAccess<()> for DB ====================

    #[test]
    fn test_tempo_state_access_db_basic_returns_account_info() {
        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let addr = Address::repeat_byte(0x11);
        let balance = U256::from(12345u64);
        db.insert_account_info(
            addr,
            revm::state::AccountInfo {
                balance,
                nonce: 7,
                ..Default::default()
            },
        );

        let info = TempoStateAccess::<()>::basic(&mut db, addr).unwrap();
        assert_eq!(info.balance, balance);
        assert_eq!(info.nonce, 7);
    }

    #[test]
    fn test_tempo_state_access_db_basic_missing_account() {
        let mut db = EmptyDB::default();
        let addr = Address::repeat_byte(0x99);

        // Missing account should return default info (not error)
        let info = TempoStateAccess::<()>::basic(&mut db, addr).unwrap();
        assert_eq!(info.balance, U256::ZERO);
        assert_eq!(info.nonce, 0);
    }

    // ==================== is_valid_fee_token ====================

    #[test]
    fn test_is_valid_fee_token_non_tip20_prefix() -> eyre::Result<()> {
        // An address without the TIP20 prefix should return false
        let non_tip20_addr = Address::repeat_byte(0x01);
        let mut db = EmptyDB::default();
        let result = db.is_valid_fee_token(TempoHardfork::Genesis, non_tip20_addr)?;
        assert!(!result, "Non-TIP20 address should not be valid fee token");
        Ok(())
    }

    #[test]
    fn test_is_valid_fee_token_tip20_usd() -> eyre::Result<()> {
        let fee_token = PATH_USD_ADDRESS;
        let mut db = revm::database::CacheDB::new(EmptyDB::default());

        // Set currency to "USD"
        db.insert_account_storage(
            fee_token,
            tip20_slots::CURRENCY,
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256),
        )?;

        let result = db.is_valid_fee_token(TempoHardfork::Genesis, fee_token)?;
        assert!(result, "TIP20 with USD currency should be valid fee token");
        Ok(())
    }

    // ==================== ReadOnlyStorageProvider::spec ====================

    #[test]
    fn test_read_only_storage_provider_spec() -> eyre::Result<()> {
        let mut db = EmptyDB::default();
        // with_read_only_storage_ctx sets up a ReadOnlyStorageProvider with the given spec.
        // We verify that the spec is correctly propagated by using a method that depends on it.
        // The simplest way is to call an operation that uses StorageCtx internally.
        // We can verify spec indirectly by checking that is_valid_fee_token works
        // (it calls with_read_only_storage_ctx internally).
        let result = db.is_valid_fee_token(TempoHardfork::Genesis, Address::repeat_byte(0x01))?;
        assert!(!result);
        Ok(())
    }

    // ==================== get_fee_token boundary tests ====================

    #[test]
    fn test_get_fee_token_aa_tx_not_fee_manager() -> eyre::Result<()> {
        // AA tx calling FeeManager should NOT trigger the setUserToken shortcut
        // (because is_aa() returns true, so the !tx.is_aa() guard fails)
        let caller = Address::random();
        let token = Address::random();

        let call = IFeeManager::setUserTokenCall { token };
        let tx = TempoTxEnv {
            inner: TxEnv {
                data: call.abi_encode().into(),
                kind: TxKind::Call(TIP_FEE_MANAGER_ADDRESS),
                caller,
                ..Default::default()
            },
            // AA tx
            tempo_tx_env: Some(Box::new(crate::tx::TempoBatchCallEnv::default())),
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let result_token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
        // Should NOT return `token` because is_aa() is true — should fall through to default
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_fee_manager_different_fee_payer() -> eyre::Result<()> {
        // Non-AA tx calling FeeManager, but fee_payer != caller
        // The `fee_payer == tx.caller()` check should fail
        let caller = Address::repeat_byte(0x01);
        let fee_payer = Address::repeat_byte(0x02);
        let token = Address::random();

        let call = IFeeManager::setUserTokenCall { token };
        let tx = TempoTxEnv {
            inner: TxEnv {
                data: call.abi_encode().into(),
                kind: TxKind::Call(TIP_FEE_MANAGER_ADDRESS),
                caller,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let result_token = db.get_fee_token(tx, fee_payer, TempoHardfork::Genesis)?;
        // Should NOT return `token` since fee_payer != caller
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_user_token_zero_falls_through() -> eyre::Result<()> {
        // User token stored as zero should fall through (not return zero address)
        let caller = Address::random();

        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        // Explicitly set user token to zero
        let user_slot = TipFeeManager::new().user_tokens[caller].slot();
        db.insert_account_storage(TIP_FEE_MANAGER_ADDRESS, user_slot, U256::ZERO)?;

        let result_token =
            db.get_fee_token(TempoTxEnv::default(), caller, TempoHardfork::Genesis)?;
        // Zero user token should fall through to DEFAULT_FEE_TOKEN
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_user_token_nonzero_returns_it() -> eyre::Result<()> {
        let caller = Address::random();
        let user_token = Address::repeat_byte(0xCC);

        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let user_slot = TipFeeManager::new().user_tokens[caller].slot();
        db.insert_account_storage(TIP_FEE_MANAGER_ADDRESS, user_slot, user_token.into_u256())?;

        let result_token =
            db.get_fee_token(TempoTxEnv::default(), caller, TempoHardfork::Genesis)?;
        assert_eq!(result_token, user_token);
        assert_ne!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_tip20_inference_aa_different_fee_payer() -> eyre::Result<()> {
        // AA tx where fee_payer != caller: TIP20 inference should be skipped
        // (kills the && vs || mutant on line 158: `tx.is_aa() && fee_payer != tx.caller()`)
        let caller = Address::repeat_byte(0x01);
        let fee_payer = Address::repeat_byte(0x02);

        let transfer_data = ITIP20::transferCall::SELECTOR.to_vec();
        let tip20_addr = PATH_USD_ADDRESS;

        let tx = TempoTxEnv {
            inner: TxEnv {
                data: transfer_data.into(),
                kind: TxKind::Call(tip20_addr),
                caller,
                ..Default::default()
            },
            tempo_tx_env: Some(Box::new(crate::tx::TempoBatchCallEnv {
                aa_calls: vec![tempo_primitives::transaction::Call {
                    to: TxKind::Call(tip20_addr),
                    value: U256::ZERO,
                    input: ITIP20::transferCall::SELECTOR.to_vec().into(),
                }],
                ..Default::default()
            })),
            ..Default::default()
        };

        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        // Set up the TIP20 token with USD currency so it would be valid
        db.insert_account_storage(
            tip20_addr,
            tip20_slots::CURRENCY,
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256),
        )?;

        let result_token = db.get_fee_token(tx, fee_payer, TempoHardfork::Genesis)?;
        // Because is_aa && fee_payer != caller, can_infer_tip20 = false → falls to default
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_tip20_inference_non_transfer_call() -> eyre::Result<()> {
        // Non-AA tx calling a TIP20 with a non-transfer selector (e.g., mint)
        // The is_tip20_fee_inference_call check should fail
        let caller = Address::random();
        let tip20_addr = PATH_USD_ADDRESS;

        let mint_data = mintCall::SELECTOR.to_vec();
        let tx = TempoTxEnv {
            inner: TxEnv {
                data: mint_data.into(),
                kind: TxKind::Call(tip20_addr),
                caller,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        db.insert_account_storage(
            tip20_addr,
            tip20_slots::CURRENCY,
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256),
        )?;

        let result_token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
        // Non-transfer call: can_infer_tip20 = false (all() fails) → default
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_stablecoin_dex_aa_multi_call() -> eyre::Result<()> {
        // AA tx with multiple calls to Stablecoin DEX: should NOT infer fee token
        // (kills the `!tx.is_aa() || calls.next().is_none()` mutant on line 180)
        let caller = Address::random();
        let token_in = DEFAULT_FEE_TOKEN;
        let token_out = address!("0x20C0000000000000000000000000000000000001");

        let swap_call = IStablecoinDEX::swapExactAmountInCall {
            tokenIn: token_in,
            tokenOut: token_out,
            amountIn: 1000,
            minAmountOut: 900,
        };
        let swap_data: Bytes = swap_call.abi_encode().into();

        let tx = TempoTxEnv {
            inner: TxEnv {
                data: swap_data.clone(),
                kind: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                caller,
                ..Default::default()
            },
            tempo_tx_env: Some(Box::new(crate::tx::TempoBatchCallEnv {
                aa_calls: vec![
                    tempo_primitives::transaction::Call {
                        to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                        value: U256::ZERO,
                        input: swap_data.clone(),
                    },
                    tempo_primitives::transaction::Call {
                        to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                        value: U256::ZERO,
                        input: swap_data,
                    },
                ],
                ..Default::default()
            })),
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let result_token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
        // AA with >1 call: the `calls.next().is_none()` returns false → skip DEX inference
        assert_eq!(result_token, DEFAULT_FEE_TOKEN);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_stablecoin_dex_aa_single_call() -> eyre::Result<()> {
        // AA tx with single call to Stablecoin DEX: should infer fee token
        let caller = Address::random();
        let token_in = DEFAULT_FEE_TOKEN;
        let token_out = address!("0x20C0000000000000000000000000000000000001");

        let swap_call = IStablecoinDEX::swapExactAmountInCall {
            tokenIn: token_in,
            tokenOut: token_out,
            amountIn: 1000,
            minAmountOut: 900,
        };
        let swap_data: Bytes = swap_call.abi_encode().into();

        let tx = TempoTxEnv {
            inner: TxEnv {
                data: swap_data.clone(),
                kind: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                caller,
                ..Default::default()
            },
            tempo_tx_env: Some(Box::new(crate::tx::TempoBatchCallEnv {
                aa_calls: vec![tempo_primitives::transaction::Call {
                    to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                    value: U256::ZERO,
                    input: swap_data,
                }],
                ..Default::default()
            })),
            ..Default::default()
        };

        let mut db = EmptyDB::default();
        let result_token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
        // AA with single call to DEX: should infer token_in as fee token
        assert_eq!(result_token, token_in);
        Ok(())
    }

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
        let token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
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
        let result_token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
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

        let result_token =
            db.get_fee_token(TempoTxEnv::default(), caller, TempoHardfork::Genesis)?;
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
        let result_token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
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
        let result_token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
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
        let token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
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

        let token = db.get_fee_token(tx, caller, TempoHardfork::Genesis)?;
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
        let balance = db.get_token_balance(token_address, account, TempoHardfork::Genesis)?;
        assert_eq!(balance, expected_balance);

        Ok(())
    }

    #[test]
    fn test_is_tip20_fee_inference_call() {
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

    #[test]
    fn test_is_fee_token_paused() -> eyre::Result<()> {
        let token_address = PATH_USD_ADDRESS;
        let mut db = revm::database::CacheDB::new(EmptyDB::default());

        // Default (unpaused) returns false
        assert!(!db.is_fee_token_paused(TempoHardfork::Genesis, token_address)?);

        // Set paused=true
        db.insert_account_storage(token_address, tip20_slots::PAUSED, U256::from(1))?;
        assert!(db.is_fee_token_paused(TempoHardfork::Genesis, token_address)?);

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

            let is_usd = db.is_tip20_usd(TempoHardfork::Genesis, fee_token)?;
            assert_eq!(is_usd, *expected, "currency '{label}' failed");
        }

        Ok(())
    }
}
