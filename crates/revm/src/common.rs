use crate::TempoTxEnv;
use alloy_consensus::transaction::{Either, Recovered};
use alloy_primitives::{Address, Bytes, TxKind, U256, uint};
use alloy_sol_types::SolCall;
use revm::{
    Database, context::JournalTr, interpreter::instructions::utility::IntoAddress,
    state::AccountInfo,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN_POST_ALLEGRETTO, DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, IFeeManager,
    IStablecoinExchange, ITIP403Registry, PATH_USD_ADDRESS, STABLECOIN_EXCHANGE_ADDRESS,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
    storage::{self, Storable, StorableType, double_mapping_slot, slots::mapping_slot},
    tip_fee_manager,
    tip20::{self, ITIP20, is_tip20_prefix},
    tip403_registry,
};
use tempo_primitives::TempoTxEnvelope;

/// Value of [`tip20::slots::CURRENCY`] when configured currency is USD.
const USD_CURRENCY_SLOT_VALUE: U256 =
    uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);

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
/// Generic parameter is used as a workaround to avoid conflicting implementations.
pub trait TempoStateAccess<T> {
    type Error;

    /// Returns [`AccountInfo`] for the given address.
    fn basic(&mut self, address: Address) -> Result<AccountInfo, Self::Error>;

    /// Returns the storage value for the given address and key.
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error>;

    /// Resolves user-level of transaction-level fee token preference.
    fn get_fee_token(
        &mut self,
        tx: impl TempoTx,
        validator: Address,
        fee_payer: Address,
        spec: TempoHardfork,
    ) -> Result<Address, Self::Error> {
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

        let user_slot = mapping_slot(fee_payer, tip_fee_manager::slots::USER_TOKENS);
        // ensure TIP_FEE_MANAGER_ADDRESS is loaded
        self.basic(TIP_FEE_MANAGER_ADDRESS)?;
        let stored_user_token = self
            .sload(TIP_FEE_MANAGER_ADDRESS, user_slot)?
            .into_address();

        if !stored_user_token.is_zero() {
            return Ok(stored_user_token);
        }

        let mut calls = tx.calls();
        if let Some((kind, input)) = calls.next() {
            // Must have a single callee
            if let Some(to) = kind.to() {
                // Must be a valid TIP-20 token
                if self.is_valid_fee_token(*to, spec)?
                // Caller must be a normal EOA
                && !tx.is_aa()
                // All calls must target the same TIP-20
                && tx.calls().all(|(k, _)| k.to() == Some(to))
                {
                    // Must be a transfer-like call
                    if ITIP20::transferCall::abi_decode(input).is_ok()
                        || ITIP20::transferWithMemoCall::abi_decode(input).is_ok()
                        || ITIP20::transferFromCall::abi_decode(input).is_ok()
                        || ITIP20::transferFromWithMemoCall::abi_decode(input).is_ok()
                        || ITIP20::startRewardCall::abi_decode(input).is_ok()
                    {
                        return Ok(*to);
                    } else {
                        return Ok(PATH_USD_ADDRESS);
                    }
                }
            }
        }

        // If calling swapExactAmountOut() or swapExactAmountIn() on the Stablecoin Exchange,
        // use the input token as the fee token (the token that will be pulled from the user).
        // For AA transactions, this only applies if there's exactly one call.
        if spec.is_allegretto() {
            let mut calls = tx.calls();
            if let Some((kind, input)) = calls.next()
                && kind.to() == Some(&STABLECOIN_EXCHANGE_ADDRESS)
                && (!tx.is_aa() || calls.next().is_none())
            {
                if let Ok(call) = IStablecoinExchange::swapExactAmountInCall::abi_decode(input)
                    && self.is_valid_fee_token(call.tokenIn, spec)?
                {
                    return Ok(call.tokenIn);
                } else if let Ok(call) =
                    IStablecoinExchange::swapExactAmountOutCall::abi_decode(input)
                    && self.is_valid_fee_token(call.tokenIn, spec)?
                {
                    return Ok(call.tokenIn);
                }
            }
        }

        // Post-allegretto, if no fee token is found, default to the first deployed TIP20
        if spec.is_allegretto() {
            Ok(DEFAULT_FEE_TOKEN_POST_ALLEGRETTO)
        } else {
            // Pre-allegretto fall back to the validator fee token preference or the default to the
            // first TIP20 deployed after PathUSD
            let validator_slot = mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
            let validator_fee_token = self
                .sload(TIP_FEE_MANAGER_ADDRESS, validator_slot)?
                .into_address();

            if validator_fee_token.is_zero() {
                Ok(DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO)
            } else {
                Ok(validator_fee_token)
            }
        }
    }

    /// Checks if the given token can be used as a fee token.
    fn is_valid_fee_token(
        &mut self,
        fee_token: Address,
        spec: TempoHardfork,
    ) -> Result<bool, Self::Error> {
        // Ensure it's a TIP20
        if !is_tip20_prefix(fee_token) {
            return Ok(false);
        }

        // Pre-Allegretto: PathUSD cannot be used as fee token
        if !spec.is_allegretto() && fee_token == PATH_USD_ADDRESS {
            return Ok(false);
        }

        // Ensure the currency is USD
        // load fee token account to ensure that we can load storage for it.
        self.basic(fee_token)?;
        Ok(self.sload(fee_token, tip20::slots::CURRENCY)? == USD_CURRENCY_SLOT_VALUE)
    }

    /// Checks if the fee payer can transfer a given token (is not blacklisted).
    fn can_fee_payer_transfer(
        &mut self,
        fee_token: Address,
        fee_payer: Address,
    ) -> Result<bool, Self::Error> {
        // Ensure it's a TIP20
        if !is_tip20_prefix(fee_token) {
            return Ok(false);
        }

        // Ensure the fee payer is not blacklisted
        let Ok(transfer_policy_id) = storage::packing::extract_packed_value::<1, u64>(
            self.sload(fee_token, tip20::slots::TRANSFER_POLICY_ID)?,
            tip20::slots::TRANSFER_POLICY_ID_OFFSET,
            <u64 as StorableType>::BYTES,
        ) else {
            // Should be infallible, but if unable to extract packed value, assume blacklisted.
            tracing::warn!(%fee_token, "failed to extract transfer_policy_id from packed value");
            return Ok(false);
        };

        // NOTE: must be synced with `fn is_authorized_internal` @crates/precompiles/src/tip403_registry/mod.rs
        let auth = {
            // Special case for always-allow and always-reject policies
            if transfer_policy_id < 2 {
                // policyId == 0 is the "always-reject" policy
                // policyId == 1 is the "always-allow" policy
                return Ok(transfer_policy_id == 1);
            }

            let policy_data_word = self.sload(
                TIP403_REGISTRY_ADDRESS,
                mapping_slot(
                    transfer_policy_id.to_be_bytes(),
                    tip403_registry::slots::POLICY_DATA,
                ),
            )?;
            let Ok(data) = tip403_registry::PolicyData::from_evm_words([policy_data_word]) else {
                tracing::warn!(
                    transfer_policy_id,
                    "failed to parse PolicyData from storage"
                );
                return Ok(false);
            };
            let Ok(policy_type) = data.policy_type.try_into() else {
                tracing::warn!(transfer_policy_id, policy_type = ?data.policy_type, "invalid policy type");
                return Ok(false);
            };

            let is_in_set = self
                .sload(
                    TIP403_REGISTRY_ADDRESS,
                    double_mapping_slot(
                        transfer_policy_id.to_be_bytes(),
                        fee_payer,
                        tip403_registry::slots::POLICY_SET,
                    ),
                )?
                .to::<bool>();

            match policy_type {
                ITIP403Registry::PolicyType::WHITELIST => is_in_set,
                ITIP403Registry::PolicyType::BLACKLIST => !is_in_set,
                ITIP403Registry::PolicyType::__Invalid => false,
            }
        };

        Ok(auth)
    }

    /// Returns the balance of the given token for the given account.
    fn get_token_balance(&mut self, token: Address, account: Address) -> Result<U256, Self::Error> {
        // Query the user's balance in the determined fee token's TIP20 contract
        let balance_slot = mapping_slot(account, tip20::slots::BALANCES);
        // Load fee token account to ensure that we can load storage for it.
        self.basic(token)?;
        self.sload(token, balance_slot)
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

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{context::TxEnv, database::EmptyDB, interpreter::instructions::utility::IntoU256};

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
        let token = db.get_fee_token(tx, Address::ZERO, caller, TempoHardfork::default())?;
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
        let result_token =
            db.get_fee_token(tx, Address::ZERO, caller, TempoHardfork::Allegretto)?;
        assert_eq!(result_token, token);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_user_token_set() -> eyre::Result<()> {
        let caller = Address::random();
        let user_token = Address::random();

        // Set user stored token preference in the FeeManager
        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let user_slot = mapping_slot(caller, tip_fee_manager::slots::USER_TOKENS);
        db.insert_account_storage(TIP_FEE_MANAGER_ADDRESS, user_slot, user_token.into_u256())
            .unwrap();

        let result_token = db.get_fee_token(
            TempoTxEnv::default(),
            Address::ZERO,
            caller,
            TempoHardfork::default(),
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
        let result_token =
            db.get_fee_token(tx, Address::ZERO, caller, TempoHardfork::Allegretto)?;
        assert_eq!(result_token, DEFAULT_FEE_TOKEN_POST_ALLEGRETTO);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_fallback_pre_allegretto() -> eyre::Result<()> {
        let caller = Address::random();
        let validator = Address::random();
        let validator_token = Address::random();

        let tx_env = TxEnv {
            caller,
            ..Default::default()
        };
        let tx = TempoTxEnv {
            inner: tx_env,
            ..Default::default()
        };

        // Validator has a token preference set
        let mut db = revm::database::CacheDB::new(EmptyDB::default());
        let validator_slot = mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
        db.insert_account_storage(
            TIP_FEE_MANAGER_ADDRESS,
            validator_slot,
            validator_token.into_u256(),
        )
        .unwrap();

        let result_token =
            db.get_fee_token(tx.clone(), validator, caller, TempoHardfork::Adagio)?;
        assert_eq!(result_token, validator_token);

        // Validator token is not set
        let mut db2 = EmptyDB::default();
        let result_token2 = db2.get_fee_token(tx, Address::ZERO, caller, TempoHardfork::Adagio)?;
        assert_eq!(result_token2, DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO);

        Ok(())
    }

    #[test]
    fn test_get_fee_token_fallback_post_allegretto() -> eyre::Result<()> {
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
        let result_token =
            db.get_fee_token(tx, Address::ZERO, caller, TempoHardfork::Allegretto)?;
        // Should fallback to DEFAULT_FEE_TOKEN when no preferences are found
        assert_eq!(result_token, DEFAULT_FEE_TOKEN_POST_ALLEGRETTO);
        Ok(())
    }

    #[test]
    fn test_get_fee_token_stablecoin_exchange_post_allegretto() -> eyre::Result<()> {
        let caller = Address::random();
        // Use PathUSD as token_in since it's a known valid USD fee token
        let token_in = DEFAULT_FEE_TOKEN_POST_ALLEGRETTO;
        let token_out = DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO;

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
        let token = db.get_fee_token(tx, Address::ZERO, caller, TempoHardfork::Allegretto)?;
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

        let token = db.get_fee_token(tx, Address::ZERO, caller, TempoHardfork::Allegretto)?;
        assert_eq!(token, token_in);

        Ok(())
    }
}
