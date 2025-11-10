use crate::TempoTxEnv;
use alloy_consensus::transaction::{Either, Recovered};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::SolCall;
use revm::{
    Database, context::JournalTr, interpreter::instructions::utility::IntoAddress,
    state::AccountInfo,
};
use tempo_contracts::precompiles::IFeeManager;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, LINKING_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    storage::slots::mapping_slot,
    tip_fee_manager,
    tip20::{self, USD_CURRENCY, is_tip20},
};
use tempo_primitives::TempoTxEnvelope;

#[auto_impl::auto_impl(&)]
pub trait TempoTx {
    fn fee_token(&self) -> Option<Address>;

    fn is_aa(&self) -> bool;

    fn calls(&self) -> impl Iterator<Item = (TxKind, &Bytes)>;

    fn caller(&self) -> Address;
}

impl TempoTx for TempoTxEnv {
    fn fee_token(&self) -> Option<Address> {
        self.fee_token
    }

    fn is_aa(&self) -> bool {
        self.aa_tx_env.is_some()
    }

    fn calls(&self) -> impl Iterator<Item = (TxKind, &Bytes)> {
        if let Some(aa) = self.aa_tx_env.as_ref() {
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

pub trait TempoStateAccess<T> {
    type Error;

    fn basic(&mut self, address: Address) -> Result<AccountInfo, Self::Error>;
    fn sload(&mut self, address: Address, key: U256) -> Result<U256, Self::Error>;

    fn is_valid_fee_token(&mut self, fee_token: Address) -> Result<bool, Self::Error> {
        if !is_tip20(fee_token) || fee_token == LINKING_USD_ADDRESS {
            return Ok(false);
        }

        // Ensure that token is initialized
        if self.basic(fee_token)?.is_empty_code_hash() {
            return Ok(false);
        }

        // TODO: find a better way to do this
        let bytes = self
            .sload(fee_token, tip20::slots::CURRENCY)?
            .to_be_bytes::<32>();
        let len = bytes[31] as usize / 2; // Last byte stores length * 2 for short strings
        if len > 31 {
            Ok(false)
        } else {
            Ok(String::from_utf8_lossy(&bytes[..len]) == USD_CURRENCY)
        }
    }

    fn get_fee_token(
        &mut self,
        tx: impl TempoTx,
        validator: Address,
        fee_payer: Address,
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

        // If tx.to() is a TIP-20 token, use that token as the fee token
        if let Some(to) = tx.calls().next().and_then(|(kind, _)| kind.to().copied())
            && tx.calls().all(|(kind, _)| kind.to() == Some(&to))
            && self.is_valid_fee_token(to)?
        {
            return Ok(to);
        }

        // Otherwise fall back to the validator fee token preference
        let validator_slot = mapping_slot(validator, tip_fee_manager::slots::VALIDATOR_TOKENS);
        let validator_fee_token = self
            .sload(TIP_FEE_MANAGER_ADDRESS, validator_slot)?
            .into_address();

        if !validator_fee_token.is_zero() {
            return Ok(validator_fee_token);
        }

        Ok(DEFAULT_FEE_TOKEN)
    }

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
