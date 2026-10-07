//! Zone-native fee settlement without token preferences or FeeAMM routing.

mod dispatch;

use alloy_primitives::{Address, IntoLogData, U256};
use tempo_precompiles::{
    account_keychain::AccountKeychain,
    error::Result,
    storage::{Handler, StorageCtx},
    tip20::{TIP20Event, TIP20Token},
    tip403_registry::AuthRole,
};
use tempo_precompiles_macros::contract;
pub use zone_primitives::constants::ZONE_FEE_MANAGER_ADDRESS;

/// Zone fee configuration and direct fee settlement.
#[contract(addr = ZONE_FEE_MANAGER_ADDRESS)]
pub struct ZoneFeeManager {
    default_fee_token: Address,
}

impl ZoneFeeManager {
    /// Initializes the precompile account marker and canonical default fee token in genesis.
    pub fn initialize(&mut self, default_fee_token: Address) -> Result<()> {
        self.__initialize()?;
        self.default_fee_token.write(default_fee_token)
    }

    /// Returns the canonical default token used when a transaction omits `fee_token`.
    pub fn default_fee_token(&self) -> Result<Address> {
        self.default_fee_token.read()
    }

    /// Debits the maximum fee into protocol-private escrow for post-transaction settlement.
    pub fn collect_fee_pre_tx(
        &mut self,
        fee_payer: Address,
        fee_token: Address,
        max_amount: U256,
        beneficiary: Address,
    ) -> Result<Address> {
        let mut token = TIP20Token::from_address(fee_token)?;
        token.ensure_authorized_as(&[
            (fee_payer, AuthRole::sender()),
            (beneficiary, AuthRole::recipient()),
        ])?;
        token.check_not_paused()?;
        token.check_and_update_spending_limit(fee_payer, max_amount)?;

        token.decrement_balance(fee_payer, max_amount)?;
        token.increment_balance(self.address, max_amount)?;
        Ok(fee_token)
    }

    /// Refunds unused gas from escrow and settles the actual fee to the beneficiary.
    pub fn collect_fee_post_tx(
        &mut self,
        fee_payer: Address,
        actual_spending: U256,
        refund: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> Result<U256> {
        let mut token = TIP20Token::from_address(fee_token)?;
        StorageCtx.set_tip1060_storage_credit_minting(false);

        if !refund.is_zero() {
            AccountKeychain::new().refund_spending_limit(fee_payer, fee_token, refund)?;

            token.decrement_balance(self.address, refund)?;
            token.increment_balance(fee_payer, refund)?;
        }

        if !actual_spending.is_zero() {
            token.decrement_balance(self.address, actual_spending)?;
            token.increment_balance(beneficiary, actual_spending)?;
            StorageCtx.emit_event(
                fee_token,
                TIP20Event::transfer(fee_payer, beneficiary, actual_spending).into_log_data(),
            )?;
        }

        Ok(actual_spending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolError;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{TIP20Error, UnknownFunctionSelector};
    use tempo_precompiles::{
        Precompile as _, TIP_FEE_MANAGER_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::ITIP20,
        tip403_registry::{ITIP403Registry, TIP403Registry},
    };

    #[test]
    fn settles_fees_from_escrow_to_beneficiary() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let (user, beneficiary, recipient) =
                (Address::random(), Address::random(), Address::random());
            let admin = Address::random();
            let mut token = TIP20Setup::create("USD", "USD", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10_000))
                .with_mint(beneficiary, U256::from(1_000))
                .apply()?;
            let mut manager = ZoneFeeManager::new();
            manager.initialize(token.address())?;
            assert_eq!(manager.default_fee_token()?, token.address());
            token.clear_emitted_events();
            manager.collect_fee_pre_tx(user, token.address(), U256::from(5_000), beneficiary)?;
            assert!(token.emitted_events().is_empty());
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ZONE_FEE_MANAGER_ADDRESS,
                })?,
                U256::from(5_000),
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: beneficiary,
                })?,
                U256::from(1_000),
            );

            // Beneficiary activity during user execution cannot touch the escrowed refund.
            token.decrement_balance(beneficiary, U256::from(1_000))?;
            token.increment_balance(recipient, U256::from(1_000))?;
            manager.collect_fee_post_tx(
                user,
                U256::from(3_000),
                U256::from(2_000),
                token.address(),
                beneficiary,
            )?;
            token.assert_emitted_events(vec![TIP20Event::transfer(
                user,
                beneficiary,
                U256::from(3_000),
            )]);
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ZONE_FEE_MANAGER_ADDRESS,
                })?,
                U256::ZERO,
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: TIP_FEE_MANAGER_ADDRESS,
                })?,
                U256::ZERO,
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: beneficiary
                })?,
                U256::from(3_000)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: recipient })?,
                U256::from(1_000),
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: user })?,
                U256::from(7_000),
            );
            Ok(())
        })
    }

    #[test]
    fn rejects_unauthorized_beneficiary_before_debit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || {
            let admin = Address::random();
            let payer = Address::random();
            let beneficiary = Address::random();
            let balance = U256::from(10_000);
            let mut token = TIP20Setup::create("USD", "USD", admin)
                .with_issuer(admin)
                .with_mint(payer, balance)
                .apply()?;
            let mut registry = TIP403Registry::new();
            registry.initialize()?;
            let policy = registry.create_policy_with_accounts(
                admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                    accounts: vec![payer],
                },
            )?;
            token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: policy,
                },
            )?;

            let mut manager = ZoneFeeManager::new();
            manager.initialize(token.address())?;
            assert!(matches!(
                manager.collect_fee_pre_tx(payer, token.address(), U256::from(5_000), beneficiary,),
                Err(TempoPrecompileError::TIP20(TIP20Error::PolicyForbids(_)))
            ));
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: payer })?,
                balance
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: ZONE_FEE_MANAGER_ADDRESS,
                })?,
                U256::ZERO
            );
            Ok(())
        })
    }

    #[test]
    fn external_calls_are_unsupported() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut manager = ZoneFeeManager::new();
            let calldata = [0xde, 0xad, 0xbe, 0xef];
            let output = manager.call(&calldata, Address::random())?;
            assert!(output.is_revert());
            let error = UnknownFunctionSelector::abi_decode(&output.bytes)?;
            assert_eq!(error.selector.as_slice(), calldata);

            Ok(())
        })
    }

    #[test]
    fn short_calldata_reverts_without_panicking() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || {
            let mut manager = ZoneFeeManager::new();
            for len in 0..4 {
                let output = manager.call(&[0u8; 3][..len], Address::random())?;
                assert!(output.is_revert());
                assert!(output.bytes.is_empty());
            }
            Ok(())
        })
    }
}
