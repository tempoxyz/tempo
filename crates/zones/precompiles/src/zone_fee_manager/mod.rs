//! Zone-native fee settlement without token preferences or FeeAMM routing.

mod dispatch;

use alloy_primitives::{Address, IntoLogData, U256};
use tempo_contracts::precompiles::TIP20Error;
use tempo_precompiles::{
    account_keychain::AccountKeychain,
    error::Result,
    storage::{Handler, StorageCtx},
    tip20::{TIP20Event, TIP20Token},
    tip403_registry::{AuthRole, TIP403Registry},
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
    ///
    /// # Errors
    /// - `PolicyForbids` — the token's TIP-403 policy rejects the payer or beneficiary or, from
    ///   T15, the beneficiary's TIP-1028 receive policy rejects the payer or the token
    /// - `ContractPaused` — the fee token is paused
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
        // Zones cannot hold blocked receipts, so a fee the beneficiary's receive policy rejects
        // is refused up front rather than settled directly.
        if self.storage.spec().is_t15()
            && TIP403Registry::new()
                .validate_receive_policy(fee_token, fee_payer, beneficiary)?
                .is_some()
        {
            return Err(TIP20Error::policy_forbids().into());
        }
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
    use evm2::precompiles::PrecompileError;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::UnknownFunctionSelector;
    use tempo_precompiles::{
        Precompile as _, RECEIVE_POLICY_GUARD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::{self, ITIP20},
        tip403_registry::{
            ALLOW_ALL_POLICY_ID, ITIP403Registry, REJECT_ALL_POLICY_ID, TIP403Registry,
        },
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
    fn rejects_fee_blocked_by_beneficiary_receive_policy() -> eyre::Result<()> {
        for hardfork in [TempoHardfork::T14, TempoHardfork::T15] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            StorageCtx::enter(&mut storage, || {
                let admin = Address::random();
                let payer = Address::random();
                let beneficiary = Address::random();
                let balance = U256::from(10_000);
                let max_fee = U256::from(5_000);
                let token = TIP20Setup::create("USD", "USD", admin)
                    .with_issuer(admin)
                    .with_mint(payer, balance)
                    .apply()?;
                TIP403Registry::new().set_receive_policy(
                    beneficiary,
                    ITIP403Registry::setReceivePolicyCall {
                        senderPolicyId: REJECT_ALL_POLICY_ID,
                        tokenFilterId: ALLOW_ALL_POLICY_ID,
                        recoveryAuthority: Address::ZERO,
                    },
                )?;

                let mut manager = ZoneFeeManager::new();
                manager.initialize(token.address())?;
                let result =
                    manager.collect_fee_pre_tx(payer, token.address(), max_fee, beneficiary);

                if hardfork.is_t15() {
                    assert!(matches!(
                        result,
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
                } else {
                    assert_eq!(result?, token.address());
                    assert_eq!(
                        token.balance_of(ITIP20::balanceOfCall {
                            account: ZONE_FEE_MANAGER_ADDRESS,
                        })?,
                        max_fee
                    );
                }
                Ok::<_, eyre::Report>(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn settles_fee_when_beneficiary_receive_policy_allows_payer() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || {
            let admin = Address::random();
            let payer = Address::random();
            let beneficiary = Address::random();
            let token = TIP20Setup::create("USD", "USD", admin)
                .with_issuer(admin)
                .with_mint(payer, U256::from(10_000))
                .apply()?;
            let mut registry = TIP403Registry::new();
            registry.initialize()?;
            let senders = registry.create_policy_with_accounts(
                admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                    accounts: vec![payer],
                },
            )?;
            registry.set_receive_policy(
                beneficiary,
                ITIP403Registry::setReceivePolicyCall {
                    senderPolicyId: senders,
                    tokenFilterId: ALLOW_ALL_POLICY_ID,
                    recoveryAuthority: Address::ZERO,
                },
            )?;

            let mut manager = ZoneFeeManager::new();
            manager.initialize(token.address())?;
            manager.collect_fee_pre_tx(payer, token.address(), U256::from(5_000), beneficiary)?;
            assert_eq!(
                manager.collect_fee_post_tx(
                    payer,
                    U256::from(3_000),
                    U256::from(2_000),
                    token.address(),
                    beneficiary,
                )?,
                U256::from(3_000)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: beneficiary
                })?,
                U256::from(3_000)
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall {
                    account: RECEIVE_POLICY_GUARD_ADDRESS,
                })?,
                U256::ZERO
            );
            Ok(())
        })
    }

    #[test]
    fn fee_rejected_when_beneficiary_token_filter_excludes_fee_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || {
            let admin = Address::random();
            let payer = Address::random();
            let beneficiary = Address::random();
            let balance = U256::from(10_000);
            let token = TIP20Setup::create("USD", "USD", admin)
                .with_issuer(admin)
                .with_mint(payer, balance)
                .apply()?;
            let mut registry = TIP403Registry::new();
            registry.initialize()?;
            let tokens = registry.create_policy_with_accounts(
                admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                    accounts: vec![Address::random()],
                },
            )?;
            registry.set_receive_policy(
                beneficiary,
                ITIP403Registry::setReceivePolicyCall {
                    senderPolicyId: ALLOW_ALL_POLICY_ID,
                    tokenFilterId: tokens,
                    recoveryAuthority: Address::ZERO,
                },
            )?;

            let mut manager = ZoneFeeManager::new();
            manager.initialize(token.address())?;
            assert!(matches!(
                manager.collect_fee_pre_tx(payer, token.address(), U256::from(5_000), beneficiary),
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
            let fee_tokens = registry.create_policy_with_accounts(
                admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                    accounts: vec![token.address()],
                },
            )?;
            registry.set_receive_policy(
                beneficiary,
                ITIP403Registry::setReceivePolicyCall {
                    senderPolicyId: ALLOW_ALL_POLICY_ID,
                    tokenFilterId: fee_tokens,
                    recoveryAuthority: Address::ZERO,
                },
            )?;
            assert_eq!(
                manager.collect_fee_pre_tx(
                    payer,
                    token.address(),
                    U256::from(5_000),
                    beneficiary
                )?,
                token.address()
            );
            Ok(())
        })
    }

    #[test]
    fn paused_fee_token_rejected_before_receive_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T15);
        StorageCtx::enter(&mut storage, || {
            let admin = Address::random();
            let payer = Address::random();
            let beneficiary = Address::random();
            let balance = U256::from(10_000);
            let token = TIP20Setup::create("USD", "USD", admin)
                .with_issuer(admin)
                .with_mint(payer, balance)
                .apply()?;
            TIP403Registry::new().set_receive_policy(
                beneficiary,
                ITIP403Registry::setReceivePolicyCall {
                    senderPolicyId: REJECT_ALL_POLICY_ID,
                    tokenFilterId: ALLOW_ALL_POLICY_ID,
                    recoveryAuthority: Address::ZERO,
                },
            )?;
            StorageCtx.sstore(token.address(), tip20::slots::PAUSED, U256::ONE)?;

            let mut manager = ZoneFeeManager::new();
            manager.initialize(token.address())?;
            assert!(matches!(
                manager.collect_fee_pre_tx(payer, token.address(), U256::from(5_000), beneficiary),
                Err(TempoPrecompileError::TIP20(TIP20Error::ContractPaused(_)))
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
            let Err(PrecompileError::Revert(output)) = manager.call(&calldata, Address::random())
            else {
                panic!("expected revert");
            };
            let error = UnknownFunctionSelector::abi_decode(&output)?;
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
                assert!(matches!(
                    manager.call(&[0u8; 3][..len], Address::random()),
                    Err(PrecompileError::Revert(output)) if output.is_empty()
                ));
            }
            Ok(())
        })
    }
}
