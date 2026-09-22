use super::*;
use crate::{funding_policy::FundingPolicy, storage::StorageCtx};
use tempo_contracts::precompiles::{FUNDING_POLICY_ADDRESS, IFundingPolicy};
use tempo_primitives::transaction::FundingPolicyAuthorization;

impl AccountKeychain {
    pub fn get_funding_policy_id(&self, account: Address, key: Address) -> Result<u64> {
        self.funding_policy_ids[account][key].read()
    }

    /// Binds a policy after native key installation, inside the same checkpoint.
    pub fn install_funding_policy(
        &mut self,
        account: Address,
        key: Address,
        policy: &FundingPolicyAuthorization,
    ) -> Result<()> {
        let mut registry = FundingPolicy::new(FUNDING_POLICY_ADDRESS);
        let id = match policy {
            FundingPolicyAuthorization::Id(id) => {
                if !registry.policy_exists(id.get())? {
                    return Err(
                        tempo_contracts::precompiles::FundingPolicyError::PolicyNotFound(
                            IFundingPolicy::PolicyNotFound {},
                        )
                        .into(),
                    );
                }
                id.get()
            }
            FundingPolicyAuthorization::Inline(policy) => {
                registry.install_policy(account, policy.clone().into())?
            }
        };
        self.funding_policy_ids[account][key].write(id)
    }
}

impl AccountKeychain {
    // Separate domain from compiler-assigned transient slots and input-permission counters.
    fn credit_slot(
        &self,
        account: Address,
        key: Address,
        token: Address,
        spender: Address,
        approval: bool,
    ) -> Result<U256> {
        use alloy::sol_types::SolValue;
        let encoded = (
            b"tempo.funding.credit.v1".as_slice(),
            account,
            key,
            token,
            spender,
            approval,
        )
            .abi_encode();
        Ok(U256::from_be_bytes(self.storage.keccak256(&encoded)?.0))
    }

    fn credit_key(&self, account: Address) -> Result<Option<Address>> {
        if !self.storage.spec().is_t13() || self.tx_origin.t_read()? != account {
            return Ok(None);
        }
        let key = self.transaction_key.t_read()?;
        Ok((!key.is_zero()).then_some(key))
    }

    pub fn validate_funding_key(&self, account: Address) -> Result<()> {
        if let Some(key) = self.credit_key(account)? {
            self.load_active_key(account, key, self.storage.timestamp().saturating_to())?;
        }
        Ok(())
    }

    /// Only measured delivery in the native funding handler creates credit.
    pub fn add_funding_credit(&self, account: Address, token: Address, amount: U256) -> Result<()> {
        self.add_credit(account, token, Address::ZERO, amount, false)
    }

    pub fn add_approval_credit(
        &self,
        account: Address,
        token: Address,
        spender: Address,
        amount: U256,
    ) -> Result<()> {
        self.add_credit(account, token, spender, amount, true)
    }

    fn add_credit(
        &self,
        account: Address,
        token: Address,
        spender: Address,
        amount: U256,
        approval: bool,
    ) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }
        if let Some(key) = self.credit_key(account)? {
            let slot = self.credit_slot(account, key, token, spender, approval)?;
            let next = self
                .storage
                .tload(ACCOUNT_KEYCHAIN_ADDRESS, slot)?
                .checked_add(amount)
                .ok_or(crate::error::TempoPrecompileError::under_overflow())?;
            StorageCtx.tstore(ACCOUNT_KEYCHAIN_ADDRESS, slot, next)?;
        }
        Ok(())
    }

    pub fn take_funding_credit(
        &self,
        account: Address,
        token: Address,
        amount: U256,
    ) -> Result<U256> {
        self.take_credit(account, token, Address::ZERO, amount, false)
    }

    fn take_credit(
        &self,
        account: Address,
        token: Address,
        spender: Address,
        amount: U256,
        approval: bool,
    ) -> Result<U256> {
        let Some(key) = self.credit_key(account)? else {
            return Ok(U256::ZERO);
        };
        let slot = self.credit_slot(account, key, token, spender, approval)?;
        let available = self.storage.tload(ACCOUNT_KEYCHAIN_ADDRESS, slot)?;
        let covered = available.min(amount);
        if !covered.is_zero() {
            StorageCtx.tstore(ACCOUNT_KEYCHAIN_ADDRESS, slot, available - covered)?;
        }
        Ok(covered)
    }

    pub fn retire_allowance_credit(
        &self,
        account: Address,
        token: Address,
        spender: Address,
        amount: U256,
    ) -> Result<()> {
        self.validate_funding_key(account)?;
        let covered = self.take_credit(account, token, spender, amount, true)?;
        self.take_funding_credit(account, token, amount - covered)?;
        Ok(())
    }

    pub fn clamp_approval_credit(
        &self,
        account: Address,
        token: Address,
        spender: Address,
        allowance: U256,
    ) -> Result<()> {
        if let Some(key) = self.credit_key(account)? {
            let slot = self.credit_slot(account, key, token, spender, true)?;
            let old = self.storage.tload(ACCOUNT_KEYCHAIN_ADDRESS, slot)?;
            if old > allowance {
                StorageCtx.tstore(ACCOUNT_KEYCHAIN_ADDRESS, slot, allowance)?;
            }
        }
        Ok(())
    }

    /// Fee debits never use funding credit.
    pub fn authorize_fee(&mut self, account: Address, token: Address, amount: U256) -> Result<()> {
        let key = self.transaction_key.t_read()?;
        if !key.is_zero() && self.tx_origin.t_read()? == account {
            self.verify_and_update_spending(account, key, token, amount)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use tempo_chainspec::hardfork::TempoHardfork;
    const OWNER: Address = Address::repeat_byte(1);
    const KEY: Address = Address::repeat_byte(2);
    const TOKEN: Address = Address::repeat_byte(3);
    const SPENDER: Address = Address::repeat_byte(4);

    fn setup(keychain: &mut AccountKeychain) -> Result<()> {
        keychain.set_tx_origin(OWNER)?;
        keychain.authorize_key(
            OWNER,
            KEY,
            SignatureType::Secp256k1,
            KeyRestrictions {
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![TokenLimit {
                    token: TOKEN,
                    amount: U256::from(100),
                    period: 0,
                }],
                allowAnyCalls: true,
                allowedCalls: vec![],
            },
            None,
        )?;
        keychain.set_transaction_key(KEY)
    }
    fn remaining(keychain: &AccountKeychain) -> U256 {
        keychain
            .get_remaining_limit(getRemainingLimitCall {
                account: OWNER,
                keyId: KEY,
                token: TOKEN,
            })
            .unwrap()
    }

    #[test]
    fn credit_offsets_output_spending_but_never_fees() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            setup(&mut keychain)?;
            keychain.verify_and_update_spending(OWNER, KEY, TOKEN, U256::from(50))?;
            keychain.add_funding_credit(OWNER, TOKEN, U256::from(50))?;
            keychain.authorize_fee(OWNER, TOKEN, U256::from(10))?;
            keychain.authorize_transfer(OWNER, TOKEN, U256::from(60))?;
            assert_eq!(remaining(&keychain), U256::from(30));
            keychain.authorize_transfer(OWNER, TOKEN, U256::from(30))?;
            assert!(
                keychain
                    .authorize_transfer(OWNER, TOKEN, U256::ONE)
                    .is_err()
            );
            Ok(())
        })
    }

    #[test]
    fn approval_credit_is_spender_bound_and_decreases_do_not_restore_credit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            setup(&mut keychain)?;
            keychain.add_funding_credit(OWNER, TOKEN, U256::from(50))?;
            let covered = keychain.authorize_approve(OWNER, TOKEN, U256::ZERO, U256::from(30))?;
            assert_eq!(covered, U256::from(30));
            keychain.add_approval_credit(OWNER, TOKEN, SPENDER, covered)?;
            keychain.retire_allowance_credit(OWNER, TOKEN, SPENDER, U256::from(10))?;
            assert_eq!(
                keychain.take_funding_credit(OWNER, TOKEN, U256::MAX)?,
                U256::from(20)
            );
            keychain.clamp_approval_credit(OWNER, TOKEN, SPENDER, U256::from(5))?;
            assert_eq!(
                keychain.take_credit(OWNER, TOKEN, SPENDER, U256::MAX, true)?,
                U256::from(5)
            );
            assert_eq!(
                keychain.take_funding_credit(OWNER, TOKEN, U256::MAX)?,
                U256::ZERO
            );
            keychain.add_approval_credit(OWNER, TOKEN, Address::ZERO, U256::from(12))?;
            assert_eq!(
                keychain.take_funding_credit(OWNER, TOKEN, U256::MAX)?,
                U256::ZERO
            );
            assert_eq!(remaining(&keychain), U256::from(100));
            Ok(())
        })
    }

    #[test]
    fn old_allowances_retire_free_credit_and_nested_reverts_restore_it() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            setup(&mut keychain)?;
            keychain.add_funding_credit(OWNER, TOKEN, U256::from(50))?;
            {
                let _checkpoint = StorageCtx.checkpoint();
                keychain.retire_allowance_credit(OWNER, TOKEN, SPENDER, U256::from(40))?;
                assert_eq!(
                    keychain.take_funding_credit(OWNER, TOKEN, U256::MAX)?,
                    U256::from(10)
                );
            }
            keychain.retire_allowance_credit(OWNER, TOKEN, SPENDER, U256::from(20))?;
            assert_eq!(
                keychain.take_funding_credit(OWNER, TOKEN, U256::MAX)?,
                U256::from(30)
            );
            Ok(())
        })
    }

    #[test]
    fn fully_covered_transfers_still_validate_key_and_scope_credit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            setup(&mut keychain)?;
            keychain.add_funding_credit(OWNER, TOKEN, U256::from(50))?;
            assert_eq!(
                keychain.take_funding_credit(SPENDER, TOKEN, U256::MAX)?,
                U256::ZERO
            );
            assert_eq!(
                keychain.take_funding_credit(OWNER, SPENDER, U256::MAX)?,
                U256::ZERO
            );
            keychain.keys[OWNER][KEY].is_revoked.write(true)?;
            assert!(
                keychain
                    .authorize_transfer(OWNER, TOKEN, U256::ONE)
                    .is_err()
            );
            Ok(())
        })
    }

    #[test]
    fn inline_policy_binding_and_failed_install_are_atomic() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            setup(&mut keychain)?;
            let policy =
                FundingPolicyAuthorization::Inline(tempo_primitives::transaction::FundingPolicy {
                    admins: vec![OWNER],
                    slippage_bps: 100,
                    routes: vec![],
                });
            {
                let _checkpoint = StorageCtx.checkpoint();
                keychain.install_funding_policy(OWNER, KEY, &policy)?;
                assert_eq!(keychain.get_funding_policy_id(OWNER, KEY)?, 1);
            }
            assert_eq!(keychain.get_funding_policy_id(OWNER, KEY)?, 0);
            assert_eq!(
                FundingPolicy::new(FUNDING_POLICY_ADDRESS).policy_id_counter()?,
                1
            );
            keychain.install_funding_policy(OWNER, KEY, &policy)?;
            assert_eq!(keychain.get_funding_policy_id(OWNER, KEY)?, 1);
            keychain.install_funding_policy(
                OWNER,
                SPENDER,
                &FundingPolicyAuthorization::Id(core::num::NonZeroU64::MIN),
            )?;
            assert_eq!(keychain.get_funding_policy_id(OWNER, SPENDER)?, 1);
            assert_eq!(
                FundingPolicy::new(FUNDING_POLICY_ADDRESS).policy_id_counter()?,
                2
            );
            Ok(())
        })
    }
    #[test]
    fn token_allowance_spending_retires_only_the_corresponding_credit() -> eyre::Result<()> {
        use crate::{storage::ContractStorage, test_util::TIP20Setup};
        for old_allowance in [false, true] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
            StorageCtx::enter(&mut storage, || -> Result<()> {
                let mut token = TIP20Setup::create("Output", "OUT", OWNER)
                    .with_issuer(OWNER)
                    .with_mint(OWNER, U256::from(100))
                    .apply()?;
                let asset = token.address();
                let mut keychain = AccountKeychain::new();
                keychain.set_tx_origin(OWNER)?;
                if old_allowance {
                    token.approve(
                        OWNER,
                        ITIP20::approveCall {
                            spender: SPENDER,
                            amount: U256::from(30),
                        },
                    )?;
                }
                keychain.authorize_key(
                    OWNER,
                    KEY,
                    SignatureType::Secp256k1,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: true,
                        limits: vec![TokenLimit {
                            token: asset,
                            amount: U256::from(50),
                            period: 0,
                        }],
                        allowAnyCalls: true,
                        allowedCalls: vec![],
                    },
                    None,
                )?;
                keychain.set_transaction_key(KEY)?;
                keychain.verify_and_update_spending(OWNER, KEY, asset, U256::from(50))?;
                keychain.add_funding_credit(OWNER, asset, U256::from(50))?;
                if !old_allowance {
                    token.approve(
                        OWNER,
                        ITIP20::approveCall {
                            spender: SPENDER,
                            amount: U256::from(30),
                        },
                    )?;
                }
                token.transfer_from(
                    SPENDER,
                    ITIP20::transferFromCall {
                        from: OWNER,
                        to: SPENDER,
                        amount: U256::from(30),
                    },
                )?;
                token.transfer(
                    OWNER,
                    ITIP20::transferCall {
                        to: SPENDER,
                        amount: U256::from(20),
                    },
                )?;
                assert!(
                    token
                        .transfer(
                            OWNER,
                            ITIP20::transferCall {
                                to: SPENDER,
                                amount: U256::ONE
                            }
                        )
                        .is_err()
                );
                token.transfer(
                    SPENDER,
                    ITIP20::transferCall {
                        to: OWNER,
                        amount: U256::from(50),
                    },
                )?;
                assert!(
                    token
                        .transfer(
                            OWNER,
                            ITIP20::transferCall {
                                to: SPENDER,
                                amount: U256::ONE
                            }
                        )
                        .is_err()
                );
                assert_eq!(
                    token.balance_of(ITIP20::balanceOfCall { account: OWNER })?,
                    U256::from(100)
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn credit_expires_between_transactions() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut keychain = AccountKeychain::new();
            setup(&mut keychain)?;
            keychain.add_funding_credit(OWNER, TOKEN, U256::from(50))
        })?;
        storage.clear_transient();
        StorageCtx::enter(&mut storage, || -> Result<()> {
            let mut keychain = AccountKeychain::new();
            keychain.set_tx_origin(OWNER)?;
            keychain.set_transaction_key(KEY)?;
            assert_eq!(
                keychain.take_funding_credit(OWNER, TOKEN, U256::MAX)?,
                U256::ZERO
            );
            Ok(())
        })?;
        Ok(())
    }
}
