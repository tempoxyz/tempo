//! TIP-20 balance storage with an opt-in holder-first layout for fresh-state experiments.

use crate::{
    error::Result,
    storage::{Handler, HandlerCache, Layout, LayoutCtx, Slot, StorableType, StorageKey},
};
use alloy::primitives::{Address, U256, keccak256};
use std::ops::{Deref, DerefMut, Index, IndexMut};

#[cfg(feature = "holder-first-balances")]
use crate::{error::TempoPrecompileError, storage::StorageCtx};
#[cfg(feature = "holder-first-balances")]
use revm::state::Bytecode;

pub const HOLDER_FIRST_BALANCES: bool = cfg!(feature = "holder-first-balances");

#[derive(Debug, Clone)]
pub struct TokenBalances {
    base_slot: U256,
    token: Address,
    cache: HandlerCache<Address, BalanceSlot>,
}

impl TokenBalances {
    pub fn new(base_slot: U256, token: Address) -> Self {
        Self {
            base_slot,
            token,
            cache: HandlerCache::new(),
        }
    }

    pub const fn slot(&self) -> U256 {
        self.base_slot
    }

    pub fn at(&self, account: &Address) -> &BalanceSlot {
        let (base_slot, token) = (self.base_slot, self.token);
        self.cache
            .get_or_insert(account, || BalanceSlot::new(base_slot, token, *account))
    }

    pub fn at_mut(&mut self, account: &Address) -> &mut BalanceSlot {
        let (base_slot, token) = (self.base_slot, self.token);
        self.cache
            .get_or_insert_mut(account, || BalanceSlot::new(base_slot, token, *account))
    }
}

impl StorableType for TokenBalances {
    const LAYOUT: Layout = Layout::Slots(1);
    type Handler = Self;

    fn handle(slot: U256, _ctx: LayoutCtx, address: Address) -> Self::Handler {
        Self::new(slot, address)
    }
}

impl Index<Address> for TokenBalances {
    type Output = BalanceSlot;

    fn index(&self, account: Address) -> &Self::Output {
        self.at(&account)
    }
}

impl IndexMut<Address> for TokenBalances {
    fn index_mut(&mut self, account: Address) -> &mut Self::Output {
        self.at_mut(&account)
    }
}

#[derive(Debug, Clone)]
pub struct BalanceSlot(Slot<U256>);

impl BalanceSlot {
    fn new(base_slot: U256, token: Address, account: Address) -> Self {
        let (address, slot) = if HOLDER_FIRST_BALANCES {
            (
                holder_storage_address(account),
                token.mapping_slot(U256::from_be_slice(account.as_slice())),
            )
        } else {
            (token, account.mapping_slot(base_slot))
        };
        Self(Slot::new(slot, address))
    }

    pub fn write(&mut self, amount: U256) -> Result<()> {
        if !amount.is_zero() {
            self.initialize_storage_account()?;
        }
        self.0.write(amount)
    }

    pub fn sinc(&mut self, amount: U256) -> Result<()> {
        if !amount.is_zero() {
            self.initialize_storage_account()?;
        }
        self.0.sinc(amount)
    }

    pub fn sdec(&mut self, amount: U256) -> Result<()> {
        if !amount.is_zero() {
            self.initialize_storage_account()?;
        }
        self.0.sdec(amount)
    }

    fn initialize_storage_account(&self) -> Result<()> {
        #[cfg(feature = "holder-first-balances")]
        {
            let mut storage = StorageCtx;
            let code = Bytecode::new_raw(vec![0x00].into());
            let initialized = storage.with_account_info(self.address(), |info| {
                if info.code_hash == code.hash_slow() {
                    Ok(true)
                } else if info.is_empty_code_hash() && info.nonce == 0 {
                    Ok(false)
                } else {
                    Err(TempoPrecompileError::Fatal(
                        "TIP-20 holder storage address collision".into(),
                    ))
                }
            })?;
            if !initialized {
                storage.set_code(self.address(), code)?;
            }
        }
        Ok(())
    }
}

impl Deref for BalanceSlot {
    type Target = Slot<U256>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BalanceSlot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn holder_storage_address(account: Address) -> Address {
    const DOMAIN: &[u8] = b"tempo.tip20.holder-balances.v1";
    let mut input = [0u8; DOMAIN.len() + 20];
    input[..DOMAIN.len()].copy_from_slice(DOMAIN);
    input[DOMAIN.len()..].copy_from_slice(account.as_slice());
    Address::from_slice(&keccak256(input).as_slice()[12..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PATH_USD_ADDRESS, storage::hashmap::HashMapStorageProvider, tip20::tip20_slots};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[cfg(not(feature = "holder-first-balances"))]
    use crate::storage::StorageCtx;

    #[test]
    fn balance_deltas_and_overwrite() -> Result<()> {
        let account = Address::repeat_byte(0x11);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut balances = TokenBalances::new(tip20_slots::BALANCES, PATH_USD_ADDRESS);
            assert_eq!(balances[account].read()?, U256::ZERO);
            balances[account].sinc(U256::from(10))?;
            balances[account].sdec(U256::from(3))?;
            assert_eq!(balances[account].read()?, U256::from(7));
            balances[account].write(U256::from(5))?;
            balances[account].sdec(U256::from(5))?;
            assert_eq!(balances[account].read()?, U256::ZERO);
            Ok(())
        })
    }

    #[cfg(not(feature = "holder-first-balances"))]
    #[test]
    fn default_layout_is_unchanged() {
        let account = Address::repeat_byte(0x22);
        let balances = TokenBalances::new(tip20_slots::BALANCES, PATH_USD_ADDRESS);
        assert_eq!(balances[account].address(), PATH_USD_ADDRESS);
        assert_eq!(
            balances[account].slot(),
            account.mapping_slot(tip20_slots::BALANCES)
        );
    }

    #[cfg(feature = "holder-first-balances")]
    #[test]
    fn tokens_share_holder_storage_but_not_balance_slots() -> Result<()> {
        let holder = Address::repeat_byte(0x33);
        let other_holder = Address::repeat_byte(0x44);
        let other_token = Address::with_last_byte(2);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut first = TokenBalances::new(tip20_slots::BALANCES, PATH_USD_ADDRESS);
            let mut second = TokenBalances::new(tip20_slots::BALANCES, other_token);
            assert_eq!(first[holder].address(), second[holder].address());
            assert_ne!(first[holder].slot(), second[holder].slot());
            assert_ne!(first[holder].address(), first[other_holder].address());
            first[holder].write(U256::from(5))?;
            second[holder].write(U256::from(9))?;
            StorageCtx.sstore(holder, first[holder].slot(), U256::MAX)?;
            assert_eq!(first[holder].read()?, U256::from(5));
            assert_eq!(second[holder].read()?, U256::from(9));
            assert_eq!(first[other_holder].read()?, U256::ZERO);
            let (_, code) = StorageCtx.account_code(first[holder].address())?;
            assert_eq!(code.original_bytes().as_ref(), &[0x00]);
            Ok(())
        })
    }

    #[cfg(feature = "holder-first-balances")]
    #[test]
    fn failed_call_reverts_balance_and_storage_account_code() -> Result<()> {
        let holder = Address::repeat_byte(0x55);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut balances = TokenBalances::new(tip20_slots::BALANCES, PATH_USD_ADDRESS);
            {
                let _guard = StorageCtx.checkpoint();
                balances[holder].write(U256::ONE)?;
            }
            assert_eq!(balances[holder].read()?, U256::ZERO);
            let (_, code) = StorageCtx.account_code(balances[holder].address())?;
            assert!(code.is_empty());
            Ok(())
        })
    }

    #[cfg(feature = "holder-first-balances")]
    #[test]
    fn existing_contract_is_never_overwritten() -> Result<()> {
        let holder = Address::repeat_byte(0x66);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut balances = TokenBalances::new(tip20_slots::BALANCES, PATH_USD_ADDRESS);
            let address = balances[holder].address();
            StorageCtx.set_code(address, Bytecode::new_raw(vec![0xfe].into()))?;
            assert_eq!(
                balances[holder].write(U256::ONE),
                Err(TempoPrecompileError::Fatal(
                    "TIP-20 holder storage address collision".into()
                ))
            );
            assert_eq!(balances[holder].read()?, U256::ZERO);
            assert_eq!(
                StorageCtx
                    .account_code(address)?
                    .1
                    .original_bytes()
                    .as_ref(),
                &[0xfe]
            );
            Ok(())
        })
    }

    #[cfg(feature = "holder-first-balances")]
    #[test]
    fn zero_writes_do_not_deploy_storage_accounts() -> Result<()> {
        let holder = Address::repeat_byte(0x77);
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut balances = TokenBalances::new(tip20_slots::BALANCES, PATH_USD_ADDRESS);
            balances[holder].write(U256::ZERO)?;
            balances[holder].sinc(U256::ZERO)?;
            balances[holder].sdec(U256::ZERO)?;
            assert!(
                StorageCtx
                    .account_code(balances[holder].address())?
                    .1
                    .is_empty()
            );
            Ok(())
        })
    }
}
