use crate::{
    error::Result,
    storage::{Mapping, Slot, thread_local::ContractCall},
};
use alloy::primitives::{Address, U256};

pub struct ThreadLocalToken {
    total_supply: Slot<U256>,
    balances: Mapping<Address, U256>,
}

// macro generated
impl ContractCall for ThreadLocalToken {
    fn _new() -> Self {
        Self {
            total_supply: Slot::new(U256::ZERO),
            balances: Mapping::new(U256::ONE),
        }
    }
}

impl ThreadLocalToken {
    pub fn total_supply(&self) -> Result<U256> {
        self.total_supply.read_tl()
    }

    fn set_total_supply(&mut self, value: U256) -> Result<()> {
        self.total_supply.write_tl(value)
    }

    pub fn balance_of(&self, account: Address) -> Result<U256> {
        self.balances.at(account).read_tl()
    }

    fn set_balance(&mut self, account: Address, balance: U256) -> Result<()> {
        self.balances.at(account).write_tl(balance)
    }

    pub fn mint(&mut self, to: Address, amount: U256) -> Result<()> {
        let balance = self.balance_of(to)?;
        let supply = self.total_supply()?;

        self.set_balance(to, balance + amount)?;
        self.set_total_supply(supply + amount)?;

        Ok(())
    }

    pub fn transfer(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
        let from_balance = self.balance_of(from)?;
        let to_balance = self.balance_of(to)?;

        self.set_balance(from, from_balance - amount)?;
        self.set_balance(to, to_balance + amount)?;

        Ok(())
    }

    pub fn transfer_with_rewards(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<()> {
        self.transfer(from, to, amount)?;

        ThreadLocalRewards::new(self, REWARDS_ADDRESS)
            .call(|rewards| rewards.distribute(amount))?;

        Ok(())
    }
}

const REWARDS_ADDRESS: Address = Address::new([0xEE; 20]);

pub struct ThreadLocalRewards {
    rewards_pool: Slot<U256>,
}

// macro generated
impl ContractCall for ThreadLocalRewards {
    fn _new() -> Self {
        Self {
            rewards_pool: Slot::new(U256::ZERO),
        }
    }
}

impl ThreadLocalRewards {
    pub fn distribute(&mut self, transfer_amount: U256) -> Result<()> {
        let reward = transfer_amount / U256::from(100);
        let pool = self.rewards_pool.read_tl()?;
        self.rewards_pool.write_tl(pool + reward)?;

        Ok(())
    }

    pub fn get_pool(&self) -> Result<U256> {
        self.rewards_pool.read_tl()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{hashmap::HashMapStorageProvider, thread_local::StorageGuard};

    #[test]
    fn test_pure_thread_local() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let _storage_guard = unsafe { StorageGuard::new(&mut storage) };

        let token_address = Address::new([0x01; 20]);
        let alice = Address::new([0xA1; 20]);
        let bob = Address::new([0xB0; 20]);
        let mut ctx = ();

        // For top-level test entry points, pass `&mut ctx` to get `ReadWrite` context
        ThreadLocalToken::new(&mut ctx, token_address).call(|token| {
            // mint
            token.mint(alice, U256::from(1000))?;
            assert_eq!(token.balance_of(alice)?, U256::from(1000));
            assert_eq!(token.total_supply()?, U256::from(1000));

            // transfer
            token.transfer(alice, bob, U256::from(100))?;
            assert_eq!(token.balance_of(alice)?, U256::from(900));
            assert_eq!(token.balance_of(bob)?, U256::from(100));

            Ok(())
        })
    }

    #[test]
    fn test_cross_contract_calls() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let _storage_guard = unsafe { StorageGuard::new(&mut storage) };

        let token_address = Address::new([0x01; 20]);
        let alice = Address::new([0xA1; 20]);
        let bob = Address::new([0xB0; 20]);
        let mut ctx = ();

        ThreadLocalToken::new(&mut ctx, token_address).call(|token| {
            token.mint(alice, U256::from(1000))?;

            // transfer with rewards - demonstrates scoped cross-contract call
            token.transfer_with_rewards(alice, bob, U256::from(100))?;
            assert_eq!(token.balance_of(alice)?, U256::from(900));
            assert_eq!(token.balance_of(bob)?, U256::from(100));

            Ok(())
        })?;

        // verify rewards were distributed (read-only context)
        ThreadLocalRewards::new(&ctx, REWARDS_ADDRESS).staticcall(|rewards| {
            let pool = rewards.get_pool()?;
            assert_eq!(pool, U256::from(1));
            Ok(())
        })
    }

    #[test]
    fn test_nested_call_depth() -> Result<()> {
        use crate::storage::thread_local::context;

        let mut storage = HashMapStorageProvider::new(1);
        let _storage_guard = unsafe { StorageGuard::new(&mut storage) };

        let addr1 = Address::new([0x01; 20]);
        let addr2 = Address::new([0x02; 20]);
        let addr3 = Address::new([0x03; 20]);
        let ctx = ();

        // demonstrate nested contract calls with automatic address stack management
        ThreadLocalToken::new(&ctx, addr1).staticcall(|token1| {
            assert_eq!(context::call_depth(), 1);

            ThreadLocalToken::new(token1, addr2).staticcall(|token2| {
                assert_eq!(context::call_depth(), 2);

                ThreadLocalToken::new(token2, addr3).staticcall(|_token3| {
                    assert_eq!(context::call_depth(), 3);
                    Ok(())
                })?;

                assert_eq!(context::call_depth(), 2);
                Ok(())
            })?;

            assert_eq!(context::call_depth(), 1);
            Ok(())
        })
    }
}
