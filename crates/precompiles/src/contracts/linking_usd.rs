use crate::contracts::{
    StorageProvider,
    tip20::TIP20Token,
    types::{ITIP20, TIP20Error},
};
use alloy::primitives::{Address, U256};

pub struct LinkingUSD<'a, S: StorageProvider> {
    pub token: TIP20Token<'a, S>,
}

impl<'a, S: StorageProvider> LinkingUSD<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            token: TIP20Token::new(0, storage),
        }
    }

    pub fn initialize(&mut self) -> Result<(), TIP20Error> {
        self.token.initialize(
            "LinkingUSD",
            "LUSD",
            "USD",
            Address::ZERO,  // No linking token for LinkingUSD
            &Address::ZERO, // No admin
        )
    }

    pub fn depth(&mut self) -> u32 {
        0
    }

    pub fn transfer(&mut self, _to: Address, _amount: U256) -> Result<bool, TIP20Error> {
        Err(TIP20Error::transfers_disabled())
    }

    pub fn transfer_from(
        &mut self,
        _from: Address,
        _to: Address,
        _amount: U256,
    ) -> Result<bool, TIP20Error> {
        Err(TIP20Error::transfers_disabled())
    }

    pub fn transfer_with_memo(
        &mut self,
        _to: Address,
        _amount: U256,
        _memo: [u8; 32],
    ) -> Result<(), TIP20Error> {
        Err(TIP20Error::transfers_disabled())
    }

    pub fn transfer_from_with_memo(
        &mut self,
        _from: Address,
        _to: Address,
        _amount: U256,
        _memo: [u8; 32],
    ) -> Result<bool, TIP20Error> {
        Err(TIP20Error::transfers_disabled())
    }

    // Delegate all other methods to the underlying TIP20Token
    pub fn name(&mut self) -> String {
        self.token.name()
    }

    pub fn symbol(&mut self) -> String {
        self.token.symbol()
    }

    pub fn currency(&mut self) -> String {
        self.token.currency()
    }

    pub fn linking_token(&mut self) -> Address {
        self.token.linking_token()
    }

    pub fn decimals(&mut self) -> u8 {
        self.token.decimals()
    }

    pub fn total_supply(&mut self) -> U256 {
        self.token.total_supply()
    }

    pub fn balance_of(&mut self, call: ITIP20::balanceOfCall) -> U256 {
        self.token.balance_of(call)
    }

    pub fn allowance(&mut self, call: ITIP20::allowanceCall) -> U256 {
        self.token.allowance(call)
    }

    pub fn approve(
        &mut self,
        sender: &Address,
        call: ITIP20::approveCall,
    ) -> Result<bool, TIP20Error> {
        self.token.approve(sender, call)
    }

    pub fn mint(&mut self, sender: &Address, call: ITIP20::mintCall) -> Result<(), TIP20Error> {
        self.token.mint(sender, call)
    }

    pub fn burn(&mut self, sender: &Address, call: ITIP20::burnCall) -> Result<(), TIP20Error> {
        self.token.burn(sender, call)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::storage::hashmap::HashMapStorageProvider;

    #[test]
    fn test_linking_usd_initialization() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);

        linking_usd
            .initialize()
            .expect("LinkingUSD initialization should succeed");

        assert_eq!(linking_usd.name(), "LinkingUSD");
        assert_eq!(linking_usd.symbol(), "LUSD");
        assert_eq!(linking_usd.depth(), 0);
    }

    #[test]
    fn test_transfers_disabled() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);

        linking_usd
            .initialize()
            .expect("LinkingUSD initialization should succeed");

        let account = Address::random();
        let amount = U256::from(100);
        let memo = [0u8; 32];

        assert!(linking_usd.transfer(account, amount).is_err());
        assert!(linking_usd.transfer_from(account, account, amount).is_err());
        assert!(
            linking_usd
                .transfer_with_memo(account, amount, memo)
                .is_err()
        );
        assert!(
            linking_usd
                .transfer_from_with_memo(account, account, amount, memo)
                .is_err()
        );
    }
}
