pub mod dispatch;

use crate::{
    STABLECOIN_EXCHANGE_ADDRESS,
    error::TempoPrecompileError,
    storage::PrecompileStorageProvider,
    tip20::{ITIP20, TIP20Token, roles::RolesAuthContract},
};
use alloy::primitives::{Address, B256, U256, keccak256};
use std::sync::LazyLock;
use tempo_contracts::precompiles::TIP20Error;

pub static TRANSFER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"TRANSFER_ROLE"));
pub static RECEIVE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"RECEIVE_ROLE"));

const NAME: &str = "linkingUSD";
const SYMBOL: &str = "linkingUSD";
const CURRENCY: &str = "USD";

pub struct LinkingUSD<'a, S: PrecompileStorageProvider> {
    pub token: TIP20Token<'a, S>,
}

impl<'a, S: PrecompileStorageProvider> LinkingUSD<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            token: TIP20Token::new(0, storage),
        }
    }

    pub fn initialize(&mut self, admin: Address) -> Result<(), TempoPrecompileError> {
        self.token
            .initialize(NAME, SYMBOL, CURRENCY, Address::ZERO, admin)
    }

    fn is_transfer_authorized(
        &mut self,
        sender: Address,
        recipient: Address,
    ) -> Result<bool, TempoPrecompileError> {
        let authorized = sender == STABLECOIN_EXCHANGE_ADDRESS
            || self.token.has_role(sender, *TRANSFER_ROLE)?
            || self.token.has_role(recipient, *RECEIVE_ROLE)?;

        Ok(authorized)
    }

    fn is_transfer_from_authorized(
        &mut self,
        sender: Address,
        from: Address,
        recipient: Address,
    ) -> Result<bool, TempoPrecompileError> {
        let authorized = sender == STABLECOIN_EXCHANGE_ADDRESS
            || self.token.has_role(from, *TRANSFER_ROLE)?
            || self.token.has_role(recipient, *RECEIVE_ROLE)?;

        Ok(authorized)
    }

    pub fn transfer(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferCall,
    ) -> Result<bool, TempoPrecompileError> {
        if self.is_transfer_authorized(msg_sender, call.to)? {
            self.token.transfer(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled().into())
        }
    }

    pub fn transfer_from(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool, TempoPrecompileError> {
        if self.is_transfer_from_authorized(msg_sender, call.from, call.to)?
            || msg_sender == STABLECOIN_EXCHANGE_ADDRESS
        {
            self.token.transfer_from(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled().into())
        }
    }

    pub fn transfer_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferWithMemoCall,
    ) -> Result<(), TempoPrecompileError> {
        if self.is_transfer_authorized(msg_sender, call.to)? {
            self.token.transfer_with_memo(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled().into())
        }
    }

    pub fn transfer_from_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool, TempoPrecompileError> {
        if self.is_transfer_from_authorized(msg_sender, call.from, call.to)?
            || msg_sender == STABLECOIN_EXCHANGE_ADDRESS
        {
            self.token.transfer_from_with_memo(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled().into())
        }
    }

    pub fn name(&mut self) -> Result<String, TempoPrecompileError> {
        self.token.name()
    }

    pub fn symbol(&mut self) -> Result<String, TempoPrecompileError> {
        self.token.symbol()
    }

    pub fn currency(&mut self) -> Result<String, TempoPrecompileError> {
        self.token.currency()
    }

    pub fn decimals(&mut self) -> Result<u8, TempoPrecompileError> {
        self.token.decimals()
    }

    pub fn total_supply(&mut self) -> Result<U256, TempoPrecompileError> {
        self.token.total_supply()
    }

    pub fn balance_of(
        &mut self,
        call: ITIP20::balanceOfCall,
    ) -> Result<U256, TempoPrecompileError> {
        self.token.balance_of(call)
    }

    pub fn allowance(&mut self, call: ITIP20::allowanceCall) -> Result<U256, TempoPrecompileError> {
        self.token.allowance(call)
    }

    pub fn approve(
        &mut self,
        sender: Address,
        call: ITIP20::approveCall,
    ) -> Result<bool, TempoPrecompileError> {
        self.token.approve(sender, call)
    }

    pub fn mint(
        &mut self,
        sender: Address,
        call: ITIP20::mintCall,
    ) -> Result<(), TempoPrecompileError> {
        self.token.mint(sender, call)
    }

    pub fn burn(
        &mut self,
        sender: Address,
        call: ITIP20::burnCall,
    ) -> Result<(), TempoPrecompileError> {
        self.token.burn(sender, call)
    }

    pub fn get_roles_contract(&mut self) -> RolesAuthContract<'_, S> {
        self.token.get_roles_contract()
    }

    pub fn pause(
        &mut self,
        sender: Address,
        call: ITIP20::pauseCall,
    ) -> Result<(), TempoPrecompileError> {
        self.token.pause(sender, call)
    }

    pub fn unpause(
        &mut self,
        sender: Address,
        call: ITIP20::unpauseCall,
    ) -> Result<(), TempoPrecompileError> {
        self.token.unpause(sender, call)
    }

    pub fn paused(&mut self) -> Result<bool, TempoPrecompileError> {
        self.token.paused()
    }
}

#[cfg(test)]
mod tests {

    use tempo_contracts::precompiles::RolesAuthError;

    use super::*;
    use crate::{
        storage::hashmap::HashMapStorageProvider,
        tip20::{IRolesAuth, ISSUER_ROLE, PAUSE_ROLE, UNPAUSE_ROLE},
    };

    fn transfer_test_setup(
        storage: &mut HashMapStorageProvider,
    ) -> (LinkingUSD<'_, HashMapStorageProvider>, Address) {
        let mut linking_usd = LinkingUSD::new(storage);
        let admin = Address::random();

        linking_usd
            .initialize(admin)
            .expect("Could not initialize linking usd");

        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE).unwrap();

        (linking_usd, admin)
    }

    #[test]
    fn test_metadata() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        assert_eq!(linking_usd.name()?, "linkingUSD");
        assert_eq!(linking_usd.symbol()?, "linkingUSD");
        assert_eq!(linking_usd.currency()?, "USD");
        Ok(())
    }

    #[test]
    fn test_transfer_reverts() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        let result = linking_usd.transfer(
            Address::random(),
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::random(),
            },
        );

        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::TIP20(TIP20Error::transfers_disabled())
        );
    }

    #[test]
    fn test_transfer_from_reverts() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        let result = linking_usd.transfer_from(
            Address::random(),
            ITIP20::transferFromCall {
                from: Address::random(),
                to: Address::random(),
                amount: U256::random(),
            },
        );
        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::TIP20(TIP20Error::transfers_disabled())
        );
    }

    #[test]
    fn test_transfer_with_memo_reverts() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        let result = linking_usd.transfer_with_memo(
            Address::random(),
            ITIP20::transferWithMemoCall {
                to: Address::random(),
                amount: U256::from(100),
                memo: [0u8; 32].into(),
            },
        );
        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::TIP20(TIP20Error::transfers_disabled())
        );
    }

    #[test]
    fn test_transfer_from_with_memo_reverts() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        let result = linking_usd.transfer_from_with_memo(
            Address::random(),
            ITIP20::transferFromWithMemoCall {
                from: Address::random(),
                to: Address::random(),
                amount: U256::from(100),
                memo: [0u8; 32].into(),
            },
        );
        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::TIP20(TIP20Error::transfers_disabled())
        );
    }

    #[test]
    fn test_mint() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, admin) = transfer_test_setup(&mut storage);
        let recipient = Address::random();
        let amount = U256::from(1000);

        let balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        linking_usd.mint(
            admin,
            ITIP20::mintCall {
                to: recipient,
                amount,
            },
        )?;

        let balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        assert_eq!(balance_after, balance_before + amount);
        Ok(())
    }

    #[test]
    fn test_burn() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let amount = U256::from(1000);

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: admin, amount })?;

        let balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: admin })?;

        linking_usd.burn(admin, ITIP20::burnCall { amount })?;

        let balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: admin })?;
        assert_eq!(balance_after, balance_before - amount);
        Ok(())
    }

    #[test]
    fn test_approve() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let owner = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);

        linking_usd.initialize(admin)?;

        let result = linking_usd.approve(owner, ITIP20::approveCall { spender, amount })?;

        assert!(result);

        let allowance = linking_usd.allowance(ITIP20::allowanceCall { owner, spender })?;
        assert_eq!(allowance, amount);
        Ok(())
    }

    #[test]
    fn test_transfer_with_stablecoin_exchange() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        linking_usd.mint(
            admin,
            ITIP20::mintCall {
                to: STABLECOIN_EXCHANGE_ADDRESS,
                amount,
            },
        )?;

        let dex_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall {
            account: STABLECOIN_EXCHANGE_ADDRESS,
        })?;

        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        let result = linking_usd.transfer(
            STABLECOIN_EXCHANGE_ADDRESS,
            ITIP20::transferCall {
                to: recipient,
                amount,
            },
        )?;
        assert!(result);

        let dex_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall {
            account: STABLECOIN_EXCHANGE_ADDRESS,
        })?;

        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        assert_eq!(dex_balance_after, dex_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
        Ok(())
    }

    #[test]
    fn test_transfer_from_with_stablecoin_exchange() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::from(1000);

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

        linking_usd.approve(
            from,
            ITIP20::approveCall {
                spender: STABLECOIN_EXCHANGE_ADDRESS,
                amount,
            },
        )?;

        let from_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;

        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;

        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender: STABLECOIN_EXCHANGE_ADDRESS,
        })?;

        let result = linking_usd.transfer_from(
            STABLECOIN_EXCHANGE_ADDRESS,
            ITIP20::transferFromCall { from, to, amount },
        )?;

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;

        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;

        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender: STABLECOIN_EXCHANGE_ADDRESS,
        })?;

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
        Ok(())
    }

    #[test]
    fn test_transfer_with_transfer_role() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;
        roles.grant_role_internal(sender, *TRANSFER_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

        let sender_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;

        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        let result = linking_usd.transfer(
            sender,
            ITIP20::transferCall {
                to: recipient,
                amount,
            },
        )?;
        assert!(result);

        let sender_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        assert_eq!(sender_balance_after, sender_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
        Ok(())
    }

    #[test]
    fn test_transfer_with_receive_role() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;
        roles.grant_role_internal(recipient, *RECEIVE_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

        let sender_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;

        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        let result = linking_usd.transfer(
            sender,
            ITIP20::transferCall {
                to: recipient,
                amount,
            },
        )?;
        assert!(result);

        let sender_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        assert_eq!(sender_balance_after, sender_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);

        Ok(())
    }

    #[test]
    fn test_transfer_from_with_transfer_role() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;
        roles.grant_role_internal(from, *TRANSFER_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

        linking_usd.approve(from, ITIP20::approveCall { spender, amount })?;

        let from_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;

        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;

        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        })?;

        let result =
            linking_usd.transfer_from(spender, ITIP20::transferFromCall { from, to, amount })?;

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        })?;

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
        Ok(())
    }

    #[test]
    fn test_transfer_from_with_receive_role() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;
        roles.grant_role_internal(to, *RECEIVE_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

        linking_usd.approve(from, ITIP20::approveCall { spender, amount })?;

        let from_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;

        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;

        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        })?;

        let result =
            linking_usd.transfer_from(spender, ITIP20::transferFromCall { from, to, amount })?;

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        })?;

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
        Ok(())
    }

    #[test]
    fn test_transfer_with_memo_with_transfer_role() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();

        roles.grant_role_internal(admin, *ISSUER_ROLE)?;
        roles.grant_role_internal(sender, *TRANSFER_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

        let sender_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        linking_usd.transfer_with_memo(
            sender,
            ITIP20::transferWithMemoCall {
                to: recipient,
                amount,
                memo: memo.into(),
            },
        )?;

        let sender_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        assert_eq!(sender_balance_after, sender_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
        Ok(())
    }

    #[test]
    fn test_transfer_with_memo_with_receive_role() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;
        roles.grant_role_internal(recipient, *RECEIVE_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

        let sender_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        linking_usd.transfer_with_memo(
            sender,
            ITIP20::transferWithMemoCall {
                to: recipient,
                amount,
                memo: memo.into(),
            },
        )?;

        let sender_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        assert_eq!(sender_balance_after, sender_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
        Ok(())
    }

    #[test]
    fn test_transfer_from_with_memo_with_stablecoin_exchange() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

        linking_usd.approve(
            from,
            ITIP20::approveCall {
                spender: STABLECOIN_EXCHANGE_ADDRESS,
                amount,
            },
        )?;

        let from_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender: STABLECOIN_EXCHANGE_ADDRESS,
        })?;

        let result = linking_usd.transfer_from_with_memo(
            STABLECOIN_EXCHANGE_ADDRESS,
            ITIP20::transferFromWithMemoCall {
                from,
                to,
                amount,
                memo: memo.into(),
            },
        )?;

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender: STABLECOIN_EXCHANGE_ADDRESS,
        })?;

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
        Ok(())
    }

    #[test]
    fn test_transfer_from_with_memo_with_transfer_role() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;
        roles.grant_role_internal(from, *TRANSFER_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

        linking_usd.approve(from, ITIP20::approveCall { spender, amount })?;

        let from_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        })?;

        let result = linking_usd.transfer_from_with_memo(
            spender,
            ITIP20::transferFromWithMemoCall {
                from,
                to,
                amount,
                memo: memo.into(),
            },
        )?;

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        })?;

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
        Ok(())
    }

    #[test]
    fn test_transfer_from_with_memo_with_receive_role() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd.initialize(admin)?;
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;
        roles.grant_role_internal(to, *RECEIVE_ROLE)?;

        linking_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

        linking_usd.approve(from, ITIP20::approveCall { spender, amount })?;

        let from_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        })?;

        let result = linking_usd.transfer_from_with_memo(
            spender,
            ITIP20::transferFromWithMemoCall {
                from,
                to,
                amount,
                memo: memo.into(),
            },
        )?;

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        })?;

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
        Ok(())
    }

    #[test]
    fn test_pause_and_unpause() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let pauser = Address::random();
        let unpauser = Address::random();

        linking_usd.initialize(admin).unwrap();

        // Grant PAUSE_ROLE and UNPAUSE_ROLE
        let mut roles = linking_usd.get_roles_contract();
        roles.grant_role_internal(pauser, *PAUSE_ROLE)?;
        roles.grant_role_internal(unpauser, *UNPAUSE_ROLE)?;

        // Verify initial state (not paused)
        assert!(!linking_usd.paused().unwrap());

        // Pause the token
        linking_usd.pause(pauser, ITIP20::pauseCall {}).unwrap();
        assert!(linking_usd.paused().unwrap());

        // Unpause the token
        linking_usd
            .unpause(unpauser, ITIP20::unpauseCall {})
            .unwrap();
        assert!(!linking_usd.paused().unwrap());
        Ok(())
    }

    #[test]
    fn test_role_management() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let user = Address::random();

        linking_usd.initialize(admin).unwrap();

        // Grant ISSUER_ROLE to user
        let mut roles = linking_usd.get_roles_contract();
        roles
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: *ISSUER_ROLE,
                    account: user,
                },
            )
            .unwrap();

        // Check that user has the role
        assert!(
            roles
                .has_role(IRolesAuth::hasRoleCall {
                    role: *ISSUER_ROLE,
                    account: user,
                })
                .expect("Could not get role")
        );

        // Revoke the role
        roles
            .revoke_role(
                admin,
                IRolesAuth::revokeRoleCall {
                    role: *ISSUER_ROLE,
                    account: user,
                },
            )
            .unwrap();

        // Check that user no longer has the role
        assert!(
            !roles
                .has_role(IRolesAuth::hasRoleCall {
                    role: *ISSUER_ROLE,
                    account: user,
                })
                .expect("Could not get role")
        );
        Ok(())
    }

    #[test]
    fn test_supply_cap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let recipient = Address::random();
        let supply_cap = U256::from(1000);

        linking_usd.initialize(admin).unwrap();

        let mut roles = linking_usd.get_roles_contract();
        roles.grant_role_internal(admin, *ISSUER_ROLE)?;

        // Set supply cap
        linking_usd
            .token
            .set_supply_cap(
                admin,
                ITIP20::setSupplyCapCall {
                    newSupplyCap: supply_cap,
                },
            )
            .unwrap();

        assert_eq!(linking_usd.token.supply_cap().unwrap(), supply_cap);

        // Try to mint more than supply cap
        let result = linking_usd.mint(
            admin,
            ITIP20::mintCall {
                to: recipient,
                amount: U256::from(1001),
            },
        );

        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::TIP20(TIP20Error::supply_cap_exceeded())
        );
        Ok(())
    }

    #[test]
    fn test_change_transfer_policy_id() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let new_policy_id = 42u64;

        linking_usd.initialize(admin).unwrap();

        // Admin can change transfer policy ID
        linking_usd
            .token
            .change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: new_policy_id,
                },
            )
            .unwrap();

        assert_eq!(
            linking_usd
                .token
                .transfer_policy_id()
                .expect("Could not get policy"),
            new_policy_id
        );

        // Non-admin cannot change transfer policy ID
        let non_admin = Address::random();
        let result = linking_usd.token.change_transfer_policy_id(
            non_admin,
            ITIP20::changeTransferPolicyIdCall { newPolicyId: 100 },
        );

        assert_eq!(
            result.unwrap_err(),
            TempoPrecompileError::RolesAuthError(RolesAuthError::unauthorized())
        );
        Ok(())
    }
}
