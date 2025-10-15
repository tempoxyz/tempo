use crate::{
    STABLECOIN_EXCHANGE_ADDRESS,
    contracts::{
        StorageProvider,
        tip20::TIP20Token,
        types::{ITIP20, TIP20Error},
    },
};
use alloy::primitives::{Address, B256, U256, keccak256};
use std::sync::LazyLock;

pub static TRANSFER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"TRANSFER_ROLE"));
pub static RECEIVE_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"RECEIVE_ROLE"));

const NAME: &str = "linkingUSD";
const SYMBOL: &str = "linkingUSD";
const CURRENCY: &str = "USD";

pub struct LinkingUSD<'a, S: StorageProvider> {
    pub token: TIP20Token<'a, S>,
}

impl<'a, S: StorageProvider> LinkingUSD<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            token: TIP20Token::new(0, storage),
        }
    }

    pub fn initialize(&mut self, admin: &Address) -> Result<(), TIP20Error> {
        self.token
            .initialize(NAME, SYMBOL, CURRENCY, Address::ZERO, admin)
    }

    fn is_transfer_authorized(&mut self, sender: &Address, recipient: &Address) -> bool {
        *sender == STABLECOIN_EXCHANGE_ADDRESS
            || self.token.has_role(sender, *TRANSFER_ROLE)
            || self.token.has_role(recipient, *RECEIVE_ROLE)
    }

    fn is_transfer_from_authorized(
        &mut self,
        sender: &Address,
        from: &Address,
        recipient: &Address,
    ) -> bool {
        *sender == STABLECOIN_EXCHANGE_ADDRESS
            || self.token.has_role(from, *TRANSFER_ROLE)
            || self.token.has_role(recipient, *RECEIVE_ROLE)
    }

    pub fn transfer(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferCall,
    ) -> Result<bool, TIP20Error> {
        if self.is_transfer_authorized(msg_sender, &call.to) {
            self.token.transfer(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled())
        }
    }

    pub fn transfer_from(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool, TIP20Error> {
        if self.is_transfer_from_authorized(msg_sender, &call.from, &call.to)
            || *msg_sender == STABLECOIN_EXCHANGE_ADDRESS
        {
            self.token.transfer_from(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled())
        }
    }

    pub fn transfer_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferWithMemoCall,
    ) -> Result<(), TIP20Error> {
        if self.is_transfer_authorized(msg_sender, &call.to) {
            self.token.transfer_with_memo(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled())
        }
    }

    pub fn transfer_from_with_memo(
        &mut self,
        msg_sender: &Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool, TIP20Error> {
        if self.is_transfer_from_authorized(msg_sender, &call.from, &call.to)
            || *msg_sender == STABLECOIN_EXCHANGE_ADDRESS
        {
            self.token.transfer_from_with_memo(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled())
        }
    }

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
    use crate::contracts::{storage::hashmap::HashMapStorageProvider, tip20::ISSUER_ROLE};

    fn transfer_test_setup(
        storage: &mut HashMapStorageProvider,
    ) -> (LinkingUSD<'_, HashMapStorageProvider>, Address) {
        let mut linking_usd = LinkingUSD::new(storage);
        let admin = Address::random();

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");

        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        (linking_usd, admin)
    }

    #[test]
    fn test_metadata() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        assert_eq!(linking_usd.name(), "linkingUSD");
        assert_eq!(linking_usd.symbol(), "linkingUSD");
        assert_eq!(linking_usd.currency(), "USD");
        assert_eq!(linking_usd.linking_token(), Address::ZERO);
    }

    #[test]
    fn test_transfer_reverts() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        let result = linking_usd.transfer(
            &Address::random(),
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::random(),
            },
        );

        assert_eq!(result.unwrap_err(), TIP20Error::transfers_disabled());
    }

    #[test]
    fn test_transfer_from_reverts() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        let result = linking_usd.transfer_from(
            &Address::random(),
            ITIP20::transferFromCall {
                from: Address::random(),
                to: Address::random(),
                amount: U256::random(),
            },
        );
        assert_eq!(result.unwrap_err(), TIP20Error::transfers_disabled());
    }

    #[test]
    fn test_transfer_with_memo_reverts() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        let result = linking_usd.transfer_with_memo(
            &Address::random(),
            ITIP20::transferWithMemoCall {
                to: Address::random(),
                amount: U256::from(100),
                memo: [0u8; 32].into(),
            },
        );
        assert_eq!(result.unwrap_err(), TIP20Error::transfers_disabled());
    }

    #[test]
    fn test_transfer_from_with_memo_reverts() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, _admin) = transfer_test_setup(&mut storage);

        let result = linking_usd.transfer_from_with_memo(
            &Address::random(),
            ITIP20::transferFromWithMemoCall {
                from: Address::random(),
                to: Address::random(),
                amount: U256::from(100),
                memo: [0u8; 32].into(),
            },
        );
        assert_eq!(result.unwrap_err(), TIP20Error::transfers_disabled());
    }

    #[test]
    fn test_mint() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut linking_usd, admin) = transfer_test_setup(&mut storage);
        let recipient = Address::random();
        let amount = U256::from(1000);

        let balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        linking_usd
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: recipient,
                    amount,
                },
            )
            .expect("Mint should succeed");

        let balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        assert_eq!(balance_after, balance_before + amount);
    }

    #[test]
    fn test_burn() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let amount = U256::from(1000);

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: admin, amount })
            .expect("Mint should succeed");

        let balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: admin });

        linking_usd
            .burn(&admin, ITIP20::burnCall { amount })
            .expect("Burn should succeed");

        let balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: admin });
        assert_eq!(balance_after, balance_before - amount);
    }

    #[test]
    fn test_approve() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let owner = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");

        let result = linking_usd
            .approve(&owner, ITIP20::approveCall { spender, amount })
            .expect("Approve should succeed");

        assert!(result);

        let allowance = linking_usd.allowance(ITIP20::allowanceCall { owner, spender });
        assert_eq!(allowance, amount);
    }

    #[test]
    fn test_transfer_with_stablecoin_exchange() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        linking_usd
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: STABLECOIN_EXCHANGE_ADDRESS,
                    amount,
                },
            )
            .expect("Mint should succeed");

        let dex_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall {
            account: STABLECOIN_EXCHANGE_ADDRESS,
        });
        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        let result = linking_usd
            .transfer(
                &STABLECOIN_EXCHANGE_ADDRESS,
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                },
            )
            .expect("Transfer should succeed");
        assert!(result);

        let dex_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall {
            account: STABLECOIN_EXCHANGE_ADDRESS,
        });
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        assert_eq!(dex_balance_after, dex_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
    }

    #[test]
    fn test_transfer_from_with_stablecoin_exchange() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::from(1000);

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: from, amount })
            .expect("Mint should succeed");

        linking_usd
            .approve(
                &from,
                ITIP20::approveCall {
                    spender: STABLECOIN_EXCHANGE_ADDRESS,
                    amount,
                },
            )
            .expect("Approve should succeed");

        let from_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender: STABLECOIN_EXCHANGE_ADDRESS,
        });

        let result = linking_usd
            .transfer_from(
                &STABLECOIN_EXCHANGE_ADDRESS,
                ITIP20::transferFromCall { from, to, amount },
            )
            .expect("TransferFrom should succeed");

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender: STABLECOIN_EXCHANGE_ADDRESS,
        });

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
    }

    #[test]
    fn test_transfer_with_transfer_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        roles.grant_role_internal(&sender, *TRANSFER_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: sender, amount })
            .expect("Mint should succeed");

        let sender_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender });
        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        let result = linking_usd
            .transfer(
                &sender,
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                },
            )
            .expect("Transfer should succeed");
        assert!(result);

        let sender_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender });
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        assert_eq!(sender_balance_after, sender_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
    }

    #[test]
    fn test_transfer_with_receive_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        roles.grant_role_internal(&recipient, *RECEIVE_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: sender, amount })
            .expect("Mint should succeed");

        let sender_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender });
        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        let result = linking_usd
            .transfer(
                &sender,
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                },
            )
            .expect("Transfer should succeed");
        assert!(result);

        let sender_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender });
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        assert_eq!(sender_balance_after, sender_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
    }

    #[test]
    fn test_transfer_from_with_transfer_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        roles.grant_role_internal(&from, *TRANSFER_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: from, amount })
            .expect("Mint should succeed");

        linking_usd
            .approve(&from, ITIP20::approveCall { spender, amount })
            .expect("Approve should succeed");

        let from_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        });

        let result = linking_usd
            .transfer_from(&spender, ITIP20::transferFromCall { from, to, amount })
            .expect("TransferFrom should succeed");

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        });

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
    }

    #[test]
    fn test_transfer_from_with_receive_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        roles.grant_role_internal(&to, *RECEIVE_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: from, amount })
            .expect("Mint should succeed");

        linking_usd
            .approve(&from, ITIP20::approveCall { spender, amount })
            .expect("Approve should succeed");

        let from_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        });

        let result = linking_usd
            .transfer_from(&spender, ITIP20::transferFromCall { from, to, amount })
            .expect("TransferFrom should succeed");

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        });

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
    }

    #[test]
    fn test_transfer_with_memo_with_transfer_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        roles.grant_role_internal(&sender, *TRANSFER_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: sender, amount })
            .expect("Mint should succeed");

        let sender_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender });
        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        linking_usd
            .transfer_with_memo(
                &sender,
                ITIP20::transferWithMemoCall {
                    to: recipient,
                    amount,
                    memo: memo.into(),
                },
            )
            .expect("Transfer with memo should succeed");

        let sender_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender });
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        assert_eq!(sender_balance_after, sender_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
    }

    #[test]
    fn test_transfer_with_memo_with_receive_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        roles.grant_role_internal(&recipient, *RECEIVE_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: sender, amount })
            .expect("Mint should succeed");

        let sender_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender });
        let recipient_balance_before =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        linking_usd
            .transfer_with_memo(
                &sender,
                ITIP20::transferWithMemoCall {
                    to: recipient,
                    amount,
                    memo: memo.into(),
                },
            )
            .expect("Transfer with memo should succeed");

        let sender_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: sender });
        let recipient_balance_after =
            linking_usd.balance_of(ITIP20::balanceOfCall { account: recipient });

        assert_eq!(sender_balance_after, sender_balance_before - amount);
        assert_eq!(recipient_balance_after, recipient_balance_before + amount);
    }

    #[test]
    fn test_transfer_from_with_memo_with_stablecoin_exchange() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: from, amount })
            .expect("Mint should succeed");

        linking_usd
            .approve(
                &from,
                ITIP20::approveCall {
                    spender: STABLECOIN_EXCHANGE_ADDRESS,
                    amount,
                },
            )
            .expect("Approve should succeed");

        let from_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender: STABLECOIN_EXCHANGE_ADDRESS,
        });

        let result = linking_usd
            .transfer_from_with_memo(
                &STABLECOIN_EXCHANGE_ADDRESS,
                ITIP20::transferFromWithMemoCall {
                    from,
                    to,
                    amount,
                    memo: memo.into(),
                },
            )
            .expect("TransferFromWithMemo should succeed");

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender: STABLECOIN_EXCHANGE_ADDRESS,
        });

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
    }

    #[test]
    fn test_transfer_from_with_memo_with_transfer_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        roles.grant_role_internal(&from, *TRANSFER_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: from, amount })
            .expect("Mint should succeed");

        linking_usd
            .approve(&from, ITIP20::approveCall { spender, amount })
            .expect("Approve should succeed");

        let from_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        });

        let result = linking_usd
            .transfer_from_with_memo(
                &spender,
                ITIP20::transferFromWithMemoCall {
                    from,
                    to,
                    amount,
                    memo: memo.into(),
                },
            )
            .expect("TransferFromWithMemo should succeed");

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        });

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
    }

    #[test]
    fn test_transfer_from_with_memo_with_receive_role() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut linking_usd = LinkingUSD::new(&mut storage);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);
        let memo = [1u8; 32];

        linking_usd
            .initialize(&admin)
            .expect("LinkingUSD initialization should succeed");
        let mut roles = linking_usd.token.get_roles_contract();
        roles.grant_role_internal(&admin, *ISSUER_ROLE);
        roles.grant_role_internal(&to, *RECEIVE_ROLE);

        linking_usd
            .mint(&admin, ITIP20::mintCall { to: from, amount })
            .expect("Mint should succeed");

        linking_usd
            .approve(&from, ITIP20::approveCall { spender, amount })
            .expect("Approve should succeed");

        let from_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_before = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_before = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        });

        let result = linking_usd
            .transfer_from_with_memo(
                &spender,
                ITIP20::transferFromWithMemoCall {
                    from,
                    to,
                    amount,
                    memo: memo.into(),
                },
            )
            .expect("TransferFromWithMemo should succeed");

        assert!(result);

        let from_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: from });
        let to_balance_after = linking_usd.balance_of(ITIP20::balanceOfCall { account: to });
        let allowance_after = linking_usd.allowance(ITIP20::allowanceCall {
            owner: from,
            spender,
        });

        assert_eq!(from_balance_after, from_balance_before - amount);
        assert_eq!(to_balance_after, to_balance_before + amount);
        assert_eq!(allowance_after, allowance_before - amount);
    }
}
