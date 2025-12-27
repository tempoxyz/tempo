pub mod dispatch;

use crate::{
    STABLECOIN_EXCHANGE_ADDRESS,
    error::Result,
    storage::StorageCtx,
    tip20::{ITIP20, TIP20Token},
};
use alloy::primitives::{Address, B256, U256, keccak256};
use std::sync::LazyLock;
pub use tempo_contracts::precompiles::IPathUSD;
use tempo_contracts::precompiles::TIP20Error;

pub static TRANSFER_ROLE: LazyLock<B256> = LazyLock::new(|| keccak256(b"TRANSFER_ROLE"));
pub static RECEIVE_WITH_MEMO_ROLE: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"RECEIVE_WITH_MEMO_ROLE"));

/// Name of TIP20 post allegretto. Note that the name and symbol are the same value
const NAME_POST_ALLEGRETTO: &str = "pathUSD";
/// Name of TIP20 pre allegretto. Note that the name and symbol are the same value
const NAME_PRE_ALLEGRETTO: &str = "linkingUSD";
const CURRENCY: &str = "USD";

pub struct PathUSD {
    pub token: TIP20Token,
    storage: StorageCtx,
}

impl Default for PathUSD {
    fn default() -> Self {
        Self::new()
    }
}

impl PathUSD {
    pub fn new() -> Self {
        Self {
            token: TIP20Token::new(0),
            storage: StorageCtx::default(),
        }
    }

    pub fn initialize(&mut self, admin: Address) -> Result<()> {
        let (name, symbol) = if self.storage.spec().is_allegretto() {
            (NAME_POST_ALLEGRETTO, NAME_POST_ALLEGRETTO)
        } else {
            (NAME_PRE_ALLEGRETTO, NAME_PRE_ALLEGRETTO)
        };

        self.token
            .initialize(name, symbol, CURRENCY, Address::ZERO, admin, Address::ZERO)
    }

    fn is_transfer_authorized(&self, sender: Address) -> Result<bool> {
        let authorized = sender == STABLECOIN_EXCHANGE_ADDRESS
            || self.token.has_role_internal(sender, *TRANSFER_ROLE)?;

        Ok(authorized)
    }

    fn is_transfer_from_authorized(&self, sender: Address, from: Address) -> Result<bool> {
        let authorized = sender == STABLECOIN_EXCHANGE_ADDRESS
            || self.token.has_role_internal(from, *TRANSFER_ROLE)?;
        Ok(authorized)
    }

    fn is_transfer_with_memo_authorized(
        &self,
        sender: Address,
        recipient: Address,
    ) -> Result<bool> {
        let authorized = sender == STABLECOIN_EXCHANGE_ADDRESS
            || self.token.has_role_internal(sender, *TRANSFER_ROLE)?
            || self
                .token
                .has_role_internal(recipient, *RECEIVE_WITH_MEMO_ROLE)?;

        Ok(authorized)
    }

    fn is_transfer_from_with_memo_authorized(
        &self,
        sender: Address,
        from: Address,
        recipient: Address,
    ) -> Result<bool> {
        let authorized = sender == STABLECOIN_EXCHANGE_ADDRESS
            || self.token.has_role_internal(from, *TRANSFER_ROLE)?
            || self
                .token
                .has_role_internal(recipient, *RECEIVE_WITH_MEMO_ROLE)?;

        Ok(authorized)
    }

    pub fn transfer(&mut self, msg_sender: Address, call: ITIP20::transferCall) -> Result<bool> {
        // Post allegretto, use default tip20 logic
        if self.storage.spec().is_allegretto() {
            return self.token.transfer(msg_sender, call);
        }

        if self.is_transfer_authorized(msg_sender)? {
            self.token.transfer(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled().into())
        }
    }

    pub fn transfer_from(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromCall,
    ) -> Result<bool> {
        // Post allegretto, use default tip20 logic
        if self.storage.spec().is_allegretto() {
            return self.token.transfer_from(msg_sender, call);
        }

        if self.is_transfer_from_authorized(msg_sender, call.from)?
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
    ) -> Result<()> {
        // Post allegretto, use default tip20 logic
        if self.storage.spec().is_allegretto() {
            return self.token.transfer_with_memo(msg_sender, call);
        }

        if self.is_transfer_with_memo_authorized(msg_sender, call.to)? {
            self.token.transfer_with_memo(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled().into())
        }
    }

    pub fn transfer_from_with_memo(
        &mut self,
        msg_sender: Address,
        call: ITIP20::transferFromWithMemoCall,
    ) -> Result<bool> {
        // Post allegretto, use default tip20 logic
        if self.storage.spec().is_allegretto() {
            return self.token.transfer_from_with_memo(msg_sender, call);
        }

        if self.is_transfer_from_with_memo_authorized(msg_sender, call.from, call.to)?
            || msg_sender == STABLECOIN_EXCHANGE_ADDRESS
        {
            self.token.transfer_from_with_memo(msg_sender, call)
        } else {
            Err(TIP20Error::transfers_disabled().into())
        }
    }

    pub fn name(&self) -> Result<String> {
        if self.storage.spec().is_allegretto() {
            Ok(NAME_POST_ALLEGRETTO.to_string())
        } else {
            self.token.name()
        }
    }

    pub fn symbol(&self) -> Result<String> {
        if self.storage.spec().is_allegretto() {
            Ok(NAME_POST_ALLEGRETTO.to_string())
        } else {
            self.token.symbol()
        }
    }

    pub fn currency(&self) -> Result<String> {
        self.token.currency()
    }

    pub fn decimals(&self) -> Result<u8> {
        self.token.decimals()
    }

    pub fn total_supply(&self) -> Result<U256> {
        self.token.total_supply()
    }

    pub fn balance_of(&self, call: ITIP20::balanceOfCall) -> Result<U256> {
        self.token.balance_of(call)
    }

    pub fn allowance(&self, call: ITIP20::allowanceCall) -> Result<U256> {
        self.token.allowance(call)
    }

    pub fn approve(&mut self, sender: Address, call: ITIP20::approveCall) -> Result<bool> {
        self.token.approve(sender, call)
    }

    pub fn mint(&mut self, sender: Address, call: ITIP20::mintCall) -> Result<()> {
        self.token.mint(sender, call)
    }

    pub fn burn(&mut self, sender: Address, call: ITIP20::burnCall) -> Result<()> {
        self.token.burn(sender, call)
    }

    pub fn pause(&mut self, sender: Address, call: ITIP20::pauseCall) -> Result<()> {
        self.token.pause(sender, call)
    }

    pub fn unpause(&mut self, sender: Address, call: ITIP20::unpauseCall) -> Result<()> {
        self.token.unpause(sender, call)
    }

    pub fn paused(&self) -> Result<bool> {
        self.token.paused()
    }

    /// Returns the PAUSE_ROLE constant
    ///
    /// This role identifier grants permission to pause the token contract.
    /// The role is computed as `keccak256("PAUSE_ROLE")`.
    pub fn pause_role() -> B256 {
        TIP20Token::pause_role()
    }

    /// Returns the UNPAUSE_ROLE constant
    ///
    /// This role identifier grants permission to unpause the token contract.
    /// The role is computed as `keccak256("UNPAUSE_ROLE")`.
    pub fn unpause_role() -> B256 {
        TIP20Token::unpause_role()
    }

    /// Returns the ISSUER_ROLE constant
    ///
    /// This role identifier grants permission to mint and burn tokens.
    /// The role is computed as `keccak256("ISSUER_ROLE")`.
    pub fn issuer_role() -> B256 {
        TIP20Token::issuer_role()
    }

    /// Returns the BURN_BLOCKED_ROLE constant
    ///
    /// This role identifier grants permission to burn tokens from blocked accounts.
    /// The role is computed as `keccak256("BURN_BLOCKED_ROLE")`.
    pub fn burn_blocked_role() -> B256 {
        TIP20Token::burn_blocked_role()
    }

    /// Returns the TRANSFER_ROLE constant
    ///
    /// This role identifier grants permission to transfer pathUSD tokens.
    /// The role is computed as `keccak256("TRANSFER_ROLE")`.
    pub fn transfer_role() -> B256 {
        *TRANSFER_ROLE
    }

    /// Returns the RECEIVE_WITH_MEMO_ROLE constant
    ///
    /// This role identifier grants permission to receive pathUSD tokens.
    /// The role is computed as `keccak256("RECEIVE_WITH_MEMO_ROLE")`.
    pub fn receive_with_memo_role() -> B256 {
        *RECEIVE_WITH_MEMO_ROLE
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::uint;
    use tempo_chainspec::hardfork::TempoHardfork;

    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::hashmap::HashMapStorageProvider,
        test_util::setup_storage,
        tip20::{IRolesAuth::Interface, ISSUER_ROLE, PAUSE_ROLE, RolesAuthError, UNPAUSE_ROLE},
        tip403_registry::{ITIP403Registry, TIP403Registry},
    };

    fn transfer_test_setup(admin: Address) -> Result<PathUSD> {
        let mut path_usd = PathUSD::new();
        path_usd.initialize(admin)?;
        path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

        Ok(path_usd)
    }

    #[test]
    fn test_metadata_pre_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Moderato);

        StorageCtx::enter(&mut storage, || {
            let path_usd = transfer_test_setup(admin)?;

            assert_eq!(path_usd.name()?, NAME_PRE_ALLEGRETTO);
            assert_eq!(path_usd.symbol()?, NAME_PRE_ALLEGRETTO);
            assert_eq!(path_usd.currency()?, "USD");
            Ok(())
        })
    }

    #[test]
    fn test_metadata_post_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Allegretto);

        StorageCtx::enter(&mut storage, || {
            let path_usd = transfer_test_setup(admin)?;

            assert_eq!(path_usd.name()?, NAME_POST_ALLEGRETTO);
            assert_eq!(path_usd.symbol()?, NAME_POST_ALLEGRETTO);
            assert_eq!(path_usd.currency()?, "USD");
            Ok(())
        })
    }

    #[test]
    fn test_transfer_reverts_pre_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Moderato);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = transfer_test_setup(admin)?;

            let result = path_usd.transfer(
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

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_reverts_pre_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Moderato);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = transfer_test_setup(admin)?;

            let result = path_usd.transfer_from(
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
            Ok(())
        })
    }

    #[test]
    fn test_transfer_with_memo_reverts_pre_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Moderato);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = transfer_test_setup(admin)?;

            let result = path_usd.transfer_with_memo(
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

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_reverts_pre_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Moderato);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = transfer_test_setup(admin)?;

            let result = path_usd.transfer_from_with_memo(
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

            Ok(())
        })
    }

    #[test]
    fn test_mint() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = transfer_test_setup(admin)?;
            let recipient = Address::random();
            let amount = U256::from(1000);

            let balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            path_usd.mint(
                admin,
                ITIP20::mintCall {
                    to: recipient,
                    amount,
                },
            )?;

            let balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(balance_after, balance_before + amount);
            Ok(())
        })
    }

    #[test]
    fn test_burn() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let amount = U256::from(1000);

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: admin, amount })?;

            let balance_before = path_usd.balance_of(ITIP20::balanceOfCall { account: admin })?;

            path_usd.burn(admin, ITIP20::burnCall { amount })?;

            let balance_after = path_usd.balance_of(ITIP20::balanceOfCall { account: admin })?;
            assert_eq!(balance_after, balance_before - amount);
            Ok(())
        })
    }

    #[test]
    fn test_approve() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let owner = Address::random();
            let spender = Address::random();
            let amount = U256::from(1000);

            path_usd.initialize(admin)?;

            let result = path_usd.approve(owner, ITIP20::approveCall { spender, amount })?;

            assert!(result);

            let allowance = path_usd.allowance(ITIP20::allowanceCall { owner, spender })?;
            assert_eq!(allowance, amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_with_stablecoin_exchange() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let recipient = Address::random();
            let amount = U256::from(1000);

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            path_usd.mint(
                admin,
                ITIP20::mintCall {
                    to: STABLECOIN_EXCHANGE_ADDRESS,
                    amount,
                },
            )?;

            let dex_balance_before = path_usd.balance_of(ITIP20::balanceOfCall {
                account: STABLECOIN_EXCHANGE_ADDRESS,
            })?;

            let recipient_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            let result = path_usd.transfer(
                STABLECOIN_EXCHANGE_ADDRESS,
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                },
            )?;
            assert!(result);

            let dex_balance_after = path_usd.balance_of(ITIP20::balanceOfCall {
                account: STABLECOIN_EXCHANGE_ADDRESS,
            })?;

            let recipient_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(dex_balance_after, dex_balance_before - amount);
            assert_eq!(recipient_balance_after, recipient_balance_before + amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_stablecoin_exchange() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let from = Address::random();
            let to = Address::random();
            let amount = U256::from(1000);

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

            path_usd.approve(
                from,
                ITIP20::approveCall {
                    spender: STABLECOIN_EXCHANGE_ADDRESS,
                    amount,
                },
            )?;

            let from_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;

            let to_balance_before = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;

            let allowance_before = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender: STABLECOIN_EXCHANGE_ADDRESS,
            })?;

            let result = path_usd.transfer_from(
                STABLECOIN_EXCHANGE_ADDRESS,
                ITIP20::transferFromCall { from, to, amount },
            )?;

            assert!(result);

            let from_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;

            let to_balance_after = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;

            let allowance_after = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender: STABLECOIN_EXCHANGE_ADDRESS,
            })?;

            assert_eq!(from_balance_after, from_balance_before - amount);
            assert_eq!(to_balance_after, to_balance_before + amount);
            assert_eq!(allowance_after, allowance_before - amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_with_transfer_role() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let sender = Address::random();
            let recipient = Address::random();
            let amount = U256::from(1000);

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd.token.grant_role_internal(sender, *TRANSFER_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

            let sender_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;

            let recipient_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            let result = path_usd.transfer(
                sender,
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                },
            )?;
            assert!(result);

            let sender_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
            let recipient_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(sender_balance_after, sender_balance_before - amount);
            assert_eq!(recipient_balance_after, recipient_balance_before + amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_with_receive_role_reverts_pre_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let admin = Address::random();
        let sender = Address::random();
        let recipient = Address::random();
        let amount = U256::from(1000);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd
                .token
                .grant_role_internal(recipient, *RECEIVE_WITH_MEMO_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

            let result = path_usd.transfer(
                sender,
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                },
            );

            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::transfers_disabled())
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_transfer_role() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd.token.grant_role_internal(from, *TRANSFER_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

            path_usd.approve(from, ITIP20::approveCall { spender, amount })?;

            let from_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;

            let to_balance_before = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;

            let allowance_before = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender,
            })?;

            let result =
                path_usd.transfer_from(spender, ITIP20::transferFromCall { from, to, amount })?;

            assert!(result);

            let from_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
            let to_balance_after = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
            let allowance_after = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender,
            })?;

            assert_eq!(from_balance_after, from_balance_before - amount);
            assert_eq!(to_balance_after, to_balance_before + amount);
            assert_eq!(allowance_after, allowance_before - amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_receive_role_reverts_pre_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let admin = Address::random();
        let from = Address::random();
        let to = Address::random();
        let spender = Address::random();
        let amount = U256::from(1000);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd
                .token
                .grant_role_internal(to, *RECEIVE_WITH_MEMO_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

            path_usd.approve(from, ITIP20::approveCall { spender, amount })?;

            let result =
                path_usd.transfer_from(spender, ITIP20::transferFromCall { from, to, amount });

            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::transfers_disabled())
            );

            Ok(())
        })
    }

    #[test]
    fn test_transfer_with_memo_with_transfer_role() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let sender = Address::random();
            let recipient = Address::random();
            let amount = U256::from(1000);
            let memo = [1u8; 32];

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd.token.grant_role_internal(sender, *TRANSFER_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

            let sender_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
            let recipient_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            path_usd.transfer_with_memo(
                sender,
                ITIP20::transferWithMemoCall {
                    to: recipient,
                    amount,
                    memo: memo.into(),
                },
            )?;

            let sender_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
            let recipient_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(sender_balance_after, sender_balance_before - amount);
            assert_eq!(recipient_balance_after, recipient_balance_before + amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_with_memo_with_receive_role() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let sender = Address::random();
            let recipient = Address::random();
            let amount = U256::from(1000);
            let memo = [1u8; 32];

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd
                .token
                .grant_role_internal(recipient, *RECEIVE_WITH_MEMO_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

            let sender_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
            let recipient_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            path_usd.transfer_with_memo(
                sender,
                ITIP20::transferWithMemoCall {
                    to: recipient,
                    amount,
                    memo: memo.into(),
                },
            )?;

            let sender_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
            let recipient_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(sender_balance_after, sender_balance_before - amount);
            assert_eq!(recipient_balance_after, recipient_balance_before + amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_with_stablecoin_exchange() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let from = Address::random();
            let to = Address::random();
            let amount = U256::from(1000);
            let memo = [1u8; 32];

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

            path_usd.approve(
                from,
                ITIP20::approveCall {
                    spender: STABLECOIN_EXCHANGE_ADDRESS,
                    amount,
                },
            )?;

            let from_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
            let to_balance_before = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
            let allowance_before = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender: STABLECOIN_EXCHANGE_ADDRESS,
            })?;

            let result = path_usd.transfer_from_with_memo(
                STABLECOIN_EXCHANGE_ADDRESS,
                ITIP20::transferFromWithMemoCall {
                    from,
                    to,
                    amount,
                    memo: memo.into(),
                },
            )?;

            assert!(result);

            let from_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
            let to_balance_after = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
            let allowance_after = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender: STABLECOIN_EXCHANGE_ADDRESS,
            })?;

            assert_eq!(from_balance_after, from_balance_before - amount);
            assert_eq!(to_balance_after, to_balance_before + amount);
            assert_eq!(allowance_after, allowance_before - amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_with_transfer_role() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let from = Address::random();
            let to = Address::random();
            let spender = Address::random();
            let amount = U256::from(1000);
            let memo = [1u8; 32];

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd.token.grant_role_internal(from, *TRANSFER_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

            path_usd.approve(from, ITIP20::approveCall { spender, amount })?;

            let from_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
            let to_balance_before = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
            let allowance_before = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender,
            })?;

            let result = path_usd.transfer_from_with_memo(
                spender,
                ITIP20::transferFromWithMemoCall {
                    from,
                    to,
                    amount,
                    memo: memo.into(),
                },
            )?;

            assert!(result);

            let from_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
            let to_balance_after = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
            let allowance_after = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender,
            })?;

            assert_eq!(from_balance_after, from_balance_before - amount);
            assert_eq!(to_balance_after, to_balance_before + amount);
            assert_eq!(allowance_after, allowance_before - amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_with_receive_role() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let from = Address::random();
            let to = Address::random();
            let spender = Address::random();
            let amount = U256::from(1000);
            let memo = [1u8; 32];

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;
            path_usd
                .token
                .grant_role_internal(to, *RECEIVE_WITH_MEMO_ROLE)?;

            path_usd.mint(admin, ITIP20::mintCall { to: from, amount })?;

            path_usd.approve(from, ITIP20::approveCall { spender, amount })?;

            let from_balance_before =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
            let to_balance_before = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
            let allowance_before = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender,
            })?;

            let result = path_usd.transfer_from_with_memo(
                spender,
                ITIP20::transferFromWithMemoCall {
                    from,
                    to,
                    amount,
                    memo: memo.into(),
                },
            )?;

            assert!(result);

            let from_balance_after =
                path_usd.balance_of(ITIP20::balanceOfCall { account: from })?;
            let to_balance_after = path_usd.balance_of(ITIP20::balanceOfCall { account: to })?;
            let allowance_after = path_usd.allowance(ITIP20::allowanceCall {
                owner: from,
                spender,
            })?;

            assert_eq!(from_balance_after, from_balance_before - amount);
            assert_eq!(to_balance_after, to_balance_before + amount);
            assert_eq!(allowance_after, allowance_before - amount);
            Ok(())
        })
    }

    #[test]
    fn test_pause_and_unpause() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let pauser = Address::random();
            let unpauser = Address::random();

            path_usd.initialize(admin)?;

            // Grant PAUSE_ROLE and UNPAUSE_ROLE
            path_usd.token.grant_role_internal(pauser, *PAUSE_ROLE)?;
            path_usd
                .token
                .grant_role_internal(unpauser, *UNPAUSE_ROLE)?;

            assert!(!path_usd.paused()?);

            path_usd.pause(pauser, ITIP20::pauseCall {})?;
            assert!(path_usd.paused()?);

            path_usd.unpause(unpauser, ITIP20::unpauseCall {})?;
            assert!(!path_usd.paused()?);
            Ok(())
        })
    }

    #[test]
    fn test_role_management() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let user = Address::random();

            path_usd.initialize(admin)?;

            // Grant ISSUER_ROLE to user
            path_usd.token.grant_role(admin, *ISSUER_ROLE, user)?;

            // Check that user has the role
            assert!(path_usd.token.has_role(user, *ISSUER_ROLE)?);

            // Revoke the role
            path_usd.token.revoke_role(admin, *ISSUER_ROLE, user)?;

            // Check that user no longer has the role
            assert!(!path_usd.token.has_role(user, *ISSUER_ROLE)?);
            Ok(())
        })
    }

    #[test]
    fn test_supply_cap() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let recipient = Address::random();
            let supply_cap = U256::from(1000);

            path_usd.initialize(admin)?;

            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            // Set supply cap
            path_usd.token.set_supply_cap(
                admin,
                ITIP20::setSupplyCapCall {
                    newSupplyCap: supply_cap,
                },
            )?;

            assert_eq!(path_usd.token.supply_cap()?, supply_cap);

            // Try to mint more than supply cap
            let result = path_usd.mint(
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
        })
    }

    #[test]
    fn test_invalid_supply_caps() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let recipient = Address::random();
            let supply_cap = U256::from(1000);
            let bad_supply_cap = uint!(0x100000000000000000000000000000000_U256);

            path_usd.initialize(admin)?;

            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            // Set supply cap to u128 max plus one
            let result = path_usd.token.set_supply_cap(
                admin,
                ITIP20::setSupplyCapCall {
                    newSupplyCap: bad_supply_cap,
                },
            );

            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::supply_cap_exceeded())
            );

            // Set supply cap
            path_usd.token.set_supply_cap(
                admin,
                ITIP20::setSupplyCapCall {
                    newSupplyCap: supply_cap,
                },
            )?;

            // Try to mint the exact supply cap
            path_usd.mint(
                admin,
                ITIP20::mintCall {
                    to: recipient,
                    amount: U256::from(1000),
                },
            )?;

            // Try to set the supply cap to something lower than the total supply
            let smaller_supply_cap = U256::from(999);
            let result = path_usd.token.set_supply_cap(
                admin,
                ITIP20::setSupplyCapCall {
                    newSupplyCap: smaller_supply_cap,
                },
            );

            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20(TIP20Error::invalid_supply_cap())
            );
            Ok(())
        })
    }

    #[test]
    fn test_change_transfer_policy_id() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            path_usd.initialize(admin)?;

            // Initialize TIP403 registry
            let mut registry = TIP403Registry::new();
            registry.initialize()?;

            // Create a valid policy
            let new_policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;

            // Admin can change transfer policy ID
            path_usd.token.change_transfer_policy_id(
                admin,
                ITIP20::changeTransferPolicyIdCall {
                    newPolicyId: new_policy_id,
                },
            )?;

            assert_eq!(path_usd.token.transfer_policy_id()?, new_policy_id);

            // Non-admin cannot change transfer policy ID
            let non_admin = Address::random();
            let result = path_usd.token.change_transfer_policy_id(
                non_admin,
                ITIP20::changeTransferPolicyIdCall { newPolicyId: 100 },
            );

            assert_eq!(
                result.unwrap_err(),
                TempoPrecompileError::RolesAuthError(RolesAuthError::unauthorized())
            );
            Ok(())
        })
    }

    #[test]
    fn test_transfer_post_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Allegretto);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let sender = Address::random();
            let recipient = Address::random();
            let amount = U256::from(1000);

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            // Mint to sender without any special roles
            path_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

            // Post-Allegretto: transfer should work without TRANSFER_ROLE
            let result = path_usd.transfer(
                sender,
                ITIP20::transferCall {
                    to: recipient,
                    amount,
                },
            )?;

            assert!(result);

            let sender_balance = path_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
            let recipient_balance =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(sender_balance, U256::ZERO);
            assert_eq!(recipient_balance, amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_post_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Allegretto);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let owner = Address::random();
            let spender = Address::random();
            let recipient = Address::random();
            let amount = U256::from(1000);

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            // Mint to owner and approve spender
            path_usd.mint(admin, ITIP20::mintCall { to: owner, amount })?;
            path_usd.approve(owner, ITIP20::approveCall { spender, amount })?;

            // Post-Allegretto: transfer_from should work without TRANSFER_ROLE
            let result = path_usd.transfer_from(
                spender,
                ITIP20::transferFromCall {
                    from: owner,
                    to: recipient,
                    amount,
                },
            )?;

            assert!(result);

            let owner_balance = path_usd.balance_of(ITIP20::balanceOfCall { account: owner })?;
            let recipient_balance =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(owner_balance, U256::ZERO);
            assert_eq!(recipient_balance, amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_with_memo_post_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Allegretto);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let sender = Address::random();
            let recipient = Address::random();
            let amount = U256::from(1000);
            let memo = [1u8; 32];

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            // Mint to sender without any special roles
            path_usd.mint(admin, ITIP20::mintCall { to: sender, amount })?;

            // Post-Allegretto: transfer_with_memo should work without TRANSFER_ROLE or RECEIVE_WITH_MEMO_ROLE
            path_usd.transfer_with_memo(
                sender,
                ITIP20::transferWithMemoCall {
                    to: recipient,
                    amount,
                    memo: memo.into(),
                },
            )?;

            let sender_balance = path_usd.balance_of(ITIP20::balanceOfCall { account: sender })?;
            let recipient_balance =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(sender_balance, U256::ZERO);
            assert_eq!(recipient_balance, amount);
            Ok(())
        })
    }

    #[test]
    fn test_transfer_from_with_memo_post_allegretto() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        storage.set_spec(TempoHardfork::Allegretto);

        StorageCtx::enter(&mut storage, || {
            let mut path_usd = PathUSD::new();
            let owner = Address::random();
            let spender = Address::random();
            let recipient = Address::random();
            let amount = U256::from(1000);
            let memo = [1u8; 32];

            path_usd.initialize(admin)?;
            path_usd.token.grant_role_internal(admin, *ISSUER_ROLE)?;

            // Mint to owner and approve spender
            path_usd.mint(admin, ITIP20::mintCall { to: owner, amount })?;
            path_usd.approve(owner, ITIP20::approveCall { spender, amount })?;

            // Post-Allegretto: transfer_from_with_memo should work without any special roles
            let result = path_usd.transfer_from_with_memo(
                spender,
                ITIP20::transferFromWithMemoCall {
                    from: owner,
                    to: recipient,
                    amount,
                    memo: memo.into(),
                },
            )?;

            assert!(result);

            let owner_balance = path_usd.balance_of(ITIP20::balanceOfCall { account: owner })?;
            let recipient_balance =
                path_usd.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(owner_balance, U256::ZERO);
            assert_eq!(recipient_balance, amount);
            Ok(())
        })
    }
}
