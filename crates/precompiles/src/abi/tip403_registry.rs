//! TIP403Registry bindings.

use tempo_precompiles_macros::abi;

#[abi(dispatch)]
#[rustfmt::skip]
pub mod ITIP403Registry {
    use alloy::primitives::Address;

    #[cfg(feature = "precompile")]
    use crate::error::Result;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
    pub enum PolicyType {
        WHITELIST = 0,
        BLACKLIST = 1,
    }

    pub trait IRegistry {
        // View functions
        fn policy_id_counter(&self) -> Result<u64>;
        fn policy_exists(&self, policy_id: u64) -> Result<bool>;
        fn policy_data(&self, policy_id: u64) -> Result<(PolicyType, Address)>;
        fn is_authorized(&self, policy_id: u64, user: Address) -> Result<bool>;

        // State-changing functions (msg_sender is injected by macro)
        fn create_policy(&mut self, admin: Address, policy_type: PolicyType) -> Result<u64>;
        fn create_policy_with_accounts(&mut self, admin: Address, policy_type: PolicyType, accounts: Vec<Address>) -> Result<u64>;
        fn set_policy_admin(&mut self, policy_id: u64, admin: Address) -> Result<()>;
        fn modify_policy_whitelist(&mut self, policy_id: u64, account: Address, allowed: bool) -> Result<()>;
        fn modify_policy_blacklist(&mut self, policy_id: u64, account: Address, restricted: bool) -> Result<()>;
    }

    pub enum Error {
        Unauthorized,
        IncompatiblePolicyType,
        PolicyNotFound,
    }

    pub enum Event {
        PolicyAdminUpdated { #[indexed] policy_id: u64, #[indexed] updater: Address, #[indexed] admin: Address },
        PolicyCreated { #[indexed] policy_id: u64, #[indexed] updater: Address, policy_type: PolicyType },
        WhitelistUpdated { #[indexed] policy_id: u64, #[indexed] updater: Address, #[indexed] account: Address, allowed: bool },
        BlacklistUpdated { #[indexed] policy_id: u64, #[indexed] updater: Address, #[indexed] account: Address, restricted: bool },
    }
}
