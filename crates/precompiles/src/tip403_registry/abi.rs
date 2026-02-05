use tempo_precompiles_macros::abi;

#[rustfmt::skip]
#[abi(no_reexport)]
#[allow(non_snake_case)]
pub mod ITIP403Registry {
    #[cfg(feature = "precompile")]
    use crate::error::Result;
    use alloy::primitives::Address;
    use tempo_chainspec::hardfork::TempoHardfork;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
    pub enum PolicyType {
        WHITELIST = 0,
        BLACKLIST = 1,
        COMPOUND = 2,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        Unauthorized,
        PolicyNotFound,
        PolicyNotSimple,
        InvalidPolicyType,
        IncompatiblePolicyType,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Event {
        PolicyAdminUpdated { #[indexed] policy_id: u64, #[indexed] updater: Address, #[indexed] admin: Address },
        PolicyCreated { #[indexed] policy_id: u64, #[indexed] updater: Address, policy_type: PolicyType },
        WhitelistUpdated { #[indexed] policy_id: u64, #[indexed] updater: Address, #[indexed] account: Address, allowed: bool },
        BlacklistUpdated { #[indexed] policy_id: u64, #[indexed] updater: Address, #[indexed] account: Address, restricted: bool },
        CompoundPolicyCreated { #[indexed] policy_id: u64, #[indexed] creator: Address, sender_policy_id: u64, recipient_policy_id: u64, mint_recipient_policy_id: u64 },
    }

    pub trait Interface {
        // View Functions
        fn policy_id_counter(&self) -> Result<u64>;
        fn policy_exists(&self, policy_id: u64) -> Result<bool>;
        fn policy_data(&self, policy_id: u64) -> Result<(PolicyType, Address)>;
        fn is_authorized(&self, policy_id: u64, user: Address) -> Result<bool>;
        #[hardfork = TempoHardfork::T2]
        fn is_authorized_sender(&self, policy_id: u64, user: Address) -> Result<bool>;
        #[hardfork = TempoHardfork::T2]
        fn is_authorized_recipient(&self, policy_id: u64, user: Address) -> Result<bool>;
        #[hardfork = TempoHardfork::T2]
        fn is_authorized_mint_recipient(&self, policy_id: u64, user: Address) -> Result<bool>;
        #[hardfork = TempoHardfork::T2]
        fn compound_policy_data(&self, policy_id: u64) -> Result<(u64, u64, u64)>;

        // State-Changing Functions
        #[msg_sender]
        fn create_policy(&mut self, admin: Address, policy_type: PolicyType) -> Result<u64>;
        #[msg_sender]
        fn create_policy_with_accounts(&mut self, admin: Address, policy_type: PolicyType, accounts: Vec<Address>) -> Result<u64>;
        #[msg_sender]
        fn set_policy_admin(&mut self, policy_id: u64, admin: Address) -> Result<()>;
        #[msg_sender]
        fn modify_policy_whitelist(&mut self, policy_id: u64, account: Address, allowed: bool) -> Result<()>;
        #[msg_sender]
        fn modify_policy_blacklist(&mut self, policy_id: u64, account: Address, restricted: bool) -> Result<()>;
        #[msg_sender]
        #[hardfork = TempoHardfork::T2]
        fn create_compound_policy(&mut self, sender_policy_id: u64, recipient_policy_id: u64, mint_recipient_policy_id: u64) -> Result<u64>;
    }
}
