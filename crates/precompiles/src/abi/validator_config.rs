//! Validator Config bindings.

use tempo_precompiles_macros::abi;

#[abi(dispatch)]
#[rustfmt::skip]
pub mod IValidatorConfig {
    use alloy::primitives::{Address, B256};

    #[cfg(feature = "precompile")]
    use crate::error::Result;

    /// Validator Config trait for managing consensus validators.
    pub trait IValidatorConfig {
        fn owner(&self) -> Result<Address>;
        fn validator_count(&self) -> Result<u64>;
        fn validators_array(&self, index: u64) -> Result<Address>;
        fn validators(&self, validator: Address) -> Result<Validator>;
        fn get_validators(&self) -> Result<Vec<Validator>>;
        fn get_next_full_dkg_ceremony(&self) -> Result<u64>;

        fn change_owner(&mut self, new_owner: Address) -> Result<()>;
        fn add_validator(&mut self, new_validator_address: Address, public_key: B256, active: bool, inbound_address: String, outbound_address: String) -> Result<()>;
        fn update_validator(&mut self, new_validator_address: Address, public_key: B256, inbound_address: String, outbound_address: String) -> Result<()>;
        fn change_validator_status(&mut self, validator: Address, active: bool) -> Result<()>;
        fn set_next_full_dkg_ceremony(&mut self, epoch: u64) -> Result<()>;
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
    pub struct Validator {
        pub public_key: B256,
        pub active: bool,
        pub index: u64,
        pub validator_address: Address,
        pub inbound_address: String,
        pub outbound_address: String,
    }

    pub enum Error {
        Unauthorized,
        ValidatorAlreadyExists,
        ValidatorNotFound,
        InvalidPublicKey,
        NotHostPort { field: String, input: String, backtrace: String },
        NotIpPort { field: String, input: String, backtrace: String },
    }
}
