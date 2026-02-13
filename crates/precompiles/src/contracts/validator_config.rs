use tempo_precompiles_macros::abi;

#[abi]
#[rustfmt::skip]
pub mod IValidatorConfig {
    #[cfg(feature = "precompiles")]
    use crate::error::Result;
    #[cfg(feature = "precompiles")]
    use tempo_chainspec::hardfork::TempoHardfork;

    use alloy::primitives::{Address, B256, U256};

    #[derive(Debug, Clone, Default, PartialEq, Eq, Storable)]
    pub struct Validator {
        pub public_key: B256,
        pub active: bool,
        pub index: u64,
        pub validator_address: Address,
        /// Address where other validators can connect to this validator.
        /// Format: `<hostname|ip>:<port>`
        pub inbound_address: String,
        /// IP address for firewall whitelisting by other validators.
        /// Format: `<ip>:<port>` - must be an IP address, not a hostname.
        pub outbound_address: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Error {
        Unauthorized,
        InvalidPublicKey,
        ValidatorNotFound,
        ValidatorAlreadyExists,
        NotIpPort { field: String, input: String, backtrace: String },
        NotHostPort { field: String, input: String, backtrace: String },
    }

    pub trait Interface {
        /// Get the owner of the precompile.
        #[getter]
        fn owner(&self) -> Result<Address>;
        /// Get the complete set of validators.
        fn get_validators(&self) -> Result<Vec<Validator>>;
        /// Get the epoch at which a fresh DKG ceremony will be triggered.
        ///
        /// The fresh DKG ceremony runs in epoch N, and epoch N+1 uses the new DKG polynomial.
        #[getter = "next_dkg_ceremony"]
        fn get_next_full_dkg_ceremony(&self) -> Result<u64>;
        /// Get validator address at a specific index in the validators array.
        fn validators_array(&self, index: U256) -> Result<Address>;
        /// Get validator information by address.
        #[getter]
        fn validators(&self, validator: Address) -> Result<Validator>;
        /// Get the current validator count.
        fn validator_count(&self) -> Result<u64>;

        #[msg_sender]
        fn add_validator(&mut self, new_validator_address: Address, public_key: B256, active: bool, inbound_address: String, outbound_address: String) -> Result<()>;
        #[msg_sender]
        fn update_validator(&mut self, new_validator_address: Address, public_key: B256, inbound_address: String, outbound_address: String) -> Result<()>;
        #[msg_sender]
        fn change_validator_status(&mut self, validator: Address, active: bool) -> Result<()>;
        #[msg_sender]
        #[hardfork = TempoHardfork::T1]
        fn change_validator_status_by_index(&mut self, index: u64, active: bool) -> Result<()>;
        #[msg_sender]
        fn change_owner(&mut self, new_owner: Address) -> Result<()>;
        #[msg_sender]
        fn set_next_full_dkg_ceremony(&mut self, epoch: u64) -> Result<()>;
    }
}
