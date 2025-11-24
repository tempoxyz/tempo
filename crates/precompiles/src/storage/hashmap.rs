use alloy::primitives::{Address, LogData, U256};
use revm::state::{AccountInfo, Bytecode};
use std::collections::HashMap;
use tempo_chainspec::hardfork::TempoHardfork;

use crate::{error::TempoPrecompileError, storage::PrecompileStorageProvider};

pub struct HashMapStorageProvider {
    internals: HashMap<(Address, U256), U256>,
    transient: HashMap<(Address, U256), U256>,
    accounts: HashMap<Address, AccountInfo>,
    pub events: HashMap<Address, Vec<LogData>>,
    chain_id: u64,
    timestamp: U256,
    beneficiary: Address,
    spec: TempoHardfork,
}

impl HashMapStorageProvider {
    pub fn new(chain_id: u64) -> Self {
        Self::new_with_spec(chain_id, TempoHardfork::default())
    }

    pub fn new_with_spec(chain_id: u64, spec: TempoHardfork) -> Self {
        Self {
            internals: HashMap::new(),
            transient: HashMap::new(),
            accounts: HashMap::new(),
            events: HashMap::new(),
            chain_id,
            #[expect(clippy::disallowed_methods)]
            timestamp: U256::from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            beneficiary: Address::ZERO,
            spec,
        }
    }

    pub fn set_nonce(&mut self, address: Address, nonce: u64) {
        let account = self.accounts.entry(address).or_default();
        account.nonce = nonce;
    }

    pub fn set_timestamp(&mut self, timestamp: U256) {
        self.timestamp = timestamp;
    }

    pub fn set_beneficiary(&mut self, beneficiary: Address) {
        self.beneficiary = beneficiary;
    }

    pub fn set_spec(&mut self, spec: TempoHardfork) {
        self.spec = spec;
    }

    pub fn with_spec(mut self, spec: TempoHardfork) -> Self {
        self.set_spec(spec);
        self
    }
}

impl PrecompileStorageProvider for HashMapStorageProvider {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn timestamp(&self) -> U256 {
        self.timestamp
    }

    fn beneficiary(&self) -> Address {
        self.beneficiary
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<(), TempoPrecompileError> {
        let account = self.accounts.entry(address).or_default();
        account.code = Some(code);
        Ok(())
    }

    fn get_account_info(
        &mut self,
        address: Address,
    ) -> Result<&'_ AccountInfo, TempoPrecompileError> {
        let account = self.accounts.entry(address).or_default();
        Ok(&*account)
    }

    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.internals.insert((address, key), value);
        Ok(())
    }

    fn tstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), TempoPrecompileError> {
        self.transient.insert((address, key), value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<(), TempoPrecompileError> {
        self.events.entry(address).or_default().push(event);
        Ok(())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        Ok(self
            .internals
            .get(&(address, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }

    fn tload(&mut self, address: Address, key: U256) -> Result<U256, TempoPrecompileError> {
        Ok(self
            .transient
            .get(&(address, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }

    fn deduct_gas(&mut self, _gas: u64) -> Result<(), TempoPrecompileError> {
        Ok(())
    }

    fn gas_used(&self) -> u64 {
        0
    }

    fn spec(&self) -> TempoHardfork {
        self.spec
    }
}
