use std::error::Error;

use alloy::primitives::{Address, Bytes, IntoLogData, U256, uint};
use revm::state::Bytecode;

use crate::contracts::{StorageProvider, storage::StorageOps};

pub struct StablecoinDex<'a, S: StorageProvider> {
    contract_address: Address,
    storage: &'a mut S,
}

// TODO: slots

impl<'a, S: StorageProvider> StablecoinDex<'a, S> {
    pub fn new(contract_address: Address, beneficiary: Address, storage: &'a mut S) -> Self {
        Self {
            contract_address,
            storage,
        }
    }

    /// Initializes the contract
    ///
    /// This ensures the [`StablecoinDex`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
        // must ensure the account is not empty, by setting some code
        self.storage
            .set_code(
                self.contract_address,
                Bytecode::new_legacy(Bytes::from_static(&[0xef])),
            )
            .expect("TODO: handle error");

        Ok(())
    }
}

impl<'a, S: StorageProvider> StorageOps for StablecoinDex<'a, S> {
    fn sstore(&mut self, slot: U256, value: U256) {
        self.storage
            .sstore(self.contract_address, slot, value)
            .expect("Storage operation failed");
    }

    fn sload(&mut self, slot: U256) -> U256 {
        self.storage
            .sload(self.contract_address, slot)
            .expect("Storage operation failed")
    }
}
