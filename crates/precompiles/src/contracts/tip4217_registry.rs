use alloy::primitives::U256;

use crate::contracts::{types::ITIP4217Registry, StorageProvider, TIP4217_REGISTRY_ADDRESS};

mod slots {
    use alloy::primitives::U256;
    pub const CURRENCY_DECIMALS: U256 = U256::ZERO;
}

#[derive(Debug)]
pub struct TIP4217Registry<'a, S: StorageProvider> {
    storage: &'a mut S,
}

impl<'a, S: StorageProvider> TIP4217Registry<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    pub fn get_currency_decimals(
        &mut self,
        call: ITIP4217Registry::getCurrencyDecimalsCall,
    ) -> u8 {
        // For now, determine decimals by the string content; if none set, default to 18.
        // Storage layout: pack first up to 31 bytes of the currency string in slot key derived from its hash.
        // Simpler: Use keccak(currency) as key into mapping-like slot.
        let key = alloy::primitives::keccak256(call.currency.as_bytes());
        let slot = crate::contracts::storage::slots::double_mapping_slot(key.0, [0u8; 32], slots::CURRENCY_DECIMALS);
        let val = self.storage.sload(TIP4217_REGISTRY_ADDRESS, slot);
        if val == U256::ZERO {
            // default 18
            18
        } else {
            val.to::<u8>()
        }
    }

    // Helper so tests or governance could set values in the mock environment (not exposed via precompile ABI)
    pub fn set_currency_decimals(&mut self, currency: &str, decimals: u8) {
        let key = alloy::primitives::keccak256(currency.as_bytes());
        let slot = crate::contracts::storage::slots::double_mapping_slot(key.0, [0u8; 32], slots::CURRENCY_DECIMALS);
        self.storage
            .sstore(TIP4217_REGISTRY_ADDRESS, slot, U256::from(decimals));
    }
}
