use alloy::primitives::U256;

use crate::contracts::{types::ITIP4217Registry, StorageProvider, TIP4217_REGISTRY_ADDRESS};


const KNOWN_DECIMALS: &[(&str, u8)] = &[
    ("USD", 6),
];

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
        // Only use built-in known mapping.
        if let Some((_, dec)) = KNOWN_DECIMALS.iter().find(|(code, _)| *code == call.currency) {
            return *dec;
        }

        // Default if unknown.
        0
    }


}
