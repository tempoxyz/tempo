use alloy::primitives::U256;

use crate::contracts::{StorageProvider, TIP4217_REGISTRY_ADDRESS, types::ITIP4217Registry};

const KNOWN_DECIMALS: &[(&str, u8)] = &[("USD", 6)];

#[derive(Debug)]
pub struct TIP4217Registry<'a, S: StorageProvider> {
    storage: &'a mut S,
}

impl<'a, S: StorageProvider> TIP4217Registry<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self { storage }
    }

    pub fn get_currency_decimals(&mut self, call: ITIP4217Registry::getCurrencyDecimalsCall) -> u8 {
        // If it's a known currency, return the decimals
        // On perf: linear scan is faster than a hashmap lookup for small sets generally.
        if let Some((_, dec)) = KNOWN_DECIMALS
            .iter()
            .find(|(code, _)| *code == call.currency)
        {
            return *dec;
        }

        // Default if unknown (tokens will reject this)
        0
    }
}
