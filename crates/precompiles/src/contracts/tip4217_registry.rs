use crate::contracts::types::ITIP4217Registry;

const KNOWN_DECIMALS: &[(&str, u8)] = &[("USD", 6)];

#[derive(Debug, Default)]
pub struct TIP4217Registry {}

impl TIP4217Registry {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_currency_usd_returns_6() {
        let mut reg = TIP4217Registry::default();
        let dec = reg.get_currency_decimals(ITIP4217Registry::getCurrencyDecimalsCall {
            currency: "USD".to_string(),
        });
        assert_eq!(dec, 6);
    }

    #[test]
    fn test_unknown_currency_returns_0() {
        let mut reg = TIP4217Registry::default();
        let dec = reg.get_currency_decimals(ITIP4217Registry::getCurrencyDecimalsCall {
            currency: "EUR".to_string(),
        });
        assert_eq!(dec, 0);
    }
}
