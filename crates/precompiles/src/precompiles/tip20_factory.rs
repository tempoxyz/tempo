use crate::precompiles::{Precompile, mutate, view};
use alloy::{primitives::Address, sol_types::SolCall};
use reth_evm::revm::precompile::{PrecompileError, PrecompileResult};

use crate::contracts::{
    storage::StorageProvider, tip20_factory::TIP20Factory, types::ITIP20Factory,
};

#[rustfmt::skip]
impl<'a, S: StorageProvider> Precompile for TIP20Factory<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata.get(..4).ok_or_else(|| {
            PrecompileError::Other("Invalid input: missing function selector".to_string())
        })?.try_into().map_err(|_| {
            PrecompileError::Other("Invalid function selector length".to_string())
        })?;

        match selector {
            ITIP20Factory::tokenIdCounterCall::SELECTOR => {
                view::<ITIP20Factory::tokenIdCounterCall>(calldata, |_call| self.token_id_counter())
            },
            ITIP20Factory::createTokenCall::SELECTOR => {
                mutate::<ITIP20Factory::createTokenCall, _>(calldata, msg_sender, |s, call| self.create_token(s, call))
            },
            _ => Err(PrecompileError::Other("Unknown function selector".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        contracts::{HashMapStorageProvider, types::TIP20Error},
        precompiles::{MUTATE_FUNC_GAS, VIEW_FUNC_GAS, expect_precompile_error},
    };
    use alloy::{
        primitives::{Bytes, U256},
        sol_types::SolValue,
    };

    use super::*;

    #[test]
    fn test_function_selector_dispatch() {
        let mut factory_storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut factory_storage);
        let sender = Address::from([1u8; 20]);

        // Test invalid selector
        let result = factory.call(&Bytes::from([0x12, 0x34, 0x56, 0x78]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));

        // Test insufficient calldata
        let result = factory.call(&Bytes::from([0x12, 0x34]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }

    #[test]
    fn test_create_token() {
        let mut factory_storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut factory_storage);
        let sender = Address::from([1u8; 20]);

        // Create token call
        let create_call = ITIP20Factory::createTokenCall {
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            currency: "USD".to_string(),
            admin: sender,
        };
        let calldata = create_call.abi_encode();

        // Execute create token
        let result = factory.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Decode the return value (should be token_id)
        let token_id = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(token_id, U256::ZERO);
    }

    #[test]
    fn test_token_id_counter() {
        let mut factory_storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut factory_storage);
        let sender = Address::from([1u8; 20]);

        // Get initial counter
        let counter_call = ITIP20Factory::tokenIdCounterCall {};
        let calldata = counter_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let initial_counter = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(initial_counter, U256::ZERO);

        // Create first token (USD supported)
        let create_call = ITIP20Factory::createTokenCall {
            name: "Token 1".to_string(),
            symbol: "TOK1".to_string(),
            currency: "USD".to_string(),
            admin: sender,
        };
        let calldata = create_call.abi_encode();
        factory.call(&Bytes::from(calldata), &sender).unwrap();

        // Check counter increased
        let counter_call = ITIP20Factory::tokenIdCounterCall {};
        let calldata = counter_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &sender).unwrap();
        let new_counter = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(new_counter, U256::from(1));

        // Create second token with unsupported currency should fail
        let create_call = ITIP20Factory::createTokenCall {
            name: "Token 2".to_string(),
            symbol: "TOK2".to_string(),
            currency: "EUR".to_string(),
            admin: sender,
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &sender);
        expect_precompile_error(&result, TIP20Error::invalid_currency());

        // Check counter increased again
        let counter_call = ITIP20Factory::tokenIdCounterCall {};
        let calldata = counter_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &sender).unwrap();
        let final_counter = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(final_counter, U256::from(2));
    }

    #[test]
    fn test_create_multiple_tokens_different_params() {
        let mut factory_storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut factory_storage);
        let admin1 = Address::from([1u8; 20]);
        let admin2 = Address::from([2u8; 20]);

        // Create token with different decimal places
        let create_call = ITIP20Factory::createTokenCall {
            name: "High Precision Token".to_string(),
            symbol: "HPT".to_string(),
            currency: "USD".to_string(),
            admin: admin1,
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &admin1).unwrap();
        let token_id1 = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(token_id1, U256::ZERO);

        // Create token with unsupported currency should fail
        let create_call = ITIP20Factory::createTokenCall {
            name: "Low Precision Token".to_string(),
            symbol: "LPT".to_string(),
            currency: "EUR".to_string(),
            admin: admin2,
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &admin2);
        expect_precompile_error(&result, TIP20Error::invalid_currency());

        // Create token with different unsupported currency should fail
        let create_call = ITIP20Factory::createTokenCall {
            name: "Japanese Yen Token".to_string(),
            symbol: "JYT".to_string(),
            currency: "JPY".to_string(),
            admin: admin1,
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &admin1);
        expect_precompile_error(&result, TIP20Error::invalid_currency());
    }

    #[test]
    fn test_create_token_with_empty_currency() {
        let mut factory_storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut factory_storage);
        let sender = Address::from([1u8; 20]);

        // Create token with empty currency should fail
        let create_call = ITIP20Factory::createTokenCall {
            name: "No Currency Token".to_string(),
            symbol: "NCT".to_string(),
            currency: String::new(),
            admin: sender,
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &sender);
        expect_precompile_error(&result, TIP20Error::invalid_currency());
    }

    #[test]
    fn test_create_token_with_various_names() {
        let mut factory_storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut factory_storage);
        let sender = Address::from([1u8; 20]);

        // Create token with longer but valid name and symbol
        let name = "Decentralized Finance Token".to_string();
        let symbol = "DEFI".to_string();

        let create_call = ITIP20Factory::createTokenCall {
            name,
            symbol,
            currency: "USD".to_string(),
            admin: sender,
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        let token_id = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(token_id, U256::ZERO);
    }

    #[test]
    fn test_different_callers_can_create_tokens() {
        let mut factory_storage = HashMapStorageProvider::new(1);
        let mut factory = TIP20Factory::new(&mut factory_storage);
        let caller1 = Address::from([1u8; 20]);
        let caller2 = Address::from([2u8; 20]);
        let caller3 = Address::from([3u8; 20]);

        // First caller creates a token
        let create_call = ITIP20Factory::createTokenCall {
            name: "Caller1 Token".to_string(),
            symbol: "C1T".to_string(),
            currency: "USD".to_string(),
            admin: caller1,
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &caller1).unwrap();
        let token_id1 = U256::abi_decode(&result.bytes).unwrap();

        // Second caller creates a token with unsupported currency should fail
        let create_call = ITIP20Factory::createTokenCall {
            name: "Caller2 Token".to_string(),
            symbol: "C2T".to_string(),
            currency: "EUR".to_string(),
            admin: caller2,
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &caller2);
        expect_precompile_error(&result, TIP20Error::invalid_currency());

        // Third caller creates a token with different admin and unsupported currency should fail
        let create_call = ITIP20Factory::createTokenCall {
            name: "Caller3 Token".to_string(),
            symbol: "C3T".to_string(),
            currency: "GBP".to_string(),
            admin: caller1, // Different admin than caller
        };
        let calldata = create_call.abi_encode();
        let result = factory.call(&Bytes::from(calldata), &caller3);
        expect_precompile_error(&result, TIP20Error::invalid_currency());

        // Verify only first token was created
        assert_eq!(token_id1, U256::ZERO);
    }
}
