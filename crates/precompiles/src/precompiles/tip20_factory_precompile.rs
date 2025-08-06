use crate::{dispatch_mutating_call, dispatch_view_call, precompiles::Precompile};
use alloy::{primitives::Address, sol_types::SolCall};
use reth::revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

use crate::contracts::{
    storage::StorageProvider,
    tip20_factory::TIP20Factory,
    types::{ITIP20Factory, TIP20Error},
};

mod gas_costs {
    pub const VIEW_FUNCTIONS: u64 = 100;
    pub const STATE_CHANGING_FUNCTIONS: u64 = 1000;
}

#[rustfmt::skip]
impl<'a, S: StorageProvider> Precompile for TIP20Factory<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector = calldata.get(..4).ok_or_else(|| { PrecompileError::Other("Invalid input: missing function selector".to_string()) })?;

        // View functions
        dispatch_view_call!(self, selector, ITIP20Factory::tokenIdCounterCall, token_id_counter, gas_costs::VIEW_FUNCTIONS);

        // State-changing functions
        dispatch_mutating_call!(self, selector, ITIP20Factory::createTokenCall, create_token, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error, returns);

        // If no selector matched, return error
        Err(PrecompileError::Other("Unknown function selector".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::contracts::HashMapStorageProvider;
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
            decimals: 18,
            currency: "USD".to_string(),
            admin: sender,
        };
        let calldata = create_call.abi_encode();

        // Execute create token
        let result = factory.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, gas_costs::STATE_CHANGING_FUNCTIONS);

        // Decode the return value (should be token_id)
        let token_id = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(token_id, U256::ZERO);
    }
}
