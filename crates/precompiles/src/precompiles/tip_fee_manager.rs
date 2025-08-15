use crate::{
    contracts::{
        storage::StorageProvider,
        tip_fee_manager::TipFeeManager,
        types::IFeeManager,
    },
    precompiles::{Precompile, view, mutate_void},
};
use alloy::{primitives::Address, sol_types::SolCall};
use reth::revm::precompile::{PrecompileError, PrecompileResult};

#[rustfmt::skip]
impl<'a, S: StorageProvider> Precompile for TipFeeManager<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata.get(..4).ok_or_else(|| { 
            PrecompileError::Other("Invalid input: missing function selector".to_string()) 
        })?.try_into().unwrap();

        match selector {
            // View functions
            IFeeManager::userTokensCall::SELECTOR => view::<IFeeManager::userTokensCall>(calldata, |call| self.user_tokens(call)),
            IFeeManager::validatorTokensCall::SELECTOR => view::<IFeeManager::validatorTokensCall>(calldata, |call| self.validator_tokens(call)),
            IFeeManager::getFeeTokenBalanceCall::SELECTOR => view::<IFeeManager::getFeeTokenBalanceCall>(calldata, |call| self.get_fee_token_balance(call)),
            IFeeManager::getPoolIdCall::SELECTOR => view::<IFeeManager::getPoolIdCall>(calldata, |call| self.get_pool_id(call)),
            IFeeManager::getPoolCall::SELECTOR => view::<IFeeManager::getPoolCall>(calldata, |call| self.get_pool(call)),
            IFeeManager::poolsCall::SELECTOR => view::<IFeeManager::poolsCall>(calldata, |call| self.pools(call)),
            IFeeManager::poolExistsCall::SELECTOR => view::<IFeeManager::poolExistsCall>(calldata, |call| self.pool_exists(call)),

            // State changing functions
            IFeeManager::setValidatorTokenCall::SELECTOR => mutate_void::<IFeeManager::setValidatorTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_validator_token(s, call)),
            IFeeManager::setUserTokenCall::SELECTOR => mutate_void::<IFeeManager::setUserTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_user_token(s, call)),
            IFeeManager::createPoolCall::SELECTOR => mutate_void::<IFeeManager::createPoolCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |_s, call| self.create_pool(call)),
            IFeeManager::collectFeeCall::SELECTOR => {
                mutate_void::<IFeeManager::collectFeeCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.collect_fee(s, call))
            }
            _ => Err(PrecompileError::Other("Unknown function selector".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contracts::{HashMapStorageProvider, types::IFeeManager},
    };
    use alloy::primitives::Address;

    #[test]
    fn test_set_validator_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let contract_addr = Address::from([0u8; 20]);
        let mut fee_manager = TipFeeManager::new(contract_addr, &mut storage);
        let validator = Address::random();
        let token = Address::random();

        let call = IFeeManager::setValidatorTokenCall { token };
        let calldata = call.abi_encode();
        let res = fee_manager.set_validator_token(&validator, call);

    }

}
