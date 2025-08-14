use crate::{
    contracts::{
        EvmStorageProvider,
        tip_fee_manager::TipFeeManager,
        types::IFeeManager,
    },
    precompiles::{Precompile, metadata, mutate, mutate_void, view},
};
use alloy::{primitives::Address, sol_types::SolCall};
use reth::revm::precompile::{PrecompileError, PrecompileResult};

#[rustfmt::skip]
impl Precompile for TipFeeManager<EvmStorageProvider<'_>> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata.get(..4).ok_or_else(|| { 
            PrecompileError::Other("Invalid input: missing function selector".to_string()) 
        })?.try_into().unwrap();

        match selector {
            // Constants
            IFeeManager::BASIS_POINTSCall::SELECTOR => metadata::<IFeeManager::BASIS_POINTSCall>(self.basis_points()),
            IFeeManager::FEE_BPSCall::SELECTOR => metadata::<IFeeManager::FEE_BPSCall>(self.fee_bps()),

            // View functions
            IFeeManager::userTokensCall::SELECTOR => view::<IFeeManager::userTokensCall>(calldata, |call| self.user_tokens(call)),
            IFeeManager::validatorTokensCall::SELECTOR => view::<IFeeManager::validatorTokensCall>(calldata, |call| self.validator_tokens(call)),
            IFeeManager::getFeeTokenBalanceCall::SELECTOR => view::<IFeeManager::getFeeTokenBalanceCall>(calldata, |call| self.get_fee_token_balance(call)),
            IFeeManager::getPoolIdCall::SELECTOR => view::<IFeeManager::getPoolIdCall>(calldata, |call| self.get_pool_id(call)),
            IFeeManager::getPoolCall::SELECTOR => view::<IFeeManager::getPoolCall>(calldata, |call| self.get_pool(call)),
            IFeeManager::poolsCall::SELECTOR => view::<IFeeManager::poolsCall>(calldata, |call| self.pools(call)),
            IFeeManager::totalSupplyCall::SELECTOR => view::<IFeeManager::totalSupplyCall>(calldata, |call| self.total_supply(call)),
            IFeeManager::poolExistsCall::SELECTOR => view::<IFeeManager::poolExistsCall>(calldata, |call| self.pool_exists(call)),
            IFeeManager::liquidityBalancesCall::SELECTOR => view::<IFeeManager::liquidityBalancesCall>(calldata, |call| self.liquidity_balances(call)),
            IFeeManager::pendingReserve0Call::SELECTOR => view::<IFeeManager::pendingReserve0Call>(calldata, |call| self.pending_reserve0(call)),
            IFeeManager::pendingReserve1Call::SELECTOR => view::<IFeeManager::pendingReserve1Call>(calldata, |call| self.pending_reserve1(call)),
            IFeeManager::getTokensWithFeesLengthCall::SELECTOR => view::<IFeeManager::getTokensWithFeesLengthCall>(calldata, |_call| self.get_tokens_with_fees_length()),
            IFeeManager::getOperationQueueLengthCall::SELECTOR => view::<IFeeManager::getOperationQueueLengthCall>(calldata, |_call| self.get_operation_queue_length()),
            IFeeManager::getDepositQueueLengthCall::SELECTOR => view::<IFeeManager::getDepositQueueLengthCall>(calldata, |_call| self.get_deposit_queue_length()),
            IFeeManager::getWithdrawQueueLengthCall::SELECTOR => view::<IFeeManager::getWithdrawQueueLengthCall>(calldata, |_call| self.get_withdraw_queue_length()),

            // State changing functions
            IFeeManager::setValidatorTokenCall::SELECTOR => mutate_void::<IFeeManager::setValidatorTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_validator_token(s, call)),
            IFeeManager::setUserTokenCall::SELECTOR => mutate_void::<IFeeManager::setUserTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_user_token(s, call)),
            IFeeManager::createPoolCall::SELECTOR => mutate_void::<IFeeManager::createPoolCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.create_pool(s, call)),
            IFeeManager::collectFeeCall::SELECTOR => mutate_void::<IFeeManager::collectFeeCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.collect_fee(s, call)),

            _ => Err(PrecompileError::Other("Unknown function selector".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        contracts::{HashMapStorageProvider, types::IFeeManager},
        precompiles::{METADATA_GAS, MUTATE_FUNC_GAS, VIEW_FUNC_GAS, expect_precompile_error},
    };
    use alloy::{primitives::{Address, U256, B256}, sol_types::SolValue};
    use alloy_primitives::Bytes;

}
