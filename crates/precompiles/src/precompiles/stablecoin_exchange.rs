//! Stablecoin DEX precompile
//!
//! This module provides the precompile interface for the Stablecoin DEX.

use crate::{
    contracts::{
        stablecoin_exchange::StablecoinExchange, storage::StorageProvider,
        types::IStablecoinExchange,
    },
    precompiles::{mutate, mutate_void, view, Precompile},
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<'a, S: StorageProvider> Precompile for StablecoinExchange<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        match selector {
            IStablecoinExchange::placeCall::SELECTOR => {
                mutate::<
                    IStablecoinExchange::placeCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |s, call| {
                    self.place(s, call.token, call.amount, call.isBid, call.tick)
                })
            }
            IStablecoinExchange::placeFlipCall::SELECTOR => {
                mutate::<
                    IStablecoinExchange::placeFlipCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |s, call| {
                    self.place_flip(
                        s,
                        call.token,
                        call.amount,
                        call.isBid,
                        call.tick,
                        call.flipTick,
                    )
                })
            }

            IStablecoinExchange::balanceOfCall::SELECTOR => {
                view::<IStablecoinExchange::balanceOfCall>(calldata, |call| {
                    self.balance_of(call.user, call.token)
                })
            }
            IStablecoinExchange::createPairCall::SELECTOR => {
                mutate::<
                    IStablecoinExchange::createPairCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |_s, call| {
                    let key = self.create_pair(&call.base);
                    Ok(key)
                })
            }
            IStablecoinExchange::withdrawCall::SELECTOR => {
                mutate_void::<
                    IStablecoinExchange::withdrawCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |s, call| {
                    self.withdraw(*s, call.token, call.amount)
                })
            }
            IStablecoinExchange::cancelCall::SELECTOR => {
                mutate_void::<
                    IStablecoinExchange::cancelCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |s, call| self.cancel(s, call.orderId))
            }
            IStablecoinExchange::sellCall::SELECTOR => {
                mutate::<
                    IStablecoinExchange::sellCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |s, call| {
                    self.sell(
                        s,
                        call.tokenIn,
                        call.tokenOut,
                        call.amountIn,
                        call.minAmountOut,
                    )
                })
            }
            IStablecoinExchange::buyCall::SELECTOR => {
                mutate::<IStablecoinExchange::buyCall, IStablecoinExchange::IStablecoinExchangeErrors>(
                    calldata,
                    msg_sender,
                    |s, call| {
                        self.buy(
                            s,
                            call.tokenIn,
                            call.tokenOut,
                            call.amountOut,
                            call.maxAmountIn,
                        )
                    },
                )
            }
            IStablecoinExchange::quoteSellCall::SELECTOR => {
                mutate::<
                    IStablecoinExchange::quoteSellCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |_, call| {
                    self.quote_sell(call.tokenIn, call.tokenOut, call.amountIn)
                })
            }
            IStablecoinExchange::quoteBuyCall::SELECTOR => {
                mutate::<
                    IStablecoinExchange::quoteBuyCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |_, call| {
                    self.quote_buy(call.tokenIn, call.tokenOut, call.amountOut)
                })
            }
            IStablecoinExchange::executeBlockCall::SELECTOR => {
                mutate_void::<
                    IStablecoinExchange::executeBlockCall,
                    IStablecoinExchange::IStablecoinExchangeErrors,
                >(calldata, msg_sender, |_s, _call| {
                    self.execute_block(msg_sender)
                })
            }

            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_place_call() {
        // TODO:
    }

    #[test]
    fn test_place_flip_call() {
        // TODO:
    }

    #[test]
    fn test_balance_of_call() {
        // TODO:
    }

    #[test]
    fn test_create_pair_call() {
        // TODO:
    }

    #[test]
    fn test_withdraw_call() {
        // TODO:
    }

    #[test]
    fn test_cancel_call() {
        // TODO:
    }

    #[test]
    fn test_sell_call() {
        // TODO:
    }

    #[test]
    fn test_buy_call() {
        // TODO:
    }

    #[test]
    fn test_quote_sell_call() {
        // TODO:
    }

    #[test]
    fn test_quote_buy_call() {
        // TODO:
    }

    #[test]
    fn test_invalid_selector() {
        // TODO:
    }

    #[test]
    fn test_missing_selector() {
        // TODO:
    }
}
