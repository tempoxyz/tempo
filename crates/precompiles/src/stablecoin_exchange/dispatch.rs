//! Stablecoin DEX precompile
//!
//! This module provides the precompile interface for the Stablecoin DEX.
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::{
    Precompile, input_cost, mutate, mutate_void,
    stablecoin_exchange::{IStablecoinExchange, StablecoinExchange},
    storage::PrecompileStorageProvider,
    view,
};

impl<'a, S: PrecompileStorageProvider> Precompile for StablecoinExchange<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        let result = match selector {
            IStablecoinExchange::placeCall::SELECTOR => {
                mutate::<IStablecoinExchange::placeCall>(calldata, msg_sender, |s, call| {
                    self.place(s, call.token, call.amount, call.isBid, call.tick)
                })
            }
            IStablecoinExchange::placeFlipCall::SELECTOR => {
                mutate::<IStablecoinExchange::placeFlipCall>(calldata, msg_sender, |s, call| {
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

            IStablecoinExchange::getOrderCall::SELECTOR => {
                view::<IStablecoinExchange::getOrderCall>(calldata, |call| {
                    self.get_order(call.orderId).map(|order| order.into())
                })
            }

            IStablecoinExchange::getPriceLevelCall::SELECTOR => {
                view::<IStablecoinExchange::getPriceLevelCall>(calldata, |call| {
                    self.get_price_level(call.base, call.tick, call.isBid)
                        .map(Into::into)
                })
            }

            IStablecoinExchange::pairKeyCall::SELECTOR => {
                view::<IStablecoinExchange::pairKeyCall>(calldata, |call| {
                    Ok(self.pair_key(call.tokenA, call.tokenB))
                })
            }

            IStablecoinExchange::booksCall::SELECTOR => {
                view::<IStablecoinExchange::booksCall>(calldata, |call| {
                    self.books(call.pairKey).map(Into::into)
                })
            }

            IStablecoinExchange::createPairCall::SELECTOR => {
                mutate::<IStablecoinExchange::createPairCall>(calldata, msg_sender, |_s, call| {
                    self.create_pair(call.base)
                })
            }
            IStablecoinExchange::withdrawCall::SELECTOR => {
                mutate_void::<IStablecoinExchange::withdrawCall>(calldata, msg_sender, |s, call| {
                    self.withdraw(s, call.token, call.amount)
                })
            }
            IStablecoinExchange::cancelCall::SELECTOR => {
                mutate_void::<IStablecoinExchange::cancelCall>(calldata, msg_sender, |s, call| {
                    self.cancel(s, call.orderId)
                })
            }
            IStablecoinExchange::swapExactAmountInCall::SELECTOR => {
                mutate::<IStablecoinExchange::swapExactAmountInCall>(
                    calldata,
                    msg_sender,
                    |s, call| {
                        self.swap_exact_amount_in(
                            s,
                            call.tokenIn,
                            call.tokenOut,
                            call.amountIn,
                            call.minAmountOut,
                        )
                    },
                )
            }
            IStablecoinExchange::swapExactAmountOutCall::SELECTOR => {
                mutate::<IStablecoinExchange::swapExactAmountOutCall>(
                    calldata,
                    msg_sender,
                    |s, call| {
                        self.swap_exact_amount_out(
                            s,
                            call.tokenIn,
                            call.tokenOut,
                            call.amountOut,
                            call.maxAmountIn,
                        )
                    },
                )
            }
            IStablecoinExchange::quoteSwapExactAmountInCall::SELECTOR => {
                view::<IStablecoinExchange::quoteSwapExactAmountInCall>(calldata, |call| {
                    self.quote_swap_exact_amount_in(call.tokenIn, call.tokenOut, call.amountIn)
                })
            }
            IStablecoinExchange::quoteSwapExactAmountOutCall::SELECTOR => {
                view::<IStablecoinExchange::quoteSwapExactAmountOutCall>(calldata, |call| {
                    self.quote_swap_exact_amount_out(call.tokenIn, call.tokenOut, call.amountOut)
                })
            }
            IStablecoinExchange::executeBlockCall::SELECTOR => {
                mutate_void::<IStablecoinExchange::executeBlockCall>(
                    calldata,
                    msg_sender,
                    |_s, _call| self.execute_block(msg_sender),
                )
            }

            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        };

        result.map(|mut res| {
            res.gas_used = self.storage.gas_used();
            res
        })
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
    fn test_swap_exact_amount_in_call() {
        // TODO:
    }

    #[test]
    fn test_swap_exact_amount_out_call() {
        // TODO:
    }

    #[test]
    fn test_quote_swap_exact_amount_in_call() {
        // TODO:
    }

    #[test]
    fn test_quote_swap_exact_amount_out_call() {
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
