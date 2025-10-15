//! Stablecoin DEX precompile
//!
//! This module provides the precompile interface for the Stablecoin DEX.

use crate::{
    contracts::{
        stablecoin_exchange::StablecoinExchange, storage::StorageProvider,
        types::IStablecoinExchange,
    },
    precompiles::{Precompile, mutate, mutate_void, view},
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

            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        HashMapStorageProvider,
        stablecoin_exchange::{offsets, slots},
        storage::{StorageOps, slots::mapping_slot},
        types::StablecoinExchangeEvents,
    };
    use alloy::{
        primitives::{Bytes, IntoLogData, U256},
        sol_types::SolValue,
    };

    /// Helper to set internal DEX balance for a user (avoids TIP20 transfer in tests)
    fn setup_balance(
        dex: &mut StablecoinExchange<'_, HashMapStorageProvider>,
        user: Address,
        token: Address,
        amount: u128,
    ) {
        let user_slot = mapping_slot(user.as_slice(), slots::BALANCES);
        let balance_slot = mapping_slot(token.as_slice(), user_slot);
        dex.sstore(balance_slot, U256::from(amount));
    }

    #[test]
    fn test_place_function() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        setup_balance(&mut dex, sender, Address::ZERO, 10000);

        let place_call = IStablecoinExchange::placeCall {
            token,
            amount: 1000,
            isBid: true,
            tick: 5,
        };
        let calldata = place_call.abi_encode();
        let result = dex.call(&Bytes::from(calldata), &sender).unwrap();
        let order_id = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id, 1);

        let events = &storage.events[&crate::STABLECOIN_EXCHANGE_ADDRESS];
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            StablecoinExchangeEvents::OrderPlaced(IStablecoinExchange::OrderPlaced {
                orderId: order_id,
                maker: sender,
                token,
                amount: 1000,
                isBid: true,
                tick: 5,
            })
            .into_log_data()
        );
    }

    #[test]
    fn test_place_flip_function() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        setup_balance(&mut dex, sender, Address::ZERO, 10000);

        let place_flip_call = IStablecoinExchange::placeFlipCall {
            token,
            amount: 2000,
            isBid: true,
            tick: 5,
            flipTick: 10,
        };
        let calldata = place_flip_call.abi_encode();
        let result = dex.call(&Bytes::from(calldata), &sender).unwrap();

        let order_id = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id, 1);

        let events = &storage.events[&crate::STABLECOIN_EXCHANGE_ADDRESS];
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            StablecoinExchangeEvents::FlipOrderPlaced(IStablecoinExchange::FlipOrderPlaced {
                orderId: order_id,
                maker: sender,
                token,
                amount: 2000,
                isBid: true,
                tick: 5,
                flipTick: 10,
            })
            .into_log_data()
        );
    }
}
