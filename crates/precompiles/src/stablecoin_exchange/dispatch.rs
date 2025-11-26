//! Stablecoin DEX precompile
//!
//! This module provides the precompile interface for the Stablecoin DEX.
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::{
    Precompile, input_cost, mutate, mutate_void,
    stablecoin_exchange::{IStablecoinExchange, StablecoinExchange},
    storage::PrecompileStorageProvider,
    unknown_selector, view,
};

impl<'a, S: PrecompileStorageProvider> Precompile for StablecoinExchange<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".into())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".into()))?;

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

            IStablecoinExchange::getTickLevelCall::SELECTOR => {
                view::<IStablecoinExchange::getTickLevelCall>(calldata, |call| {
                    let level = self.get_price_level(call.base, call.tick, call.isBid)?;
                    Ok((level.head, level.tail, level.total_liquidity).into())
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

            IStablecoinExchange::activeOrderIdCall::SELECTOR => {
                view::<IStablecoinExchange::activeOrderIdCall>(calldata, |_call| {
                    self.active_order_id()
                })
            }
            IStablecoinExchange::pendingOrderIdCall::SELECTOR => {
                view::<IStablecoinExchange::pendingOrderIdCall>(calldata, |_call| {
                    self.pending_order_id()
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
            IStablecoinExchange::MIN_TICKCall::SELECTOR => {
                view::<IStablecoinExchange::MIN_TICKCall>(calldata, |_call| {
                    Ok(crate::stablecoin_exchange::MIN_TICK)
                })
            }
            IStablecoinExchange::MAX_TICKCall::SELECTOR => {
                view::<IStablecoinExchange::MAX_TICKCall>(calldata, |_call| {
                    Ok(crate::stablecoin_exchange::MAX_TICK)
                })
            }
            IStablecoinExchange::PRICE_SCALECall::SELECTOR => {
                view::<IStablecoinExchange::PRICE_SCALECall>(calldata, |_call| {
                    Ok(crate::stablecoin_exchange::PRICE_SCALE)
                })
            }
            IStablecoinExchange::MIN_PRICECall::SELECTOR => {
                view::<IStablecoinExchange::MIN_PRICECall>(calldata, |_call| Ok(self.min_price()))
            }
            IStablecoinExchange::MAX_PRICECall::SELECTOR => {
                view::<IStablecoinExchange::MAX_PRICECall>(calldata, |_call| Ok(self.max_price()))
            }
            IStablecoinExchange::tickToPriceCall::SELECTOR => {
                view::<IStablecoinExchange::tickToPriceCall>(calldata, |call| {
                    Ok(crate::stablecoin_exchange::tick_to_price(call.tick))
                })
            }
            IStablecoinExchange::priceToTickCall::SELECTOR => {
                view::<IStablecoinExchange::priceToTickCall>(calldata, |call| {
                    self.price_to_tick(call.price)
                })
            }

            _ => unknown_selector(selector, self.storage.gas_used(), self.storage.spec()),
        };

        result.map(|mut res| {
            res.gas_used = self.storage.gas_used();
            res
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        Precompile,
        path_usd::{PathUSD, TRANSFER_ROLE},
        stablecoin_exchange::{IStablecoinExchange, MIN_ORDER_AMOUNT, StablecoinExchange},
        storage::{ContractStorage, PrecompileStorageProvider, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
        tip20::{ISSUER_ROLE, ITIP20, TIP20Token},
    };
    use alloy::{
        primitives::{Address, Bytes, U256},
        sol_types::{SolCall, SolValue},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::IStablecoinExchange::IStablecoinExchangeCalls;

    /// Setup a basic exchange with tokens and liquidity for swap tests
    fn setup_exchange_with_liquidity<S: PrecompileStorageProvider>(
        storage: &mut S,
    ) -> (StablecoinExchange<'_, S>, Address, Address, Address) {
        let mut exchange = StablecoinExchange::new(storage);
        exchange.initialize().unwrap();

        let admin = Address::random();
        let user = Address::random();
        let amount = 200_000_000u128;

        // Initialize quote token (PathUSD)
        let mut quote = PathUSD::new(exchange.storage);
        quote.initialize(admin).unwrap();

        quote
            .token
            .grant_role_internal(admin, *ISSUER_ROLE)
            .unwrap();
        quote
            .token
            .grant_role_internal(user, *TRANSFER_ROLE)
            .unwrap();

        quote
            .mint(
                admin,
                ITIP20::mintCall {
                    to: user,
                    amount: U256::from(amount),
                },
            )
            .unwrap();

        quote
            .approve(
                user,
                ITIP20::approveCall {
                    spender: exchange.address,
                    amount: U256::from(amount),
                },
            )
            .unwrap();

        // Initialize base token
        let quote_address = quote.token.address();
        let mut base = TIP20Token::new(1, quote.token.storage());
        base.initialize("BASE", "BASE", "USD", quote_address, admin, Address::ZERO)
            .unwrap();

        base.grant_role_internal(admin, *ISSUER_ROLE).unwrap();

        base.approve(
            user,
            ITIP20::approveCall {
                spender: exchange.address,
                amount: U256::from(amount),
            },
        )
        .unwrap();

        base.mint(
            admin,
            ITIP20::mintCall {
                to: user,
                amount: U256::from(amount),
            },
        )
        .unwrap();

        let base_token = base.address();
        let quote_token = quote.token.address();

        // Create pair and add liquidity
        exchange.create_pair(base_token).unwrap();

        // Place an order to provide liquidity
        exchange
            .place(user, base_token, MIN_ORDER_AMOUNT, true, 0)
            .unwrap();

        // Execute block to activate orders
        exchange.execute_block(Address::ZERO).unwrap();

        (exchange, base_token, quote_token, user)
    }

    #[test]
    fn test_place_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        let call = IStablecoinExchange::placeCall {
            token,
            amount: 100u128,
            isBid: true,
            tick: 0,
        };
        let calldata = call.abi_encode();

        // Should dispatch to place function (may fail due to business logic, but dispatch works)
        let result = exchange.call(&Bytes::from(calldata), sender);
        // Ok indicates successful dispatch (either success or TempoPrecompileError)
        assert!(result.is_ok());
    }

    #[test]
    fn test_place_flip_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        let call = IStablecoinExchange::placeFlipCall {
            token,
            amount: 100u128,
            isBid: true,
            tick: 0,
            flipTick: 10,
        };
        let calldata = call.abi_encode();

        // Should dispatch to place_flip function
        let result = exchange.call(&Bytes::from(calldata), sender);
        // Ok indicates successful dispatch (either success or TempoPrecompileError)
        assert!(result.is_ok());
    }

    #[test]
    fn test_balance_of_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::from([1u8; 20]);
        let user = Address::from([2u8; 20]);
        let token = Address::from([3u8; 20]);

        let call = IStablecoinExchange::balanceOfCall { user, token };
        let calldata = call.abi_encode();

        // Should dispatch to balance_of function and succeed (returns 0 for uninitialized)
        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());
    }

    #[test]
    fn test_min_price_pre_moderato() {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::ZERO;
        let call = IStablecoinExchange::MIN_PRICECall {};
        let calldata = call.abi_encode();

        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());

        let output = result.unwrap().bytes;
        let returned_value = u32::abi_decode(&output).unwrap();

        assert_eq!(
            returned_value, 67_232,
            "Pre-moderato MIN_PRICE should be 67_232"
        );
    }

    #[test]
    fn test_min_price_post_moderato() {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::ZERO;
        let call = IStablecoinExchange::MIN_PRICECall {};
        let calldata = call.abi_encode();

        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());

        let output = result.unwrap().bytes;
        let returned_value = u32::abi_decode(&output).unwrap();

        assert_eq!(
            returned_value, 98_000,
            "Post-moderato MIN_PRICE should be 98_000"
        );
    }

    #[test]
    fn test_max_price_pre_moderato() {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::ZERO;
        let call = IStablecoinExchange::MAX_PRICECall {};
        let calldata = call.abi_encode();

        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());

        let output = result.unwrap().bytes;
        let returned_value = u32::abi_decode(&output).unwrap();

        assert_eq!(
            returned_value, 132_767,
            "Pre-moderato MAX_PRICE should be 132_767"
        );
    }

    #[test]
    fn test_max_price_post_moderato() {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::ZERO;
        let call = IStablecoinExchange::MAX_PRICECall {};
        let calldata = call.abi_encode();

        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());

        let output = result.unwrap().bytes;
        let returned_value = u32::abi_decode(&output).unwrap();

        assert_eq!(
            returned_value, 102_000,
            "Post-moderato MAX_PRICE should be 102_000"
        );
    }

    #[test]
    fn test_create_pair_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::from([1u8; 20]);
        let base = Address::from([2u8; 20]);

        let call = IStablecoinExchange::createPairCall { base };
        let calldata = call.abi_encode();

        // Should dispatch to create_pair function
        let result = exchange.call(&Bytes::from(calldata), sender);
        // Ok indicates successful dispatch (either success or TempoPrecompileError)
        assert!(result.is_ok());
    }

    #[test]
    fn test_withdraw_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        let call = IStablecoinExchange::withdrawCall {
            token,
            amount: 100u128,
        };
        let calldata = call.abi_encode();

        // Should dispatch to withdraw function
        let result = exchange.call(&Bytes::from(calldata), sender);
        // Ok indicates successful dispatch (either success or TempoPrecompileError)
        assert!(result.is_ok());
    }

    #[test]
    fn test_cancel_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::from([1u8; 20]);

        let call = IStablecoinExchange::cancelCall { orderId: 1u128 };
        let calldata = call.abi_encode();

        // Should dispatch to cancel function
        let result = exchange.call(&Bytes::from(calldata), sender);
        // Ok indicates successful dispatch (either success or TempoPrecompileError)
        assert!(result.is_ok());
    }

    #[test]
    fn test_swap_exact_amount_in_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut exchange, base_token, quote_token, user) =
            setup_exchange_with_liquidity(&mut storage);

        // Set balance for the swapper
        exchange
            .set_balance(user, base_token, 1_000_000u128)
            .unwrap();

        let call = IStablecoinExchange::swapExactAmountInCall {
            tokenIn: base_token,
            tokenOut: quote_token,
            amountIn: 100_000u128,
            minAmountOut: 90_000u128,
        };
        let calldata = call.abi_encode();

        // Should dispatch to swap_exact_amount_in function and succeed
        let result = exchange.call(&Bytes::from(calldata), user);
        assert!(result.is_ok());
    }

    #[test]
    fn test_swap_exact_amount_out_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut exchange, base_token, quote_token, user) =
            setup_exchange_with_liquidity(&mut storage);

        // Place an ask order to provide liquidity for selling base
        exchange
            .place(user, base_token, MIN_ORDER_AMOUNT, false, 0)
            .unwrap();
        exchange.execute_block(Address::ZERO).unwrap();

        // Set balance for the swapper
        exchange
            .set_balance(user, quote_token, 1_000_000u128)
            .unwrap();

        let call = IStablecoinExchange::swapExactAmountOutCall {
            tokenIn: quote_token,
            tokenOut: base_token,
            amountOut: 50_000u128,
            maxAmountIn: 60_000u128,
        };
        let calldata = call.abi_encode();

        // Should dispatch to swap_exact_amount_out function and succeed
        let result = exchange.call(&Bytes::from(calldata), user);
        assert!(result.is_ok());
    }

    #[test]
    fn test_quote_swap_exact_amount_in_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut exchange, base_token, quote_token, _user) =
            setup_exchange_with_liquidity(&mut storage);

        let sender = Address::random();

        let call = IStablecoinExchange::quoteSwapExactAmountInCall {
            tokenIn: base_token,
            tokenOut: quote_token,
            amountIn: 100_000u128,
        };
        let calldata = call.abi_encode();

        // Should dispatch to quote_swap_exact_amount_in function and succeed
        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());
    }

    #[test]
    fn test_quote_swap_exact_amount_out_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let (mut exchange, base_token, quote_token, user) =
            setup_exchange_with_liquidity(&mut storage);

        // Place an ask order to provide liquidity for selling base
        exchange
            .place(user, base_token, MIN_ORDER_AMOUNT, false, 0)
            .unwrap();
        exchange.execute_block(Address::ZERO).unwrap();

        let sender = Address::random();

        let call = IStablecoinExchange::quoteSwapExactAmountOutCall {
            tokenIn: quote_token,
            tokenOut: base_token,
            amountOut: 50_000u128,
        };
        let calldata = call.abi_encode();

        // Should dispatch to quote_swap_exact_amount_out function and succeed
        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());
    }

    #[test]
    fn test_active_order_id_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::random();

        let call = IStablecoinExchange::activeOrderIdCall {};
        let calldata = call.abi_encode();

        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());

        let output = result.unwrap();
        let active_order_id = u128::abi_decode(&output.bytes).unwrap();
        assert_eq!(active_order_id, 0); // Should be 0 initially
    }

    #[test]
    fn test_pending_order_id_call() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::random();

        let call = IStablecoinExchange::pendingOrderIdCall {};
        let calldata = call.abi_encode();

        let result = exchange.call(&Bytes::from(calldata), sender);
        assert!(result.is_ok());

        let output = result.unwrap();
        let pending_order_id = u128::abi_decode(&output.bytes).unwrap();
        assert_eq!(pending_order_id, 0); // Should be 0 initially
    }

    #[test]
    fn test_invalid_selector() {
        use tempo_chainspec::hardfork::TempoHardfork;
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Moderato);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::from([1u8; 20]);

        // Use an invalid selector that doesn't match any function - should return Ok with reverted status
        let calldata = Bytes::from([0x12, 0x34, 0x56, 0x78]);

        let result = exchange.call(&calldata, sender);
        assert!(result.is_ok());
        assert!(result.unwrap().reverted);
    }

    #[test]
    fn test_missing_selector() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);
        exchange.initialize().unwrap();

        let sender = Address::from([1u8; 20]);

        // Use calldata that's too short to contain a selector
        let calldata = Bytes::from([0x12, 0x34]);

        let result = exchange.call(&calldata, sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }

    #[test]
    fn stablecoin_exchange_test_selector_coverage() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut exchange = StablecoinExchange::new(&mut storage);

        let unsupported = check_selector_coverage(
            &mut exchange,
            IStablecoinExchangeCalls::SELECTORS,
            "IStablecoinExchange",
            IStablecoinExchangeCalls::name_by_selector,
        );

        assert_full_coverage([unsupported]);
    }
}
