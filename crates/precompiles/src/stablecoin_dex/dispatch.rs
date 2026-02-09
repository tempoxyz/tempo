//! Stablecoin DEX precompile
//!
//! This module provides the precompile interface for the Stablecoin DEX.
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::IStablecoinDEX::IStablecoinDEXCalls;

use crate::{
    Precompile, dispatch_call, input_cost, mutate, mutate_void,
    stablecoin_dex::{StablecoinDEX, orderbook::compute_book_key},
    view,
};

impl Precompile for StablecoinDEX {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(
            calldata,
            IStablecoinDEXCalls::abi_decode,
            |call| match call {
                IStablecoinDEXCalls::place(call) => mutate(call, msg_sender, |s, c| {
                    self.place(s, c.token, c.amount, c.isBid, c.tick)
                }),
                IStablecoinDEXCalls::placeFlip(call) => mutate(call, msg_sender, |s, c| {
                    self.place_flip(s, c.token, c.amount, c.isBid, c.tick, c.flipTick, false)
                }),
                IStablecoinDEXCalls::balanceOf(call) => {
                    view(call, |c| self.balance_of(c.user, c.token))
                }
                IStablecoinDEXCalls::getOrder(call) => view(call, |c| {
                    self.get_order(c.orderId).map(|order| order.into())
                }),
                IStablecoinDEXCalls::getTickLevel(call) => view(call, |c| {
                    let level = self.get_price_level(c.base, c.tick, c.isBid)?;
                    Ok((level.head, level.tail, level.total_liquidity).into())
                }),
                IStablecoinDEXCalls::pairKey(call) => {
                    view(call, |c| Ok(compute_book_key(c.tokenA, c.tokenB)))
                }
                IStablecoinDEXCalls::books(call) => {
                    view(call, |c| self.books(c.pairKey).map(Into::into))
                }
                IStablecoinDEXCalls::nextOrderId(call) => view(call, |_| self.next_order_id()),
                IStablecoinDEXCalls::createPair(call) => {
                    mutate(call, msg_sender, |_, c| self.create_pair(c.base))
                }
                IStablecoinDEXCalls::withdraw(call) => {
                    mutate_void(call, msg_sender, |s, c| self.withdraw(s, c.token, c.amount))
                }
                IStablecoinDEXCalls::cancel(call) => {
                    mutate_void(call, msg_sender, |s, c| self.cancel(s, c.orderId))
                }
                IStablecoinDEXCalls::cancelStaleOrder(call) => {
                    mutate_void(call, msg_sender, |_, c| self.cancel_stale_order(c.orderId))
                }
                IStablecoinDEXCalls::swapExactAmountIn(call) => mutate(call, msg_sender, |s, c| {
                    self.swap_exact_amount_in(s, c.tokenIn, c.tokenOut, c.amountIn, c.minAmountOut)
                }),
                IStablecoinDEXCalls::swapExactAmountOut(call) => {
                    mutate(call, msg_sender, |s, c| {
                        self.swap_exact_amount_out(
                            s,
                            c.tokenIn,
                            c.tokenOut,
                            c.amountOut,
                            c.maxAmountIn,
                        )
                    })
                }
                IStablecoinDEXCalls::quoteSwapExactAmountIn(call) => view(call, |c| {
                    self.quote_swap_exact_amount_in(c.tokenIn, c.tokenOut, c.amountIn)
                }),
                IStablecoinDEXCalls::quoteSwapExactAmountOut(call) => view(call, |c| {
                    self.quote_swap_exact_amount_out(c.tokenIn, c.tokenOut, c.amountOut)
                }),
                IStablecoinDEXCalls::MIN_TICK(call) => {
                    view(call, |_| Ok(crate::stablecoin_dex::MIN_TICK))
                }
                IStablecoinDEXCalls::MAX_TICK(call) => {
                    view(call, |_| Ok(crate::stablecoin_dex::MAX_TICK))
                }
                IStablecoinDEXCalls::TICK_SPACING(call) => {
                    view(call, |_| Ok(crate::stablecoin_dex::TICK_SPACING))
                }
                IStablecoinDEXCalls::PRICE_SCALE(call) => {
                    view(call, |_| Ok(crate::stablecoin_dex::PRICE_SCALE))
                }
                IStablecoinDEXCalls::MIN_ORDER_AMOUNT(call) => {
                    view(call, |_| Ok(crate::stablecoin_dex::MIN_ORDER_AMOUNT))
                }
                IStablecoinDEXCalls::MIN_PRICE(call) => view(call, |_| Ok(self.min_price())),
                IStablecoinDEXCalls::MAX_PRICE(call) => view(call, |_| Ok(self.max_price())),
                IStablecoinDEXCalls::tickToPrice(call) => {
                    view(call, |c| self.tick_to_price(c.tick))
                }
                IStablecoinDEXCalls::priceToTick(call) => {
                    view(call, |c| self.price_to_tick(c.price))
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        Precompile,
        stablecoin_dex::{IStablecoinDEX, MIN_ORDER_AMOUNT, StablecoinDEX},
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{Address, U256},
        sol_types::{SolCall, SolValue},
    };
    use tempo_contracts::precompiles::IStablecoinDEX::IStablecoinDEXCalls;

    /// Setup a basic exchange with tokens and liquidity for swap tests
    fn setup_exchange_with_liquidity() -> eyre::Result<(StablecoinDEX, Address, Address, Address)> {
        let mut exchange = StablecoinDEX::new();
        exchange.initialize()?;

        let admin = Address::random();
        let user = Address::random();
        let amount = 200_000_000u128;

        // Initialize quote token (pathUSD)
        let quote = TIP20Setup::path_usd(admin)
            .with_issuer(admin)
            .with_mint(user, U256::from(amount))
            .with_approval(user, exchange.address, U256::from(amount))
            .apply()?;

        let base = TIP20Setup::create("USDC", "USDC", admin)
            .with_issuer(admin)
            .with_mint(user, U256::from(amount))
            .with_approval(user, exchange.address, U256::from(amount))
            .apply()?;

        // Create pair and add liquidity
        exchange.create_pair(base.address())?;

        // Place an order to provide liquidity
        exchange.place(user, base.address(), MIN_ORDER_AMOUNT, true, 0)?;

        Ok((exchange, base.address(), quote.address(), user))
    }

    #[test]
    fn test_place_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::random();
            let token = Address::random();

            let call = IStablecoinDEX::placeCall {
                token,
                amount: 100u128,
                isBid: true,
                tick: 0,
            };
            let calldata = call.abi_encode();

            // Should dispatch to place function (may fail due to business logic, but dispatch works)
            let result = exchange.call(&calldata, sender);
            // Ok indicates successful dispatch (either success or TempoPrecompileError)
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_place_flip_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::random();
            let token = Address::random();

            let call = IStablecoinDEX::placeFlipCall {
                token,
                amount: 100u128,
                isBid: true,
                tick: 0,
                flipTick: 10,
            };
            let calldata = call.abi_encode();

            // Should dispatch to place_flip function
            let result = exchange.call(&calldata, sender);
            // Ok indicates successful dispatch (either success or TempoPrecompileError)
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_balance_of_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::random();
            let token = Address::random();
            let user = Address::random();

            let call = IStablecoinDEX::balanceOfCall { user, token };
            let calldata = call.abi_encode();

            // Should dispatch to balance_of function and succeed (returns 0 for uninitialized)
            let result = exchange.call(&calldata, sender);
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_min_price() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::ZERO;
            let call = IStablecoinDEX::MIN_PRICECall {};
            let calldata = call.abi_encode();

            let result = exchange.call(&calldata, sender);
            assert!(result.is_ok());

            let output = result?.bytes;
            let returned_value = u32::abi_decode(&output)?;

            assert_eq!(returned_value, 98_000, "MIN_PRICE should be 98_000");
            Ok(())
        })
    }

    #[test]
    fn test_tick_spacing() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::ZERO;
            let call = IStablecoinDEX::TICK_SPACINGCall {};
            let calldata = call.abi_encode();

            let result = exchange.call(&calldata, sender);
            assert!(result.is_ok());

            let output = result?.bytes;
            let returned_value = i16::abi_decode(&output)?;

            let expected = crate::stablecoin_dex::TICK_SPACING;
            assert_eq!(
                returned_value, expected,
                "TICK_SPACING should be {expected}"
            );
            Ok(())
        })
    }

    #[test]
    fn test_max_price() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::ZERO;
            let call = IStablecoinDEX::MAX_PRICECall {};
            let calldata = call.abi_encode();

            let result = exchange.call(&calldata, sender);
            assert!(result.is_ok());

            let output = result?.bytes;
            let returned_value = u32::abi_decode(&output)?;

            assert_eq!(returned_value, 102_000, "MAX_PRICE should be 102_000");
            Ok(())
        })
    }

    #[test]
    fn test_create_pair_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::random();
            let base = Address::from([2u8; 20]);

            let call = IStablecoinDEX::createPairCall { base };
            let calldata = call.abi_encode();

            // Should dispatch to create_pair function
            let result = exchange.call(&calldata, sender);
            // Ok indicates successful dispatch (either success or TempoPrecompileError)
            assert!(result.is_ok());
            Ok(())
        })
    }

    #[test]
    fn test_withdraw_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::random();
            let token = Address::random();

            let call = IStablecoinDEX::withdrawCall {
                token,
                amount: 100u128,
            };
            let calldata = call.abi_encode();

            // Should dispatch to withdraw function
            let result = exchange.call(&calldata, sender);
            // Ok indicates successful dispatch (either success or TempoPrecompileError)
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_cancel_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();
            exchange.initialize()?;

            let sender = Address::random();

            let call = IStablecoinDEX::cancelCall { orderId: 1u128 };
            let calldata = call.abi_encode();

            // Should dispatch to cancel function
            let result = exchange.call(&calldata, sender);
            // Ok indicates successful dispatch (either success or TempoPrecompileError)
            assert!(result.is_ok());
            Ok(())
        })
    }

    #[test]
    fn test_swap_exact_amount_in_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let (mut exchange, base_token, quote_token, user) = setup_exchange_with_liquidity()?;

            // Set balance for the swapper
            exchange.set_balance(user, base_token, 1_000_000u128)?;

            let call = IStablecoinDEX::swapExactAmountInCall {
                tokenIn: base_token,
                tokenOut: quote_token,
                amountIn: 100_000u128,
                minAmountOut: 90_000u128,
            };
            let calldata = call.abi_encode();

            // Should dispatch to swap_exact_amount_in function and succeed
            let result = exchange.call(&calldata, user);
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_swap_exact_amount_out_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let (mut exchange, base_token, quote_token, user) = setup_exchange_with_liquidity()?;

            // Place an ask order to provide liquidity for selling base
            exchange.place(user, base_token, MIN_ORDER_AMOUNT, false, 0)?;

            // Set balance for the swapper
            exchange.set_balance(user, quote_token, 1_000_000u128)?;

            let call = IStablecoinDEX::swapExactAmountOutCall {
                tokenIn: quote_token,
                tokenOut: base_token,
                amountOut: 50_000u128,
                maxAmountIn: 60_000u128,
            };
            let calldata = call.abi_encode();

            // Should dispatch to swap_exact_amount_out function and succeed
            let result = exchange.call(&calldata, user);
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_quote_swap_exact_amount_in_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let (mut exchange, base_token, quote_token, _user) = setup_exchange_with_liquidity()?;

            let sender = Address::random();

            let call = IStablecoinDEX::quoteSwapExactAmountInCall {
                tokenIn: base_token,
                tokenOut: quote_token,
                amountIn: 100_000u128,
            };
            let calldata = call.abi_encode();

            // Should dispatch to quote_swap_exact_amount_in function and succeed
            let result = exchange.call(&calldata, sender);
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_quote_swap_exact_amount_out_call() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let (mut exchange, base_token, quote_token, user) = setup_exchange_with_liquidity()?;

            // Place an ask order to provide liquidity for selling base
            exchange.place(user, base_token, MIN_ORDER_AMOUNT, false, 0)?;

            let sender = Address::random();

            let call = IStablecoinDEX::quoteSwapExactAmountOutCall {
                tokenIn: quote_token,
                tokenOut: base_token,
                amountOut: 50_000u128,
            };
            let calldata = call.abi_encode();

            // Should dispatch to quote_swap_exact_amount_out function and succeed
            let result = exchange.call(&calldata, sender);
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn stablecoin_dex_test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut exchange = StablecoinDEX::new();

            let unsupported = check_selector_coverage(
                &mut exchange,
                IStablecoinDEXCalls::SELECTORS,
                "IStablecoinDEX",
                IStablecoinDEXCalls::name_by_selector,
            );

            // All selectors should be supported
            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
