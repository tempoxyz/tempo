//! Stablecoin DEX precompile dispatch (auto-generated via `#[contract(..., dispatch)]`).

#[cfg(test)]
mod tests {

    use crate::{
        Precompile,
        stablecoin_dex::{IStablecoinDEX, MIN_ORDER_AMOUNT, StablecoinDEX, traits::*},
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{Address, U256},
        sol_types::{SolCall, SolValue},
    };

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
                is_bid: true,
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
                is_bid: true,
                tick: 0,
                flip_tick: 10,
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

            let call = IStablecoinDEX::cancelCall { order_id: 1u128 };
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
                token_in: base_token,
                token_out: quote_token,
                amount_in: 100_000u128,
                min_amount_out: 90_000u128,
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
                token_in: quote_token,
                token_out: base_token,
                amount_out: 50_000u128,
                max_amount_in: 60_000u128,
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
                token_in: base_token,
                token_out: quote_token,
                amount_in: 100_000u128,
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
                token_in: quote_token,
                token_out: base_token,
                amount_out: 50_000u128,
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

            let interface_unsupported = check_selector_coverage(
                &mut exchange,
                IStablecoinDEX::InterfaceCalls::SELECTORS,
                "IStablecoinDEX::Interface",
                IStablecoinDEX::InterfaceCalls::name_by_selector,
            );

            let constants_unsupported = check_selector_coverage(
                &mut exchange,
                IStablecoinDEX::ConstantsCalls::SELECTORS,
                "IStablecoinDEX::Constants",
                IStablecoinDEX::ConstantsCalls::name_by_selector,
            );

            // All selectors should be supported
            assert_full_coverage([interface_unsupported, constants_unsupported]);

            Ok(())
        })
    }
}
