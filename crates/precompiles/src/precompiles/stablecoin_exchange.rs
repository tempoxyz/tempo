//! Stablecoin DEX precompile
//!
//! This module provides the precompile interface for the Stablecoin DEX.

use crate::{
    contracts::{
        stablecoin_exchange::StablecoinExchange, storage::StorageProvider,
        types::IStablecoinExchange,
    },
    precompiles::{Precompile, mutate},
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

            IStablecoinExchange::balanceOfCall::SELECTOR => Err(PrecompileError::Other(
                "balanceOf not yet implemented".to_string(),
            )),
            IStablecoinExchange::withdrawCall::SELECTOR => Err(PrecompileError::Other(
                "withdraw not yet implemented".to_string(),
            )),
            IStablecoinExchange::cancelCall::SELECTOR => Err(PrecompileError::Other(
                "cancel not yet implemented".to_string(),
            )),
            IStablecoinExchange::sellCall::SELECTOR => Err(PrecompileError::Other(
                "sell not yet implemented".to_string(),
            )),
            IStablecoinExchange::buyCall::SELECTOR => Err(PrecompileError::Other(
                "buy not yet implemented".to_string(),
            )),
            IStablecoinExchange::quoteSellCall::SELECTOR => Err(PrecompileError::Other(
                "quoteSell not yet implemented".to_string(),
            )),
            IStablecoinExchange::quoteBuyCall::SELECTOR => Err(PrecompileError::Other(
                "quoteBuy not yet implemented".to_string(),
            )),

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
    use revm::interpreter::instructions::utility::IntoU256;

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
        assert_eq!(order_id, 0); // First order should have ID 0

        let events = &storage.events[&crate::STABLECOIN_DEX_ADDRESS];
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
        assert_eq!(order_id, 0);

        let events = &storage.events[&crate::STABLECOIN_DEX_ADDRESS];
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

    #[test]
    fn test_multiple_orders_increment_ids() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        setup_balance(&mut dex, sender, Address::ZERO, 10000);
        setup_balance(&mut dex, sender, token, 10000);

        // Place first order
        let place_call = IStablecoinExchange::placeCall {
            token,
            amount: 1000,
            isBid: true,
            tick: 5,
        };
        let result = dex
            .call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();
        let order_id_1 = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id_1, 0);

        // Place second order
        let place_call_2 = IStablecoinExchange::placeCall {
            token,
            amount: 2000,
            isBid: false,
            tick: -3,
        };
        let result = dex
            .call(&Bytes::from(place_call_2.abi_encode()), &sender)
            .unwrap();
        let order_id_2 = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id_2, 1);

        // Place third order (flip)
        let place_flip_call = IStablecoinExchange::placeFlipCall {
            token,
            amount: 3000,
            isBid: true,
            tick: 10,
            flipTick: 15,
        };
        let result = dex
            .call(&Bytes::from(place_flip_call.abi_encode()), &sender)
            .unwrap();
        let order_id_3 = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id_3, 2);
    }

    #[test]
    fn test_order_storage_persistence() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);
        let amount = 1500u128;
        let tick = 7i16;

        setup_balance(&mut dex, sender, Address::ZERO, 10000);

        let place_call = IStablecoinExchange::placeCall {
            token,
            amount,
            isBid: true,
            tick,
        };
        let result = dex
            .call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();
        let order_id = u128::abi_decode(&result.bytes).unwrap();

        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);

        let stored_amount = dex.sload(order_slot + offsets::ORDER_AMOUNT_OFFSET);
        assert_eq!(stored_amount, U256::from(amount));

        let stored_tick = dex.sload(order_slot + offsets::ORDER_TICK_OFFSET);
        assert_eq!(stored_tick, U256::from(tick as i128 as u128));

        let is_bid = dex
            .sload(order_slot + offsets::ORDER_IS_BID_OFFSET)
            .to::<bool>();
        assert!(is_bid);

        let is_flip = dex
            .sload(order_slot + offsets::ORDER_IS_FLIP_OFFSET)
            .to::<bool>();
        assert!(!is_flip);

        let stored_flip_tick = dex.sload(order_slot + offsets::ORDER_FLIP_TICK_OFFSET);
        assert_eq!(stored_flip_tick, U256::ZERO);

        let flip_amount = 2500u128;
        let flip_order_tick = 5i16;
        let flip_tick_value = 12i16;

        let place_flip_call = IStablecoinExchange::placeFlipCall {
            token,
            amount: flip_amount,
            isBid: true,
            tick: flip_order_tick,
            flipTick: flip_tick_value,
        };
        let result = dex
            .call(&Bytes::from(place_flip_call.abi_encode()), &sender)
            .unwrap();
        let flip_order_id = u128::abi_decode(&result.bytes).unwrap();

        let flip_order_slot = mapping_slot(flip_order_id.to_be_bytes(), slots::ORDERS);

        let stored_is_flip = dex.sload(flip_order_slot + offsets::ORDER_IS_FLIP_OFFSET);
        assert_eq!(stored_is_flip, U256::from(1u8));

        let stored_flip_tick = dex.sload(flip_order_slot + offsets::ORDER_FLIP_TICK_OFFSET);
        assert_eq!(
            stored_flip_tick,
            U256::from(flip_tick_value as i128 as u128)
        );

        let stored_flip_order_tick = dex.sload(flip_order_slot + offsets::ORDER_TICK_OFFSET);
        assert_eq!(
            stored_flip_order_tick,
            U256::from(flip_order_tick as i128 as u128)
        );
    }

    #[test]
    fn test_pending_order_id_tracking() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        setup_balance(&mut dex, sender, Address::ZERO, 10000);

        let initial_pending = dex.sload(slots::PENDING_ORDER_ID);
        assert_eq!(initial_pending, U256::ZERO);

        let place_call = IStablecoinExchange::placeCall {
            token,
            amount: 1000,
            isBid: true,
            tick: 5,
        };
        dex.call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();

        let pending_after_first = dex.sload(slots::PENDING_ORDER_ID);
        assert_eq!(pending_after_first, U256::from(1));

        dex.call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();

        let pending_after_second = dex.sload(slots::PENDING_ORDER_ID);
        assert_eq!(pending_after_second, U256::from(2));
    }

    #[test]
    fn test_place_flip_bid_with_valid_flip_tick() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        setup_balance(&mut dex, sender, Address::ZERO, 10000);

        // For bid orders, flip_tick must be > tick
        let place_flip_call = IStablecoinExchange::placeFlipCall {
            token,
            amount: 2000,
            isBid: true, // bid
            tick: 5,
            flipTick: 10, // flipTick > tick (valid)
        };
        let result = dex.call(&Bytes::from(place_flip_call.abi_encode()), &sender);

        // Should succeed
        assert!(result.is_ok());
        let order_id = u128::abi_decode(&result.unwrap().bytes).unwrap();
        assert_eq!(order_id, 0);
    }

    #[test]
    fn test_place_flip_ask_with_valid_flip_tick() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        setup_balance(&mut dex, sender, token, 10000);

        let place_flip_call = IStablecoinExchange::placeFlipCall {
            token,
            amount: 2000,
            isBid: false,
            tick: 10,
            flipTick: 5,
        };
        let result = dex.call(&Bytes::from(place_flip_call.abi_encode()), &sender);

        assert!(result.is_ok());
        let order_id = u128::abi_decode(&result.unwrap().bytes).unwrap();
        assert_eq!(order_id, 0);
    }

    #[test]
    fn test_place_flip_bid_with_invalid_flip_tick_returns_error() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        let place_flip_call = IStablecoinExchange::placeFlipCall {
            token,
            amount: 2000,
            isBid: true,
            tick: 10,
            flipTick: 3,
        };

        let result = dex.call(&Bytes::from(place_flip_call.abi_encode()), &sender);

        assert!(
            result.is_err(),
            "Expected error for invalid flip tick constraint"
        );
    }

    #[test]
    fn test_place_flip_ask_with_invalid_flip_tick_returns_error() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        let place_flip_call = IStablecoinExchange::placeFlipCall {
            token,
            amount: 2000,
            isBid: false,
            tick: 10,
            flipTick: 15,
        };

        let result = dex.call(&Bytes::from(place_flip_call.abi_encode()), &sender);

        assert!(
            result.is_err(),
            "Expected error for invalid flip tick constraint"
        );
    }

    #[test]
    fn test_negative_ticks_are_stored_correctly() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);
        let negative_tick = -15i16;

        setup_balance(&mut dex, sender, token, 10000);

        let place_call = IStablecoinExchange::placeCall {
            token,
            amount: 1000,
            isBid: false,
            tick: negative_tick,
        };
        let result = dex
            .call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();
        let order_id = u128::abi_decode(&result.bytes).unwrap();

        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);
        let stored_tick = dex.sload(order_slot + offsets::ORDER_TICK_OFFSET);

        let expected = U256::from(negative_tick as i128 as u128);
        assert_eq!(stored_tick, expected);
    }

    #[test]
    fn test_invalid_selector() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        let result = dex.call(&Bytes::from([0x12, 0x34, 0x56, 0x78]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));

        let result = dex.call(&Bytes::from([0x12, 0x34]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }

    #[test]
    fn test_sender_address_stored_correctly() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinExchange::new(&mut storage);
        dex.initialize();

        let sender = Address::from([0xAB; 20]);
        let token = Address::from([2u8; 20]);

        setup_balance(&mut dex, sender, Address::ZERO, 10000);

        let place_call = IStablecoinExchange::placeCall {
            token,
            amount: 1000,
            isBid: true,
            tick: 5,
        };
        let result = dex
            .call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();
        let order_id = u128::abi_decode(&result.bytes).unwrap();

        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);
        let stored_maker = dex.sload(order_slot + offsets::ORDER_MAKER_OFFSET);
        assert_eq!(stored_maker, sender.into_u256());
    }
}
