//! Stablecoin DEX precompile
//!
//! This module provides the precompile interface for the Stablecoin DEX.

use crate::{
    contracts::{stablecoin_dex::StablecoinDex, storage::StorageProvider, types::IStablecoinDex},
    precompiles::{Precompile, mutate},
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<'a, S: StorageProvider> Precompile for StablecoinDex<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        match selector {
            IStablecoinDex::placeCall::SELECTOR => {
                mutate::<IStablecoinDex::placeCall, IStablecoinDex::IStablecoinDexErrors>(
                    calldata,
                    msg_sender,
                    |s, call| Ok(self.place(s, call.token, call.amount, call.isBid, call.tick)),
                )
            }
            IStablecoinDex::placeFlipCall::SELECTOR => {
                mutate::<IStablecoinDex::placeFlipCall, IStablecoinDex::IStablecoinDexErrors>(
                    calldata,
                    msg_sender,
                    |s, call| {
                        Ok(self.place_flip(
                            s,
                            call.token,
                            call.amount,
                            call.isBid,
                            call.tick,
                            call.flipTick,
                        ))
                    },
                )
            }

            IStablecoinDex::balanceOfCall::SELECTOR => Err(PrecompileError::Other(
                "balanceOf not yet implemented".to_string(),
            )),
            IStablecoinDex::withdrawCall::SELECTOR => Err(PrecompileError::Other(
                "withdraw not yet implemented".to_string(),
            )),
            IStablecoinDex::cancelCall::SELECTOR => Err(PrecompileError::Other(
                "cancel not yet implemented".to_string(),
            )),
            IStablecoinDex::sellCall::SELECTOR => Err(PrecompileError::Other(
                "sell not yet implemented".to_string(),
            )),
            IStablecoinDex::buyCall::SELECTOR => Err(PrecompileError::Other(
                "buy not yet implemented".to_string(),
            )),
            IStablecoinDex::quoteSellCall::SELECTOR => Err(PrecompileError::Other(
                "quoteSell not yet implemented".to_string(),
            )),
            IStablecoinDex::quoteBuyCall::SELECTOR => Err(PrecompileError::Other(
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
        stablecoin_dex::{offsets, slots},
        storage::{StorageOps, slots::mapping_slot},
        types::StablecoinDexEvent,
    };
    use alloy::{
        primitives::{Bytes, IntoLogData, U256},
        sol_types::SolValue,
    };
    use revm::interpreter::instructions::utility::IntoU256;

    #[test]
    fn test_place_function() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        // Create a place call
        let place_call = IStablecoinDex::placeCall {
            token,
            amount: 1000,
            isBid: true,
            tick: 5,
        };
        let calldata = place_call.abi_encode();

        // Execute place
        let result = dex.call(&Bytes::from(calldata), &sender).unwrap();

        // Decode the return value (should be order_id)
        let order_id = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id, 1); // First order should have ID 1

        // Verify OrderPlaced event was emitted
        let events = &storage.events[&crate::STABLECOIN_DEX_ADDRESS];
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            StablecoinDexEvent::OrderPlaced(IStablecoinDex::OrderPlaced {
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
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        // Create a placeFlip call (bid: flip_tick must be > tick)
        let place_flip_call = IStablecoinDex::placeFlipCall {
            token,
            amount: 2000,
            isBid: true,
            tick: 5,
            flipTick: 10,
        };
        let calldata = place_flip_call.abi_encode();

        // Execute placeFlip
        let result = dex.call(&Bytes::from(calldata), &sender).unwrap();

        // Decode the return value
        let order_id = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id, 1);

        // Verify FlipOrderPlaced event was emitted
        let events = &storage.events[&crate::STABLECOIN_DEX_ADDRESS];
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            StablecoinDexEvent::FlipOrderPlaced(IStablecoinDex::FlipOrderPlaced {
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
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        // Place first order
        let place_call = IStablecoinDex::placeCall {
            token,
            amount: 1000,
            isBid: true,
            tick: 5,
        };
        let result = dex
            .call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();
        let order_id_1 = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id_1, 1);

        // Place second order
        let place_call_2 = IStablecoinDex::placeCall {
            token,
            amount: 2000,
            isBid: false,
            tick: -3,
        };
        let result = dex
            .call(&Bytes::from(place_call_2.abi_encode()), &sender)
            .unwrap();
        let order_id_2 = u128::abi_decode(&result.bytes).unwrap();
        assert_eq!(order_id_2, 2);

        // Place third order (flip)
        let place_flip_call = IStablecoinDex::placeFlipCall {
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
        assert_eq!(order_id_3, 3);
    }

    #[test]
    fn test_order_storage_persistence() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);
        let amount = 1500u128;
        let tick = 7i16;

        // Place an order
        let place_call = IStablecoinDex::placeCall {
            token,
            amount,
            isBid: true,
            tick,
        };
        let result = dex
            .call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();
        let order_id = u128::abi_decode(&result.bytes).unwrap();

        // Verify order is stored correctly by reading from storage
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);

        // Check amount
        let stored_amount = dex.sload(order_slot + offsets::ORDER_AMOUNT_OFFSET);
        assert_eq!(stored_amount, U256::from(amount));

        // Check tick
        let stored_tick = dex.sload(order_slot + offsets::ORDER_TICK_OFFSET);
        assert_eq!(stored_tick, U256::from(tick as i128 as u128));

        // Check side (bid = true = 1)
        let stored_side = dex.sload(order_slot + offsets::ORDER_SIDE_OFFSET);
        assert_eq!(stored_side, U256::from(1u8));

        // Check is_flip (false = 0)
        let stored_is_flip = dex.sload(order_slot + offsets::ORDER_IS_FLIP_OFFSET);
        assert_eq!(stored_is_flip, U256::ZERO);
    }

    #[test]
    fn test_flip_order_storage_persistence() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);
        let amount = 2500u128;
        let tick = 5i16;
        let flip_tick = 12i16;

        // Place a flip order
        let place_flip_call = IStablecoinDex::placeFlipCall {
            token,
            amount,
            isBid: true,
            tick,
            flipTick: flip_tick,
        };
        let result = dex
            .call(&Bytes::from(place_flip_call.abi_encode()), &sender)
            .unwrap();
        let order_id = u128::abi_decode(&result.bytes).unwrap();

        // Verify flip order is stored correctly
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);

        // Check is_flip (true = 1)
        let stored_is_flip = dex.sload(order_slot + offsets::ORDER_IS_FLIP_OFFSET);
        assert_eq!(stored_is_flip, U256::from(1u8));

        // Check flip_tick
        let stored_flip_tick = dex.sload(order_slot + offsets::ORDER_FLIP_TICK_OFFSET);
        assert_eq!(stored_flip_tick, U256::from(flip_tick as i128 as u128));
    }

    #[test]
    fn test_pending_order_id_tracking() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        // Initially pending_order_id should be 0
        let initial_pending = dex.sload(slots::PENDING_ORDER_ID);
        assert_eq!(initial_pending, U256::ZERO);

        // Place first order
        let place_call = IStablecoinDex::placeCall {
            token,
            amount: 1000,
            isBid: true,
            tick: 5,
        };
        dex.call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();

        // Check pending_order_id incremented to 1
        let pending_after_first = dex.sload(slots::PENDING_ORDER_ID);
        assert_eq!(pending_after_first, U256::from(1));

        // Place second order
        dex.call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();

        // Check pending_order_id incremented to 2
        let pending_after_second = dex.sload(slots::PENDING_ORDER_ID);
        assert_eq!(pending_after_second, U256::from(2));
    }

    #[test]
    fn test_place_flip_ask_with_valid_flip_tick() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        // For ask orders, flip_tick must be < tick
        let place_flip_call = IStablecoinDex::placeFlipCall {
            token,
            amount: 2000,
            isBid: false, // ask
            tick: 10,
            flipTick: 5, // flipTick < tick (valid)
        };
        let result = dex.call(&Bytes::from(place_flip_call.abi_encode()), &sender);

        // Should succeed
        assert!(result.is_ok());
        let order_id = u128::abi_decode(&result.unwrap().bytes).unwrap();
        assert_eq!(order_id, 1);
    }

    #[test]
    fn test_place_flip_bid_with_invalid_flip_tick_panics() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        // For bid orders, flip_tick must be > tick
        // This violates the constraint: flipTick (3) <= tick (10)
        let place_flip_call = IStablecoinDex::placeFlipCall {
            token,
            amount: 2000,
            isBid: true, // bid
            tick: 10,
            flipTick: 3, // flipTick < tick (invalid, should be > tick)
        };

        // This should panic because Order::new_flip will return Err
        // and we call .expect() which panics
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dex.call(&Bytes::from(place_flip_call.abi_encode()), &sender)
        }));

        assert!(
            result.is_err(),
            "Expected panic for invalid flip tick constraint"
        );
    }

    #[test]
    fn test_place_flip_ask_with_invalid_flip_tick_panics() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);

        // For ask orders, flip_tick must be < tick
        // This violates the constraint: flipTick (15) >= tick (10)
        let place_flip_call = IStablecoinDex::placeFlipCall {
            token,
            amount: 2000,
            isBid: false, // ask
            tick: 10,
            flipTick: 15, // flipTick > tick (invalid, should be < tick)
        };

        // This should panic
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dex.call(&Bytes::from(place_flip_call.abi_encode()), &sender)
        }));

        assert!(
            result.is_err(),
            "Expected panic for invalid flip tick constraint"
        );
    }

    #[test]
    fn test_negative_ticks_are_stored_correctly() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([1u8; 20]);
        let token = Address::from([2u8; 20]);
        let negative_tick = -15i16;

        // Place order with negative tick
        let place_call = IStablecoinDex::placeCall {
            token,
            amount: 1000,
            isBid: false,
            tick: negative_tick,
        };
        let result = dex
            .call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();
        let order_id = u128::abi_decode(&result.bytes).unwrap();

        // Verify negative tick is stored correctly
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);
        let stored_tick = dex.sload(order_slot + offsets::ORDER_TICK_OFFSET);

        // Cast i16 through i128 to preserve sign, then to u128 for storage
        let expected = U256::from(negative_tick as i128 as u128);
        assert_eq!(stored_tick, expected);
    }

    #[test]
    fn test_invalid_selector() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        let sender = Address::from([1u8; 20]);

        // Test with invalid selector
        let result = dex.call(&Bytes::from([0x12, 0x34, 0x56, 0x78]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));

        // Test with insufficient calldata
        let result = dex.call(&Bytes::from([0x12, 0x34]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }

    #[test]
    fn test_sender_address_stored_correctly() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut dex = StablecoinDex::new(&mut storage);
        dex.initialize();

        let sender = Address::from([0xAB; 20]);
        let token = Address::from([2u8; 20]);

        // Place an order
        let place_call = IStablecoinDex::placeCall {
            token,
            amount: 1000,
            isBid: true,
            tick: 5,
        };
        let result = dex
            .call(&Bytes::from(place_call.abi_encode()), &sender)
            .unwrap();
        let order_id = u128::abi_decode(&result.bytes).unwrap();

        // Verify sender address is stored correctly
        let order_slot = mapping_slot(order_id.to_be_bytes(), slots::ORDERS);
        let stored_maker = dex.sload(order_slot + offsets::ORDER_MAKER_OFFSET);
        assert_eq!(stored_maker, sender.into_u256());
    }
}
