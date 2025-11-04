// Module for tip20_rewards_registry precompile
pub mod dispatch;

use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS,
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, slots::mapping_slot},
    tip20::{TIP20Token, address_to_token_id_unchecked},
};
use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolValue,
};
use revm::{
    interpreter::instructions::utility::{IntoAddress, IntoU256},
    state::Bytecode,
};
use tracing::warn;

pub use tempo_contracts::precompiles::{ITIP20RewardsRegistry, TIP20RewardsRegistryError};

pub mod slots {
    use alloy::primitives::{U256, uint};

    pub const LAST_UPDATED_TIMESTAMP: U256 = uint!(0_U256);
    // Mapping of (uint128 => []address) to indicate all tip20 tokens with reward streams
    // ending at the specified timestamp
    pub const STREAMS_ENDING_AT: U256 = uint!(1_U256);
    // Mapping of (bytes32 => U256) mapping `streamKey` to `index` in `streamsEndingAt` array
    pub const STREAM_INDEX: U256 = uint!(2_U256);
}

/// TIPRewardsRegistry precompile that tracks stream end times
/// Maps timestamp -> Vec of token addresses with streams ending at that time
pub struct TIP20RewardsRegistry<'a, S: PrecompileStorageProvider> {
    storage: &'a mut S,
    address: Address,
}

impl<'a, S: PrecompileStorageProvider> TIP20RewardsRegistry<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            storage,
            address: TIP20_REWARDS_REGISTRY_ADDRESS,
        }
    }

    /// Initializes the TIP20 rewards registry contract.
    ///
    /// Ensures the [`TIP20RewardsRegistry`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<(), TempoPrecompileError> {
        self.storage.set_code(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Get the last updated timestamp
    fn get_last_updated_timestamp(&mut self) -> Result<u128, TempoPrecompileError> {
        let val = self
            .storage
            .sload(self.address, slots::LAST_UPDATED_TIMESTAMP)?;
        Ok(val.to::<u128>())
    }

    /// Set the last updated timestamp
    fn set_last_updated_timestamp(&mut self, timestamp: u128) -> Result<(), TempoPrecompileError> {
        self.storage.sstore(
            self.address,
            slots::LAST_UPDATED_TIMESTAMP,
            U256::from(timestamp),
        )
    }

    fn get_stream_index(&mut self, stream_key: B256) -> Result<U256, TempoPrecompileError> {
        let index_slot = mapping_slot(stream_key, slots::STREAM_INDEX);
        self.storage.sload(self.address, index_slot)
    }

    fn remove_stream_index(&mut self, stream_key: B256) -> Result<(), TempoPrecompileError> {
        let index_slot = mapping_slot(stream_key, slots::STREAM_INDEX);
        self.storage.sstore(self.address, index_slot, U256::ZERO)
    }

    /// Add a token to the registry for a given stream end time
    pub fn add_stream(
        &mut self,
        token: Address,
        end_time: u128,
    ) -> Result<(), TempoPrecompileError> {
        let stream_key = keccak256((token, end_time).abi_encode());

        let array_slot = mapping_slot(end_time.to_be_bytes(), slots::STREAMS_ENDING_AT);
        let index = self.storage.sload(self.address, array_slot)?;
        let index_slot = mapping_slot(stream_key, slots::STREAM_INDEX);
        self.storage.sstore(self.address, index_slot, index)?;

        self.push_stream_ending_at_timestamp(token, end_time)?;

        Ok(())
    }

    /// Remove stream before it is finalized
    pub fn remove_stream(
        &mut self,
        token: Address,
        end_time: u128,
    ) -> Result<(), TempoPrecompileError> {
        let stream_key = keccak256((token, end_time).abi_encode());
        let index = self.get_stream_index(stream_key)?;

        let array_slot = mapping_slot(end_time.to_be_bytes(), slots::STREAMS_ENDING_AT);
        let length = self.storage.sload(self.address, array_slot)?;
        let last_index = length - U256::ONE;

        if index != last_index {
            // Elements are stored at array_slot + 1 + index
            let last_element_slot = array_slot + U256::ONE + last_index;
            let last_token = self
                .storage
                .sload(self.address, last_element_slot)?
                .into_address();

            let current_element_slot = array_slot + U256::ONE + index;
            self.storage
                .sstore(self.address, current_element_slot, last_token.into_u256())?;

            let last_stream_key = keccak256((last_token, end_time).abi_encode());
            let last_index_slot = mapping_slot(last_stream_key, slots::STREAM_INDEX);
            self.storage.sstore(self.address, last_index_slot, index)?;
        }

        // Update length of the array and remove the stream key from `streamIndex`
        self.storage.sstore(self.address, array_slot, last_index)?;
        self.remove_stream_index(stream_key)?;

        Ok(())
    }

    /// Appends a TIP20 token address to the array corresponding with `timestamp` in storage.
    pub fn push_stream_ending_at_timestamp(
        &mut self,
        address: Address,
        timestamp: u128,
    ) -> Result<(), TempoPrecompileError> {
        let array_slot = mapping_slot(timestamp.to_be_bytes(), slots::STREAMS_ENDING_AT);
        let length = self.storage.sload(self.address, array_slot)?;

        // Push the token address to the array and increment the array length
        // Elements are stored at array_slot + 1 + index (array_slot stores the length)
        let element_slot = array_slot + U256::ONE + length;
        self.storage
            .sstore(self.address, element_slot, address.into_u256())?;
        self.storage
            .sstore(self.address, array_slot, length + U256::ONE)
    }

    /// Gets all TIP20 token addresses with streams ending at `timestamp` from storage
    pub fn get_streams_ending_at_timestamp(
        &mut self,
        timestamp: u128,
    ) -> Result<Vec<Address>, TempoPrecompileError> {
        let array_slot = mapping_slot(timestamp.to_be_bytes(), slots::STREAMS_ENDING_AT);
        let length = self.storage.sload(self.address, array_slot)?;

        let mut tokens = Vec::new();
        for i in 0..length.to::<u64>() {
            // Elements are stored at array_slot + 1 + index
            let element_slot = array_slot + U256::ONE + U256::from(i);
            let token_addr = self
                .storage
                .sload(self.address, element_slot)?
                .into_address();
            tokens.push(token_addr);
        }

        Ok(tokens)
    }

    /// Finalize streams for all tokens ending at the current timestamp
    pub fn finalize_streams(&mut self, sender: Address) -> Result<(), TempoPrecompileError> {
        if sender != Address::ZERO {
            return Err(TIP20RewardsRegistryError::unauthorized().into());
        }

        let current_timestamp = self.storage.timestamp().to::<u128>();
        let mut last_updated = self.get_last_updated_timestamp()?;

        if last_updated == 0 {
            last_updated = current_timestamp - 1;
        }

        if current_timestamp == last_updated {
            return Ok(());
        }

        let mut next_timestamp = last_updated + 1;

        while current_timestamp >= next_timestamp {
            let tokens = self.get_streams_ending_at_timestamp(next_timestamp)?;
            let mut failed_tokens = Vec::new();

            for token in tokens {
                let token_id = address_to_token_id_unchecked(token);
                let mut tip20_token = TIP20Token::new(token_id, self.storage);

                // Try to finalize streams for this token
                match tip20_token.finalize_streams(self.address, next_timestamp) {
                    Ok(()) => {
                        // Successfully finalized - remove the stream index mapping
                        let stream_key = keccak256((token, next_timestamp).abi_encode());
                        self.remove_stream_index(stream_key)?;
                    }
                    Err(e) => {
                        // Failed to finalize - keep in array for retry
                        warn!(
                            target: "tempo::precompiles::tip20_rewards_registry",
                            token = ?token,
                            timestamp = next_timestamp,
                            error = ?e,
                            "Failed to finalize streams for token, will retry on next block"
                        );
                        failed_tokens.push(token);
                    }
                }
            }

            // Rebuild the array with only failed tokens
            let array_slot = mapping_slot(next_timestamp.to_be_bytes(), slots::STREAMS_ENDING_AT);

            for (i, token) in failed_tokens.iter().enumerate() {
                let element_slot = array_slot + U256::from(i);
                self.storage
                    .sstore(self.address, element_slot, token.into_u256())?;

                // Update the stream index mapping
                let stream_key = keccak256((token, next_timestamp).abi_encode());
                let index_slot = mapping_slot(stream_key, slots::STREAM_INDEX);
                self.storage
                    .sstore(self.address, index_slot, U256::from(i))?;
            }

            // Update the array length
            self.storage
                .sstore(self.address, array_slot, U256::from(failed_tokens.len()))?;

            next_timestamp += 1;
        }

        self.set_last_updated_timestamp(current_timestamp)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LINKING_USD_ADDRESS,
        storage::hashmap::HashMapStorageProvider,
        tip20::{rewards::slots as reward_slots, token_id_to_address},
        tip20_factory::TIP20Factory,
    };
    use alloy::primitives::{Address, U256};
    use tempo_contracts::precompiles::ITIP20Factory;

    /// Test that when finalize_streams fails for one token but succeeds for others,
    /// only the successfully finalized tokens are removed from the registry array.
    /// The failed token should remain in the array for retry on the next block.
    #[test]
    fn test_finalize_streams_partial_failure() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        // Create TIP20 factory and initialize it
        let mut factory = TIP20Factory::new(&mut storage);
        factory.initialize()?;

        // Create three tokens
        let token1_id_u256 = factory.create_token(
            admin,
            ITIP20Factory::createTokenCall {
                name: "Token1".to_string(),
                symbol: "TK1".to_string(),
                currency: "USD".to_string(),
                quoteToken: LINKING_USD_ADDRESS,
                admin,
            },
        )?;
        let token1_id = token1_id_u256.to::<u64>();
        let token1_address = token_id_to_address(token1_id);

        let token2_id_u256 = factory.create_token(
            admin,
            ITIP20Factory::createTokenCall {
                name: "Token2".to_string(),
                symbol: "TK2".to_string(),
                currency: "USD".to_string(),
                quoteToken: LINKING_USD_ADDRESS,
                admin,
            },
        )?;
        let token2_id = token2_id_u256.to::<u64>();
        let token2_address = token_id_to_address(token2_id);

        let token3_id_u256 = factory.create_token(
            admin,
            ITIP20Factory::createTokenCall {
                name: "Token3".to_string(),
                symbol: "TK3".to_string(),
                currency: "USD".to_string(),
                quoteToken: LINKING_USD_ADDRESS,
                admin,
            },
        )?;
        let token3_id = token3_id_u256.to::<u64>();
        let token3_address = token_id_to_address(token3_id);

        // Initialize registry
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let end_time = 100u128;

        // Add all three tokens to the registry for the same end time
        registry.add_stream(token1_address, end_time)?;
        registry.add_stream(token2_address, end_time)?;
        registry.add_stream(token3_address, end_time)?;

        // Verify all three are in the array
        let tokens_before = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(tokens_before.len(), 3);

        // Set up token1 and token3 with valid state (scheduled rate decrease)
        let rate = U256::from(100);
        let slot1 = mapping_slot(
            end_time.to_be_bytes(),
            reward_slots::SCHEDULED_RATE_DECREASE,
        );
        registry.storage.sstore(token1_address, slot1, rate)?;
        registry
            .storage
            .sstore(token1_address, reward_slots::TOTAL_REWARD_PER_SECOND, rate)?;

        let slot3 = mapping_slot(
            end_time.to_be_bytes(),
            reward_slots::SCHEDULED_RATE_DECREASE,
        );
        registry.storage.sstore(token3_address, slot3, rate)?;
        registry
            .storage
            .sstore(token3_address, reward_slots::TOTAL_REWARD_PER_SECOND, rate)?;

        // Corrupt token2's state: set scheduled_rate_decrease > total_reward_per_second
        // This will cause an underflow error when trying to finalize
        let slot2 = mapping_slot(
            end_time.to_be_bytes(),
            reward_slots::SCHEDULED_RATE_DECREASE,
        );
        registry
            .storage
            .sstore(token2_address, slot2, U256::from(1000))?; // Large decrease
        registry.storage.sstore(
            token2_address,
            reward_slots::TOTAL_REWARD_PER_SECOND,
            U256::from(10),
        )?; // Small total

        // Set timestamp and call finalize_streams
        registry.storage.set_timestamp(U256::from(end_time));
        registry.finalize_streams(Address::ZERO)?;

        // Check the results:
        // - Token2 should still be in the array (failed to finalize)
        // - Token1 and Token3 should be removed (successfully finalized)
        let tokens_after = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(tokens_after.len(), 1, "Only the failed token should remain");
        assert_eq!(
            tokens_after[0], token2_address,
            "Token2 should remain in array"
        );

        // Verify token1 and token3 were finalized (scheduled_rate_decrease cleared)
        let token1_rate = registry.storage.sload(token1_address, slot1)?;
        assert_eq!(
            token1_rate,
            U256::ZERO,
            "Token1 should have cleared scheduled decrease"
        );

        let token3_rate = registry.storage.sload(token3_address, slot3)?;
        assert_eq!(
            token3_rate,
            U256::ZERO,
            "Token3 should have cleared scheduled decrease"
        );

        // Verify token2 was NOT finalized (scheduled_rate_decrease still set)
        let token2_rate = registry.storage.sload(token2_address, slot2)?;
        assert_eq!(
            token2_rate,
            U256::from(1000),
            "Token2 should still have scheduled decrease"
        );

        Ok(())
    }
}
