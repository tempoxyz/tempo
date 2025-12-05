// Module for tip20_rewards_registry precompile
pub mod dispatch;

use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip20::{TIP20Token, address_to_token_id_unchecked},
};
use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol_types::SolValue,
};

pub use tempo_contracts::precompiles::{ITIP20RewardsRegistry, TIP20RewardsRegistryError};
use tempo_precompiles_macros::contract;

/// TIPRewardsRegistry precompile that tracks stream end times
/// Maps timestamp -> Vec of token addresses with streams ending at that time
#[contract]
pub struct TIP20RewardsRegistry {
    last_updated_timestamp: u128,
    ending_streams: Mapping<u128, Vec<Address>>,
    stream_index: Mapping<B256, U256>,
}

impl TIP20RewardsRegistry {
    /// Creates an instance of the precompile.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new() -> Self {
        Self::__new(TIP20_REWARDS_REGISTRY_ADDRESS)
    }

    /// Initializes the TIP20 rewards registry contract.
    ///
    /// Ensures the [`TIP20RewardsRegistry`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Add a token to the registry for a given stream end time
    pub fn add_stream(&mut self, token: Address, end_time: u128) -> Result<()> {
        let stream_key = keccak256((token, end_time).abi_encode());
        let stream_ending_at = self.ending_streams.at(end_time);
        let length = stream_ending_at.len()?;

        self.stream_index.at(stream_key).write(U256::from(length))?;
        stream_ending_at.push(token)
    }

    /// Remove stream before it is finalized
    pub fn remove_stream(&mut self, token: Address, end_time: u128) -> Result<()> {
        let stream_key = keccak256((token, end_time).abi_encode());
        let index: usize = self.stream_index.at(stream_key).read()?.to();

        let stream_ending_at = self.ending_streams.at(end_time);
        let length = stream_ending_at.len()?;
        let last_index = length
            .checked_sub(1)
            .ok_or(TempoPrecompileError::under_overflow())?;

        // If removing element that's not the last, swap with last element
        if index != last_index {
            let last_token = stream_ending_at.at(last_index).read()?;
            stream_ending_at.at(index).write(last_token)?;

            // Update stream_index for the moved element
            let last_stream_key = keccak256((last_token, end_time).abi_encode());
            self.stream_index
                .at(last_stream_key)
                .write(U256::from(index))?;
        }

        // Remove last element and clear its index
        stream_ending_at.pop()?;
        self.stream_index.at(stream_key).delete()?;

        Ok(())
    }

    /// Finalize streams for all tokens ending at the current timestamp
    pub fn finalize_streams(&mut self, sender: Address) -> Result<()> {
        if sender != Address::ZERO {
            return Err(TIP20RewardsRegistryError::unauthorized().into());
        }

        let current_timestamp = self.storage.timestamp().to::<u128>();
        let mut last_updated = self.last_updated_timestamp.read()?;

        if last_updated == 0 {
            last_updated = current_timestamp.saturating_sub(1);
        }

        if current_timestamp == last_updated {
            return Ok(());
        }

        let mut next_timestamp = last_updated
            .checked_add(1)
            .ok_or(TempoPrecompileError::under_overflow())?;

        while current_timestamp >= next_timestamp {
            let tokens = self.ending_streams.at(next_timestamp).read()?;

            for token in tokens {
                let token_id = address_to_token_id_unchecked(token);
                let mut tip20_token = TIP20Token::new(token_id);
                tip20_token.finalize_streams(self.address, next_timestamp)?;

                let stream_key = keccak256((token, next_timestamp).abi_encode());
                self.stream_index.at(stream_key).delete()?;
            }

            // Clear all elements from the vec
            self.ending_streams.at(next_timestamp).delete()?;

            next_timestamp = next_timestamp
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?;
        }

        self.last_updated_timestamp.write(current_timestamp)?;

        Ok(())
    }

    /// Helper method to get the count of streams at a given end time (for testing)
    #[cfg(test)]
    pub(crate) fn get_stream_count_at(&self, end_time: u128) -> Result<usize> {
        self.ending_streams.at(end_time).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageContext, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20_rewards_registry::TIP20RewardsRegistry,
    };
    use alloy::primitives::Address;
    use tempo_contracts::precompiles::ITIP20;

    #[test]
    fn test_add_stream() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let token = Address::random();
        let token2 = Address::random();
        StorageContext::enter(&mut storage, || {
            StorageContext.set_timestamp(U256::from(1000));

            let mut registry = TIP20RewardsRegistry::new();
            registry.initialize()?;

            let end_time = 2000u128;

            registry.add_stream(token, end_time)?;

            let streams = registry.ending_streams.at(end_time).read()?;
            assert_eq!(streams.len(), 1);
            assert_eq!(streams[0], token);

            let stream_key = keccak256((token, end_time).abi_encode());
            let index = registry.stream_index.at(stream_key).read()?;
            assert_eq!(index, U256::ZERO);

            registry.add_stream(token2, end_time)?;

            let streams = registry.ending_streams.at(end_time).read()?;
            assert_eq!(streams.len(), 2);
            assert!(streams.contains(&token));
            assert!(streams.contains(&token2));

            let stream_key2 = keccak256((token2, end_time).abi_encode());
            let index2 = registry.stream_index.at(stream_key2).read()?;
            assert_eq!(index2, U256::ONE);

            Ok(())
        })
    }

    #[test]
    fn test_remove_stream() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let token1 = Address::random();
        let token2 = Address::random();
        let token3 = Address::random();
        let non_existent_token = Address::random();
        StorageContext::enter(&mut storage, || {
            StorageContext.set_timestamp(U256::from(1000));

            let mut registry = TIP20RewardsRegistry::new();
            registry.initialize()?;

            let end_time = 2000u128;

            // Add three streams
            registry.add_stream(token1, end_time)?;
            registry.add_stream(token2, end_time)?;
            registry.add_stream(token3, end_time)?;

            let streams = registry.ending_streams.at(end_time).read()?;
            assert_eq!(streams.len(), 3);
            assert_eq!(streams[0], token1);
            assert_eq!(streams[1], token2);
            assert_eq!(streams[2], token3);

            registry.remove_stream(token2, end_time)?;

            let streams = registry.ending_streams.at(end_time).read()?;
            assert_eq!(streams.len(), 2);
            assert_eq!(streams[0], token1);
            assert_eq!(streams[1], token3);

            // Verify indices are updated correctly
            let stream_key1 = keccak256((token1, end_time).abi_encode());
            let stream_key2 = keccak256((token2, end_time).abi_encode());
            let stream_key3 = keccak256((token3, end_time).abi_encode());

            let index1 = registry.stream_index.at(stream_key1).read()?;
            let index2 = registry.stream_index.at(stream_key2).read()?;
            let index3 = registry.stream_index.at(stream_key3).read()?;

            assert_eq!(index1, U256::ZERO);
            assert_eq!(index2, U256::ZERO);
            assert_eq!(index3, U256::ONE);

            registry.remove_stream(token3, end_time)?;
            let streams = registry.ending_streams.at(end_time).read()?;
            assert_eq!(streams.len(), 1);
            assert_eq!(streams[0], token1);

            registry.remove_stream(token1, end_time)?;

            let streams = registry.ending_streams.at(end_time).read()?;
            assert_eq!(streams.len(), 0);

            // Test removing non-existent stream
            let result = registry.remove_stream(non_existent_token, end_time);
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_streams_ending_at() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let token1 = Address::random();
        let token2 = Address::random();
        let token3 = Address::random();
        let token4 = Address::random();
        StorageContext::enter(&mut storage, || {
            StorageContext.set_timestamp(U256::from(1000));

            let mut registry = TIP20RewardsRegistry::new();
            registry.initialize()?;

            let timestamp = 2000u128;

            let empty_streams = registry.ending_streams.at(timestamp).read()?;
            assert_eq!(empty_streams.len(), 0);

            registry.add_stream(token1, timestamp)?;
            registry.add_stream(token2, timestamp)?;
            registry.add_stream(token3, timestamp)?;

            let streams = registry.ending_streams.at(timestamp).read()?;
            assert_eq!(streams.len(), 3);
            assert_eq!(streams[0], token1);
            assert_eq!(streams[1], token2);
            assert_eq!(streams[2], token3);

            let other_timestamp = 3000u128;
            let other_streams = registry.ending_streams.at(other_timestamp).read()?;
            assert_eq!(other_streams.len(), 0);

            registry.add_stream(token4, other_timestamp)?;

            let streams1 = registry.ending_streams.at(timestamp).read()?;
            let streams2 = registry.ending_streams.at(other_timestamp).read()?;

            assert_eq!(streams1.len(), 3);
            assert_eq!(streams2.len(), 1);
            assert_eq!(streams2[0], token4);

            Ok(())
        })
    }

    #[test]
    fn test_finalize_streams() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let unauthorized = Address::random();
        StorageContext::enter(&mut storage, || {
            StorageContext.set_timestamp(U256::from(1500));

            let mut registry = TIP20RewardsRegistry::new();
            registry.initialize()?;

            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(admin, U256::from(100e18 as u128))
                .apply()?;
            let token_addr = token.address();

            // Start a reward stream that lasts 5 seconds from current time (1500)
            let current_time = token.storage().timestamp().to::<u128>();
            let stream_duration = 5;
            let stream_id = token.start_reward(
                admin,
                ITIP20::startRewardCall {
                    amount: U256::from(100e18 as u128),
                    secs: stream_duration,
                },
            )?;
            assert_eq!(stream_id, 1);

            // Test unauthorized caller
            let result = registry.finalize_streams(unauthorized);
            assert!(matches!(
                result.unwrap_err(),
                TempoPrecompileError::TIP20RewardsRegistry(
                    TIP20RewardsRegistryError::Unauthorized(_)
                )
            ));

            let result = registry.finalize_streams(Address::ZERO);
            assert!(result.is_ok());

            // Verify the stream was added to registry at the correct end time
            let end_time = current_time + stream_duration as u128;
            let streams_before = registry.ending_streams.at(end_time).read()?;
            assert_eq!(streams_before.len(), 1);
            assert_eq!(streams_before[0], token_addr);

            // Fast forward to the end time to simulate stream completion
            registry.storage.set_timestamp(U256::from(end_time));
            registry.finalize_streams(Address::ZERO)?;

            let last_updated = registry.last_updated_timestamp.read()?;
            assert_eq!(last_updated, end_time);

            // Verify streams were cleared from the registry
            let streams_after = registry.ending_streams.at(end_time).read()?;
            assert_eq!(streams_after.len(), 0);

            let result = registry.finalize_streams(Address::ZERO);
            assert!(result.is_ok());

            Ok(())
        })
    }
}
