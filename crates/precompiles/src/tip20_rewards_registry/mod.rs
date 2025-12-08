// Module for tip20_rewards_registry precompile
pub mod dispatch;

use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{Mapping, PrecompileStorageProvider, VecSlotExt},
    tip20::{TIP20Token, address_to_token_id_unchecked},
};
use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolValue,
};
use revm::state::Bytecode;

pub use tempo_contracts::precompiles::{ITIP20RewardsRegistry, TIP20RewardsRegistryError};
use tempo_precompiles_macros::contract;

/// TIPRewardsRegistry precompile that tracks stream end times
/// Maps timestamp -> Vec of token addresses with streams ending at that time
#[contract]
pub struct TIP20RewardsRegistry {
    last_updated_timestamp: u128,
    streams_ending_at: Mapping<u128, Vec<Address>>,
    stream_index: Mapping<B256, U256>,
}

/// Helper type to easily interact with the `stream_ending_at` array
type StreamEndingAt = Mapping<u128, Vec<Address>>;

impl<'a, S: PrecompileStorageProvider> TIP20RewardsRegistry<'a, S> {
    /// Creates an instance of the precompile.
    ///
    /// Caution: This does not initialize the account, see [`Self::initialize`].
    pub fn new(storage: &'a mut S) -> Self {
        Self::_new(TIP20_REWARDS_REGISTRY_ADDRESS, storage)
    }

    /// Initializes the TIP20 rewards registry contract.
    ///
    /// Ensures the [`TIP20RewardsRegistry`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        self.storage.set_code(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Add a token to the registry for a given stream end time
    pub fn add_stream(&mut self, token: Address, end_time: u128) -> Result<()> {
        let stream_key = keccak256((token, end_time).abi_encode());
        let stream_ending_at = StreamEndingAt::new(slots::STREAMS_ENDING_AT).at(end_time);
        let length = stream_ending_at.len(self)?;

        self.sstore_stream_index(stream_key, U256::from(length))?;
        stream_ending_at.push(self, token)
    }

    /// Remove stream before it is finalized
    pub fn remove_stream(&mut self, token: Address, end_time: u128) -> Result<()> {
        let stream_key = keccak256((token, end_time).abi_encode());
        let index = self.sload_stream_index(stream_key)?.to::<usize>();

        let stream_ending_at = StreamEndingAt::new(slots::STREAMS_ENDING_AT).at(end_time);
        let length = stream_ending_at.len(self)?;
        let last_index = length
            .checked_sub(1)
            .ok_or(TempoPrecompileError::under_overflow())?;

        // If removing element that's not the last, swap with last element
        if index != last_index {
            let last_token = stream_ending_at.read_at(self, last_index)?;
            stream_ending_at.write_at(self, index, last_token)?;

            // Update stream_index for the moved element
            let last_stream_key = keccak256((last_token, end_time).abi_encode());
            self.sstore_stream_index(last_stream_key, U256::from(index))?;
        }

        // Remove last element and clear its index
        stream_ending_at.pop(self)?;
        self.clear_stream_index(stream_key)?;

        Ok(())
    }

    /// Finalize streams for all tokens ending at the current timestamp
    pub fn finalize_streams(&mut self, sender: Address) -> Result<()> {
        if sender != Address::ZERO {
            return Err(TIP20RewardsRegistryError::unauthorized().into());
        }

        let current_timestamp = self.storage.timestamp().to::<u128>();
        let mut last_updated = self.sload_last_updated_timestamp()?;

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
            let tokens = self.sload_streams_ending_at(next_timestamp)?;

            for token in tokens {
                let token_id = address_to_token_id_unchecked(token);
                let mut tip20_token = TIP20Token::new(token_id, self.storage);
                tip20_token.finalize_streams(self.address, next_timestamp)?;

                let stream_key = keccak256((token, next_timestamp).abi_encode());
                self.clear_stream_index(stream_key)?;
            }

            // Clear all elements from the vec
            self.clear_streams_ending_at(next_timestamp)?;

            next_timestamp = next_timestamp
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?;
        }

        self.sstore_last_updated_timestamp(current_timestamp)?;

        Ok(())
    }

    /// Helper method to get the count of streams at a given end time (for testing)
    #[cfg(test)]
    pub(crate) fn get_stream_count_at(&mut self, end_time: u128) -> Result<usize> {
        StreamEndingAt::new(slots::STREAMS_ENDING_AT)
            .at(end_time)
            .len(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, hashmap::HashMapStorageProvider},
        tip20::{ISSUER_ROLE, TIP20Token, tests::initialize_path_usd},
        tip20_rewards_registry::TIP20RewardsRegistry,
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::ITIP20;

    fn setup_registry(timestamp: u64) -> (HashMapStorageProvider, Address) {
        let mut storage = HashMapStorageProvider::new(timestamp);
        let admin = Address::random();
        initialize_path_usd(&mut storage, admin).unwrap();
        (storage, admin)
    }

    #[test]
    fn test_add_stream() -> eyre::Result<()> {
        let (mut storage, _admin) = setup_registry(1000);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let token_addr = Address::random();
        let end_time = 2000u128;

        registry.add_stream(token_addr, end_time)?;

        let streams = registry.sload_streams_ending_at(end_time)?;
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0], token_addr);

        let stream_key = keccak256((token_addr, end_time).abi_encode());
        let index = registry.sload_stream_index(stream_key)?;
        assert_eq!(index, U256::ZERO);

        let token_addr2 = Address::random();
        registry.add_stream(token_addr2, end_time)?;

        let streams = registry.sload_streams_ending_at(end_time)?;
        assert_eq!(streams.len(), 2);
        assert!(streams.contains(&token_addr));
        assert!(streams.contains(&token_addr2));

        let stream_key2 = keccak256((token_addr2, end_time).abi_encode());
        let index2 = registry.sload_stream_index(stream_key2)?;
        assert_eq!(index2, U256::ONE);

        Ok(())
    }

    #[test]
    fn test_remove_stream() -> eyre::Result<()> {
        let (mut storage, _admin) = setup_registry(1000);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let token1 = Address::random();
        let token2 = Address::random();
        let token3 = Address::random();
        let end_time = 2000u128;

        // Add three streams
        registry.add_stream(token1, end_time)?;
        registry.add_stream(token2, end_time)?;
        registry.add_stream(token3, end_time)?;

        let streams = registry.sload_streams_ending_at(end_time)?;
        assert_eq!(streams.len(), 3);
        assert_eq!(streams[0], token1);
        assert_eq!(streams[1], token2);
        assert_eq!(streams[2], token3);

        registry.remove_stream(token2, end_time)?;

        let streams = registry.sload_streams_ending_at(end_time)?;
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0], token1);
        assert_eq!(streams[1], token3);

        // Verify indices are updated correctly
        let stream_key1 = keccak256((token1, end_time).abi_encode());
        let stream_key2 = keccak256((token2, end_time).abi_encode());
        let stream_key3 = keccak256((token3, end_time).abi_encode());

        let index1 = registry.sload_stream_index(stream_key1)?;
        let index2 = registry.sload_stream_index(stream_key2)?;
        let index3 = registry.sload_stream_index(stream_key3)?;

        assert_eq!(index1, U256::ZERO);
        assert_eq!(index2, U256::ZERO);
        assert_eq!(index3, U256::ONE);

        registry.remove_stream(token3, end_time)?;
        let streams = registry.sload_streams_ending_at(end_time)?;
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0], token1);

        registry.remove_stream(token1, end_time)?;

        let streams = registry.sload_streams_ending_at(end_time)?;
        assert_eq!(streams.len(), 0);

        // Test removing non-existent stream
        let non_existent_token = Address::random();
        let result = registry.remove_stream(non_existent_token, end_time);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_sload_streams_ending_at() -> eyre::Result<()> {
        let (mut storage, _admin) = setup_registry(1000);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let timestamp = 2000u128;

        let empty_streams = registry.sload_streams_ending_at(timestamp)?;
        assert_eq!(empty_streams.len(), 0);

        let token1 = Address::random();
        let token2 = Address::random();
        let token3 = Address::random();

        registry.add_stream(token1, timestamp)?;
        registry.add_stream(token2, timestamp)?;
        registry.add_stream(token3, timestamp)?;

        let streams = registry.sload_streams_ending_at(timestamp)?;
        assert_eq!(streams.len(), 3);
        assert_eq!(streams[0], token1);
        assert_eq!(streams[1], token2);
        assert_eq!(streams[2], token3);

        let other_timestamp = 3000u128;
        let other_streams = registry.sload_streams_ending_at(other_timestamp)?;
        assert_eq!(other_streams.len(), 0);

        let token4 = Address::random();
        registry.add_stream(token4, other_timestamp)?;

        let streams1 = registry.sload_streams_ending_at(timestamp)?;
        let streams2 = registry.sload_streams_ending_at(other_timestamp)?;

        assert_eq!(streams1.len(), 3);
        assert_eq!(streams2.len(), 1);
        assert_eq!(streams2[0], token4);

        Ok(())
    }

    #[test]
    fn test_finalize_streams() -> eyre::Result<()> {
        let (mut storage, admin) = setup_registry(1500);
        // The rewards registry was disabled post moderato so init storage with adagio
        storage.set_spec(TempoHardfork::Adagio);

        // Create a TIP20 token and start a reward stream
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)?;
        let token_addr = token.address();

        token.grant_role_internal(admin, *ISSUER_ROLE)?;

        // Mint tokens for the reward
        let reward_amount = U256::from(100e18);
        token.mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: reward_amount,
            },
        )?;

        // Start a reward stream that lasts 5 seconds from current time (1500)
        let current_time = token.storage().timestamp().to::<u128>();
        let stream_id = token.start_reward(
            admin,
            ITIP20::startRewardCall {
                amount: reward_amount,
                secs: 5,
            },
        )?;
        assert_eq!(stream_id, 1);

        let end_time = current_time + 5;
        let mut registry = TIP20RewardsRegistry::new(token.storage());
        registry.initialize()?;

        // Test unauthorized caller
        let unauthorized = Address::random();
        let result = registry.finalize_streams(unauthorized);
        assert!(matches!(
            result.unwrap_err(),
            TempoPrecompileError::TIP20RewardsRegistry(TIP20RewardsRegistryError::Unauthorized(_))
        ));

        let result = registry.finalize_streams(Address::ZERO);
        assert!(result.is_ok());

        // Verify the stream was added to registry at the correct end time
        let streams_before = registry.sload_streams_ending_at(end_time)?;
        assert_eq!(streams_before.len(), 1);
        assert_eq!(streams_before[0], token_addr);

        // Fast forward to the end time to simulate stream completion
        registry.storage.set_timestamp(U256::from(end_time));
        registry.finalize_streams(Address::ZERO)?;

        let last_updated = registry.sload_last_updated_timestamp()?;
        assert_eq!(last_updated, end_time);

        // Verify streams were cleared from the registry
        let streams_after = registry.sload_streams_ending_at(end_time)?;
        assert_eq!(streams_after.len(), 0);

        let result = registry.finalize_streams(Address::ZERO);
        assert!(result.is_ok());

        Ok(())
    }
}
