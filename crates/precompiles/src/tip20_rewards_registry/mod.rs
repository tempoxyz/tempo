// Module for tip20_rewards_registry precompile
pub mod dispatch;

use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS,
    error::{Result, TempoPrecompileError},
    storage::{ContractStorage, PrecompileStorageProvider, slots::mapping_slot},
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
    pub fn initialize(&mut self) -> Result<()> {
        self.storage.set_code(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Get the last updated timestamp
    fn get_last_updated_timestamp(&mut self) -> Result<u128> {
        let val = self
            .storage
            .sload(self.address, slots::LAST_UPDATED_TIMESTAMP)?;
        Ok(val.to::<u128>())
    }

    /// Set the last updated timestamp
    fn set_last_updated_timestamp(&mut self, timestamp: u128) -> Result<()> {
        self.storage.sstore(
            self.address,
            slots::LAST_UPDATED_TIMESTAMP,
            U256::from(timestamp),
        )
    }

    fn get_stream_index(&mut self, stream_key: B256) -> Result<U256> {
        let index_slot = mapping_slot(stream_key, slots::STREAM_INDEX);
        self.storage.sload(self.address, index_slot)
    }

    fn set_stream_index(&mut self, stream_key: B256, index: U256) -> Result<()> {
        let index_slot = mapping_slot(stream_key, slots::STREAM_INDEX);
        self.storage.sstore(self.address, index_slot, index)
    }

    fn remove_stream_index(&mut self, stream_key: B256) -> Result<()> {
        let index_slot = mapping_slot(stream_key, slots::STREAM_INDEX);
        self.storage.sstore(self.address, index_slot, U256::ZERO)
    }

    /// Add a token to the registry for a given stream end time
    pub fn add_stream(&mut self, token: Address, end_time: u128) -> Result<()> {
        let stream_key = keccak256((token, end_time).abi_encode());

        let array_slot = mapping_slot(end_time.to_be_bytes(), slots::STREAMS_ENDING_AT);
        let index = self.storage.sload(self.address, array_slot)?;
        self.set_stream_index(stream_key, index)?;

        self.push_stream_ending_at_timestamp(token, end_time)?;

        Ok(())
    }

    /// Remove stream before it is finalized
    pub fn remove_stream(&mut self, token: Address, end_time: u128) -> Result<()> {
        let stream_key = keccak256((token, end_time).abi_encode());
        let index = self.get_stream_index(stream_key)?;

        let array_slot = mapping_slot(end_time.to_be_bytes(), slots::STREAMS_ENDING_AT);
        let length = self.storage.sload(self.address, array_slot)?;
        let last_index = length
            .checked_sub(U256::ONE)
            .ok_or(TempoPrecompileError::under_overflow())?;

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
            self.set_stream_index(last_stream_key, index)?;
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
    ) -> Result<()> {
        let array_slot = mapping_slot(timestamp.to_be_bytes(), slots::STREAMS_ENDING_AT);
        let length = self.storage.sload(self.address, array_slot)?;

        // Push the token address to the array and increment the array length
        // Elements are stored at array_slot + 1 + index (array_slot stores the length)
        let element_slot = array_slot + U256::ONE + length;
        self.storage
            .sstore(self.address, element_slot, address.into_u256())?;
        self.storage.sstore(
            self.address,
            array_slot,
            length
                .checked_add(U256::ONE)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )
    }

    /// Gets all TIP20 token addresses with streams ending at `timestamp` from storage
    pub fn get_streams_ending_at_timestamp(&mut self, timestamp: u128) -> Result<Vec<Address>> {
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
    pub fn finalize_streams(&mut self, sender: Address) -> Result<()> {
        if sender != Address::ZERO {
            return Err(TIP20RewardsRegistryError::unauthorized().into());
        }

        let current_timestamp = self.storage.timestamp().to::<u128>();
        let mut last_updated = self.get_last_updated_timestamp()?;

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
            let tokens = self.get_streams_ending_at_timestamp(next_timestamp)?;

            for token in tokens {
                let token_id = address_to_token_id_unchecked(token);
                let mut tip20_token = TIP20Token::new(token_id, self.storage);
                tip20_token.finalize_streams(self.address, next_timestamp)?;

                let stream_key = keccak256((token, next_timestamp).abi_encode());
                self.remove_stream_index(stream_key)?;
            }

            let array_slot = mapping_slot(next_timestamp.to_be_bytes(), slots::STREAMS_ENDING_AT);
            self.storage.sstore(self.address, array_slot, U256::ZERO)?;

            next_timestamp = next_timestamp
                .checked_add(1)
                .ok_or(TempoPrecompileError::under_overflow())?;
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
        error::TempoPrecompileError,
        storage::hashmap::HashMapStorageProvider,
        tip20::{ISSUER_ROLE, TIP20Token, tests::initialize_linking_usd},
        tip20_rewards_registry::TIP20RewardsRegistry,
    };
    use tempo_contracts::precompiles::ITIP20;

    fn setup_registry(timestamp: u64) -> (HashMapStorageProvider, Address) {
        let mut storage = HashMapStorageProvider::new(timestamp);
        let admin = Address::random();
        initialize_linking_usd(&mut storage, admin).unwrap();
        (storage, admin)
    }

    #[test]
    fn test_get_set_last_updated_timestamp() -> eyre::Result<()> {
        let (mut storage, _admin) = setup_registry(1000);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let initial_timestamp = registry.get_last_updated_timestamp()?;
        assert_eq!(initial_timestamp, 0);

        let new_timestamp = 5000u128;
        registry.set_last_updated_timestamp(new_timestamp)?;

        let updated_timestamp = registry.get_last_updated_timestamp()?;
        assert_eq!(updated_timestamp, new_timestamp);

        registry.set_last_updated_timestamp(u128::MAX)?;
        let max_timestamp = registry.get_last_updated_timestamp()?;
        assert_eq!(max_timestamp, u128::MAX);

        Ok(())
    }

    #[test]
    fn test_get_set_stream_index() -> eyre::Result<()> {
        let (mut storage, _admin) = setup_registry(1000);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let token = Address::random();
        let end_time = 2000u128;
        let stream_key = keccak256((token, end_time).abi_encode());

        let initial_index = registry.get_stream_index(stream_key)?;
        assert_eq!(initial_index, U256::ZERO);

        let test_index = U256::from(42);
        registry.set_stream_index(stream_key, test_index)?;

        let retrieved_index = registry.get_stream_index(stream_key)?;
        assert_eq!(retrieved_index, test_index);

        registry.remove_stream_index(stream_key)?;
        let cleared_index = registry.get_stream_index(stream_key)?;
        assert_eq!(cleared_index, U256::ZERO);

        Ok(())
    }

    #[test]
    fn test_add_stream() -> eyre::Result<()> {
        let (mut storage, _admin) = setup_registry(1000);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let token_addr = Address::random();
        let end_time = 2000u128;

        registry.add_stream(token_addr, end_time)?;

        let streams = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0], token_addr);

        let stream_key = keccak256((token_addr, end_time).abi_encode());
        let index = registry.get_stream_index(stream_key)?;
        assert_eq!(index, U256::ZERO);

        let token_addr2 = Address::random();
        registry.add_stream(token_addr2, end_time)?;

        let streams = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(streams.len(), 2);
        assert!(streams.contains(&token_addr));
        assert!(streams.contains(&token_addr2));

        let stream_key2 = keccak256((token_addr2, end_time).abi_encode());
        let index2 = registry.get_stream_index(stream_key2)?;
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

        let streams = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(streams.len(), 3);
        assert_eq!(streams[0], token1);
        assert_eq!(streams[1], token2);
        assert_eq!(streams[2], token3);

        registry.remove_stream(token2, end_time)?;

        let streams = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0], token1);
        assert_eq!(streams[1], token3);

        // Verify indices are updated correctly
        let stream_key1 = keccak256((token1, end_time).abi_encode());
        let stream_key2 = keccak256((token2, end_time).abi_encode());
        let stream_key3 = keccak256((token3, end_time).abi_encode());

        let index1 = registry.get_stream_index(stream_key1)?;
        let index2 = registry.get_stream_index(stream_key2)?;
        let index3 = registry.get_stream_index(stream_key3)?;

        assert_eq!(index1, U256::ZERO);
        assert_eq!(index2, U256::ZERO);
        assert_eq!(index3, U256::ONE);

        registry.remove_stream(token3, end_time)?;
        let streams = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0], token1);

        registry.remove_stream(token1, end_time)?;

        let streams = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(streams.len(), 0);

        // Test removing non-existent stream
        let non_existent_token = Address::random();
        let result = registry.remove_stream(non_existent_token, end_time);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_push_stream_ending_at_timestamp() -> eyre::Result<()> {
        let (mut storage, _admin) = setup_registry(1000);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let timestamp = 2000u128;
        let token1 = Address::random();
        let token2 = Address::random();

        registry.push_stream_ending_at_timestamp(token1, timestamp)?;

        let streams = registry.get_streams_ending_at_timestamp(timestamp)?;
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0], token1);

        registry.push_stream_ending_at_timestamp(token2, timestamp)?;

        let streams = registry.get_streams_ending_at_timestamp(timestamp)?;
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0], token1);
        assert_eq!(streams[1], token2);

        let timestamp2 = 3000u128;
        let token3 = Address::random();
        registry.push_stream_ending_at_timestamp(token3, timestamp2)?;

        let streams1 = registry.get_streams_ending_at_timestamp(timestamp)?;
        let streams2 = registry.get_streams_ending_at_timestamp(timestamp2)?;
        assert_eq!(streams1.len(), 2);
        assert_eq!(streams2.len(), 1);
        assert_eq!(streams2[0], token3);

        Ok(())
    }

    #[test]
    fn test_get_streams_ending_at_timestamp() -> eyre::Result<()> {
        let (mut storage, _admin) = setup_registry(1000);
        let mut registry = TIP20RewardsRegistry::new(&mut storage);
        registry.initialize()?;

        let timestamp = 2000u128;

        let empty_streams = registry.get_streams_ending_at_timestamp(timestamp)?;
        assert_eq!(empty_streams.len(), 0);

        let token1 = Address::random();
        let token2 = Address::random();
        let token3 = Address::random();

        registry.push_stream_ending_at_timestamp(token1, timestamp)?;
        registry.push_stream_ending_at_timestamp(token2, timestamp)?;
        registry.push_stream_ending_at_timestamp(token3, timestamp)?;

        let streams = registry.get_streams_ending_at_timestamp(timestamp)?;
        assert_eq!(streams.len(), 3);
        assert_eq!(streams[0], token1);
        assert_eq!(streams[1], token2);
        assert_eq!(streams[2], token3);

        let other_timestamp = 3000u128;
        let other_streams = registry.get_streams_ending_at_timestamp(other_timestamp)?;
        assert_eq!(other_streams.len(), 0);

        let token4 = Address::random();
        registry.push_stream_ending_at_timestamp(token4, other_timestamp)?;

        let streams1 = registry.get_streams_ending_at_timestamp(timestamp)?;
        let streams2 = registry.get_streams_ending_at_timestamp(other_timestamp)?;

        assert_eq!(streams1.len(), 3);
        assert_eq!(streams2.len(), 1);
        assert_eq!(streams2[0], token4);

        Ok(())
    }

    #[test]
    fn test_finalize_streams() -> eyre::Result<()> {
        let (mut storage, admin) = setup_registry(1500);

        // Create a TIP20 token and start a reward stream
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, admin)?;
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
        let streams_before = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(streams_before.len(), 1);
        assert_eq!(streams_before[0], token_addr);

        // Fast forward to the end time to simulate stream completion
        registry.storage.set_timestamp(U256::from(end_time));
        registry.finalize_streams(Address::ZERO)?;

        let last_updated = registry.get_last_updated_timestamp()?;
        assert_eq!(last_updated, end_time);

        // Verify streams were cleared from the registry
        let streams_after = registry.get_streams_ending_at_timestamp(end_time)?;
        assert_eq!(streams_after.len(), 0);

        let result = registry.finalize_streams(Address::ZERO);
        assert!(result.is_ok());

        Ok(())
    }
}
