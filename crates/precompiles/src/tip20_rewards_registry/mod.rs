// Module for tip20_rewards_registry precompile
pub mod dispatch;

pub use tempo_contracts::precompiles::ITIPRewardsRegistry;

use crate::storage::PrecompileStorageProvider;
use alloy::primitives::{Address, B256, keccak256};

/// TIPRewardsRegistry precompile that tracks stream end times
/// Maps timestamp -> Vec of token addresses with streams ending at that time
pub struct TIPRewardsRegistry<'a, S: PrecompileStorageProvider> {
    storage: &'a mut S,
    registry_address: Address,
}

impl<'a, S: PrecompileStorageProvider> TIPRewardsRegistry<'a, S> {
    pub fn new(registry_address: Address, storage: &'a mut S) -> Self {
        Self {
            storage,
            registry_address,
        }
    }

    /// Mapping: timestamp -> Vec<Address> of tokens with streams ending at that time
    fn streams_ending_at_slot(timestamp: u128) -> Vec<u8> {
        let mut key = b"streams_ending_at".to_vec();
        key.extend_from_slice(&timestamp.to_le_bytes());
        key
    }

    /// Mapping: keccak256(token_address || timestamp) -> bool
    /// Tracks if a stream has already been registered for this token at this end time
    fn stream_registered_slot(token: Address, timestamp: u128) -> B256 {
        let mut data = Vec::new();
        data.extend_from_slice(token.as_slice());
        data.extend_from_slice(&timestamp.to_le_bytes());
        keccak256(&data)
    }

    /// Add a token to the registry for a given stream end time
    pub fn add_stream(&mut self, token: Address, end_time: u128) {
        // Check if already registered
        let registered_key = Self::stream_registered_slot(token, end_time);
        let registered = self.storage.get_value(registered_key.to_vec());

        if !registered.is_empty() && registered[0] != 0 {
            // Already registered, skip
            return;
        }

        // Mark as registered
        self.storage.set_value(registered_key.to_vec(), vec![1u8]);

        // Get current list of tokens for this end time
        let slot = Self::streams_ending_at_slot(end_time);
        let mut data = self.storage.get_value(slot.clone());

        // Parse existing addresses
        let mut tokens = Vec::new();
        for chunk in data.chunks(20) {
            if chunk.len() == 20 {
                tokens.push(Address::from_slice(chunk));
            }
        }

        // Add new token
        tokens.push(token);

        // Serialize and store
        let mut serialized = Vec::new();
        for token_addr in tokens {
            serialized.extend_from_slice(token_addr.as_slice());
        }
        self.storage.set_value(slot, serialized);
    }

    /// Get all tokens with streams ending at the given timestamp
    pub fn get_tokens_ending_at(&self, timestamp: u128) -> Vec<Address> {
        let slot = Self::streams_ending_at_slot(timestamp);
        let data = self.storage.get_value(slot);

        let mut tokens = Vec::new();
        for chunk in data.chunks(20) {
            if chunk.len() == 20 {
                tokens.push(Address::from_slice(chunk));
            }
        }
        tokens
    }

    /// Finalize streams for all tokens ending at the given timestamp
    pub fn finalize_streams(&mut self, timestamp: u128) -> Vec<Address> {
        let tokens = self.get_tokens_ending_at(timestamp);

        // Clear the mapping entries for this timestamp
        let slot = Self::streams_ending_at_slot(timestamp);
        self.storage.set_value(slot, vec![]);

        // TODO: Call finalize_streams on each token's TIP20 precompile
        // This will be done by the caller after getting the list of tokens

        tokens
    }

    /// Finalize streams with system call check
    pub fn finalize_streams_checked(
        &mut self,
        msg_sender: &Address,
        timestamp: u128,
    ) -> Result<Vec<Address>, crate::error::TempoPrecompileError> {
        if *msg_sender != Address::ZERO {
            return Err(crate::error::TempoPrecompileError::Fatal(
                "Only system can call finalize_streams".to_string(),
            ));
        }
        Ok(self.finalize_streams(timestamp))
    }
}
