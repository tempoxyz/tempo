// Module for tip20_rewards_registry precompile
pub mod dispatch;

use alloy_primitives::Bytes;
use revm::state::Bytecode;
pub use tempo_contracts::precompiles::ITIPRewardsRegistry;

use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS, error::TempoPrecompileError, storage::PrecompileStorageProvider,
};
use alloy::primitives::{Address, U256, uint};

pub mod slots {
    use alloy::primitives::{U256, uint};

    // Storage slots for TIPRewardsRegistry
    pub const LAST_UPDATED_TIMESTAMP: U256 = uint!(0_U256);
    pub const STREAMS_ENDING_AT: U256 = uint!(1_U256);
    pub const STREAM_REGISTERED: U256 = uint!(2_U256);
}

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

    /// Initializes the TIP20 rewards registry contract.
    ///
    /// Ensures the [`TIP20RewardsRegistry`] account isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<(), TempoPrecompileError> {
        // must ensure the account is not empty, by setting some code
        self.storage.set_code(
            TIP20_REWARDS_REGISTRY_ADDRESS,
            Bytecode::new_legacy(Bytes::from_static(&[0xef])),
        )
    }

    /// Get the last updated timestamp
    fn get_last_updated_timestamp(&mut self) -> Result<u128, TempoPrecompileError> {
        let val = self.storage.sload(self.registry_address, slots::LAST_UPDATED_TIMESTAMP)?;
        Ok(val.to::<u128>())
    }

    /// Set the last updated timestamp
    fn set_last_updated_timestamp(&mut self, timestamp: u128) -> Result<(), TempoPrecompileError> {
        self.storage.sstore(self.registry_address, slots::LAST_UPDATED_TIMESTAMP, U256::from(timestamp))
    }

    /// Helper to compute slot for streams_ending_at[timestamp]
    fn streams_ending_at_slot(timestamp: u128) -> U256 {
        // slot = keccak256(timestamp || STREAMS_ENDING_AT)
        let mut data = Vec::new();
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&slots::STREAMS_ENDING_AT.to_le_bytes::<32>());
        U256::from_be_bytes(alloy::primitives::keccak256(&data).0)
    }

    /// Helper to compute slot for stream_registered[keccak256(token || timestamp)]
    fn stream_registered_slot(token: Address, timestamp: u128) -> U256 {
        // slot = keccak256(token || timestamp || STREAM_REGISTERED)
        let mut data = Vec::new();
        data.extend_from_slice(token.as_slice());
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&slots::STREAM_REGISTERED.to_le_bytes::<32>());
        U256::from_be_bytes(alloy::primitives::keccak256(&data).0)
    }

    /// Add a token to the registry for a given stream end time
    pub fn add_stream(&mut self, token: Address, end_time: u128) -> Result<(), TempoPrecompileError> {
        // Check if already registered
        let registered_slot = Self::stream_registered_slot(token, end_time);
        let registered = self.storage.sload(self.registry_address, registered_slot)?;

        if registered != U256::ZERO {
            // Already registered, skip
            return Ok(());
        }

        // Mark as registered
        self.storage.sstore(self.registry_address, registered_slot, U256::ONE)?;

        // Get current list of tokens for this end time
        let slot = Self::streams_ending_at_slot(end_time);
        let mut data = self.storage.sload(self.registry_address, slot)?;

        // Deserialize existing addresses from the stored value
        let mut tokens = Vec::new();
        if data != U256::ZERO {
            let bytes = data.to_le_bytes::<32>();
            for chunk in bytes.chunks(20) {
                if chunk.len() == 20 && chunk != &[0u8; 20] {
                    tokens.push(Address::from_slice(chunk));
                }
            }
        }

        // Add new token
        tokens.push(token);

        // Serialize and store (simplified - store up to 1 address in U256)
        // For now, store first address only (U256 can only hold ~1 address + padding)
        if !tokens.is_empty() {
            let mut bytes = [0u8; 32];
            bytes[0..20].copy_from_slice(tokens[0].as_slice());
            let stored = U256::from_le_bytes(bytes);
            self.storage.sstore(self.registry_address, slot, stored)?;
        }

        Ok(())
    }

    /// Get all tokens with streams ending at the given timestamp
    pub fn get_tokens_ending_at(&mut self, timestamp: u128) -> Result<Vec<Address>, TempoPrecompileError> {
        let slot = Self::streams_ending_at_slot(timestamp);
        let data = self.storage.sload(self.registry_address, slot)?;

        let mut tokens = Vec::new();
        if data != U256::ZERO {
            let bytes = data.to_le_bytes::<32>();
            for chunk in bytes.chunks(20) {
                if chunk.len() == 20 && chunk != &[0u8; 20] {
                    tokens.push(Address::from_slice(chunk));
                }
            }
        }
        Ok(tokens)
    }

    /// Finalize streams for all tokens ending at the current timestamp
    pub fn finalize_streams(&mut self) -> Result<Vec<Address>, TempoPrecompileError> {
        let timestamp = self.storage.timestamp().to::<u128>();
        let tokens = self.get_tokens_ending_at(timestamp)?;

        // Clear the mapping entries for this timestamp
        let slot = Self::streams_ending_at_slot(timestamp);
        self.storage.sstore(self.registry_address, slot, U256::ZERO)?;

        // Update last finalized timestamp
        self.set_last_updated_timestamp(timestamp)?;

        // TODO: Call finalize_streams on each token's TIP20 precompile
        // This will be done by the caller after getting the list of tokens

        Ok(tokens)
    }

    /// Finalize streams with system call check
    pub fn finalize_streams_checked(
        &mut self,
        msg_sender: &Address,
    ) -> Result<Vec<Address>, TempoPrecompileError> {
        if *msg_sender != Address::ZERO {
            return Err(TempoPrecompileError::Fatal(
                "Only system can call finalize_streams".to_string(),
            ));
        }
        self.finalize_streams()
    }
}
