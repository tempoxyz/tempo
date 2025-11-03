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
            let last_element_slot = array_slot + last_index;
            let last_token = self
                .storage
                .sload(self.address, last_element_slot)?
                .into_address();

            let current_element_slot = array_slot + index;
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
        let element_slot = array_slot + length;
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
            let element_slot = array_slot + U256::from(i);
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

            for token in tokens {
                let token_id = address_to_token_id_unchecked(token);
                let mut tip20_token = TIP20Token::new(token_id, self.storage);
                tip20_token.finalize_streams(self.address, next_timestamp)?;

                let stream_key = keccak256((token, next_timestamp).abi_encode());
                self.remove_stream_index(stream_key)?;
            }

            let array_slot = mapping_slot(next_timestamp.to_be_bytes(), slots::STREAMS_ENDING_AT);
            self.storage.sstore(self.address, array_slot, U256::ZERO)?;

            next_timestamp += 1;
        }

        self.set_last_updated_timestamp(current_timestamp)?;

        Ok(())
    }
}
