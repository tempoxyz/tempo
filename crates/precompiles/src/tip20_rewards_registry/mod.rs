// Module for tip20_rewards_registry precompile
pub mod dispatch;

use crate::{
    TIP20_REWARDS_REGISTRY_ADDRESS,
    error::TempoPrecompileError,
    storage::{PrecompileStorageProvider, slots::mapping_slot},
    tip20::{TIP20Token, address_to_token_id_unchecked},
};
use alloy::{
    primitives::{Address, Bytes, U256, keccak256},
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
    // Mapping of (bytes32 => bool) to indicate if a rewards stream exists.
    // Mapping key is derived via keccak256(abi.encode(tip20_address, end_time))
    pub const STREAM_REGISTERED: U256 = uint!(2_U256);
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

    fn get_stream_registered(
        &mut self,
        token: &Address,
        end_time: u128,
    ) -> Result<bool, TempoPrecompileError> {
        let key = keccak256((token, end_time).abi_encode());
        let slot = mapping_slot(key, slots::STREAM_REGISTERED);
        Ok(self.storage.sload(self.address, slot)?.to::<bool>())
    }

    fn set_stream_registered(
        &mut self,
        token: &Address,
        end_time: u128,
    ) -> Result<(), TempoPrecompileError> {
        let key = keccak256((token, end_time).abi_encode());
        let slot = mapping_slot(key, slots::STREAM_REGISTERED);
        self.storage.sstore(self.address, slot, U256::from(true))
    }

    /// Add a token to the registry for a given stream end time
    pub fn add_stream(
        &mut self,
        token: &Address,
        end_time: u128,
    ) -> Result<(), TempoPrecompileError> {
        // Check if already registered
        if self.get_stream_registered(token, end_time)? {
            return Ok(());
        }

        self.set_stream_registered(token, end_time)?;
        self.push_stream_ending_at_timestamp(token, end_time)?;

        Ok(())
    }

    /// Appends a TIP20 token address to the array corresponding with `timestamp` in storage.
    pub fn push_stream_ending_at_timestamp(
        &mut self,
        address: &Address,
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
    pub fn finalize_streams(&mut self, sender: &Address) -> Result<(), TempoPrecompileError> {
        if *sender != Address::ZERO {
            return Err(TIP20RewardsRegistryError::unauthorized().into());
        }

        let current_timestamp = self.storage.timestamp().to::<u128>();
        let mut last_updated_timestamp = self.get_last_updated_timestamp()?;
        if last_updated_timestamp == 0 {
            last_updated_timestamp = current_timestamp - 1;
        }

        if current_timestamp == last_updated_timestamp {
            return Ok(());
        }

        let mut next_timestamp = last_updated_timestamp + 1;
        // Loop through all streams ending at current timestamp and finalize each token stream
        while current_timestamp >= next_timestamp {
            let tokens = self.get_streams_ending_at_timestamp(next_timestamp)?;
            for addr in tokens {
                let token_id = address_to_token_id_unchecked(&addr);
                let mut token = TIP20Token::new(token_id, self.storage);
                token.finalize_streams(self.address, next_timestamp)?;
            }
            next_timestamp += 1;
        }

        self.set_last_updated_timestamp(next_timestamp)?;

        Ok(())
    }
}
