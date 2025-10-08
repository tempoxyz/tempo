//! Stablecoin DEX types and utilities.

pub mod error;
pub mod order;

pub use error::OrderError;
pub use order::LimitOrder;

use alloy::primitives::{Address, Bytes, U256};
use revm::state::Bytecode;

use crate::{
    STABLECOIN_DEX_ADDRESS,
    contracts::{StorageProvider, storage::StorageOps},
};

pub struct StablecoinDex<'a, S: StorageProvider> {
    address: Address,
    storage: &'a mut S,
}

// TODO: slots

impl<'a, S: StorageProvider> StablecoinDex<'a, S> {
    pub fn new(storage: &'a mut S) -> Self {
        Self {
            address: STABLECOIN_DEX_ADDRESS,
            storage,
        }
    }

    /// Initializes the contract
    ///
    /// This ensures the [`StablecoinDex`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) {
        // must ensure the account is not empty, by setting some code
        self.storage
            .set_code(
                self.address,
                Bytecode::new_legacy(Bytes::from_static(&[0xef])),
            )
            .expect("TODO: handle error");
    }
}

impl<'a, S: StorageProvider> StorageOps for StablecoinDex<'a, S> {
    fn sstore(&mut self, slot: U256, value: U256) {
        self.storage
            .sstore(self.address, slot, value)
            .expect("Storage operation failed");
    }

    fn sload(&mut self, slot: U256) -> U256 {
        self.storage
            .sload(self.address, slot)
            .expect("Storage operation failed")
    }
}

impl<'a, S: StorageProvider> StablecoinDex<'a, S> {
    pub fn balance_of(&mut self, _user: Address, _token: Address) -> u128 {
        todo!()
    }

    pub fn quote_buy(
        &mut self,
        _token_in: Address,
        _token_out: Address,
        _amount_out: u128,
    ) -> u128 {
        todo!()
    }

    pub fn quote_sell(
        &mut self,
        _token_in: Address,
        _token_out: Address,
        _amount_in: u128,
    ) -> u128 {
        todo!()
    }

    pub fn sell(
        &mut self,
        _token_in: Address,
        _token_out: Address,
        _amount_in: u128,
        _min_amount_out: u128,
    ) -> u128 {
        todo!()
    }

    pub fn buy(
        &mut self,
        _token_in: Address,
        _token_out: Address,
        _amount_out: u128,
        _max_amount_in: u128,
    ) -> u128 {
        todo!()
    }

    pub fn place(&mut self, _token: Address, _amount: u128, _is_bid: bool, _tick: i16) -> u128 {
        todo!()
    }

    pub fn place_flip(
        &mut self,
        _token: Address,
        _amount: u128,
        _is_bid: bool,
        _tick: i16,
        _flip_tick: i16,
    ) -> u128 {
        todo!()
    }

    pub fn cancel(&mut self, _order_id: u128) {
        todo!()
    }

    pub fn withdraw(&mut self, _token: Address, _amount: u128) {
        todo!()
    }
}
