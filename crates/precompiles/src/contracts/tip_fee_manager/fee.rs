use crate::contracts::{
    TIP20Token, address_to_token_id_unchecked,
    storage::{StorageOps, StorageProvider},
    tip_fee_manager::{
        amm::{PoolKey, TIPFeeAMM},
        slots::{
            collected_fees_slot, token_in_fees_array_slot, user_token_slot, validator_token_slot,
        },
    },
    types::{FeeManagerEvent, IFeeManager, ITIP20, ITIPFeeAMM},
};

// Re-export PoolKey for backward compatibility with tests
use alloy::primitives::{Address, IntoLogData, U256, uint};
use alloy_primitives::Bytes;
use reth_evm::revm::{
    interpreter::instructions::utility::{IntoAddress, IntoU256},
    state::Bytecode,
};

#[derive(Debug)]
pub enum FeeToken {
    User(TokenBalance),
    Validator(TokenBalance),
}

#[derive(Debug)]
pub struct TokenBalance {
    pub address: Address,
    pub balance: U256,
}

impl TokenBalance {
    pub fn new(address: Address, balance: U256) -> Self {
        Self { address, balance }
    }
}

impl FeeToken {
    /// Returns the balance from the fee token
    pub fn balance(&self) -> U256 {
        match self {
            Self::User(token_balance) => token_balance.balance,
            Self::Validator(token_balance) => token_balance.balance,
        }
    }

    /// Returns the token address from the fee token
    pub fn address(&self) -> Address {
        match self {
            Self::User(token_balance) => token_balance.address,
            Self::Validator(token_balance) => token_balance.address,
        }
    }
}
