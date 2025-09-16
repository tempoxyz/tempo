use alloy_primitives::{Address, U256};

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
