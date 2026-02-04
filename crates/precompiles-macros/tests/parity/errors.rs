//! Error encoding parity tests between `#[abi]` and `sol!`.

use alloy::{
    primitives::{Address, U256},
    sol_types::SolError,
};
use alloy_sol_macro::sol;
use tempo_precompiles_macros::abi;

use super::assert_error_parity;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    error Unauthorized();

    #[derive(Debug, PartialEq, Eq)]
    error Paused();

    #[derive(Debug, PartialEq, Eq)]
    error InsufficientBalance(address account, uint256 balance, uint256 required);

    #[derive(Debug, PartialEq, Eq)]
    error InvalidAmount(uint256 amount);
}

#[abi]
mod rust {
    use super::*;

    pub enum Error {
        Unauthorized,
        Paused,
        InsufficientBalance {
            account: Address,
            balance: U256,
            required: U256,
        },
        InvalidAmount {
            amount: U256,
        },
    }
}

#[test]
fn unit_error_parity() {
    assert_error_parity::<Unauthorized, rust::Unauthorized>();
    assert_error_parity::<Paused, rust::Paused>();
}

#[test]
fn unit_error_encoding() {
    let sol_err = Unauthorized {};
    let our_err = rust::Unauthorized;

    assert_eq!(sol_err.abi_encode(), our_err.abi_encode());

    // Decode round-trip
    let decoded = rust::Unauthorized::abi_decode(&sol_err.abi_encode()).unwrap();
    assert_eq!(our_err, decoded);
}

#[test]
fn field_error_parity() {
    assert_error_parity::<InsufficientBalance, rust::InsufficientBalance>();
    assert_error_parity::<InvalidAmount, rust::InvalidAmount>();
}

#[test]
fn field_error_encoding() {
    let sol_err = InsufficientBalance {
        account: Address::repeat_byte(0x11),
        balance: U256::from(50),
        required: U256::from(100),
    };
    let our_err = rust::InsufficientBalance {
        account: Address::repeat_byte(0x11),
        balance: U256::from(50),
        required: U256::from(100),
    };

    assert_eq!(sol_err.abi_encode(), our_err.abi_encode());

    // Cross-decode
    let decoded = rust::InsufficientBalance::abi_decode(&sol_err.abi_encode()).unwrap();
    assert_eq!(our_err, decoded);
}
