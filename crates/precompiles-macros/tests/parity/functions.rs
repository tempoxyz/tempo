#![allow(unused_imports, unreachable_pub)]
//! Function call encoding parity tests between `#[abi]` and `sol!`.

use alloy::{
    primitives::{Address, U256},
    sol_types::SolCall,
};
use alloy_sol_macro::sol;
use tempo_precompiles_macros::abi;

use super::assert_call_parity;

#[allow(dead_code)]
type Result<T> = core::result::Result<T, ()>;

sol! {
    struct UserInfo {
        address addr;
        uint256 balance;
    }

    function totalSupply() external view returns (uint256);
    function name() external view returns (string);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function getUser(address account) external view returns (UserInfo);
    function updateUser(UserInfo user) external;
    function batchUpdate(UserInfo[] users) external;
    function sumValues(uint256[] values) external pure returns (uint256);
    function setAddresses(address[3] addrs) external;
    function getUserBalance(address user) external view returns (uint256);
    function setMaxAmount(uint256 max) external;
    function isValidAddress(address addr) external view returns (bool);
}

#[abi]
mod rust {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct UserInfo {
        pub addr: Address,
        pub balance: U256,
    }

    pub trait Interface {
        fn total_supply(&self) -> Result<U256>;
        fn name(&self) -> Result<String>;
        fn balance_of(&self, account: Address) -> Result<U256>;
        fn transfer(&mut self, to: Address, amount: U256) -> Result<bool>;
        fn approve(&mut self, spender: Address, amount: U256) -> Result<bool>;
        fn get_user(&self, account: Address) -> Result<UserInfo>;
        fn update_user(&mut self, user: UserInfo) -> Result<()>;
        fn batch_update(&mut self, users: Vec<UserInfo>) -> Result<()>;
        fn sum_values(&self, values: Vec<U256>) -> Result<U256>;
        fn set_addresses(&mut self, addrs: [Address; 3]) -> Result<()>;
        fn get_user_balance(&self, user: Address) -> Result<U256>;
        fn set_max_amount(&mut self, max: U256) -> Result<()>;
        fn is_valid_address(&self, addr: Address) -> Result<bool>;
    }
}

#[test]
fn getter_parity() {
    assert_call_parity::<totalSupplyCall, rust::totalSupplyCall>();
    assert_call_parity::<nameCall, rust::nameCall>();
}

#[test]
fn getter_encoding() {
    let sol_call = totalSupplyCall {};
    let our_call = rust::totalSupplyCall {};

    assert_eq!(sol_call.abi_encode(), our_call.abi_encode());
}

#[test]
fn primitive_params_parity() {
    assert_call_parity::<balanceOfCall, rust::balanceOfCall>();
    assert_call_parity::<transferCall, rust::transferCall>();
    assert_call_parity::<approveCall, rust::approveCall>();
}

#[test]
fn primitive_params_encoding() {
    let sol_call = transferCall {
        to: Address::repeat_byte(0x11),
        amount: U256::from(1000),
    };
    let our_call = rust::transferCall {
        to: Address::repeat_byte(0x11),
        amount: U256::from(1000),
    };

    assert_eq!(sol_call.abi_encode(), our_call.abi_encode());

    // Decode round-trip
    let decoded = rust::transferCall::abi_decode(&sol_call.abi_encode()).unwrap();
    assert_eq!(our_call.to, decoded.to);
    assert_eq!(our_call.amount, decoded.amount);
}

#[test]
fn struct_param_parity() {
    assert_call_parity::<getUserCall, rust::getUserCall>();
    assert_call_parity::<updateUserCall, rust::updateUserCall>();
    assert_call_parity::<batchUpdateCall, rust::batchUpdateCall>();
}

#[test]
fn struct_param_signature() {
    // Critical: struct params use tuple notation, not struct names
    assert_eq!(updateUserCall::SIGNATURE, "updateUser((address,uint256))");
    assert_eq!(
        batchUpdateCall::SIGNATURE,
        "batchUpdate((address,uint256)[])"
    );
}

#[test]
fn struct_param_encoding() {
    let sol_call = updateUserCall {
        user: UserInfo {
            addr: Address::repeat_byte(0xAA),
            balance: U256::from(500),
        },
    };
    let our_call = rust::updateUserCall {
        user: rust::UserInfo {
            addr: Address::repeat_byte(0xAA),
            balance: U256::from(500),
        },
    };

    assert_eq!(sol_call.abi_encode(), our_call.abi_encode());
}

#[test]
fn array_params_parity() {
    assert_call_parity::<sumValuesCall, rust::sumValuesCall>();
    assert_call_parity::<setAddressesCall, rust::setAddressesCall>();
}

#[test]
fn array_params_encoding() {
    let sol_call = sumValuesCall {
        values: vec![U256::from(1), U256::from(2), U256::from(3)],
    };
    let our_call = rust::sumValuesCall {
        values: vec![U256::from(1), U256::from(2), U256::from(3)],
    };

    assert_eq!(sol_call.abi_encode(), our_call.abi_encode());

    let sol_call = setAddressesCall {
        addrs: [
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
            Address::repeat_byte(0x03),
        ],
    };
    let our_call = rust::setAddressesCall {
        addrs: [
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
            Address::repeat_byte(0x03),
        ],
    };

    assert_eq!(sol_call.abi_encode(), our_call.abi_encode());
}

#[test]
fn case_conversion_parity() {
    // snake_case methods -> camelCase Solidity functions
    assert_call_parity::<getUserBalanceCall, rust::getUserBalanceCall>();
    assert_call_parity::<setMaxAmountCall, rust::setMaxAmountCall>();
    assert_call_parity::<isValidAddressCall, rust::isValidAddressCall>();
}
