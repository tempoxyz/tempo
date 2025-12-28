//! Integration tests for the `#[solidity]` macro.

use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::sol_types::{SolCall, SolError, SolEvent, SolInterface, SolStruct, SolValue};
use std::collections::HashMap;
use tempo_precompiles_macros::solidity;

#[solidity]
mod structs {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Transfer {
        pub from: Address,
        pub to: Address,
        pub amount: U256,
        pub approved: bool,
        pub hash: B256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Inner {
        pub value: U256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Outer {
        pub inner: Inner,
        pub extra: Address,
    }
}

#[test]
fn test_struct_encoding_decoding() {
    use structs::Transfer;

    let transfer = Transfer {
        from: Address::random(),
        to: Address::random(),
        amount: U256::random(),
        approved: true,
        hash: B256::random(),
    };

    // Round-trip encode/decode using SolValue
    let encoded = transfer.abi_encode();
    let decoded = Transfer::abi_decode(&encoded).unwrap();
    assert_eq!(transfer, decoded);

    // Verify EIP-712 root type format
    let root_type = Transfer::eip712_root_type();
    assert_eq!(
        root_type.as_ref(),
        "Transfer(address from,address to,uint256 amount,bool approved,bytes32 hash)"
    );
}

#[test]
fn test_nested_struct_eip712() {
    use structs::{Inner, Outer};

    // Verify Inner roundtrip
    let inner = Inner {
        value: U256::random(),
    };
    let encoded = inner.abi_encode();
    let decoded = Inner::abi_decode(&encoded).unwrap();
    assert_eq!(inner, decoded);

    // Verify Outer roundtrip with nested struct
    let outer = Outer {
        inner,
        extra: Address::random(),
    };
    let outer_encoded = outer.abi_encode();
    let outer_decoded = Outer::abi_decode(&outer_encoded).unwrap();
    assert_eq!(outer, outer_decoded);

    // Verify EIP-712 signatures
    assert_eq!(Inner::eip712_root_type().as_ref(), "Inner(uint256 value)");
    assert_eq!(
        Outer::eip712_root_type().as_ref(),
        "Outer(Inner inner,address extra)"
    );

    // Verify components include dependency
    let components = Outer::eip712_components();
    assert!(components.iter().any(|c| c.as_ref().starts_with("Inner(")));
}

#[solidity]
mod unit_enums {
    pub enum Status {
        Pending,
        Active,
        Completed,
        Cancelled,
    }
}

#[test]
fn test_unit_enum() {
    use unit_enums::Status;

    // Test From<Status> for u8
    assert_eq!(u8::from(Status::Pending), 0);
    assert_eq!(u8::from(Status::Active), 1);
    assert_eq!(u8::from(Status::Completed), 2);
    assert_eq!(u8::from(Status::Cancelled), 3);

    // Test TryFrom<u8> for Status
    assert_eq!(Status::try_from(0u8).unwrap(), Status::Pending);
    assert_eq!(Status::try_from(1u8).unwrap(), Status::Active);
    assert_eq!(Status::try_from(2u8).unwrap(), Status::Completed);
    assert_eq!(Status::try_from(3u8).unwrap(), Status::Cancelled);
    assert!(Status::try_from(255u8).is_err());

    // Test SolValue encoding as uint8
    let encoded = Status::Active.abi_encode();
    let decoded = Status::abi_decode(&encoded).unwrap();
    assert_eq!(decoded, Status::Active);
}

type Result<T> = core::result::Result<T, ()>;

#[solidity]
mod e2e {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct TokenInfo {
        pub name: B256,
        pub decimals: U256,
    }

    pub enum Error {
        Unauthorized,
        Paused,
        InsufficientBalance { available: U256 },
    }

    pub enum Event {
        Transfer {
            #[indexed]
            from: Address,
            #[indexed]
            to: Address,
            amount: U256,
        },
    }

    pub trait Interface {
        fn info(&self) -> Result<TokenInfo>;
        fn is_paused(&self) -> Result<bool>;
        fn balance_of(&self, account: Address) -> Result<U256>;
        fn transfer(&mut self, to: Address, amount: U256) -> Result<bool>;
        fn pause(&mut self) -> Result<()>;
    }
}

#[test]
fn test_error_enum_selectors() {
    use e2e::{Error, InsufficientBalance, Paused, Unauthorized};

    // Verify Unauthorized struct exists and has correct selector
    let unauthorized = Unauthorized;
    let selector = Unauthorized::SELECTOR;
    let expected: [u8; 4] = keccak256(b"Unauthorized()")[..4].try_into().unwrap();
    assert_eq!(selector, expected);

    // Verify Paused struct has correct selector
    let paused = Paused;
    let selector = Paused::SELECTOR;
    let expected: [u8; 4] = keccak256(b"Paused()")[..4].try_into().unwrap();
    assert_eq!(selector, expected);

    // Verify InsufficientBalance struct has correct selector
    let insufficient = InsufficientBalance {
        available: U256::from(50),
    };
    let selector = InsufficientBalance::SELECTOR;
    let expected: [u8; 4] = keccak256(b"InsufficientBalance(uint256)")[..4]
        .try_into()
        .unwrap();
    assert_eq!(selector, expected);

    // Verify constructor methods
    let err = Error::unauthorized();
    assert!(matches!(err, Error::Unauthorized(_)));

    let err = Error::paused();
    assert!(matches!(err, Error::Paused(_)));

    let err = Error::insufficient_balance(U256::from(100));
    assert!(matches!(err, Error::InsufficientBalance(_)));

    // Verify encoding
    let encoded = unauthorized.abi_encode();
    let decoded = Unauthorized::abi_decode(&encoded).unwrap();
    assert_eq!(format!("{unauthorized:?}"), format!("{decoded:?}"));

    let encoded = paused.abi_encode();
    let decoded = Paused::abi_decode(&encoded).unwrap();
    assert_eq!(format!("{paused:?}"), format!("{decoded:?}"));

    let encoded = insufficient.abi_encode();
    let decoded = InsufficientBalance::abi_decode(&encoded).unwrap();
    assert_eq!(insufficient.available, decoded.available);
}

#[allow(dead_code)]
struct TestToken {
    info: e2e::TokenInfo,
    paused: bool,
    balances: HashMap<Address, U256>,
    admin: Address,
}

impl e2e::Interface for TestToken {
    fn info(&self) -> Result<e2e::TokenInfo> {
        Ok(self.info.clone())
    }

    fn is_paused(&self) -> Result<bool> {
        Ok(self.paused)
    }

    fn balance_of(&self, account: Address) -> Result<U256> {
        Ok(*self.balances.get(&account).unwrap_or(&U256::ZERO))
    }

    fn transfer(&mut self, msg_sender: Address, to: Address, amount: U256) -> Result<bool> {
        if self.paused {
            return Err(());
        }
        let sender_balance = *self.balances.get(&msg_sender).unwrap_or(&U256::ZERO);
        if sender_balance < amount {
            return Err(());
        }
        self.balances.insert(msg_sender, sender_balance - amount);
        let to_balance = *self.balances.get(&to).unwrap_or(&U256::ZERO);
        self.balances.insert(to, to_balance + amount);
        Ok(true)
    }

    fn pause(&mut self, msg_sender: Address) -> Result<()> {
        if msg_sender != self.admin {
            return Err(());
        }
        self.paused = true;
        Ok(())
    }
}

#[test]
fn test_event_enum_indexed() {
    use alloy::sol_types::private::IntoLogData;
    use e2e::{Event, Transfer};

    // Verify event signature
    let expected_sig = "Transfer(address,address,uint256)";
    assert_eq!(Transfer::SIGNATURE, expected_sig);

    // Verify selector matches keccak256 of signature
    let expected_topic: [u8; 32] = keccak256(expected_sig.as_bytes()).into();
    assert_eq!(Transfer::SIGNATURE_HASH.0, expected_topic);

    // Verify IntoLogData implementation via Event enum
    let event = Event::transfer(Address::random(), Address::random(), U256::random());
    let log_data = event.to_log_data();
    assert!(!log_data.topics().is_empty());
}

#[test]
fn test_interface_call_structs() {
    use e2e::{Calls, balanceOfCall, infoCall, isPausedCall, transferCall};

    let account = Address::random();
    let to = Address::random();
    let amount = U256::random();

    // Verify selectors match keccak256(signature)[..4]
    let expected: [u8; 4] = keccak256(b"balanceOf(address)")[..4].try_into().unwrap();
    assert_eq!(balanceOfCall::SELECTOR, expected);

    let expected: [u8; 4] = keccak256(b"info()")[..4].try_into().unwrap();
    assert_eq!(infoCall::SELECTOR, expected);

    let expected: [u8; 4] = keccak256(b"isPaused()")[..4].try_into().unwrap();
    assert_eq!(isPausedCall::SELECTOR, expected);

    let expected: [u8; 4] = keccak256(b"transfer(address,uint256)")[..4]
        .try_into()
        .unwrap();
    assert_eq!(transferCall::SELECTOR, expected);

    // Verify Calls enum can decode by selector
    let call_data = balanceOfCall { account }.abi_encode();
    let decoded = Calls::abi_decode(&call_data).unwrap();
    assert!(matches!(decoded, Calls::balanceOf(_)));

    // Verify SolCall encoding round-trip
    let call = transferCall { to, amount };
    let encoded = call.abi_encode();
    let decoded = transferCall::abi_decode(&encoded).unwrap();
    assert_eq!(call.to, decoded.to);
    assert_eq!(call.amount, decoded.amount);
}

#[test]
fn test_full_module_integration() {
    use e2e::{Calls, Event, Interface, TokenInfo, balanceOfCall, transferCall};

    let admin = Address::random();
    let user1 = Address::random();
    let user2 = Address::random();
    let amount = U256::random().min(U256::from(10));
    let transfer_amount = amount / U256::from(2);

    let mut token = TestToken {
        info: TokenInfo {
            name: B256::random(),
            decimals: U256::random(),
        },
        paused: false,
        balances: HashMap::new(),
        admin,
    };
    token.balances.insert(user1, amount);

    // Test dispatch pattern: decode Calls, match selector, call method
    let call_data = balanceOfCall { account: user1 }.abi_encode();
    let decoded = Calls::abi_decode(&call_data).unwrap();

    let result = match decoded {
        Calls::balanceOf(call) => token.balance_of(call.account),
        _ => Err(()),
    };
    assert_eq!(result.unwrap(), amount);

    // Test transfer dispatch
    let call_data = transferCall {
        to: user2,
        amount: transfer_amount,
    }
    .abi_encode();
    let decoded = Calls::abi_decode(&call_data).unwrap();

    let result = match decoded {
        Calls::transfer(call) => token.transfer(user1, call.to, call.amount),
        _ => Err(()),
    };
    assert!(result.unwrap());

    // Verify balances after transfer
    assert_eq!(token.balance_of(user1).unwrap(), transfer_amount);
    assert_eq!(token.balance_of(user2).unwrap(), transfer_amount);

    // Test pause (admin only)
    let result = token.pause(user1);
    assert!(result.is_err());

    let result = token.pause(admin);
    assert!(result.is_ok());
    assert!(token.is_paused().unwrap());

    // Test transfer fails when paused
    let result = token.transfer(user1, user2, transfer_amount);
    assert!(result.is_err());

    // Verify error selectors are correct
    let selector = e2e::Unauthorized::SELECTOR;
    let expected: [u8; 4] = keccak256(b"Unauthorized()")[..4].try_into().unwrap();
    assert_eq!(selector, expected);

    // Verify event can be constructed
    let event = Event::transfer(user1, user2, transfer_amount);
    assert!(matches!(event, Event::Transfer(_)));
}
