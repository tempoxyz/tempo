#![allow(unused_imports, unreachable_pub)]
//! Struct encoding parity tests between `#[abi]` and `sol!`.

use alloy::{
    primitives::{Address, B256, Bytes, I256, U256},
    sol_types::SolValue,
};
use alloy_sol_macro::sol;
use tempo_precompiles_macros::abi;

use super::assert_encoding_parity;

sol! {
    struct Transfer {
        address from;
        address to;
        uint256 amount;
    }

    struct Inner {
        uint256 value;
        bytes32 hash;
    }

    struct Outer {
        address owner;
        Inner data;
    }

    struct Message {
        string content;
        bytes data;
        address sender;
    }

    struct Arrays {
        uint256[] values;
        address[3] fixedAddrs;
    }

    struct AllPrimitives {
        address addr;
        bool flag;
        uint8 small;
        uint256 big;
        int256 signed;
        bytes32 hash;
    }

    struct SignedInts {
        int8 small;
        int128 medium;
        int256 big;
    }
}

#[abi]
mod rust {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Transfer {
        pub from: Address,
        pub to: Address,
        pub amount: U256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Inner {
        pub value: U256,
        pub hash: B256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Outer {
        pub owner: Address,
        pub data: Inner,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Message {
        pub content: String,
        pub data: Bytes,
        pub sender: Address,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Arrays {
        pub values: Vec<U256>,
        pub fixed_addrs: [Address; 3],
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AllPrimitives {
        pub addr: Address,
        pub flag: bool,
        pub small: u8,
        pub big: U256,
        pub signed: I256,
        pub hash: B256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SignedInts {
        pub small: i8,
        pub medium: i128,
        pub big: I256,
    }
}

#[test]
fn simple_struct_encoding() {
    let sol_val = Transfer {
        from: Address::ZERO,
        to: Address::repeat_byte(0x11),
        amount: U256::from(1000),
    };
    let our_val = rust::Transfer {
        from: Address::ZERO,
        to: Address::repeat_byte(0x11),
        amount: U256::from(1000),
    };

    assert_encoding_parity(&sol_val, &our_val);

    // Round-trip decode
    let decoded = rust::Transfer::abi_decode(&sol_val.abi_encode()).unwrap();
    assert_eq!(our_val, decoded);
}

#[test]
fn nested_struct_encoding() {
    let sol_val = Outer {
        owner: Address::repeat_byte(0xAA),
        data: Inner {
            value: U256::from(42),
            hash: B256::repeat_byte(0xBB),
        },
    };
    let our_val = rust::Outer {
        owner: Address::repeat_byte(0xAA),
        data: rust::Inner {
            value: U256::from(42),
            hash: B256::repeat_byte(0xBB),
        },
    };

    assert_encoding_parity(&sol_val, &our_val);

    // Cross-decode: decode sol! encoded bytes with our type
    let decoded = rust::Outer::abi_decode(&sol_val.abi_encode()).unwrap();
    assert_eq!(our_val, decoded);
}

#[test]
fn dynamic_types_encoding() {
    let sol_val = Message {
        content: "Hello, World!".to_string(),
        data: Bytes::from(vec![0x01, 0x02, 0x03, 0x04]),
        sender: Address::repeat_byte(0x55),
    };
    let our_val = rust::Message {
        content: "Hello, World!".to_string(),
        data: Bytes::from(vec![0x01, 0x02, 0x03, 0x04]),
        sender: Address::repeat_byte(0x55),
    };

    assert_encoding_parity(&sol_val, &our_val);

    let decoded = rust::Message::abi_decode(&sol_val.abi_encode()).unwrap();
    assert_eq!(our_val, decoded);
}

#[test]
fn array_encoding() {
    let sol_val = Arrays {
        values: vec![U256::from(1), U256::from(2), U256::from(3)],
        fixedAddrs: [
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
            Address::repeat_byte(0x03),
        ],
    };
    let our_val = rust::Arrays {
        values: vec![U256::from(1), U256::from(2), U256::from(3)],
        fixed_addrs: [
            Address::repeat_byte(0x01),
            Address::repeat_byte(0x02),
            Address::repeat_byte(0x03),
        ],
    };

    assert_encoding_parity(&sol_val, &our_val);

    let decoded = rust::Arrays::abi_decode(&sol_val.abi_encode()).unwrap();
    assert_eq!(our_val, decoded);
}

#[test]
fn empty_array_encoding() {
    let sol_val = Arrays {
        values: vec![],
        fixedAddrs: [Address::ZERO, Address::ZERO, Address::ZERO],
    };
    let our_val = rust::Arrays {
        values: vec![],
        fixed_addrs: [Address::ZERO, Address::ZERO, Address::ZERO],
    };

    assert_encoding_parity(&sol_val, &our_val);
}

#[test]
fn all_primitives_encoding() {
    let sol_val = AllPrimitives {
        addr: Address::repeat_byte(0xAB),
        flag: true,
        small: 255,
        big: U256::MAX,
        signed: I256::try_from(-1i64).unwrap(),
        hash: B256::repeat_byte(0xCD),
    };
    let our_val = rust::AllPrimitives {
        addr: Address::repeat_byte(0xAB),
        flag: true,
        small: 255,
        big: U256::MAX,
        signed: I256::try_from(-1i64).unwrap(),
        hash: B256::repeat_byte(0xCD),
    };

    assert_encoding_parity(&sol_val, &our_val);

    let decoded = rust::AllPrimitives::abi_decode(&sol_val.abi_encode()).unwrap();
    assert_eq!(our_val, decoded);
}

#[test]
fn signed_int_encoding() {
    let sol_val = SignedInts {
        small: -1,
        medium: -1000,
        big: I256::try_from(-1i64).unwrap(),
    };
    let our_val = rust::SignedInts {
        small: -1,
        medium: -1000,
        big: I256::try_from(-1i64).unwrap(),
    };

    assert_encoding_parity(&sol_val, &our_val);

    let decoded = rust::SignedInts::abi_decode(&sol_val.abi_encode()).unwrap();
    assert_eq!(our_val, decoded);
}
