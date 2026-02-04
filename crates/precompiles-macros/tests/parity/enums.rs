#![allow(unused_imports, unreachable_pub)]
//! Enum encoding parity tests between `#[abi]` and `sol!`.

use alloy::sol_types::SolValue;
use alloy_sol_macro::sol;
use tempo_precompiles_macros::abi;

use super::assert_encoding_parity;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    enum Status {
        Pending,
        Active,
        Completed
    }
}

#[abi]
mod rust {
    pub enum Status {
        Pending,
        Active,
        Completed,
    }
}

#[test]
fn unit_enum_encoding() {
    let sol_val = Status::Active;
    let our_val = rust::Status::Active;

    assert_encoding_parity(&sol_val, &our_val);
}

#[test]
fn unit_enum_all_variants() {
    for (sol_val, our_val) in [
        (Status::Pending, rust::Status::Pending),
        (Status::Active, rust::Status::Active),
        (Status::Completed, rust::Status::Completed),
    ] {
        assert_encoding_parity(&sol_val, &our_val);

        // Round-trip decode
        let decoded = rust::Status::abi_decode(&sol_val.abi_encode()).unwrap();
        assert_eq!(our_val, decoded);
    }
}
