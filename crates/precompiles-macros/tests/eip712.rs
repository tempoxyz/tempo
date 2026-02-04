#![allow(unused_imports, unreachable_pub)]
//! EIP-712 tests for the `#[abi]` macro.
//!
//! These tests mirror alloy's `sol-types/tests/macros/sol/eip712.rs` to ensure
//! our implementation produces identical results.
//!
//! # Test Categories
//!
//! 1. **encode_type_nesting**: Verifies `eip712_encode_type()` produces correctly
//!    ordered type strings with nested struct dependencies.
//!
//! 2. **encode_data_nesting**: Uses the canonical Mail/Person example from EIP-712
//!    spec with known test vectors.
//!
//! 3. **Edge cases**: Deep nesting, diamond dependencies, arrays of structs, etc.

use alloy::{
    primitives::{Address, B256, U256, b256},
    sol_types::{SolStruct, SolValue, eip712_domain},
};
use tempo_precompiles_macros::abi;

#[abi]
mod nesting {
    use super::*;

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct A {
        pub a: U256,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct B {
        pub b: B256,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct C {
        pub a: A,
        pub b: B,
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct D {
        pub c: C,
        pub a: A,
        pub b: B,
    }
}

#[test]
fn encode_type_nesting() {
    use nesting::{A, B, C, D};

    // Simple structs have no dependencies
    assert_eq!(A::eip712_encode_type().as_ref(), "A(uint256 a)");
    assert_eq!(B::eip712_encode_type().as_ref(), "B(bytes32 b)");

    // C depends on A and B - components sorted alphabetically
    assert_eq!(
        C::eip712_encode_type().as_ref(),
        "C(A a,B b)A(uint256 a)B(bytes32 b)"
    );

    // D depends on C, A, B - all unique components sorted alphabetically
    // Note: C's dependencies (A, B) are included, then C itself
    assert_eq!(
        D::eip712_encode_type().as_ref(),
        "D(C c,A a,B b)A(uint256 a)B(bytes32 b)C(A a,B b)"
    );
}

#[test]
fn encode_type_root_only() {
    use nesting::{A, B};

    // Structs without dependencies: encode_type == root_type
    assert_eq!(A::eip712_root_type(), A::eip712_encode_type());
    assert_eq!(B::eip712_root_type(), B::eip712_encode_type());
}

#[test]
fn encode_type_components() {
    use nesting::{A, B, C, D};

    // No dependencies
    assert!(A::eip712_components().is_empty());
    assert!(B::eip712_components().is_empty());

    // C has A and B as components
    let c_components = C::eip712_components();
    assert_eq!(c_components.len(), 2);
    assert!(c_components.iter().any(|c| c.as_ref() == "A(uint256 a)"));
    assert!(c_components.iter().any(|c| c.as_ref() == "B(bytes32 b)"));

    // D has A, B, C as components
    let d_components = D::eip712_components();
    assert_eq!(d_components.len(), 3);
    assert!(d_components.iter().any(|c| c.as_ref() == "A(uint256 a)"));
    assert!(d_components.iter().any(|c| c.as_ref() == "B(bytes32 b)"));
    assert!(d_components.iter().any(|c| c.as_ref() == "C(A a,B b)"));
}

#[abi]
mod mail {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Person {
        pub name: String,
        pub wallet: Address,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Mail {
        pub from: Person,
        pub to: Person,
        pub contents: String,
    }
}

#[test]
fn encode_data_nesting() {
    use mail::{Mail, Person};

    let domain = eip712_domain! {};

    let mail = Mail {
        from: Person {
            name: "Cow".to_owned(),
            wallet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                .parse()
                .unwrap(),
        },
        to: Person {
            name: "Bob".to_owned(),
            wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                .parse()
                .unwrap(),
        },
        contents: "Hello, Bob!".to_owned(),
    };

    // Known EIP-712 test vector (from alloy's tests)
    assert_eq!(
        mail.eip712_signing_hash(&domain),
        b256!("25c3d40a39e639a4d0b6e4d2ace5e1281e039c88494d97d8d08f99a6ea75d775")
    );
}

#[test]
fn mail_encode_type() {
    use mail::{Mail, Person};

    assert_eq!(
        Person::eip712_encode_type().as_ref(),
        "Person(string name,address wallet)"
    );

    assert_eq!(
        Mail::eip712_encode_type().as_ref(),
        "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    );
}

#[test]
fn mail_type_hash() {
    use alloy::primitives::keccak256;
    use mail::Mail;

    // typeHash = keccak256(encodeType)
    let encode_type = Mail::eip712_encode_type();
    let expected_type_hash = keccak256(encode_type.as_bytes());

    let mail = Mail {
        from: mail::Person {
            name: String::new(),
            wallet: Address::ZERO,
        },
        to: mail::Person {
            name: String::new(),
            wallet: Address::ZERO,
        },
        contents: String::new(),
    };

    assert_eq!(mail.eip712_type_hash(), expected_type_hash);
}

#[abi]
mod deep {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Level1 {
        pub value: U256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Level2 {
        pub level1: Level1,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Level3 {
        pub level2: Level2,
        pub extra: bool,
    }
}

#[test]
fn deep_nesting_3_levels() {
    use deep::{Level1, Level2, Level3};

    assert_eq!(
        Level1::eip712_encode_type().as_ref(),
        "Level1(uint256 value)"
    );

    assert_eq!(
        Level2::eip712_encode_type().as_ref(),
        "Level2(Level1 level1)Level1(uint256 value)"
    );

    // Level3 depends on Level2, which depends on Level1
    // All transitive dependencies included, sorted alphabetically
    assert_eq!(
        Level3::eip712_encode_type().as_ref(),
        "Level3(Level2 level2,bool extra)Level1(uint256 value)Level2(Level1 level1)"
    );
}

#[test]
fn deep_nesting_components() {
    use deep::{Level1, Level2, Level3};

    assert!(Level1::eip712_components().is_empty());

    let l2_components = Level2::eip712_components();
    assert_eq!(l2_components.len(), 1);
    assert!(
        l2_components
            .iter()
            .any(|c| c.as_ref() == "Level1(uint256 value)")
    );

    let l3_components = Level3::eip712_components();
    assert_eq!(l3_components.len(), 2);
    assert!(
        l3_components
            .iter()
            .any(|c| c.as_ref() == "Level1(uint256 value)")
    );
    assert!(
        l3_components
            .iter()
            .any(|c| c.as_ref() == "Level2(Level1 level1)")
    );
}

#[abi]
mod diamond {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct A {
        pub value: U256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct B {
        pub a: A,
        pub b_field: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct C {
        pub a: A,
        pub c_field: Address,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct D {
        pub b: B,
        pub c: C,
    }
}

#[test]
fn diamond_dependency() {
    use diamond::{A, B, C, D};

    assert_eq!(A::eip712_encode_type().as_ref(), "A(uint256 value)");

    assert_eq!(
        B::eip712_encode_type().as_ref(),
        "B(A a,bool bField)A(uint256 value)"
    );

    assert_eq!(
        C::eip712_encode_type().as_ref(),
        "C(A a,address cField)A(uint256 value)"
    );

    // D depends on B and C, both depend on A
    // A should appear only once (deduplication)
    let d_encode_type = D::eip712_encode_type();
    assert_eq!(
        d_encode_type.as_ref(),
        "D(B b,C c)A(uint256 value)B(A a,bool bField)C(A a,address cField)"
    );

    // Verify A is not duplicated
    let a_count = d_encode_type.matches("A(uint256 value)").count();
    assert_eq!(a_count, 1, "A should appear exactly once (deduplication)");
}

#[test]
fn diamond_components_dedup() {
    use diamond::D;

    let components = D::eip712_components();

    // Should have A, B, C (not A, A, B, C)
    assert_eq!(components.len(), 3);

    // Verify no duplicates
    let mut seen = std::collections::HashSet::new();
    for c in &components {
        assert!(
            seen.insert(c.as_ref()),
            "Duplicate component found: {}",
            c.as_ref()
        );
    }
}

#[abi]
mod duplicate {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Point {
        pub x: U256,
        pub y: U256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Line {
        pub start: Point,
        pub end: Point,
    }
}

#[test]
fn duplicate_dependency_dedup() {
    use duplicate::{Line, Point};

    assert_eq!(
        Point::eip712_encode_type().as_ref(),
        "Point(uint256 x,uint256 y)"
    );

    // Point appears twice in Line's fields but should only appear once in encodeType
    let line_encode_type = Line::eip712_encode_type();
    assert_eq!(
        line_encode_type.as_ref(),
        "Line(Point start,Point end)Point(uint256 x,uint256 y)"
    );

    let point_count = line_encode_type
        .matches("Point(uint256 x,uint256 y)")
        .count();
    assert_eq!(point_count, 1, "Point should appear exactly once");
}

#[abi]
mod arrays {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Item {
        pub id: U256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Container {
        pub items: Vec<Item>,
    }
}

#[test]
fn array_of_structs_eip712() {
    use arrays::{Container, Item};

    assert_eq!(Item::eip712_encode_type().as_ref(), "Item(uint256 id)");

    // Array notation in root type, component still included
    assert_eq!(
        Container::eip712_root_type().as_ref(),
        "Container(Item[] items)"
    );

    assert_eq!(
        Container::eip712_encode_type().as_ref(),
        "Container(Item[] items)Item(uint256 id)"
    );
}

#[test]
fn type_hash_matches_keccak_encode_type() {
    use alloy::primitives::keccak256;
    use nesting::{A, B, C, D};

    fn check_type_hash<T: SolStruct + Default>() {
        let instance = T::default();
        let encode_type = T::eip712_encode_type();
        let expected = keccak256(encode_type.as_bytes());
        assert_eq!(
            instance.eip712_type_hash(),
            expected,
            "type_hash mismatch for {}",
            T::NAME
        );
    }

    check_type_hash::<A>();
    check_type_hash::<B>();
    check_type_hash::<C>();
    check_type_hash::<D>();
}

#[test]
fn hash_struct_composition() {
    use alloy::primitives::Keccak256;
    use nesting::A;

    let a = A { a: U256::from(42) };

    // Manual computation: hashStruct = keccak256(typeHash || encodeData)
    let mut hasher = Keccak256::new();
    hasher.update(a.eip712_type_hash());
    hasher.update(a.eip712_encode_data());
    let expected = hasher.finalize();

    assert_eq!(a.eip712_hash_struct(), expected);
}

#[test]
fn nested_struct_abi_roundtrip() {
    use nesting::{A, B, C, D};

    let a = A { a: U256::from(1) };
    let b = B {
        b: B256::repeat_byte(0x42),
    };
    let c = C {
        a: a.clone(),
        b: b.clone(),
    };
    let d = D {
        c: c.clone(),
        a: a.clone(),
        b: b.clone(),
    };

    // Round-trip all structs
    assert_eq!(A::abi_decode(&a.abi_encode()).unwrap(), a);
    assert_eq!(B::abi_decode(&b.abi_encode()).unwrap(), b);
    assert_eq!(C::abi_decode(&c.abi_encode()).unwrap(), c);
    assert_eq!(D::abi_decode(&d.abi_encode()).unwrap(), d);
}
