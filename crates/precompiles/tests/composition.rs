//! Tests for TIP20 abi module types (Calls, Error, Event).
//!
//! These tests verify the solidity-generated types work correctly without
//! using the #[contract] macro (which has path issues in integration tests).

use alloy::{
    primitives::{Address, B256, IntoLogData, U256},
    sol_types::{SolCall, SolInterface},
};
use tempo_precompiles::tip20::abi;

#[test]
fn test_calls_enum_decode() {
    // Test Token calls
    let call = abi::balanceOfCall {
        account: Address::random(),
    };
    let encoded = <abi::ITokenCalls as SolInterface>::abi_encode(&call.clone().into());

    let decoded = abi::Calls::abi_decode(&encoded).unwrap();
    assert!(matches!(
        decoded,
        abi::Calls::IToken(abi::ITokenCalls::balanceOf(_))
    ));

    // Test RolesAuth calls
    let call = abi::hasRoleCall {
        role: B256::random(),
        account: Address::random(),
    };
    let encoded = <abi::IRolesAuthCalls as SolInterface>::abi_encode(&call.into());

    let decoded = abi::Calls::abi_decode(&encoded).unwrap();
    assert!(matches!(
        decoded,
        abi::Calls::IRolesAuth(abi::IRolesAuthCalls::hasRole(_))
    ));
}

#[test]
fn test_calls_selectors() {
    assert!(!abi::Calls::SELECTORS.is_empty());

    // Verify all selectors are valid
    for selector in abi::Calls::SELECTORS {
        assert!(abi::Calls::valid_selector(*selector));
    }

    // Check specific selectors
    assert!(abi::Calls::valid_selector(abi::balanceOfCall::SELECTOR));
    assert!(abi::Calls::valid_selector(abi::hasRoleCall::SELECTOR));
    assert!(abi::Calls::valid_selector(
        abi::distributeRewardCall::SELECTOR
    ));
}

#[test]
fn test_error_constructors() {
    let err = abi::Error::insufficient_balance(U256::from(100), U256::from(200), Address::random());
    assert!(matches!(err, abi::Error::InsufficientBalance(_)));

    let err = abi::Error::unauthorized();
    assert!(matches!(err, abi::Error::Unauthorized(_)));
}

#[test]
fn test_event_constructors() {
    let event = abi::Event::transfer(Address::random(), Address::random(), U256::from(100));
    assert!(matches!(event, abi::Event::Transfer(_)));
    let log_data = event.into_log_data();
    assert!(!log_data.topics().is_empty());

    let event = abi::Event::role_membership_updated(
        B256::random(),
        Address::random(),
        Address::random(),
        true,
    );
    assert!(matches!(event, abi::Event::RoleMembershipUpdated(_)));
}

#[test]
fn test_unknown_selector_returns_error() {
    let unknown_calldata = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00];
    let result = abi::Calls::abi_decode(&unknown_calldata);
    assert!(result.is_err());
}

#[test]
fn test_sol_call_trait_methods() {
    let call = abi::balanceOfCall {
        account: Address::random(),
    };

    // Test SolCall trait via associated items
    assert_eq!(
        <abi::balanceOfCall as SolCall>::SELECTOR,
        abi::balanceOfCall::SELECTOR
    );
    assert!(<abi::balanceOfCall as SolCall>::abi_encoded_size(&call) > 0);
}
