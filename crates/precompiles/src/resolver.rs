//! Field resolver for computing storage slot locations.
//!
//! This module provides utilities to resolve storage slot addresses for fields
//! in tempo precompile contracts based on field names and optional mapping keys.

use alloy::primitives::U256;
use thiserror::Error;

#[cfg(any(test, feature = "test-utils"))]
use crate::{
    account_keychain::AccountKeychain, nonce::NonceManager, stablecoin_dex::StablecoinDEX,
    tip_fee_manager::TipFeeManager, tip20::TIP20Token, tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry, validator_config::ValidatorConfig,
};

/// Errors that can occur during field resolution.
#[derive(Debug, Error)]
pub enum ResolverError {
    /// The specified contract name is not recognized.
    #[error("unknown contract: {0}")]
    UnknownContract(String),

    /// The specified field name is not recognized for the contract.
    #[error("unknown field: {0}")]
    UnknownField(String),

    /// A required mapping key is missing.
    #[error("missing key at index {0}")]
    MissingKey(usize),

    /// A provided key could not be parsed.
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

/// Metadata about a storage field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldMetadata {
    /// The computed storage slot
    pub slot: U256,
    /// Byte offset within the slot (for packed fields)
    pub offset: usize,
    /// Size in bytes
    pub bytes: usize,
    /// Whether this is a mapping field
    pub is_mapping: bool,
    /// Nesting depth (0 = direct field, 1 = Mapping<K,V>, 2 = Mapping<K,Mapping<...>>)
    pub nesting_depth: u8,
}

/// Resolves the storage metadata for a field in a contract.
///
/// # Arguments
///
/// * `contract` - The contract name (e.g., "TIP20Token")
/// * `field` - The field name (e.g., "total_supply", "balances")
/// * `keys` - Optional mapping keys for nested mappings (e.g., holder address for balances)
///
/// # Returns
///
/// The field metadata including computed storage slot.
#[cfg(any(test, feature = "test-utils"))]
pub fn metadata_for(
    contract: &str,
    field: &str,
    keys: &[&str],
) -> Result<FieldMetadata, ResolverError> {
    match contract {
        "TIP20Token" => TIP20Token::metadata_for(field, keys),
        "TIP20Factory" => TIP20Factory::metadata_for(field, keys),
        "NonceManager" => NonceManager::metadata_for(field, keys),
        "AccountKeychain" => AccountKeychain::metadata_for(field, keys),
        "StablecoinDEX" => StablecoinDEX::metadata_for(field, keys),
        "TIP403Registry" => TIP403Registry::metadata_for(field, keys),
        "TipFeeManager" => TipFeeManager::metadata_for(field, keys),
        "ValidatorConfig" => ValidatorConfig::metadata_for(field, keys),
        _ => Err(ResolverError::UnknownContract(contract.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account_keychain::slots as account_keychain_slots, nonce::slots as nonce_slots,
        stablecoin_dex::slots as stablecoin_dex_slots,
        tip403_registry::slots as tip403_registry_slots,
        validator_config::slots as validator_config_slots,
    };

    const TEST_HOLDER: &str = "0x1111111111111111111111111111111111111111";
    const TEST_SPENDER: &str = "0x2222222222222222222222222222222222222222";

    #[test]
    fn test_resolve_simple_field() {
        let slot = metadata_for("TIP20Token", "total_supply", &[])
            .unwrap()
            .slot;
        assert!(!slot.is_zero() || slot == U256::from(9));
    }

    #[test]
    fn test_resolve_balances() {
        let slot = metadata_for("TIP20Token", "balances", &[TEST_HOLDER])
            .unwrap()
            .slot;
        assert!(!slot.is_zero());
    }

    #[test]
    fn test_resolve_balances_different_holders() {
        let slot1 = metadata_for("TIP20Token", "balances", &[TEST_HOLDER])
            .unwrap()
            .slot;
        let slot2 = metadata_for("TIP20Token", "balances", &[TEST_SPENDER])
            .unwrap()
            .slot;
        assert_ne!(slot1, slot2);
    }

    #[test]
    fn test_resolve_allowances() {
        let slot = metadata_for("TIP20Token", "allowances", &[TEST_HOLDER, TEST_SPENDER])
            .unwrap()
            .slot;
        assert!(!slot.is_zero());
    }

    #[test]
    fn test_resolve_missing_key() {
        let result = metadata_for("TIP20Token", "balances", &[]);
        assert!(matches!(result, Err(ResolverError::MissingKey(0))));
    }

    #[test]
    fn test_resolve_invalid_key() {
        let result = metadata_for("TIP20Token", "balances", &["not_an_address"]);
        assert!(matches!(result, Err(ResolverError::InvalidKey(_))));
    }

    #[test]
    fn test_resolve_unknown_field() {
        let result = metadata_for("TIP20Token", "nonexistent_field", &[]);
        assert!(matches!(result, Err(ResolverError::UnknownField(_))));
    }

    #[test]
    fn test_resolve_unknown_contract() {
        let result = metadata_for("UnknownContract", "field", &[]);
        assert!(matches!(result, Err(ResolverError::UnknownContract(_))));
    }

    #[test]
    fn test_resolve_currency() {
        let slot = metadata_for("TIP20Token", "currency", &[]).unwrap().slot;
        assert!(!slot.is_zero() || slot == U256::from(4));
    }

    #[test]
    fn test_resolve_transfer_policy_id() {
        let slot = metadata_for("TIP20Token", "transfer_policy_id", &[])
            .unwrap()
            .slot;
        assert!(!slot.is_zero() || slot == U256::from(8));
    }

    // NonceManager tests
    #[test]
    fn test_resolve_nonce_manager_nonces() {
        let slot = metadata_for("NonceManager", "nonces", &[TEST_HOLDER, "5"])
            .unwrap()
            .slot;
        assert!(!slot.is_zero());
    }

    #[test]
    fn test_resolve_nonce_manager_expiring_nonce_ring_ptr() {
        let slot = metadata_for("NonceManager", "expiring_nonce_ring_ptr", &[])
            .unwrap()
            .slot;
        assert_eq!(slot, nonce_slots::EXPIRING_NONCE_RING_PTR);
    }

    // AccountKeychain tests
    #[test]
    fn test_resolve_account_keychain_keys() {
        let slot = metadata_for("AccountKeychain", "keys", &[TEST_HOLDER, TEST_SPENDER])
            .unwrap()
            .slot;
        assert!(!slot.is_zero());
    }

    #[test]
    fn test_resolve_account_keychain_transaction_key() {
        let slot = metadata_for("AccountKeychain", "transaction_key", &[])
            .unwrap()
            .slot;
        assert_eq!(slot, account_keychain_slots::TRANSACTION_KEY);
    }

    // StablecoinDEX tests
    #[test]
    fn test_resolve_stablecoin_dex_next_order_id() {
        let slot = metadata_for("StablecoinDEX", "next_order_id", &[])
            .unwrap()
            .slot;
        assert_eq!(slot, stablecoin_dex_slots::NEXT_ORDER_ID);
    }

    #[test]
    fn test_resolve_stablecoin_dex_balances() {
        let slot = metadata_for("StablecoinDEX", "balances", &[TEST_HOLDER, TEST_SPENDER])
            .unwrap()
            .slot;
        assert!(!slot.is_zero());
    }

    // TIP403Registry tests
    #[test]
    fn test_resolve_tip403_registry_policy_id_counter() {
        let slot = metadata_for("TIP403Registry", "policy_id_counter", &[])
            .unwrap()
            .slot;
        assert_eq!(slot, tip403_registry_slots::POLICY_ID_COUNTER);
    }

    #[test]
    fn test_resolve_tip403_registry_policy_set() {
        let slot = metadata_for("TIP403Registry", "policy_set", &["1", TEST_HOLDER])
            .unwrap()
            .slot;
        assert!(!slot.is_zero());
    }

    // TipFeeManager tests
    #[test]
    fn test_resolve_tip_fee_manager_validator_tokens() {
        let slot = metadata_for("TipFeeManager", "validator_tokens", &[TEST_HOLDER])
            .unwrap()
            .slot;
        assert!(!slot.is_zero());
    }

    #[test]
    fn test_resolve_tip_fee_manager_collected_fees() {
        let slot = metadata_for(
            "TipFeeManager",
            "collected_fees",
            &[TEST_HOLDER, TEST_SPENDER],
        )
        .unwrap()
        .slot;
        assert!(!slot.is_zero());
    }

    // ValidatorConfig tests
    #[test]
    fn test_resolve_validator_config_owner() {
        let slot = metadata_for("ValidatorConfig", "owner", &[]).unwrap().slot;
        assert_eq!(slot, validator_config_slots::OWNER);
    }

    #[test]
    fn test_resolve_validator_config_validators() {
        let slot = metadata_for("ValidatorConfig", "validators", &[TEST_HOLDER])
            .unwrap()
            .slot;
        assert!(!slot.is_zero());
    }

    #[test]
    fn test_resolve_validator_config_next_dkg_ceremony() {
        let slot = metadata_for("ValidatorConfig", "next_dkg_ceremony", &[])
            .unwrap()
            .slot;
        assert_eq!(slot, validator_config_slots::NEXT_DKG_CEREMONY);
    }
}
