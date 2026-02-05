//! Field resolver for computing storage slot locations.
//!
//! This module provides utilities to resolve storage slot addresses for fields
//! in tempo precompile contracts based on field names and optional mapping keys.
//!
//! For test-utils, this module also provides the `SeedFromJson` trait and `SeedFn`
//! function pointer for seeding storage fields from JSON values.

use alloy::primitives::{Address, FixedBytes, U256};
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

    /// An error occurred during JSON seeding.
    #[error("seed error: {0}")]
    Seed(#[from] SeedError),
}

/// Errors that can occur during JSON seeding.
#[derive(Debug, Error)]
pub enum SeedError {
    /// Expected a different JSON type.
    #[error("expected {expected}, got {got}")]
    TypeMismatch {
        expected: &'static str,
        got: &'static str,
    },

    /// Value is out of range for the target type.
    #[error("value out of range: {0}")]
    OutOfRange(String),

    /// Failed to parse a value.
    #[error("parse error: {0}")]
    Parse(String),

    /// String is too long for short string encoding.
    #[error("string too long: {len} bytes (max 31)")]
    StringTooLong { len: usize },
}

/// Function pointer type for seeding a field from JSON.
///
/// Takes the JSON value and returns the encoded U256 word.
/// The caller is responsible for packing into the correct slot offset.
pub type SeedFn = fn(&serde_json::Value) -> Result<U256, SeedError>;

/// Trait for types that can be parsed from JSON for storage seeding.
///
/// Implementations convert a JSON value to the type, which can then be
/// encoded to a U256 word using `FromWord::to_word()`.
pub trait SeedFromJson: Sized {
    /// Parse this type from a JSON value.
    fn from_json(value: &serde_json::Value) -> Result<Self, SeedError>;
}

/// Metadata about a storage field.
#[derive(Debug, Clone, Copy)]
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
    /// Function to seed this field from JSON.
    pub seed: SeedFn,
}

impl PartialEq for FieldMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.slot == other.slot
            && self.offset == other.offset
            && self.bytes == other.bytes
            && self.is_mapping == other.is_mapping
            && self.nesting_depth == other.nesting_depth
    }
}

impl Eq for FieldMetadata {}

/// Helper to parse a string as a number (decimal or hex).
fn parse_numeric_str<T, F>(s: &str, parse_fn: F) -> Result<T, SeedError>
where
    F: Fn(&str, u32) -> Result<T, std::num::ParseIntError>,
{
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        parse_fn(hex, 16).map_err(|e| SeedError::Parse(e.to_string()))
    } else {
        parse_fn(s, 10).map_err(|e| SeedError::Parse(e.to_string()))
    }
}

impl SeedFromJson for bool {
    fn from_json(value: &serde_json::Value) -> Result<Self, SeedError> {
        if let Some(b) = value.as_bool() {
            return Ok(b);
        }
        if let Some(n) = value.as_u64() {
            return Ok(n != 0);
        }
        if let Some(s) = value.as_str() {
            return match s.to_lowercase().as_str() {
                "true" | "1" => Ok(true),
                "false" | "0" => Ok(false),
                _ => Err(SeedError::Parse(format!("invalid bool: {s}"))),
            };
        }
        Err(SeedError::TypeMismatch {
            expected: "bool",
            got: json_type_name(value),
        })
    }
}

impl SeedFromJson for Address {
    fn from_json(value: &serde_json::Value) -> Result<Self, SeedError> {
        let s = value.as_str().ok_or(SeedError::TypeMismatch {
            expected: "address string",
            got: json_type_name(value),
        })?;
        s.parse().map_err(|e| SeedError::Parse(format!("{e}")))
    }
}

impl SeedFromJson for U256 {
    fn from_json(value: &serde_json::Value) -> Result<Self, SeedError> {
        let s = value.as_str().ok_or(SeedError::TypeMismatch {
            expected: "U256 string",
            got: json_type_name(value),
        })?;
        parse_u256_str(s)
    }
}

fn parse_u256_str(s: &str) -> Result<U256, SeedError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        U256::from_str_radix(hex, 16).map_err(|e| SeedError::Parse(e.to_string()))
    } else {
        U256::from_str_radix(s, 10).map_err(|e| SeedError::Parse(e.to_string()))
    }
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

macro_rules! impl_seed_from_json_uint {
    ($($ty:ty),*) => {
        $(
            impl SeedFromJson for $ty {
                fn from_json(value: &serde_json::Value) -> Result<Self, SeedError> {
                    if let Some(n) = value.as_u64() {
                        return <$ty>::try_from(n).map_err(|_| SeedError::OutOfRange(
                            format!("{} does not fit in {}", n, stringify!($ty))
                        ));
                    }
                    if let Some(s) = value.as_str() {
                        return parse_numeric_str(s, |s, radix| <$ty>::from_str_radix(s, radix));
                    }
                    Err(SeedError::TypeMismatch {
                        expected: stringify!($ty),
                        got: json_type_name(value),
                    })
                }
            }
        )*
    };
}

macro_rules! impl_seed_from_json_int {
    ($($ty:ty),*) => {
        $(
            impl SeedFromJson for $ty {
                fn from_json(value: &serde_json::Value) -> Result<Self, SeedError> {
                    if let Some(n) = value.as_i64() {
                        return <$ty>::try_from(n).map_err(|_| SeedError::OutOfRange(
                            format!("{} does not fit in {}", n, stringify!($ty))
                        ));
                    }
                    if let Some(s) = value.as_str() {
                        return parse_numeric_str(s, |s, radix| <$ty>::from_str_radix(s, radix));
                    }
                    Err(SeedError::TypeMismatch {
                        expected: stringify!($ty),
                        got: json_type_name(value),
                    })
                }
            }
        )*
    };
}

impl_seed_from_json_uint!(u8, u16, u32, u64, u128);
impl_seed_from_json_int!(i8, i16, i32, i64, i128);

/// Implement SeedFromJson for FixedBytes<N> where N is 1..=32.
macro_rules! impl_seed_from_json_fixed_bytes {
    ($($n:literal),*) => {
        $(
            impl SeedFromJson for FixedBytes<$n> {
                fn from_json(value: &serde_json::Value) -> Result<Self, SeedError> {
                    let s = value.as_str().ok_or(SeedError::TypeMismatch {
                        expected: concat!("FixedBytes<", stringify!($n), "> hex string"),
                        got: json_type_name(value),
                    })?;
                    s.parse().map_err(|e| SeedError::Parse(format!("{e}")))
                }
            }
        )*
    };
}

impl_seed_from_json_fixed_bytes!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32
);

/// Marker type for Solidity short string encoding (≤31 bytes).
///
/// Encodes as: left-aligned bytes with (length * 2) in the LSB.
pub struct ShortString;

impl ShortString {
    /// Maximum length for short strings.
    pub const MAX_LEN: usize = 31;

    /// Seed function for short string fields.
    pub fn seed(value: &serde_json::Value) -> Result<U256, SeedError> {
        let s = value.as_str().ok_or(SeedError::TypeMismatch {
            expected: "string",
            got: json_type_name(value),
        })?;
        Self::encode(s)
    }

    /// Encode a string as a Solidity short string.
    pub fn encode(s: &str) -> Result<U256, SeedError> {
        let bytes = s.as_bytes();
        if bytes.len() > Self::MAX_LEN {
            return Err(SeedError::StringTooLong { len: bytes.len() });
        }

        let mut buf = [0u8; 32];
        buf[..bytes.len()].copy_from_slice(bytes);
        buf[31] = (bytes.len() * 2) as u8;

        Ok(U256::from_be_bytes(buf))
    }
}

/// Marker type for array/vec length fields.
///
/// Stores only the length of the array at the base slot.
pub struct VecLen;

impl VecLen {
    /// Seed function for vec length fields.
    pub fn seed(value: &serde_json::Value) -> Result<U256, SeedError> {
        let arr = value.as_array().ok_or(SeedError::TypeMismatch {
            expected: "array",
            got: json_type_name(value),
        })?;
        Ok(U256::from(arr.len()))
    }
}

/// Trait for types that can provide a seed function.
///
/// Primitives (types with `Layout::Bytes`) implement this via a blanket impl.
/// Struct types use `struct_seed_unsupported` as a fallback.
pub trait Seedable {
    /// Returns the seed function for this type.
    fn seed_fn() -> SeedFn;
}

/// Blanket implementation for primitives.
///
/// Types that implement `SeedFromJson + FromWord` are primitives with `Layout::Bytes`.
/// The `FromWord` trait is sealed and only implemented for primitive types.
impl<T: SeedFromJson + crate::storage::FromWord> Seedable for T {
    fn seed_fn() -> SeedFn {
        |value| {
            let v = T::from_json(value)?;
            Ok(v.to_word())
        }
    }
}

/// A placeholder seed function for struct types that require custom seeding.
///
/// This is used for structs like `AuthorizedKey`, `PolicyData`, etc. that have
/// custom `encode_to_slot()` methods. The actual encoding is done via the
/// struct-specific seed functions registered in the execution-tests database.
pub fn struct_seed_unsupported(_value: &serde_json::Value) -> Result<U256, SeedError> {
    Err(SeedError::Parse(
        "struct types require custom seed functions registered in execution-tests".to_string(),
    ))
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
