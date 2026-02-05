//! Database seeding for test vectors.
//!
//! This module provides utilities to create an in-memory CacheDB
//! populated with the prestate defined in a test vector.
//!
//! The seeding system uses a generic approach driven by `FieldMetadata` from
//! the precompile resolver. Most fields are automatically inferred from their
//! byte size (32 = U256, 20 = Address, etc.), with special cases handled via
//! an explicit `SeedKind` override table.

use crate::vector::{PrecompileState, Prestate};
use alloy_primitives::{Address, B256, Bytes, U256};
use revm::{
    DatabaseRef,
    database::{CacheDB, EmptyDB},
    primitives::KECCAK_EMPTY,
    state::{AccountInfo, Bytecode},
};
use tempo_precompiles::{
    account_keychain::AuthorizedKey,
    resolver::metadata_for,
    storage::{FromWord, packing::insert_into_word},
    tip403_registry::PolicyData,
};

/// Marker bytecode for precompile accounts (invalid opcode, won't execute).
/// TIP20 tokens check `is_initialized()` which requires non-empty code hash.
const PRECOMPILE_MARKER_BYTECODE: u8 = 0xEF;

/// Maximum length for Solidity short strings.
const MAX_SHORT_STRING_LEN: usize = 31;

// ============================================================================
// SeedKind: Override table for special encoding cases
// ============================================================================

/// Specifies how a field should be encoded when seeding.
/// Most fields use `DefaultPrimitive`, which infers the type from `meta.bytes`.
#[derive(Debug, Clone, Copy)]
enum SeedKind {
    /// Infer encoding from meta.bytes (32=U256, 20=Address, 8=u64, etc.)
    DefaultPrimitive,
    /// Encode as Solidity short string (≤31 bytes, length*2 in LSB)
    ShortString,
    /// Store array length only (for Vec fields)
    ArrayLenOnly,
    /// Encode AuthorizedKey struct
    AuthorizedKeyStruct,
    /// Encode PolicyData struct
    PolicyDataStruct,
}

/// Returns the `SeedKind` for a given (contract, field) pair.
/// Fields not in this table use `DefaultPrimitive`, which infers type from metadata.
fn seed_kind(contract: &str, field: &str) -> SeedKind {
    match (contract, field) {
        // Short string fields (Solidity string encoding)
        ("TIP20Token", "name" | "symbol" | "currency") => SeedKind::ShortString,

        // Array length-only fields (store length at base slot)
        ("StablecoinDEX", "book_keys") => SeedKind::ArrayLenOnly,
        ("ValidatorConfig", "validators_array") => SeedKind::ArrayLenOnly,

        // Complex struct fields with custom encoders
        ("AccountKeychain", "keys") => SeedKind::AuthorizedKeyStruct,
        ("TIP403Registry", "policy_data") => SeedKind::PolicyDataStruct,

        // All other fields use default primitive inference
        _ => SeedKind::DefaultPrimitive,
    }
}

/// A database seeded from a test vector's prestate.
pub struct VectorDatabase {
    /// The underlying CacheDB
    pub db: CacheDB<EmptyDB>,
}

impl VectorDatabase {
    /// Create a new database from a prestate definition.
    pub fn from_prestate(prestate: &Prestate) -> eyre::Result<Self> {
        let mut db = CacheDB::new(EmptyDB::default());

        // Insert accounts (balance, nonce)
        for (address, account) in &prestate.accounts {
            let code_hash = prestate
                .code
                .get(address)
                .map(hash_bytes)
                .unwrap_or(KECCAK_EMPTY);

            let info = AccountInfo {
                balance: U256::ZERO,
                nonce: account.nonce,
                code_hash,
                code: prestate
                    .code
                    .get(address)
                    .map(|c| Bytecode::new_raw(c.clone())),
                ..Default::default()
            };

            db.insert_account_info(*address, info);
        }

        // Insert code for addresses not in accounts
        for (address, code) in &prestate.code {
            if !prestate.accounts.contains_key(address) {
                let info = AccountInfo {
                    balance: U256::ZERO,
                    nonce: 0,
                    code_hash: hash_bytes(code),
                    code: Some(Bytecode::new_raw(code.clone())),
                    ..Default::default()
                };
                db.insert_account_info(*address, info);
            }
        }

        // Insert storage
        for (address, slots) in &prestate.storage {
            // Ensure account exists
            if !prestate.accounts.contains_key(address) && !prestate.code.contains_key(address) {
                db.insert_account_info(*address, AccountInfo::default());
            }

            for (slot, value) in slots {
                db.insert_account_storage(*address, *slot, *value)?;
            }
        }

        let mut vector_db = Self { db };
        vector_db.seed_precompiles(&prestate.precompiles)?;
        Ok(vector_db)
    }

    /// Seeds precompile state from test vector definitions.
    ///
    /// For each precompile in the prestate, parses the fields JSON and writes
    /// the appropriate storage slots using the resolver.
    fn seed_precompiles(&mut self, precompiles: &[PrecompileState]) -> eyre::Result<()> {
        for precompile in precompiles {
            self.seed_precompile(precompile)?;
        }
        Ok(())
    }

    /// Seeds a single precompile's state using the generic field seeder.
    fn seed_precompile(&mut self, precompile: &PrecompileState) -> eyre::Result<()> {
        let address = precompile.address;
        let contract = &precompile.name;

        // Ensure the precompile account exists with bytecode.
        let marker_code = Bytecode::new_raw(Bytes::from_static(&[PRECOMPILE_MARKER_BYTECODE]));
        let info = AccountInfo {
            code_hash: alloy_primitives::keccak256([PRECOMPILE_MARKER_BYTECODE]),
            code: Some(marker_code),
            ..Default::default()
        };
        self.db.insert_account_info(address, info);

        let fields = precompile
            .fields
            .as_object()
            .ok_or_else(|| eyre::eyre!("fields must be an object"))?;

        for (field_name, value) in fields {
            self.seed_field(address, contract, field_name, value)?;
        }

        Ok(())
    }

    /// Generic entry point for seeding a single field.
    /// Handles scalars, mappings (nested or flat), and arrays based on JSON shape.
    fn seed_field(
        &mut self,
        address: Address,
        contract: &str,
        field: &str,
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        let kind = seed_kind(contract, field);

        // Handle array length fields specially
        if matches!(kind, SeedKind::ArrayLenOnly) {
            let arr = value
                .as_array()
                .ok_or_else(|| eyre::eyre!("{} must be an array", field))?;
            let meta = metadata_for(contract, field, &[])?;
            self.db
                .insert_account_storage(address, meta.slot, U256::from(arr.len()))?;
            return Ok(());
        }

        // Check if this is a mapping by trying to get metadata without keys
        let base_meta = metadata_for(contract, field, &[]);

        match base_meta {
            Ok(meta) if meta.is_mapping => {
                // This is a mapping field - traverse the JSON object
                self.seed_mapping(address, contract, field, value, vec![], meta.nesting_depth)?;
            }
            Ok(_) => {
                // Non-mapping field - seed as scalar
                self.seed_scalar(address, contract, field, &[], value)?;
            }
            Err(tempo_precompiles::resolver::ResolverError::MissingKey(_)) => {
                // Needs keys - it's a mapping
                let meta = metadata_for(contract, field, &["0x0000000000000000000000000000000000000000"])?;
                self.seed_mapping(address, contract, field, value, vec![], meta.nesting_depth)?;
            }
            Err(e) => return Err(eyre::eyre!("field resolution failed: {}", e)),
        }

        Ok(())
    }

    /// Recursively traverses a mapping's JSON object and seeds each leaf value.
    fn seed_mapping(
        &mut self,
        address: Address,
        contract: &str,
        field: &str,
        value: &serde_json::Value,
        keys: Vec<String>,
        remaining_depth: u8,
    ) -> eyre::Result<()> {
        let map = value
            .as_object()
            .ok_or_else(|| eyre::eyre!("{} must be an object", field))?;

        for (key, inner_value) in map {
            let mut new_keys = keys.clone();
            new_keys.push(key.clone());

            if remaining_depth > 1 && inner_value.is_object() {
                // More nesting levels to go
                self.seed_mapping(
                    address,
                    contract,
                    field,
                    inner_value,
                    new_keys,
                    remaining_depth - 1,
                )?;
            } else {
                // Leaf value - seed as scalar
                let key_refs: Vec<&str> = new_keys.iter().map(|s| s.as_str()).collect();
                self.seed_scalar(address, contract, field, &key_refs, inner_value)?;
            }
        }

        Ok(())
    }

    /// Seeds a scalar value at a specific storage slot.
    /// Uses `insert_into_word` for packed fields, writing directly for full-slot values.
    fn seed_scalar(
        &mut self,
        address: Address,
        contract: &str,
        field: &str,
        keys: &[&str],
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        let meta = metadata_for(contract, field, keys)?;
        let kind = seed_kind(contract, field);
        let is_packed = meta.offset > 0 || meta.bytes < 32;

        // For packed fields, read current slot value
        let current = if is_packed {
            self.db.storage_ref(address, meta.slot).unwrap_or(U256::ZERO)
        } else {
            U256::ZERO
        };

        // Encode and optionally pack based on SeedKind
        let final_value = match kind {
            SeedKind::ShortString => {
                let s = value
                    .as_str()
                    .ok_or_else(|| eyre::eyre!("{} must be a string", field))?;
                encode_short_string(s)?
            }
            SeedKind::AuthorizedKeyStruct => {
                let info = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("{} value must be an object", field))?;
                encode_authorized_key(info)?
            }
            SeedKind::PolicyDataStruct => {
                let info = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("{} value must be an object", field))?;
                encode_policy_data(info)?
            }
            SeedKind::ArrayLenOnly => {
                unreachable!("ArrayLenOnly handled in seed_field")
            }
            SeedKind::DefaultPrimitive => {
                // Use insert_into_word with typed values for proper packing
                encode_and_pack_by_size(field, meta.bytes, value, current, meta.offset, is_packed)?
            }
        };

        self.db.insert_account_storage(address, meta.slot, final_value)?;
        Ok(())
    }

    /// Get a reference to the underlying database.
    pub fn inner(&self) -> &CacheDB<EmptyDB> {
        &self.db
    }

    /// Read a storage slot from the database.
    pub fn storage(&self, address: Address, slot: U256) -> eyre::Result<U256> {
        self.db
            .storage_ref(address, slot)
            .map_err(|e| eyre::eyre!("storage read failed: {:?}", e))
    }

    /// Read account info from the database.
    pub fn account(&self, address: Address) -> eyre::Result<Option<AccountInfo>> {
        self.db
            .basic_ref(address)
            .map_err(|e| eyre::eyre!("account read failed: {:?}", e))
    }
}

/// Compute keccak256 hash of bytes
fn hash_bytes(data: &Bytes) -> B256 {
    alloy_primitives::keccak256(data)
}

/// Encodes a string as a Solidity short string (≤31 bytes).
/// Format: left-aligned bytes with (length * 2) in the LSB.
fn encode_short_string(s: &str) -> eyre::Result<U256> {
    let bytes = s.as_bytes();
    if bytes.len() > MAX_SHORT_STRING_LEN {
        return Err(eyre::eyre!(
            "string too long for short string encoding: {} bytes",
            bytes.len()
        ));
    }

    let mut buf = [0u8; 32];
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[31] = (bytes.len() * 2) as u8;

    Ok(U256::from_be_bytes(buf))
}

/// Encodes a JSON value based on byte size and packs it using `insert_into_word`.
/// Uses typed parsing and the precompile packing infrastructure for correctness.
/// Maps: 32 -> U256, 20 -> Address, 16 -> u128, 8 -> u64, 4 -> u32, 1 -> bool/u8
fn encode_and_pack_by_size(
    field: &str,
    bytes: usize,
    value: &serde_json::Value,
    current: U256,
    offset: usize,
    is_packed: bool,
) -> eyre::Result<U256> {
    // Macro to handle packing vs direct encoding for typed values
    macro_rules! pack_or_encode {
        ($v:expr) => {
            if is_packed {
                insert_into_word(current, $v, offset, bytes)
                    .map_err(|e| eyre::eyre!("packing failed: {}", e))
            } else {
                Ok($v.to_word())
            }
        };
    }

    match bytes {
        32 => {
            // U256 or B256 - full slot, no packing needed
            if let Some(s) = value.as_str() {
                if s.starts_with("0x") && s.len() == 66 {
                    let hash: B256 = s.parse()?;
                    return Ok(U256::from_be_bytes(hash.0));
                }
                parse_u256_str(s)
            } else {
                Err(eyre::eyre!("{} must be a string for U256/B256", field))
            }
        }
        20 => {
            let addr_str = value
                .as_str()
                .ok_or_else(|| eyre::eyre!("{} must be an address string", field))?;
            let addr: Address = addr_str.parse()?;
            pack_or_encode!(&addr)
        }
        16 => {
            let v = parse_u128_value(value)?;
            pack_or_encode!(&v)
        }
        8 => {
            let v = parse_u64_value(value)?;
            pack_or_encode!(&v)
        }
        4 => {
            let v = parse_u64_value(value)?;
            if v > u32::MAX as u64 {
                return Err(eyre::eyre!("{} value {} exceeds u32::MAX", field, v));
            }
            pack_or_encode!(&(v as u32))
        }
        1 => {
            if let Some(b) = value.as_bool() {
                pack_or_encode!(&b)
            } else if let Some(n) = value.as_u64() {
                if n > u8::MAX as u64 {
                    return Err(eyre::eyre!("{} value {} exceeds u8::MAX", field, n));
                }
                pack_or_encode!(&(n as u8))
            } else {
                Err(eyre::eyre!("{} must be a boolean or small integer", field))
            }
        }
        _ => {
            // Unknown size - try to parse as U256 (fallback for raw packed data)
            parse_u256_value(value)
        }
    }
}

/// Parses a JSON value as U256 (accepts decimal or hex string).
fn parse_u256_value(value: &serde_json::Value) -> eyre::Result<U256> {
    let s = value
        .as_str()
        .ok_or_else(|| eyre::eyre!("expected string value for U256"))?;
    parse_u256_str(s)
}

/// Parses a string as U256 (accepts decimal or hex).
fn parse_u256_str(s: &str) -> eyre::Result<U256> {
    if s.starts_with("0x") || s.starts_with("0X") {
        U256::from_str_radix(&s[2..], 16).map_err(|e| eyre::eyre!("invalid hex U256: {}", e))
    } else {
        U256::from_str_radix(s, 10).map_err(|e| eyre::eyre!("invalid decimal U256: {}", e))
    }
}

/// Parses a JSON value as u64 (accepts number or decimal/hex string).
fn parse_u64_value(value: &serde_json::Value) -> eyre::Result<u64> {
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    let s = value
        .as_str()
        .ok_or_else(|| eyre::eyre!("expected number or string for u64"))?;
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| eyre::eyre!("invalid hex u64: {}", e))
    } else {
        s.parse()
            .map_err(|e| eyre::eyre!("invalid decimal u64: {}", e))
    }
}

/// Parses a JSON value as u128 (accepts number or decimal/hex string).
fn parse_u128_value(value: &serde_json::Value) -> eyre::Result<u128> {
    if let Some(n) = value.as_u64() {
        return Ok(n as u128);
    }
    let s = value
        .as_str()
        .ok_or_else(|| eyre::eyre!("expected number or string for u128"))?;
    if s.starts_with("0x") || s.starts_with("0X") {
        u128::from_str_radix(&s[2..], 16).map_err(|e| eyre::eyre!("invalid hex u128: {}", e))
    } else {
        s.parse()
            .map_err(|e| eyre::eyre!("invalid decimal u128: {}", e))
    }
}

/// Encodes an AuthorizedKey struct from JSON into a packed U256.
/// Uses the actual AuthorizedKey::encode_to_slot method for correctness.
fn encode_authorized_key(info: &serde_json::Map<String, serde_json::Value>) -> eyre::Result<U256> {
    let signature_type = info
        .get("signature_type")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;

    let expiry = info
        .get("expiry")
        .map(parse_u64_value)
        .transpose()?
        .unwrap_or(0);

    let enforce_limits = info
        .get("enforce_limits")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let is_revoked = info
        .get("is_revoked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let key = AuthorizedKey {
        signature_type,
        expiry,
        enforce_limits,
        is_revoked,
    };

    Ok(key.encode_to_slot())
}

/// Encodes a PolicyData struct from JSON into a packed U256.
/// Uses the actual PolicyData::encode_to_slot method for correctness.
fn encode_policy_data(info: &serde_json::Map<String, serde_json::Value>) -> eyre::Result<U256> {
    let policy_type = info
        .get("policy_type")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;

    let admin_str = info
        .get("admin")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0000000000000000000000000000000000000000");
    let admin: Address = admin_str.parse()?;

    let data = PolicyData { policy_type, admin };

    Ok(data.encode_to_slot())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::AccountState;
    use alloy_primitives::{address, uint};
    use std::collections::BTreeMap;
    use tempo_contracts::precompiles::DEFAULT_FEE_TOKEN;

    #[test]
    fn test_empty_prestate() {
        let prestate = Prestate::default();
        let db = VectorDatabase::from_prestate(&prestate).unwrap();
        // Empty prestate should create an empty DB (no precompiles seeded)
        assert!(db.db.cache.accounts.is_empty());
    }

    #[test]
    fn test_account_seeding() {
        let mut prestate = Prestate::default();
        let addr = address!("1111111111111111111111111111111111111111");
        prestate.accounts.insert(addr, AccountState { nonce: 5 });

        let db = VectorDatabase::from_prestate(&prestate).unwrap();
        let account = db.account(addr).unwrap().unwrap();

        assert_eq!(account.balance, U256::ZERO);
        assert_eq!(account.nonce, 5);
    }

    #[test]
    fn test_storage_seeding() {
        let mut prestate = Prestate::default();
        let addr = address!("2222222222222222222222222222222222222222");

        let mut slots = BTreeMap::new();
        slots.insert(U256::from(0), U256::from(42));
        slots.insert(U256::from(1), U256::from(100));
        prestate.storage.insert(addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        assert_eq!(db.storage(addr, U256::from(0)).unwrap(), U256::from(42));
        assert_eq!(db.storage(addr, U256::from(1)).unwrap(), U256::from(100));
        assert_eq!(db.storage(addr, U256::from(2)).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_code_seeding() {
        let mut prestate = Prestate::default();
        let addr = address!("3333333333333333333333333333333333333333");
        let code = Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xf3]); // PUSH 0, PUSH 0, RETURN

        prestate.code.insert(addr, code);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();
        let account = db.account(addr).unwrap().unwrap();

        assert_ne!(account.code_hash, KECCAK_EMPTY);
        assert!(account.code.is_some());
    }

    #[test]
    fn test_precompile_seeding() {
        let mut prestate = Prestate::default();

        // Seed DEFAULT_FEE_TOKEN with USD currency and a balance
        let sender = address!("abcdef0000000000000000000000000000000001");
        prestate.precompiles.push(PrecompileState {
            name: "TIP20Token".to_string(),
            address: DEFAULT_FEE_TOKEN,
            fields: serde_json::json!({
                "currency": "USD",
                "transfer_policy_id": 1,
                "balances": {
                    "0xabcdef0000000000000000000000000000000001": "1000000000000"
                }
            }),
        });

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        // Check that fee token has USD currency set
        let currency_slot = metadata_for("TIP20Token", "currency", &[]).unwrap().slot;
        let currency = db.storage(DEFAULT_FEE_TOKEN, currency_slot).unwrap();
        let expected_usd =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);
        assert_eq!(currency, expected_usd);

        // Check that sender has balance in fee token
        let sender_str = format!("{sender:?}");
        let balance_slot = metadata_for("TIP20Token", "balances", &[&sender_str]).unwrap().slot;
        let balance = db.storage(DEFAULT_FEE_TOKEN, balance_slot).unwrap();
        assert_eq!(balance, U256::from(1_000_000_000_000u64));
    }

    #[test]
    fn test_encode_short_string() {
        // "USD" should encode as 0x5553440000...000006
        let encoded = encode_short_string("USD").unwrap();
        let expected =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);
        assert_eq!(encoded, expected);

        // Empty string
        let empty = encode_short_string("").unwrap();
        assert_eq!(empty, U256::ZERO);

        // Max length (31 bytes)
        let max = encode_short_string("1234567890123456789012345678901").unwrap();
        assert!(max != U256::ZERO);

        // Too long should error
        let too_long = encode_short_string("12345678901234567890123456789012");
        assert!(too_long.is_err());
    }

    #[test]
    fn test_parse_u256_value() {
        // Decimal
        let dec = parse_u256_value(&serde_json::json!("1000")).unwrap();
        assert_eq!(dec, U256::from(1000));

        // Hex
        let hex = parse_u256_value(&serde_json::json!("0x3e8")).unwrap();
        assert_eq!(hex, U256::from(1000));

        // Non-string should error
        let non_str = parse_u256_value(&serde_json::json!(1000));
        assert!(non_str.is_err());
    }

    #[test]
    fn test_transfer_policy_id_packing() {
        let mut prestate = Prestate::default();

        prestate.precompiles.push(PrecompileState {
            name: "TIP20Token".to_string(),
            address: DEFAULT_FEE_TOKEN,
            fields: serde_json::json!({
                "transfer_policy_id": 1
            }),
        });

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        let slot = metadata_for("TIP20Token", "transfer_policy_id", &[]).unwrap().slot;
        let value = db.storage(DEFAULT_FEE_TOKEN, slot).unwrap();

        // Policy ID = 1 shifted left by 160 bits
        let expected =
            uint!(0x0000000000000000000000010000000000000000000000000000000000000000_U256);
        assert_eq!(value, expected);
    }
}
