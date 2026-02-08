//! Post-execution state capture.
//!
//! Reads specified storage slots and nonces after execution
//! to include in the execution fingerprint.

use crate::vector::{Checks, FieldKey, FieldSpec};
use alloy_primitives::{Address, Bytes, U256};
use revm::DatabaseRef;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tempo_precompiles::{
    resolver::{FieldMetadata, metadata_for},
    storage::packing::extract_from_word,
};

/// Captured precompile field values
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrecompileFieldValues {
    /// The precompile contract name
    pub name: String,
    /// Field values (simple fields and mapping values)
    pub fields: BTreeMap<String, FieldValue>,
}

/// A captured field value.
///
/// Values are stored as `Bytes` to support fields of any size (packed fields,
/// full slots, or multi-slot types like structs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum FieldValue {
    /// Simple field value (non-mapping)
    Simple(Bytes),
    /// Mapping values by key(s)
    Mapping(BTreeMap<String, Bytes>),
}

/// Captured post-execution state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostExecutionState {
    /// Storage values per address, per slot
    pub storage: BTreeMap<Address, BTreeMap<U256, U256>>,
    /// Account nonces
    pub nonces: BTreeMap<Address, u64>,
    /// Precompile field values per address
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub precompiles: BTreeMap<Address, PrecompileFieldValues>,
}

// Note: Native balances are not tracked - Tempo uses TIP20 tokens instead

/// Convert U256 to Bytes (full 32-byte big-endian representation).
fn u256_to_bytes(value: U256) -> Bytes {
    Bytes::copy_from_slice(&value.to_be_bytes::<32>())
}

/// Convert U256 to Bytes with specific byte count (right-aligned extraction).
fn u256_to_bytes_sized(value: U256, size: usize) -> Bytes {
    let full = value.to_be_bytes::<32>();
    let start = 32 - size;
    Bytes::copy_from_slice(&full[start..])
}

/// Read a field value from storage using the field metadata.
///
/// This function handles:
/// - Packed fields: extracts the correct portion of a slot based on offset and bytes
/// - Full-slot fields: returns the entire slot value
/// - Multi-slot fields: reads and concatenates consecutive slots
///
/// Returns the value as `Bytes` with exactly `metadata.bytes` length.
fn read_field_value<DB>(db: &DB, address: Address, metadata: &FieldMetadata) -> eyre::Result<Bytes>
where
    DB: DatabaseRef,
    DB::Error: std::fmt::Debug,
{
    let num_slots = metadata.bytes.div_ceil(32);

    // Read all required slots
    let mut slot_values = Vec::with_capacity(num_slots);
    for i in 0..num_slots {
        let slot_addr = metadata.slot + U256::from(i);
        let value = db.storage_ref(address, slot_addr).map_err(|e| {
            eyre::eyre!(
                "storage read failed for {:?} slot {:?}: {:?}",
                address,
                slot_addr,
                e
            )
        })?;
        slot_values.push(value);
    }

    // For packed fields within a single slot, extract the relevant bytes
    if num_slots == 1 && (metadata.offset > 0 || metadata.bytes < 32) {
        let extracted = extract_from_word::<U256>(slot_values[0], metadata.offset, metadata.bytes)
            .map_err(|e| eyre::eyre!("extract_from_word failed: {:?}", e))?;
        return Ok(u256_to_bytes_sized(extracted, metadata.bytes));
    }

    // For full slots or multi-slot values, concatenate and trim to exact size
    if num_slots == 1 {
        return Ok(u256_to_bytes(slot_values[0]));
    }

    // Multi-slot: concatenate all slots
    let mut result = Vec::with_capacity(num_slots * 32);
    for slot_value in &slot_values {
        result.extend_from_slice(&slot_value.to_be_bytes::<32>());
    }
    // Trim to exact byte count (last slot may have padding)
    result.truncate(metadata.bytes);
    Ok(Bytes::from(result))
}

impl PostExecutionState {
    /// Capture state from a database according to the specified checks
    pub fn capture<DB>(db: &DB, checks: &Checks) -> eyre::Result<Self>
    where
        DB: DatabaseRef,
        DB::Error: std::fmt::Debug,
    {
        let mut storage = BTreeMap::new();
        let mut nonces = BTreeMap::new();

        // Read storage slots
        for (address, slots) in &checks.storage {
            let mut addr_storage = BTreeMap::new();
            for slot in slots {
                let value = db.storage_ref(*address, *slot).map_err(|e| {
                    eyre::eyre!(
                        "storage read failed for {:?} slot {:?}: {:?}",
                        address,
                        slot,
                        e
                    )
                })?;
                addr_storage.insert(*slot, value);
            }
            if !addr_storage.is_empty() {
                storage.insert(*address, addr_storage);
            }
        }

        // Read nonces
        for address in &checks.nonces {
            let account = db
                .basic_ref(*address)
                .map_err(|e| eyre::eyre!("account read failed for {:?}: {:?}", address, e))?;
            let nonce = account.map(|a| a.nonce).unwrap_or(0);
            nonces.insert(*address, nonce);
        }

        // Read precompile fields
        let mut precompiles = BTreeMap::new();
        for check in &checks.precompiles {
            let mut field_values = BTreeMap::new();

            for spec in &check.fields {
                match spec {
                    FieldSpec::Simple(field_name) => {
                        let metadata = metadata_for(&check.name, field_name, &[]).map_err(|e| {
                            eyre::eyre!(
                                "metadata_for failed for {}.{}: {:?}",
                                check.name,
                                field_name,
                                e
                            )
                        })?;
                        let value = read_field_value(db, check.address, &metadata)?;
                        field_values.insert(field_name.clone(), FieldValue::Simple(value));
                    }
                    FieldSpec::WithKeys { field, keys } => {
                        let mut mapping_values = BTreeMap::new();
                        for key in keys {
                            let key_strs: Vec<&str> = match key {
                                FieldKey::Single(k) => vec![k.as_str()],
                                FieldKey::Tuple(ks) => ks.iter().map(|s| s.as_str()).collect(),
                            };
                            let metadata =
                                metadata_for(&check.name, field, &key_strs).map_err(|e| {
                                    eyre::eyre!(
                                        "metadata_for failed for {}.{} with keys {:?}: {:?}",
                                        check.name,
                                        field,
                                        key_strs,
                                        e
                                    )
                                })?;
                            let value = read_field_value(db, check.address, &metadata)?;
                            let key_str = match key {
                                FieldKey::Single(k) => k.clone(),
                                FieldKey::Tuple(ks) => ks.join(","),
                            };
                            mapping_values.insert(key_str, value);
                        }
                        field_values.insert(field.clone(), FieldValue::Mapping(mapping_values));
                    }
                }
            }

            if !field_values.is_empty() {
                precompiles.insert(
                    check.address,
                    PrecompileFieldValues {
                        name: check.name.clone(),
                        fields: field_values,
                    },
                );
            }
        }

        Ok(Self {
            storage,
            nonces,
            precompiles,
        })
    }

    /// Create an empty state (no checks specified)
    pub fn empty() -> Self {
        Self {
            storage: BTreeMap::new(),
            nonces: BTreeMap::new(),
            precompiles: BTreeMap::new(),
        }
    }

    /// Check if any state was captured
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty() && self.nonces.is_empty() && self.precompiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::VectorDatabase,
        vector::{AccountState, Checks, Prestate},
    };
    use alloy_primitives::address;

    #[test]
    fn test_capture_empty_checks() {
        let prestate = Prestate::default();
        let db = VectorDatabase::from_prestate(&prestate).unwrap();
        let checks = Checks::default();

        let state = PostExecutionState::capture(&db.db, &checks).unwrap();

        assert!(state.is_empty());
    }

    #[test]
    fn test_capture_nonces() {
        let mut prestate = Prestate::default();
        let addr = address!("1111111111111111111111111111111111111111");

        prestate.accounts.insert(addr, AccountState { nonce: 42 });

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        let checks = Checks {
            nonces: vec![addr],
            ..Default::default()
        };

        let state = PostExecutionState::capture(&db.db, &checks).unwrap();

        assert_eq!(state.nonces.get(&addr), Some(&42));
    }

    #[test]
    fn test_capture_storage() {
        let mut prestate = Prestate::default();
        let addr = address!("3333333333333333333333333333333333333333");

        let mut slots = BTreeMap::new();
        slots.insert(U256::from(0), U256::from(100));
        slots.insert(U256::from(1), U256::from(200));
        slots.insert(U256::from(2), U256::from(300));
        prestate.storage.insert(addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        // Only check slots 0 and 2 (not 1)
        let mut storage_checks = BTreeMap::new();
        storage_checks.insert(addr, vec![U256::from(0), U256::from(2)]);

        let checks = Checks {
            storage: storage_checks,
            ..Default::default()
        };

        let state = PostExecutionState::capture(&db.db, &checks).unwrap();

        let addr_storage = state.storage.get(&addr).unwrap();
        assert_eq!(addr_storage.get(&U256::from(0)), Some(&U256::from(100)));
        assert_eq!(addr_storage.get(&U256::from(2)), Some(&U256::from(300)));
        assert_eq!(addr_storage.get(&U256::from(1)), None); // Not checked
    }

    #[test]
    fn test_capture_nonexistent_account() {
        let prestate = Prestate::default();
        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        let addr = address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

        let checks = Checks {
            nonces: vec![addr],
            ..Default::default()
        };

        let state = PostExecutionState::capture(&db.db, &checks).unwrap();

        // Non-existent accounts should return zero nonce
        assert_eq!(state.nonces.get(&addr), Some(&0));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut storage = BTreeMap::new();
        let mut addr_storage = BTreeMap::new();
        addr_storage.insert(U256::from(0), U256::from(42));
        storage.insert(
            address!("1111111111111111111111111111111111111111"),
            addr_storage,
        );

        let mut nonces = BTreeMap::new();
        nonces.insert(address!("3333333333333333333333333333333333333333"), 5u64);

        let state = PostExecutionState {
            storage,
            nonces,
            precompiles: BTreeMap::new(),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: PostExecutionState = serde_json::from_str(&json).unwrap();

        assert_eq!(state, parsed);
    }

    #[test]
    fn test_capture_precompile_simple_field() {
        use crate::vector::PrecompileCheck;
        use tempo_precompiles::resolver::metadata_for;

        let token_addr = address!("20C0000000000000000000000000000000000001");

        // Get the slot for total_supply
        let slot = metadata_for("TIP20Token", "total_supply", &[])
            .unwrap()
            .slot;

        // Seed the storage with a value
        let mut prestate = Prestate::default();
        let mut slots = BTreeMap::new();
        slots.insert(slot, U256::from(1_000_000));
        prestate.storage.insert(token_addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        let checks = Checks {
            precompiles: vec![PrecompileCheck {
                name: "TIP20Token".to_string(),
                address: token_addr,
                fields: vec![FieldSpec::Simple("total_supply".to_string())],
            }],
            ..Default::default()
        };

        let state = PostExecutionState::capture(&db.db, &checks).unwrap();

        let precompile = state.precompiles.get(&token_addr).unwrap();
        assert_eq!(precompile.name, "TIP20Token");
        assert_eq!(
            precompile.fields.get("total_supply"),
            Some(&FieldValue::Simple(u256_to_bytes(U256::from(1_000_000))))
        );
    }

    #[test]
    fn test_capture_precompile_mapping_field() {
        use crate::vector::PrecompileCheck;
        use tempo_precompiles::resolver::metadata_for;

        let token_addr = address!("20C0000000000000000000000000000000000001");
        let holder = "0x1111111111111111111111111111111111111111";

        // Get the slot for balances[holder]
        let slot = metadata_for("TIP20Token", "balances", &[holder])
            .unwrap()
            .slot;

        // Seed the storage with a balance
        let mut prestate = Prestate::default();
        let mut slots = BTreeMap::new();
        slots.insert(slot, U256::from(500));
        prestate.storage.insert(token_addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        let checks = Checks {
            precompiles: vec![PrecompileCheck {
                name: "TIP20Token".to_string(),
                address: token_addr,
                fields: vec![FieldSpec::WithKeys {
                    field: "balances".to_string(),
                    keys: vec![FieldKey::Single(holder.to_string())],
                }],
            }],
            ..Default::default()
        };

        let state = PostExecutionState::capture(&db.db, &checks).unwrap();

        let precompile = state.precompiles.get(&token_addr).unwrap();
        match precompile.fields.get("balances") {
            Some(FieldValue::Mapping(m)) => {
                assert_eq!(m.get(holder), Some(&u256_to_bytes(U256::from(500))));
            }
            other => panic!("expected Mapping, got {other:?}"),
        }
    }

    #[test]
    fn test_capture_precompile_nested_mapping() {
        use crate::vector::PrecompileCheck;
        use tempo_precompiles::resolver::metadata_for;

        let token_addr = address!("20C0000000000000000000000000000000000001");
        let owner = "0x1111111111111111111111111111111111111111";
        let spender = "0x2222222222222222222222222222222222222222";

        // Get the slot for allowances[owner][spender]
        let slot = metadata_for("TIP20Token", "allowances", &[owner, spender])
            .unwrap()
            .slot;

        // Seed the storage with an allowance
        let mut prestate = Prestate::default();
        let mut slots = BTreeMap::new();
        slots.insert(slot, U256::from(1000));
        prestate.storage.insert(token_addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        let checks = Checks {
            precompiles: vec![PrecompileCheck {
                name: "TIP20Token".to_string(),
                address: token_addr,
                fields: vec![FieldSpec::WithKeys {
                    field: "allowances".to_string(),
                    keys: vec![FieldKey::Tuple(vec![
                        owner.to_string(),
                        spender.to_string(),
                    ])],
                }],
            }],
            ..Default::default()
        };

        let state = PostExecutionState::capture(&db.db, &checks).unwrap();

        let precompile = state.precompiles.get(&token_addr).unwrap();
        let expected_key = format!("{owner},{spender}");
        match precompile.fields.get("allowances") {
            Some(FieldValue::Mapping(m)) => {
                assert_eq!(m.get(&expected_key), Some(&u256_to_bytes(U256::from(1000))));
            }
            other => panic!("expected Mapping, got {other:?}"),
        }
    }

    #[test]
    fn test_precompile_serialization_roundtrip() {
        let token_addr = address!("20C0000000000000000000000000000000000001");

        let mut fields = BTreeMap::new();
        fields.insert(
            "total_supply".to_string(),
            FieldValue::Simple(u256_to_bytes(U256::from(1_000_000))),
        );

        let mut mapping = BTreeMap::new();
        mapping.insert(
            "0x1111111111111111111111111111111111111111".to_string(),
            u256_to_bytes(U256::from(500)),
        );
        fields.insert("balances".to_string(), FieldValue::Mapping(mapping));

        let mut precompiles = BTreeMap::new();
        precompiles.insert(
            token_addr,
            PrecompileFieldValues {
                name: "TIP20Token".to_string(),
                fields,
            },
        );

        let state = PostExecutionState {
            storage: BTreeMap::new(),
            nonces: BTreeMap::new(),
            precompiles,
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: PostExecutionState = serde_json::from_str(&json).unwrap();

        assert_eq!(state, parsed);
    }

    #[test]
    fn test_read_field_value_full_slot() {
        use tempo_precompiles::resolver::FieldMetadata;

        let addr = address!("20C0000000000000000000000000000000000001");
        let mut prestate = Prestate::default();
        let mut slots = BTreeMap::new();
        slots.insert(U256::from(5), U256::from(0x1234567890ABCDEF_u64));
        prestate.storage.insert(addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        // Full 32-byte field at offset 0
        let metadata = FieldMetadata {
            slot: U256::from(5),
            offset: 0,
            bytes: 32,
            is_mapping: false,
            nesting_depth: 0,
        };

        let value = super::read_field_value(&db.db, addr, &metadata).unwrap();
        assert_eq!(value, u256_to_bytes(U256::from(0x1234567890ABCDEF_u64)));
    }

    #[test]
    fn test_read_field_value_packed_u8() {
        use tempo_precompiles::resolver::FieldMetadata;

        let addr = address!("20C0000000000000000000000000000000000001");
        let mut prestate = Prestate::default();

        // Pack three u8 values into a slot:
        // offset 0: 0xAA (170)
        // offset 1: 0xBB (187)
        // offset 2: 0xCC (204)
        let packed_value = U256::from(0xCCBBAA_u32);

        let mut slots = BTreeMap::new();
        slots.insert(U256::from(10), packed_value);
        prestate.storage.insert(addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        // Read first byte at offset 0
        let metadata0 = FieldMetadata {
            slot: U256::from(10),
            offset: 0,
            bytes: 1,
            is_mapping: false,
            nesting_depth: 0,
        };
        assert_eq!(
            super::read_field_value(&db.db, addr, &metadata0).unwrap(),
            Bytes::from(vec![0xAA])
        );

        // Read second byte at offset 1
        let metadata1 = FieldMetadata {
            slot: U256::from(10),
            offset: 1,
            bytes: 1,
            is_mapping: false,
            nesting_depth: 0,
        };
        assert_eq!(
            super::read_field_value(&db.db, addr, &metadata1).unwrap(),
            Bytes::from(vec![0xBB])
        );

        // Read third byte at offset 2
        let metadata2 = FieldMetadata {
            slot: U256::from(10),
            offset: 2,
            bytes: 1,
            is_mapping: false,
            nesting_depth: 0,
        };
        assert_eq!(
            super::read_field_value(&db.db, addr, &metadata2).unwrap(),
            Bytes::from(vec![0xCC])
        );
    }

    #[test]
    fn test_read_field_value_packed_mixed_types() {
        use tempo_precompiles::resolver::FieldMetadata;

        let addr = address!("20C0000000000000000000000000000000000001");
        let mut prestate = Prestate::default();

        // Pack a u8 (1 byte) followed by a u64 (8 bytes):
        // offset 0: u8 = 0x42 (66)
        // offset 1-8: u64 = 0x123456789ABCDEF0
        let u8_val = U256::from(0x42_u8);
        let u64_val = U256::from(0x123456789ABCDEF0_u64) << 8; // shift left by 1 byte (8 bits)
        let packed_value = u8_val | u64_val;

        let mut slots = BTreeMap::new();
        slots.insert(U256::from(20), packed_value);
        prestate.storage.insert(addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        // Read u8 at offset 0
        let metadata_u8 = FieldMetadata {
            slot: U256::from(20),
            offset: 0,
            bytes: 1,
            is_mapping: false,
            nesting_depth: 0,
        };
        assert_eq!(
            super::read_field_value(&db.db, addr, &metadata_u8).unwrap(),
            Bytes::from(vec![0x42])
        );

        // Read u64 at offset 1
        let metadata_u64 = FieldMetadata {
            slot: U256::from(20),
            offset: 1,
            bytes: 8,
            is_mapping: false,
            nesting_depth: 0,
        };
        assert_eq!(
            super::read_field_value(&db.db, addr, &metadata_u64).unwrap(),
            u256_to_bytes_sized(U256::from(0x123456789ABCDEF0_u64), 8)
        );
    }

    #[test]
    fn test_read_field_value_address_packed_with_bool() {
        use tempo_precompiles::resolver::FieldMetadata;

        let addr = address!("20C0000000000000000000000000000000000001");
        let mut prestate = Prestate::default();

        // Pack an Address (20 bytes) followed by a bool (1 byte):
        // offset 0-19: Address = 0x1111111111111111111111111111111111111111
        // offset 20: bool = true (0x01)
        let test_address = address!("1111111111111111111111111111111111111111");
        let address_val = U256::from_be_slice(&test_address.0[..]);
        let bool_val = U256::from(1) << (20 * 8); // shift left by 20 bytes
        let packed_value = address_val | bool_val;

        let mut slots = BTreeMap::new();
        slots.insert(U256::from(30), packed_value);
        prestate.storage.insert(addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        // Read address at offset 0
        let metadata_addr = FieldMetadata {
            slot: U256::from(30),
            offset: 0,
            bytes: 20,
            is_mapping: false,
            nesting_depth: 0,
        };
        let read_addr = super::read_field_value(&db.db, addr, &metadata_addr).unwrap();
        assert_eq!(read_addr, Bytes::copy_from_slice(&test_address.0[..]));

        // Read bool at offset 20
        let metadata_bool = FieldMetadata {
            slot: U256::from(30),
            offset: 20,
            bytes: 1,
            is_mapping: false,
            nesting_depth: 0,
        };
        assert_eq!(
            super::read_field_value(&db.db, addr, &metadata_bool).unwrap(),
            Bytes::from(vec![0x01])
        );
    }

    #[test]
    fn test_read_field_value_multi_slot() {
        use tempo_precompiles::resolver::FieldMetadata;

        let addr = address!("20C0000000000000000000000000000000000001");
        let mut prestate = Prestate::default();

        // Store two consecutive slots for a 64-byte value
        let slot0_val = U256::from(0x1111111111111111_u64);
        let slot1_val = U256::from(0x2222222222222222_u64);

        let mut slots = BTreeMap::new();
        slots.insert(U256::from(100), slot0_val);
        slots.insert(U256::from(101), slot1_val);
        prestate.storage.insert(addr, slots);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        // Read a 64-byte field spanning 2 slots
        let metadata = FieldMetadata {
            slot: U256::from(100),
            offset: 0,
            bytes: 64,
            is_mapping: false,
            nesting_depth: 0,
        };

        let value = super::read_field_value(&db.db, addr, &metadata).unwrap();
        assert_eq!(value.len(), 64);

        // First 32 bytes should be slot0, next 32 should be slot1
        let mut expected = Vec::with_capacity(64);
        expected.extend_from_slice(&slot0_val.to_be_bytes::<32>());
        expected.extend_from_slice(&slot1_val.to_be_bytes::<32>());
        assert_eq!(value, Bytes::from(expected));
    }
}
