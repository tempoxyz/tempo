//! Post-execution state capture.
//!
//! Reads specified storage slots and nonces after execution
//! to include in the execution fingerprint.

use crate::vector::{Checks, FieldKey, FieldSpec};
use alloy_primitives::{Address, U256};
use revm::DatabaseRef;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tempo_precompiles::resolver::slot_for;

/// Captured precompile field values
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrecompileFieldValues {
    /// The precompile contract name
    pub name: String,
    /// Field values (simple fields and mapping values)
    pub fields: BTreeMap<String, FieldValue>,
}

/// A captured field value
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum FieldValue {
    /// Simple field value
    Simple(U256),
    /// Mapping values by key(s)
    Mapping(BTreeMap<String, U256>),
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
                        let slot = slot_for(&check.name, field_name, &[])
                            .map_err(|e| eyre::eyre!("slot_for failed: {:?}", e))?;
                        let value = db.storage_ref(check.address, slot).map_err(|e| {
                            eyre::eyre!(
                                "storage read failed for {:?} slot {:?}: {:?}",
                                check.address,
                                slot,
                                e
                            )
                        })?;
                        field_values.insert(field_name.clone(), FieldValue::Simple(value));
                    }
                    FieldSpec::WithKeys { field, keys } => {
                        let mut mapping_values = BTreeMap::new();
                        for key in keys {
                            let key_strs: Vec<&str> = match key {
                                FieldKey::Single(k) => vec![k.as_str()],
                                FieldKey::Tuple(ks) => ks.iter().map(|s| s.as_str()).collect(),
                            };
                            let slot = slot_for(&check.name, field, &key_strs)
                                .map_err(|e| eyre::eyre!("slot_for failed: {:?}", e))?;
                            let value = db.storage_ref(check.address, slot).map_err(|e| {
                                eyre::eyre!(
                                    "storage read failed for {:?} slot {:?}: {:?}",
                                    check.address,
                                    slot,
                                    e
                                )
                            })?;
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

        prestate.accounts.insert(
            addr,
            AccountState {
                nonce: 42,
                ..Default::default()
            },
        );

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
        use tempo_precompiles::resolver::slot_for;

        let token_addr = address!("20C0000000000000000000000000000000000001");

        // Get the slot for total_supply
        let slot = slot_for("TIP20Token", "total_supply", &[]).unwrap();

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
            Some(&FieldValue::Simple(U256::from(1_000_000)))
        );
    }

    #[test]
    fn test_capture_precompile_mapping_field() {
        use crate::vector::PrecompileCheck;
        use tempo_precompiles::resolver::slot_for;

        let token_addr = address!("20C0000000000000000000000000000000000001");
        let holder = "0x1111111111111111111111111111111111111111";

        // Get the slot for balances[holder]
        let slot = slot_for("TIP20Token", "balances", &[holder]).unwrap();

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
                assert_eq!(m.get(holder), Some(&U256::from(500)));
            }
            other => panic!("expected Mapping, got {:?}", other),
        }
    }

    #[test]
    fn test_capture_precompile_nested_mapping() {
        use crate::vector::PrecompileCheck;
        use tempo_precompiles::resolver::slot_for;

        let token_addr = address!("20C0000000000000000000000000000000000001");
        let owner = "0x1111111111111111111111111111111111111111";
        let spender = "0x2222222222222222222222222222222222222222";

        // Get the slot for allowances[owner][spender]
        let slot = slot_for("TIP20Token", "allowances", &[owner, spender]).unwrap();

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
        let expected_key = format!("{},{}", owner, spender);
        match precompile.fields.get("allowances") {
            Some(FieldValue::Mapping(m)) => {
                assert_eq!(m.get(&expected_key), Some(&U256::from(1000)));
            }
            other => panic!("expected Mapping, got {:?}", other),
        }
    }

    #[test]
    fn test_precompile_serialization_roundtrip() {
        let token_addr = address!("20C0000000000000000000000000000000000001");

        let mut fields = BTreeMap::new();
        fields.insert(
            "total_supply".to_string(),
            FieldValue::Simple(U256::from(1_000_000)),
        );

        let mut mapping = BTreeMap::new();
        mapping.insert(
            "0x1111111111111111111111111111111111111111".to_string(),
            U256::from(500),
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
}
