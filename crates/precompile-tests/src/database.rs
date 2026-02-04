//! Database seeding for test vectors.
//!
//! This module provides utilities to create an in-memory CacheDB
//! populated with the prestate defined in a test vector.

use crate::vector::{PrecompileState, Prestate};
use alloy_primitives::{Address, B256, Bytes, U256};
use revm::{
    DatabaseRef,
    database::{CacheDB, EmptyDB},
    primitives::KECCAK_EMPTY,
    state::{AccountInfo, Bytecode},
};
use tempo_precompiles::{
    account_keychain::AuthorizedKey, resolver::slot_for, tip403_registry::PolicyData,
};

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
                .map(keccak256)
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
                    code_hash: keccak256(code),
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

    /// Seeds a single precompile's state.
    fn seed_precompile(&mut self, precompile: &PrecompileState) -> eyre::Result<()> {
        let address = precompile.address;
        let name = &precompile.name;

        // Ensure the precompile account exists with bytecode.
        // TIP20 tokens check `is_initialized()` which requires non-empty code hash.
        // We use 0xEF as a marker bytecode (invalid opcode, won't execute).
        let marker_code = Bytecode::new_raw(Bytes::from_static(&[0xEF]));
        let info = AccountInfo {
            code_hash: alloy_primitives::keccak256([0xEF]),
            code: Some(marker_code),
            ..Default::default()
        };
        self.db.insert_account_info(address, info);

        let fields = precompile
            .fields
            .as_object()
            .ok_or_else(|| eyre::eyre!("fields must be an object"))?;

        for (field_name, value) in fields {
            match name.as_str() {
                "TIP20Token" => self.seed_tip20_field(address, field_name, value)?,
                "NonceManager" => self.seed_nonce_field(address, field_name, value)?,
                "AccountKeychain" => {
                    self.seed_account_keychain_field(address, field_name, value)?
                }
                "StablecoinDEX" => self.seed_stablecoin_dex_field(address, field_name, value)?,
                "TIP403Registry" => self.seed_tip403_registry_field(address, field_name, value)?,
                "TipFeeManager" => self.seed_tip_fee_manager_field(address, field_name, value)?,
                "ValidatorConfig" => {
                    self.seed_validator_config_field(address, field_name, value)?
                }
                _ => return Err(eyre::eyre!("unsupported precompile: {}", name)),
            }
        }

        Ok(())
    }

    /// Seeds a single TIP20Token field.
    fn seed_tip20_field(
        &mut self,
        address: Address,
        field_name: &str,
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        match field_name {
            // Simple string fields (name, symbol, currency)
            "name" | "symbol" | "currency" => {
                let s = value
                    .as_str()
                    .ok_or_else(|| eyre::eyre!("{} must be a string", field_name))?;
                let encoded = encode_short_string(s)?;
                let slot = slot_for("TIP20Token", field_name, &[])?;
                self.db.insert_account_storage(address, slot, encoded)?;
            }

            // Simple U256 fields
            "total_supply" | "supply_cap" | "global_reward_per_token" => {
                let v = parse_u256_value(value)?;
                let slot = slot_for("TIP20Token", field_name, &[])?;
                self.db.insert_account_storage(address, slot, v)?;
            }

            // Packed field: transfer_policy_id (u64 at byte offset 20 in slot 7)
            "transfer_policy_id" => {
                let policy_id = parse_u64_value(value)?;
                let slot = slot_for("TIP20Token", field_name, &[])?;

                // Read current slot value to preserve other packed fields
                let current = self.db.storage_ref(address, slot).unwrap_or(U256::ZERO);

                // Clear the u64 at offset 20 (bytes 20-27 from the right in big-endian)
                // and set the new value. The u64 is at bit position 160.
                let mask: U256 = U256::from(u64::MAX) << 160;
                let cleared = current & !mask;
                let new_value = cleared | (U256::from(policy_id) << 160);

                self.db.insert_account_storage(address, slot, new_value)?;
            }

            // u128 fields
            "opted_in_supply" => {
                let v = parse_u128_value(value)?;
                let slot = slot_for("TIP20Token", field_name, &[])?;
                self.db
                    .insert_account_storage(address, slot, U256::from(v))?;
            }

            // Address fields
            "quote_token" | "next_quote_token" => {
                let addr_str = value
                    .as_str()
                    .ok_or_else(|| eyre::eyre!("{} must be an address string", field_name))?;
                let addr: Address = addr_str.parse()?;
                let slot = slot_for("TIP20Token", field_name, &[])?;
                self.db.insert_account_storage(
                    address,
                    slot,
                    U256::from_be_slice(addr.as_slice()),
                )?;
            }

            // Boolean fields
            "paused" => {
                let b = value
                    .as_bool()
                    .ok_or_else(|| eyre::eyre!("{} must be a boolean", field_name))?;
                let slot = slot_for("TIP20Token", field_name, &[])?;
                self.db
                    .insert_account_storage(address, slot, U256::from(b as u8))?;
            }

            // Mapping fields: balances
            "balances" => {
                let balances = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("balances must be an object"))?;
                for (holder, amount) in balances {
                    let slot = slot_for("TIP20Token", "balances", &[holder])?;
                    let v = parse_u256_value(amount)?;
                    self.db.insert_account_storage(address, slot, v)?;
                }
            }

            // Mapping fields: allowances (nested mapping)
            "allowances" => {
                let allowances = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("allowances must be an object"))?;
                for (owner, spenders) in allowances {
                    let spender_map = spenders
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("allowances[owner] must be an object"))?;
                    for (spender, amount) in spender_map {
                        let slot =
                            slot_for("TIP20Token", "allowances", &[owner, spender])?;
                        let v = parse_u256_value(amount)?;
                        self.db.insert_account_storage(address, slot, v)?;
                    }
                }
            }

            // Unknown field
            _ => {
                return Err(eyre::eyre!("unknown TIP20Token field: {}", field_name));
            }
        }

        Ok(())
    }

    /// Seeds a single NonceManager field.
    fn seed_nonce_field(
        &mut self,
        address: Address,
        field_name: &str,
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        match field_name {
            // Nested mapping: nonces[account][nonce_key] = u64
            "nonces" => {
                let accounts = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("nonces must be an object"))?;
                for (account, nonce_keys) in accounts {
                    let nonce_key_map = nonce_keys
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("nonces[account] must be an object"))?;
                    for (nonce_key, nonce_value) in nonce_key_map {
                        let slot =
                            slot_for("NonceManager", "nonces", &[account, nonce_key])?;
                        let v = parse_u64_value(nonce_value)?;
                        self.db
                            .insert_account_storage(address, slot, U256::from(v))?;
                    }
                }
            }
            // Mapping: expiring_nonce_seen[tx_hash] = u64
            "expiring_nonce_seen" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("expiring_nonce_seen must be an object"))?;
                for (tx_hash, expiry) in entries {
                    let slot =
                        slot_for("NonceManager", "expiring_nonce_seen", &[tx_hash])?;
                    let v = parse_u64_value(expiry)?;
                    self.db
                        .insert_account_storage(address, slot, U256::from(v))?;
                }
            }
            // Mapping: expiring_nonce_ring[index] = B256
            "expiring_nonce_ring" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("expiring_nonce_ring must be an object"))?;
                for (index, tx_hash) in entries {
                    let slot = slot_for("NonceManager", "expiring_nonce_ring", &[index])?;
                    let hash: B256 = tx_hash
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("tx_hash must be a string"))?
                        .parse()?;
                    self.db
                        .insert_account_storage(address, slot, U256::from_be_bytes(hash.0))?;
                }
            }
            // Simple u32 field
            "expiring_nonce_ring_ptr" => {
                let v = parse_u64_value(value)? as u32;
                let slot = slot_for("NonceManager", field_name, &[])?;
                self.db
                    .insert_account_storage(address, slot, U256::from(v))?;
            }
            _ => {
                return Err(eyre::eyre!("unknown NonceManager field: {}", field_name));
            }
        }
        Ok(())
    }

    /// Seeds a single AccountKeychain field.
    fn seed_account_keychain_field(
        &mut self,
        address: Address,
        field_name: &str,
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        match field_name {
            // Nested mapping: keys[account][key_id] = AuthorizedKey
            "keys" => {
                let accounts = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("keys must be an object"))?;
                for (account, key_ids) in accounts {
                    let key_id_map = key_ids
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("keys[account] must be an object"))?;
                    for (key_id, key_info) in key_id_map {
                        let slot =
                            slot_for("AccountKeychain", "keys", &[account, key_id])?;
                        let info = key_info
                            .as_object()
                            .ok_or_else(|| eyre::eyre!("key info must be an object"))?;
                        let encoded = encode_authorized_key(info)?;
                        self.db.insert_account_storage(address, slot, encoded)?;
                    }
                }
            }
            // Nested mapping: spending_limits[limit_key][token] = U256
            "spending_limits" => {
                let limit_keys = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("spending_limits must be an object"))?;
                for (limit_key, tokens) in limit_keys {
                    let token_map = tokens
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("spending_limits[key] must be an object"))?;
                    for (token, amount) in token_map {
                        let slot = slot_for(
                            "AccountKeychain",
                            "spending_limits",
                            &[limit_key.as_str(), token.as_str()],
                        )?;
                        let v = parse_u256_value(amount)?;
                        self.db.insert_account_storage(address, slot, v)?;
                    }
                }
            }
            // Address fields (transient)
            "transaction_key" | "tx_origin" => {
                let addr_str = value
                    .as_str()
                    .ok_or_else(|| eyre::eyre!("{} must be an address string", field_name))?;
                let addr: Address = addr_str.parse()?;
                let slot = slot_for("AccountKeychain", field_name, &[])?;
                self.db.insert_account_storage(
                    address,
                    slot,
                    U256::from_be_slice(addr.as_slice()),
                )?;
            }
            _ => {
                return Err(eyre::eyre!("unknown AccountKeychain field: {}", field_name));
            }
        }
        Ok(())
    }

    /// Seeds a single StablecoinDEX field.
    fn seed_stablecoin_dex_field(
        &mut self,
        address: Address,
        field_name: &str,
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        match field_name {
            // Mapping: books[book_key] = Orderbook (complex struct, seed as raw U256)
            "books" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("books must be an object"))?;
                for (book_key, data) in entries {
                    let slot = slot_for("StablecoinDEX", "books", &[book_key])?;
                    let v = parse_u256_value(data)?;
                    self.db.insert_account_storage(address, slot, v)?;
                }
            }
            // Mapping: orders[order_id] = Order (complex struct, seed as raw U256)
            "orders" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("orders must be an object"))?;
                for (order_id, data) in entries {
                    let slot = slot_for("StablecoinDEX", "orders", &[order_id])?;
                    let v = parse_u256_value(data)?;
                    self.db.insert_account_storage(address, slot, v)?;
                }
            }
            // Nested mapping: balances[user][token] = u128
            "balances" => {
                let users = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("balances must be an object"))?;
                for (user, tokens) in users {
                    let token_map = tokens
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("balances[user] must be an object"))?;
                    for (token, amount) in token_map {
                        let slot = slot_for("StablecoinDEX", "balances", &[user, token])?;
                        let v = parse_u128_value(amount)?;
                        self.db
                            .insert_account_storage(address, slot, U256::from(v))?;
                    }
                }
            }
            // Simple u128 field
            "next_order_id" => {
                let v = parse_u128_value(value)?;
                let slot = slot_for("StablecoinDEX", field_name, &[])?;
                self.db
                    .insert_account_storage(address, slot, U256::from(v))?;
            }
            // Vec<B256> - store length at base slot
            "book_keys" => {
                let arr = value
                    .as_array()
                    .ok_or_else(|| eyre::eyre!("book_keys must be an array"))?;
                let slot = slot_for("StablecoinDEX", field_name, &[])?;
                self.db
                    .insert_account_storage(address, slot, U256::from(arr.len()))?;
            }
            _ => {
                return Err(eyre::eyre!("unknown StablecoinDEX field: {}", field_name));
            }
        }
        Ok(())
    }

    /// Seeds a single TIP403Registry field.
    fn seed_tip403_registry_field(
        &mut self,
        address: Address,
        field_name: &str,
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        match field_name {
            // Simple u64 field
            "policy_id_counter" => {
                let v = parse_u64_value(value)?;
                let slot = slot_for("TIP403Registry", field_name, &[])?;
                self.db
                    .insert_account_storage(address, slot, U256::from(v))?;
            }
            // Mapping: policy_data[policy_id] = PolicyData
            "policy_data" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("policy_data must be an object"))?;
                for (policy_id, data) in entries {
                    let slot = slot_for("TIP403Registry", "policy_data", &[policy_id])?;
                    let info = data
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("policy_data[id] must be an object"))?;
                    let encoded = encode_policy_data(info)?;
                    self.db.insert_account_storage(address, slot, encoded)?;
                }
            }
            // Nested mapping: policy_set[policy_id][account] = bool
            "policy_set" => {
                let policies = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("policy_set must be an object"))?;
                for (policy_id, accounts) in policies {
                    let account_map = accounts
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("policy_set[id] must be an object"))?;
                    for (account, authorized) in account_map {
                        let slot = slot_for(
                            "TIP403Registry",
                            "policy_set",
                            &[policy_id.as_str(), account.as_str()],
                        )?;
                        let b = authorized
                            .as_bool()
                            .ok_or_else(|| eyre::eyre!("policy_set value must be boolean"))?;
                        self.db
                            .insert_account_storage(address, slot, U256::from(b as u8))?;
                    }
                }
            }
            _ => {
                return Err(eyre::eyre!("unknown TIP403Registry field: {}", field_name));
            }
        }
        Ok(())
    }

    /// Seeds a single TipFeeManager field.
    fn seed_tip_fee_manager_field(
        &mut self,
        address: Address,
        field_name: &str,
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        match field_name {
            // Mapping: validator_tokens[validator] = Address
            "validator_tokens" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("validator_tokens must be an object"))?;
                for (validator, token) in entries {
                    let slot =
                        slot_for("TipFeeManager", "validator_tokens", &[validator])?;
                    let addr: Address = token
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("token must be a string"))?
                        .parse()?;
                    self.db.insert_account_storage(
                        address,
                        slot,
                        U256::from_be_slice(addr.as_slice()),
                    )?;
                }
            }
            // Mapping: user_tokens[user] = Address
            "user_tokens" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("user_tokens must be an object"))?;
                for (user, token) in entries {
                    let slot = slot_for("TipFeeManager", "user_tokens", &[user])?;
                    let addr: Address = token
                        .as_str()
                        .ok_or_else(|| eyre::eyre!("token must be a string"))?
                        .parse()?;
                    self.db.insert_account_storage(
                        address,
                        slot,
                        U256::from_be_slice(addr.as_slice()),
                    )?;
                }
            }
            // Nested mapping: collected_fees[validator][token] = U256
            "collected_fees" => {
                let validators = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("collected_fees must be an object"))?;
                for (validator, tokens) in validators {
                    let token_map = tokens
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("collected_fees[v] must be an object"))?;
                    for (token, amount) in token_map {
                        let slot = slot_for(
                            "TipFeeManager",
                            "collected_fees",
                            &[validator.as_str(), token.as_str()],
                        )?;
                        let v = parse_u256_value(amount)?;
                        self.db.insert_account_storage(address, slot, v)?;
                    }
                }
            }
            // Mapping: pools[pool_id] = Pool (complex struct, seed as raw U256)
            "pools" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("pools must be an object"))?;
                for (pool_id, data) in entries {
                    let slot = slot_for("TipFeeManager", "pools", &[pool_id])?;
                    let v = parse_u256_value(data)?;
                    self.db.insert_account_storage(address, slot, v)?;
                }
            }
            // Mapping: total_supply[pool_id] = U256
            "total_supply" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("total_supply must be an object"))?;
                for (pool_id, amount) in entries {
                    let slot = slot_for("TipFeeManager", "total_supply", &[pool_id])?;
                    let v = parse_u256_value(amount)?;
                    self.db.insert_account_storage(address, slot, v)?;
                }
            }
            // Nested mapping: liquidity_balances[pool_id][provider] = U256
            "liquidity_balances" => {
                let pools = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("liquidity_balances must be an object"))?;
                for (pool_id, providers) in pools {
                    let provider_map = providers
                        .as_object()
                        .ok_or_else(|| eyre::eyre!("liquidity_balances[id] must be an object"))?;
                    for (provider, amount) in provider_map {
                        let slot = slot_for(
                            "TipFeeManager",
                            "liquidity_balances",
                            &[pool_id.as_str(), provider.as_str()],
                        )?;
                        let v = parse_u256_value(amount)?;
                        self.db.insert_account_storage(address, slot, v)?;
                    }
                }
            }
            _ => {
                return Err(eyre::eyre!("unknown TipFeeManager field: {}", field_name));
            }
        }
        Ok(())
    }

    /// Seeds a single ValidatorConfig field.
    fn seed_validator_config_field(
        &mut self,
        address: Address,
        field_name: &str,
        value: &serde_json::Value,
    ) -> eyre::Result<()> {
        match field_name {
            // Simple address field
            "owner" => {
                let addr_str = value
                    .as_str()
                    .ok_or_else(|| eyre::eyre!("owner must be an address string"))?;
                let addr: Address = addr_str.parse()?;
                let slot = slot_for("ValidatorConfig", field_name, &[])?;
                self.db.insert_account_storage(
                    address,
                    slot,
                    U256::from_be_slice(addr.as_slice()),
                )?;
            }
            // Vec<Address> - store length at base slot
            "validators_array" => {
                let arr = value
                    .as_array()
                    .ok_or_else(|| eyre::eyre!("validators_array must be an array"))?;
                let slot = slot_for("ValidatorConfig", field_name, &[])?;
                self.db
                    .insert_account_storage(address, slot, U256::from(arr.len()))?;
            }
            // Mapping: validators[validator] = Validator (complex struct, seed as raw U256)
            "validators" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| eyre::eyre!("validators must be an object"))?;
                for (validator, data) in entries {
                    let slot = slot_for("ValidatorConfig", "validators", &[validator])?;
                    let v = parse_u256_value(data)?;
                    self.db.insert_account_storage(address, slot, v)?;
                }
            }
            // Simple u64 field
            "next_dkg_ceremony" => {
                let v = parse_u64_value(value)?;
                let slot = slot_for("ValidatorConfig", field_name, &[])?;
                self.db
                    .insert_account_storage(address, slot, U256::from(v))?;
            }
            _ => {
                return Err(eyre::eyre!("unknown ValidatorConfig field: {}", field_name));
            }
        }
        Ok(())
    }

    /// Get a reference to the underlying database.
    pub fn inner(&self) -> &CacheDB<EmptyDB> {
        &self.db
    }

    /// Get a mutable reference to the underlying database.
    pub fn inner_mut(&mut self) -> &mut CacheDB<EmptyDB> {
        &mut self.db
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
fn keccak256(data: &Bytes) -> B256 {
    alloy_primitives::keccak256(data)
}

/// Encodes a string as a Solidity short string (≤31 bytes).
/// Format: left-aligned bytes with (length * 2) in the LSB.
fn encode_short_string(s: &str) -> eyre::Result<U256> {
    let bytes = s.as_bytes();
    if bytes.len() > 31 {
        return Err(eyre::eyre!(
            "string too long for short string encoding: {} bytes",
            bytes.len()
        ));
    }

    let mut buf = [0u8; 32];
    buf[..bytes.len()].copy_from_slice(bytes);
    // Set the length * 2 in the last byte
    buf[31] = (bytes.len() * 2) as u8;

    Ok(U256::from_be_bytes(buf))
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
        prestate.accounts.insert(
            addr,
            AccountState {
                nonce: 5,
                ..Default::default()
            },
        );

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

        prestate.code.insert(addr, code.clone());

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
        let currency_slot = slot_for("TIP20Token", "currency", &[]).unwrap();
        let currency = db.storage(DEFAULT_FEE_TOKEN, currency_slot).unwrap();
        let expected_usd =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);
        assert_eq!(currency, expected_usd);

        // Check that sender has balance in fee token
        let sender_str = format!("{:?}", sender);
        let balance_slot =
            slot_for("TIP20Token", "balances", &[&sender_str]).unwrap();
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

        let slot = slot_for("TIP20Token", "transfer_policy_id", &[]).unwrap();
        let value = db.storage(DEFAULT_FEE_TOKEN, slot).unwrap();

        // Policy ID = 1 shifted left by 160 bits
        let expected =
            uint!(0x0000000000000000000000010000000000000000000000000000000000000000_U256);
        assert_eq!(value, expected);
    }
}
