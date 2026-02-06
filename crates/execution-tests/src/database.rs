//! Database seeding for test vectors.
//!
//! This module provides utilities to create an in-memory CacheDB
//! populated with the prestate defined in a test vector.

use crate::{genesis, vector::Prestate};
use alloy_primitives::{Address, U256, keccak256};
use revm::{
    database::{CacheDB, EmptyDB},
    inspector::JournalExt,
    primitives::KECCAK_EMPTY,
    state::{AccountInfo, Bytecode},
};

/// A database seeded from a test vector's prestate.
pub struct VectorDatabase {
    /// The underlying CacheDB
    pub db: CacheDB<EmptyDB>,
}

impl VectorDatabase {
    /// Create a new database from a prestate definition.
    ///
    /// Genesis initialization is always performed first to set up all Tempo
    /// precompiles (TIP403Registry, TIP20Factory, PATH_USD, etc.).
    pub fn from_prestate(prestate: &Prestate) -> eyre::Result<Self> {
        let mut db = CacheDB::new(EmptyDB::default());

        // Always run genesis initialization first
        let admin = prestate
            .genesis_path_usd
            .as_ref()
            .and_then(|g| g.admin)
            .unwrap_or(genesis::GENESIS_ADMIN);

        let balances: Vec<(Address, U256)> = prestate
            .genesis_path_usd
            .as_ref()
            .map(|g| {
                g.balances
                    .iter()
                    .map(|b| (b.account, b.balance))
                    .collect()
            })
            .unwrap_or_default();

        // Create a TempoEvm, run genesis, and extract the state from journaled_state
        let mut evm = genesis::create_genesis_evm_with_balances(admin, &balances)?;

        // Extract state from journaled_state.evm_state() which includes pending changes
        // (finish() only returns the underlying database without uncommitted journal entries)
        let evm_state = evm.ctx_mut().journaled_state.evm_state();
        for (address, account) in evm_state.iter() {
            let info = AccountInfo {
                balance: account.info.balance,
                nonce: account.info.nonce,
                code_hash: account.info.code_hash,
                code: account.info.code.clone(),
                ..Default::default()
            };
            db.insert_account_info(*address, info);

            // Storage uses present_value from the journaled state
            for (slot, value) in &account.storage {
                db.insert_account_storage(*address, *slot, value.present_value)?;
            }
        }

        // Insert accounts (balance, nonce) - these override genesis if specified
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

        Ok(Self { db })
    }

    /// Get a reference to the underlying database.
    pub fn inner(&self) -> &CacheDB<EmptyDB> {
        &self.db
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::AccountState;
    use alloy_primitives::{Bytes, address};
    use revm::DatabaseRef;
    use std::collections::BTreeMap;
    use tempo_precompiles::PATH_USD_ADDRESS;

    #[test]
    fn test_default_prestate_has_genesis() {
        use tempo_precompiles::resolver::metadata_for;

        // Even empty prestate should have genesis initialized
        let prestate = Prestate::default();
        let db = VectorDatabase::from_prestate(&prestate).unwrap();

        // PATH_USD should be in the database (genesis always runs)
        let account = db.db.basic_ref(PATH_USD_ADDRESS).unwrap();
        assert!(account.is_some(), "PATH_USD should exist after genesis");

        // Check that PATH_USD has storage (currency field)
        let num_accounts = db.db.cache.accounts.len();
        assert!(
            num_accounts > 5,
            "Genesis should create multiple precompile accounts, got {}",
            num_accounts
        );

        // Check that the currency field is set correctly
        let currency_meta = metadata_for("TIP20Token", "currency", &[]).unwrap();
        let currency_value = db.db.storage_ref(PATH_USD_ADDRESS, currency_meta.slot).unwrap();
        // "USD" as short string: 0x555344...06 (USD bytes + length 3*2=6 in the last nibble)
        assert!(
            !currency_value.is_zero(),
            "PATH_USD currency should be set, got {:?}",
            currency_value
        );
    }

    #[test]
    fn test_account_seeding() {
        let mut prestate = Prestate::default();
        let addr = address!("1111111111111111111111111111111111111111");
        prestate.accounts.insert(addr, AccountState { nonce: 5 });

        let db = VectorDatabase::from_prestate(&prestate).unwrap();
        let account = db.db.basic_ref(addr).unwrap().unwrap();

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

        assert_eq!(
            db.db.storage_ref(addr, U256::from(0)).unwrap(),
            U256::from(42)
        );
        assert_eq!(
            db.db.storage_ref(addr, U256::from(1)).unwrap(),
            U256::from(100)
        );
        assert_eq!(db.db.storage_ref(addr, U256::from(2)).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_code_seeding() {
        let mut prestate = Prestate::default();
        let addr = address!("3333333333333333333333333333333333333333");
        let code = Bytes::from(vec![0x60, 0x00, 0x60, 0x00, 0xf3]); // PUSH 0, PUSH 0, RETURN

        prestate.code.insert(addr, code);

        let db = VectorDatabase::from_prestate(&prestate).unwrap();
        let account = db.db.basic_ref(addr).unwrap().unwrap();

        assert_ne!(account.code_hash, KECCAK_EMPTY);
        assert!(account.code.is_some());
    }
}
