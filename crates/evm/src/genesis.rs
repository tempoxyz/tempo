//! Shared Tempo genesis state initialization.
//!
//! Tempo L1 and Zone genesis generators both initialize precompiles and standard contracts in an
//! in-memory Tempo EVM, then serialize the resulting state into a genesis allocation. This module
//! holds the pieces they share; chain-specific accounts, anchors and policies remain with each
//! generator.

use crate::{SYSTEM_CALL_GAS_LIMIT, TempoBlockEnv, TempoEvm, TempoEvmExt, build_tempo_evm};
use alloy_genesis::{ChainConfig, GenesisAccount};
use alloy_primitives::{Address, Bytes, U256};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, InMemoryDB, SystemTx, precompile::NoPrecompiles},
    interpreter::GasTracker,
};
use tempo_chainspec::TempoHardfork;
use tempo_contracts::{
    ARACHNID_CREATE2_FACTORY_ADDRESS, PERMIT2_ADDRESS, PERMIT2_SALT,
    contracts::ARACHNID_CREATE2_FACTORY_BYTECODE,
};
use tempo_precompiles::storage::{StorageActions, StorageCtx, evm::EvmPrecompileStorageProvider};

/// In-memory EVM used to build genesis state.
pub type GenesisEvm = TempoEvm<'static>;

/// Fully resolved configuration for an in-memory genesis EVM.
#[derive(Debug)]
pub struct GenesisEvmEnv {
    /// Tempo hardfork active while constructing genesis state.
    pub spec: TempoHardfork,
    /// Chain ID exposed to EVM execution.
    pub chain_id: u64,
    /// Block environment used by genesis system calls.
    pub block_env: TempoBlockEnv,
}

/// Returns the EVM environment used for genesis initialization: timestamp zero and `chain_id`.
///
/// Callers may adjust limits before [`create_genesis_evm`].
pub fn genesis_evm_env(chain_id: u64) -> GenesisEvmEnv {
    let block_env = TempoBlockEnv {
        timestamp: U256::ZERO,
        ..Default::default()
    };
    GenesisEvmEnv {
        spec: TempoHardfork::T0,
        chain_id,
        block_env,
    }
}

/// Creates an empty in-memory genesis EVM.
pub fn create_genesis_evm(env: GenesisEvmEnv) -> GenesisEvm {
    build_tempo_evm(
        env.spec,
        env.chain_id,
        env.block_env,
        InMemoryDB::default(),
        NoPrecompiles::default(),
        TempoEvmExt::default(),
    )
}

/// Runs `f` with precompile storage bound to the genesis EVM, with storage actions disabled.
pub fn with_genesis_storage<R>(evm: &mut GenesisEvm, f: impl FnOnce() -> R) -> R {
    let spec = evm.config_spec_id();
    let non_creditable_slots = evm.ext().non_creditable_slots.clone();
    let mut gas = GasTracker::new(u64::MAX);
    let mut storage = EvmPrecompileStorageProvider::new(evm, &mut gas, spec, false)
        .with_actions(StorageActions::disabled())
        .with_non_creditable_slots(non_creditable_slots);
    let result = StorageCtx::enter(&mut storage, f);
    drop(storage);

    evm.state_mut().commit_transaction();
    evm.state_mut().clear_transaction_state();
    result
}

/// Deploys the Arachnid CREATE2 factory by directly inserting it into the EVM state.
pub fn deploy_arachnid_create2_factory(evm: &mut GenesisEvm) {
    println!("Deploying Arachnid CREATE2 factory at {ARACHNID_CREATE2_FACTORY_ADDRESS}");

    evm.overlay_db_mut().insert_account_info(
        &ARACHNID_CREATE2_FACTORY_ADDRESS,
        AccountInfo::default().with_code(Bytecode::new_raw(ARACHNID_CREATE2_FACTORY_BYTECODE)),
    );
}

/// Deploys Permit2 via the Arachnid CREATE2 factory.
///
/// Requires [`deploy_arachnid_create2_factory`] first.
pub fn deploy_permit2(evm: &mut GenesisEvm) -> eyre::Result<()> {
    // Build calldata for Arachnid CREATE2 factory: salt (32 bytes) || creation bytecode
    let calldata: Bytes = PERMIT2_SALT
        .as_slice()
        .iter()
        .chain(tempo_contracts::Permit2::BYTECODE.iter())
        .copied()
        .collect();

    println!("Deploying Permit2 via CREATE2 to {PERMIT2_ADDRESS}");

    let result = evm.system_call(
        SystemTx::new(ARACHNID_CREATE2_FACTORY_ADDRESS, calldata)
            .with_caller(Address::ZERO)
            .with_gas_limit(SYSTEM_CALL_GAS_LIMIT),
    )?;
    if !result.result().status {
        eyre::bail!("Permit2 deployment failed: {:?}", result.result());
    }
    let _ = result.commit();

    println!("Permit2 deployed successfully at {PERMIT2_ADDRESS}");
    Ok(())
}

/// Converts EVM account state into a genesis account, omitting empty storage.
pub fn genesis_account(
    info: &AccountInfo,
    storage: impl IntoIterator<Item = (U256, U256)>,
) -> GenesisAccount {
    let storage = storage
        .into_iter()
        .map(|(slot, value)| (slot.into(), value.into()))
        .collect::<std::collections::BTreeMap<_, _>>();
    GenesisAccount {
        nonce: Some(info.nonce),
        balance: info.balance,
        code: info.code.as_ref().map(Bytecode::original_bytes),
        storage: (!storage.is_empty()).then_some(storage),
        ..Default::default()
    }
}

/// Returns a genesis account holding predeployed runtime `code` with nonce one.
pub fn predeployed_contract(code: &'static [u8]) -> GenesisAccount {
    GenesisAccount {
        code: Some(Bytes::from_static(code)),
        nonce: Some(1),
        ..Default::default()
    }
}

/// Returns a chain config with every supported Ethereum hardfork active at genesis.
///
/// Tempo hardfork activations are written separately, see
/// `tempo_chainspec::cli::TempoHardforkArgs::write_to`.
pub fn ethereum_chain_config(chain_id: u64) -> ChainConfig {
    ChainConfig {
        chain_id,
        homestead_block: Some(0),
        eip150_block: Some(0),
        eip155_block: Some(0),
        eip158_block: Some(0),
        byzantium_block: Some(0),
        constantinople_block: Some(0),
        petersburg_block: Some(0),
        istanbul_block: Some(0),
        berlin_block: Some(0),
        london_block: Some(0),
        merge_netsplit_block: Some(0),
        shanghai_time: Some(0),
        cancun_time: Some(0),
        prague_time: Some(0),
        osaka_time: Some(0),
        terminal_total_difficulty: Some(U256::ZERO),
        terminal_total_difficulty_passed: true,
        deposit_contract_address: Some(Address::ZERO),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploys_permit2_through_create2_factory() {
        let mut evm = create_genesis_evm(genesis_evm_env(1337));
        deploy_arachnid_create2_factory(&mut evm);
        deploy_permit2(&mut evm).unwrap();

        let state = &evm.overlay_db().cache;
        let permit2 = state.accounts[&PERMIT2_ADDRESS]
            .as_ref()
            .expect("Permit2 account must exist");
        assert!(!state.contracts[&permit2.code_hash].is_empty());
    }

    #[test]
    fn genesis_account_omits_empty_storage() {
        let info = AccountInfo {
            nonce: 3,
            ..Default::default()
        };
        assert_eq!(genesis_account(&info, []).storage, None);
        let account = genesis_account(&info, [(U256::ONE, U256::from(2))]);
        assert_eq!(account.nonce, Some(3));
        assert_eq!(account.storage.unwrap().len(), 1);
    }
}
