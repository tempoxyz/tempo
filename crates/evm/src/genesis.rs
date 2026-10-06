//! Shared Tempo genesis state initialization.
//!
//! Tempo L1 and Zone genesis generators both initialize precompiles and standard contracts in an
//! in-memory Tempo EVM, then serialize the resulting state into a genesis allocation. This module
//! holds the pieces they share; chain-specific accounts, anchors and policies remain with each
//! generator.

use crate::evm::{TempoEvm, TempoEvmFactory};
use alloy_genesis::{ChainConfig, GenesisAccount};
use alloy_primitives::{Address, Bytes, U256};
use reth_evm::{
    Evm as _, EvmEnv, EvmFactory as _,
    revm::{
        DatabaseCommit as _,
        database::InMemoryDB,
        state::{AccountInfo, Bytecode},
    },
};
use tempo_chainspec::TempoHardfork;
use tempo_contracts::{
    ARACHNID_CREATE2_FACTORY_ADDRESS, PERMIT2_ADDRESS, PERMIT2_SALT,
    contracts::ARACHNID_CREATE2_FACTORY_BYTECODE,
};
use tempo_precompiles::storage::{StorageActions, StorageCtx};
use tempo_revm::TempoBlockEnv;

/// In-memory EVM used to build genesis state.
pub type GenesisEvm = TempoEvm<InMemoryDB>;

/// Returns the EVM environment used for genesis initialization: timestamp zero and `chain_id`.
///
/// Callers may adjust limits before [`create_genesis_evm`].
pub fn genesis_evm_env(chain_id: u64) -> EvmEnv<TempoHardfork, TempoBlockEnv> {
    // revm sets timestamp to 1 by default, override it to 0 for genesis initializations
    let mut env = EvmEnv::default().with_timestamp(U256::ZERO);
    env.cfg_env.chain_id = chain_id;
    env
}

/// Creates an empty in-memory genesis EVM.
pub fn create_genesis_evm(env: EvmEnv<TempoHardfork, TempoBlockEnv>) -> GenesisEvm {
    TempoEvmFactory::default().create_evm(InMemoryDB::default(), env)
}

/// Runs `f` with precompile storage bound to the genesis EVM, with storage actions disabled.
pub fn with_genesis_storage<R>(evm: &mut GenesisEvm, f: impl FnOnce() -> R) -> R {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        StorageActions::disabled(),
        f,
    )
}

/// Deploys the Arachnid CREATE2 factory by directly inserting it into the EVM state.
pub fn deploy_arachnid_create2_factory(evm: &mut GenesisEvm) {
    println!("Deploying Arachnid CREATE2 factory at {ARACHNID_CREATE2_FACTORY_ADDRESS}");

    evm.db_mut().insert_account_info(
        ARACHNID_CREATE2_FACTORY_ADDRESS,
        AccountInfo {
            code: Some(Bytecode::new_raw(ARACHNID_CREATE2_FACTORY_BYTECODE)),
            nonce: 0,
            ..Default::default()
        },
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

    let result =
        evm.transact_system_call(Address::ZERO, ARACHNID_CREATE2_FACTORY_ADDRESS, calldata)?;
    if !result.result.is_success() {
        eyre::bail!("Permit2 deployment failed: {result:?}");
    }
    evm.db_mut().commit(result.state);

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
        code: info.code.as_ref().map(|code| code.original_bytes()),
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

        let permit2 = &evm.db_mut().cache.accounts[&PERMIT2_ADDRESS];
        assert!(
            permit2
                .info
                .code
                .as_ref()
                .is_some_and(|code| !code.is_empty())
        );
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
