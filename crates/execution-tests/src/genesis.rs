//! Genesis initialization for test vectors.
//!
//! Replicates the genesis setup from xtask to initialize precompiles
//! with their default state, similar to how a real Tempo network starts.

use alloy_evm::{EvmEnv, EvmFactory};
use alloy_primitives::{Address, U256};
use revm::database::{CacheDB, EmptyDB};
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::evm::{TempoEvm, TempoEvmFactory};
use tempo_precompiles::{
    PATH_USD_ADDRESS, account_keychain::AccountKeychain, nonce::NonceManager,
    stablecoin_dex::StablecoinDEX, storage::StorageCtx, tip_fee_manager::TipFeeManager,
    tip20::TIP20Token, tip20_factory::TIP20Factory, tip403_registry::TIP403Registry,
    validator_config::ValidatorConfig,
};

/// Default admin address for genesis setup.
/// Using a deterministic address for reproducibility.
pub const GENESIS_ADMIN: Address = Address::new([0x11; 20]);

/// Initializes all precompiles with their default genesis state. Replicates `xtask/genesis`.
pub fn initialize_genesis(
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
    admin: Address,
) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        || -> eyre::Result<()> {
            // Initialize TIP403Registry (required by TIP20)
            TIP403Registry::new().initialize()?;

            // Initialize TIP20Factory
            TIP20Factory::new().initialize()?;

            // Create PATH_USD token
            TIP20Factory::new().create_token_reserved_address(
                PATH_USD_ADDRESS,
                "pathUSD",
                "pathUSD",
                "USD",
                Address::ZERO, // quote_token
                admin,
            )?;

            // Initialize other precompiles
            TipFeeManager::new().initialize()?;
            StablecoinDEX::new().initialize()?;
            NonceManager::new().initialize()?;
            AccountKeychain::new().initialize()?;
            ValidatorConfig::new().initialize(admin)?;

            Ok(())
        },
    )
}

/// Initializes genesis and optionally mints tokens to specified addresses.
pub fn initialize_genesis_with_balances(
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
    admin: Address,
    balances: &[(Address, U256)],
) -> eyre::Result<()> {
    // First do the base genesis initialization
    initialize_genesis(evm, admin)?;

    // Then mint balances
    if !balances.is_empty() {
        let ctx = evm.ctx_mut();
        StorageCtx::enter_evm(
            &mut ctx.journaled_state,
            &ctx.block,
            &ctx.cfg,
            &ctx.tx,
            || -> eyre::Result<()> {
                let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)
                    .map_err(|e| eyre::eyre!("PATH_USD not found: {:?}", e))?;

                // Grant ISSUER_ROLE to admin for minting
                token.grant_role_internal(admin, *tempo_precompiles::tip20::ISSUER_ROLE)?;

                for (recipient, amount) in balances {
                    token.mint(
                        admin,
                        ITIP20::mintCall {
                            to: *recipient,
                            amount: *amount,
                        },
                    )?;
                }

                Ok(())
            },
        )
    } else {
        Ok(())
    }
}

/// Creates a fresh EVM with genesis state initialized.
pub fn create_genesis_evm(admin: Address) -> eyre::Result<TempoEvm<CacheDB<EmptyDB>>> {
    let db = CacheDB::new(EmptyDB::default());
    let env = EvmEnv::default().with_timestamp(U256::ZERO);
    let factory = TempoEvmFactory::default();
    let mut evm = factory.create_evm(db, env);

    initialize_genesis(&mut evm, admin)?;

    Ok(evm)
}

/// Creates a fresh EVM with genesis state and specified balances.
pub fn create_genesis_evm_with_balances(
    admin: Address,
    balances: &[(Address, U256)],
) -> eyre::Result<TempoEvm<CacheDB<EmptyDB>>> {
    let db = CacheDB::new(EmptyDB::default());
    let env = EvmEnv::default().with_timestamp(U256::ZERO);
    let factory = TempoEvmFactory::default();
    let mut evm = factory.create_evm(db, env);

    initialize_genesis_with_balances(&mut evm, admin, balances)?;

    Ok(evm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_precompiles::storage::ContractStorage;

    #[test]
    fn test_initialize_genesis() {
        let mut evm = create_genesis_evm(GENESIS_ADMIN).expect("Genesis initialization failed");

        // Verify PATH_USD exists and is initialized
        let ctx = evm.ctx_mut();
        StorageCtx::enter_evm(
            &mut ctx.journaled_state,
            &ctx.block,
            &ctx.cfg,
            &ctx.tx,
            || -> eyre::Result<()> {
                let token = TIP20Token::from_address(PATH_USD_ADDRESS)
                    .map_err(|e| eyre::eyre!("PATH_USD not found: {:?}", e))?;
                assert!(token.is_initialized()?, "PATH_USD not initialized");
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn test_initialize_genesis_with_balances() {
        let recipient = Address::new([0x22; 20]);
        let amount = U256::from(1_000_000_000_000u64);

        let mut evm = create_genesis_evm_with_balances(GENESIS_ADMIN, &[(recipient, amount)])
            .expect("Genesis with balances failed");

        // Verify balance was minted
        let ctx = evm.ctx_mut();
        StorageCtx::enter_evm(
            &mut ctx.journaled_state,
            &ctx.block,
            &ctx.cfg,
            &ctx.tx,
            || -> eyre::Result<()> {
                let token = TIP20Token::from_address(PATH_USD_ADDRESS)
                    .map_err(|e| eyre::eyre!("PATH_USD not found: {:?}", e))?;
                let balance = token.balance_of(ITIP20::balanceOfCall { account: recipient })?;
                assert_eq!(balance, amount);
                Ok(())
            },
        )
        .unwrap();
    }
}
