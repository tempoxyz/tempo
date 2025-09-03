use alloy::{
    genesis::{ChainConfig, Genesis, GenesisAccount},
    primitives::{Address, Bytes, U256, address},
    signers::{local::MnemonicBuilder, utils::secret_key_to_address},
};
use alloy_signer_local::coins_bip39::English;
use clap::Parser;
use rayon::prelude::*;
use reth::revm::{
    context::ContextTr,
    db::{CacheDB, EmptyDB},
    inspector::JournalExt,
};
use reth_evm::{Evm, EvmEnv, EvmFactory, EvmInternals};
use simple_tqdm::{ParTqdm, Tqdm};
use std::{collections::BTreeMap, fs, path::PathBuf};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::{
    CREATEX_ADDRESS, DEFAULT_7702_DELEGATE_ADDRESS, MULTICALL_ADDRESS, PERMIT2_ADDRESS,
};
use tempo_evm::evm::{TempoEvm, TempoEvmFactory};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    contracts::{
        EvmStorageProvider, IFeeManager, ITIP20, ITIP20Factory, TIP20Factory, TIP20Token,
        TipFeeManager, tip20::ISSUER_ROLE,
    },
};

/// Generate genesis allocation file for testing
#[derive(Parser, Debug)]
pub struct GenesisArgs {
    /// Number of accounts to generate
    #[arg(short, long, default_value = "50000")]
    pub accounts: u32,

    /// Output file path
    #[arg(short, long)]
    pub output: PathBuf,

    /// Mnemonic to use for account generation
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    pub mnemonic: String,

    /// Balance for each account
    #[arg(long, default_value = "0xD3C21BCECCEDA1000000")]
    pub balance: U256,

    /// Chain ID
    #[arg(long, short, default_value = "1337")]
    pub chain_id: u64,

    /// Base fee
    #[arg(long, default_value_t = TEMPO_BASE_FEE.into())]
    pub base_fee_per_gas: u128,
}

impl GenesisArgs {
    pub async fn run(self) -> eyre::Result<()> {
        println!("Generating {:?} accounts", self.accounts);
        let addresses: Vec<Address> = (0..self.accounts)
            .into_par_iter()
            .tqdm()
            .map(|worker_id| -> eyre::Result<Address> {
                let signer = MnemonicBuilder::<English>::default()
                    .phrase(self.mnemonic.clone())
                    .index(worker_id)?
                    .build()?;
                let address = secret_key_to_address(signer.credential());
                Ok(address)
            })
            .collect::<eyre::Result<Vec<Address>>>()?;

        // Deploy TestUSD fee token
        let admin = addresses[0];
        let mut evm = setup_tempo_evm();
        let fee_token_id = create_and_mint_token(
            "TestUSD",
            "TestUSD",
            "USD",
            admin,
            U256::from(u128::MAX),
            &mut evm,
        )?;

        {
            let block = evm.block.clone();
            let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
            let mut provider = EvmStorageProvider::new(evm_internals, 1);
            let mut token = TIP20Token::new(fee_token_id, &mut provider);
            let fee_token = token.token_address;
            println!("Minting TestUSD to all addresses");
            // Mint TestUSD to all addresses
            for address in addresses.iter().tqdm() {
                token
                    .mint(
                        &admin,
                        ITIP20::mintCall {
                            to: *address,
                            amount: U256::from(u64::MAX),
                        },
                    )
                    .expect("Could not mint fee token");
            }

            let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, token.storage);
            for address in addresses.iter().tqdm() {
                fee_manager
                    .set_user_token(address, IFeeManager::setUserTokenCall { token: fee_token })
                    .expect("Could not set fee token");
            }

            fee_manager
                .set_validator_token(
                    &Address::ZERO,
                    IFeeManager::setValidatorTokenCall { token: fee_token },
                )
                .expect("Could not 0x00 validator fee token");
        }

        // Save EVM state to allocation
        println!("Saving EVM state to allocation");
        let evm_state = evm.ctx_mut().journaled_state.evm_state();
        let mut genesis_alloc: BTreeMap<Address, GenesisAccount> = evm_state
            .iter()
            .tqdm()
            .map(|(address, account)| {
                let storage = if !account.storage.is_empty() {
                    Some(
                        account
                            .storage
                            .iter()
                            .map(|(key, val)| ((*key).into(), val.present_value.into()))
                            .collect(),
                    )
                } else {
                    None
                };
                let genesis_account = GenesisAccount {
                    nonce: Some(account.info.nonce),
                    code: account.info.code.as_ref().map(|c| c.original_bytes()),
                    storage,
                    ..Default::default()
                };
                (*address, genesis_account)
            })
            .collect();

        genesis_alloc.insert(
            MULTICALL_ADDRESS,
            GenesisAccount {
                code: Some(tempo_contracts::Multicall::DEPLOYED_BYTECODE.clone()),
                nonce: Some(1),
                ..Default::default()
            },
        );

        genesis_alloc.insert(
            DEFAULT_7702_DELEGATE_ADDRESS,
            GenesisAccount {
                code: Some(tempo_contracts::IthacaAccount::DEPLOYED_BYTECODE.clone()),
                nonce: Some(1),
                ..Default::default()
            },
        );

        genesis_alloc.insert(
            CREATEX_ADDRESS,
            GenesisAccount {
                code: Some(tempo_contracts::CreateX::DEPLOYED_BYTECODE.clone()),
                nonce: Some(1),
                ..Default::default()
            },
        );

        genesis_alloc.insert(
            PERMIT2_ADDRESS,
            GenesisAccount {
                code: Some(tempo_contracts::Permit2::DEPLOYED_BYTECODE.clone()),
                nonce: Some(1),
                ..Default::default()
            },
        );

        let chain_config = ChainConfig {
            chain_id: self.chain_id,
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
            terminal_total_difficulty: Some(U256::from(0)),
            terminal_total_difficulty_passed: true,
            deposit_contract_address: Some(address!("0x00000000219ab540356cBB839Cbe05303d7705Fa")),
            ..Default::default()
        };

        let mut genesis = Genesis::default()
            .with_gas_limit(0xfffffffffff)
            .with_base_fee(Some(self.base_fee_per_gas))
            .with_nonce(0x42)
            .with_extra_data(Bytes::from_static(b"tempo-genesis"))
            .with_coinbase(Address::ZERO);

        genesis.alloc = genesis_alloc;
        genesis.config = chain_config;

        let json = serde_json::to_string_pretty(&genesis)?;
        fs::write(self.output, json)?;

        Ok(())
    }
}

fn setup_tempo_evm() -> TempoEvm<CacheDB<EmptyDB>> {
    let db = CacheDB::default();
    let env = EvmEnv::default();
    let factory = TempoEvmFactory::default();
    factory.create_evm(db, env)
}

/// Initializes the TIP20 factory contract and creates a token
fn create_and_mint_token(
    symbol: &str,
    name: &str,
    currency: &str,
    admin: Address,
    mint_amount: U256,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) -> eyre::Result<u64> {
    let chain_id = evm.chain_id();
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmStorageProvider::new(evm_internals, chain_id);

    let token_id = {
        let mut factory = TIP20Factory::new(&mut provider);
        factory
            .initialize()
            .expect("Could not initialize tip20 factory");
        factory
            .create_token(
                &admin,
                ITIP20Factory::createTokenCall {
                    name: name.into(),
                    symbol: symbol.into(),
                    currency: currency.into(),
                    admin,
                },
            )
            .expect("Could not create token")
            .to::<u64>()
    };

    let mut token = TIP20Token::new(token_id, &mut provider);
    token
        .get_roles_contract()
        .grant_role_internal(&admin, *ISSUER_ROLE);

    let result = token.set_supply_cap(
        &admin,
        ITIP20::setSupplyCapCall {
            newSupplyCap: U256::MAX,
        },
    );
    assert!(result.is_ok());

    token
        .mint(
            &admin,
            ITIP20::mintCall {
                to: admin,
                amount: mint_amount,
            },
        )
        .expect("Token minting failed");

    Ok(token_id)
}
