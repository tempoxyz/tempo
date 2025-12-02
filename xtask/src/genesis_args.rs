use alloy::{
    genesis::{ChainConfig, Genesis, GenesisAccount},
    primitives::{Address, U256, address},
    signers::{local::MnemonicBuilder, utils::secret_key_to_address},
};
use alloy_primitives::Bytes;
use eyre::WrapErr as _;
use indicatif::{ParallelProgressIterator, ProgressIterator};
use rayon::prelude::*;
use reth_evm::{
    EvmEnv, EvmFactory, EvmInternals,
    revm::{
        database::{CacheDB, EmptyDB},
        inspector::JournalExt,
    },
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_BASE_FEE};
use tempo_commonware_node_config::{Peers, PublicPolynomial, SigningKey, SigningShare};
use tempo_contracts::{
    ARACHNID_CREATE2_FACTORY_ADDRESS, CREATEX_ADDRESS, DEFAULT_7702_DELEGATE_ADDRESS,
    MULTICALL_ADDRESS, PERMIT2_ADDRESS, SAFE_DEPLOYER_ADDRESS,
    contracts::ARACHNID_CREATE2_FACTORY_BYTECODE, precompiles::ITIP20Factory,
};
use tempo_evm::evm::{TempoEvm, TempoEvmFactory};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    nonce::NonceManager,
    stablecoin_exchange::StablecoinExchange,
    storage::{ContractStorage, evm::EvmPrecompileStorageProvider},
    tip_fee_manager::{IFeeManager, TipFeeManager},
    tip20::{ISSUER_ROLE, ITIP20, TIP20Token, address_to_token_id_unchecked},
    tip20_factory::TIP20Factory,
    tip20_rewards_registry::TIP20RewardsRegistry,
    tip403_registry::TIP403Registry,
    validator_config::ValidatorConfig,
};

/// Generate genesis allocation file for testing
#[derive(Debug, clap::Args)]
pub(crate) struct GenesisArgs {
    /// Number of accounts to generate
    #[arg(short, long, default_value = "50000")]
    accounts: u32,

    /// Mnemonic to use for account generation
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    /// Balance for each account
    #[arg(long, default_value = "0xD3C21BCECCEDA1000000")]
    balance: U256,

    /// Coinbase address
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
    coinbase: Address,

    /// Chain ID
    #[arg(long, short, default_value = "1337")]
    chain_id: u64,

    /// Base fee
    #[arg(long, default_value_t = TEMPO_BASE_FEE.into())]
    base_fee_per_gas: u128,

    /// Genesis block gas limit
    #[arg(long, default_value_t = 17000000000000)]
    gas_limit: u64,

    /// Adagio hardfork activation timestamp (defaults to 0 = active at genesis)
    #[arg(long, default_value_t = 0)]
    adagio_time: u64,

    /// Moderato hardfork activation timestamp (defaults to 0 = active at genesis)
    #[arg(long, default_value_t = 0)]
    pub moderato_time: u64,

    /// Allegretto hardfork activation timestamp
    #[arg(long)]
    pub allegretto_time: Option<u64>,

    #[arg(long, default_value_t = 302_400)]
    epoch_length: u64,

    /// A comma-separated list of `<ip>:<port>`.
    #[arg(long, value_name = "<ip>:<port>", value_delimiter = ',')]
    validators: Vec<SocketAddr>,

    /// A fixed seed to generate all signing keys and group shares. This is
    /// intended for use in development and testing. Use at your own peril.
    #[arg(long)]
    pub(crate) seed: Option<u64>,
}

pub(crate) struct ConsensusConfig {
    pub(crate) public_polynomial: PublicPolynomial,
    pub(crate) peers: Peers,
    pub(crate) validators: Vec<Validator>,
}

#[derive(Clone, Debug)]
pub(crate) struct Validator {
    pub(crate) addr: SocketAddr,
    pub(crate) signing_key: SigningKey,
    pub(crate) signing_share: SigningShare,
}

impl Validator {
    pub(crate) fn dst_dir(&self, path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().join(self.addr.to_string())
    }
    pub(crate) fn dst_signing_key(&self, path: impl AsRef<Path>) -> PathBuf {
        self.dst_dir(path).join("signing.key")
    }

    pub(crate) fn dst_signing_share(&self, path: impl AsRef<Path>) -> PathBuf {
        self.dst_dir(path).join("signing.share")
    }
}

impl GenesisArgs {
    /// Generates a genesis json file.
    ///
    /// It creates a new genesis allocation for the configured accounts.
    /// And creates accounts for system contracts.
    pub(crate) async fn generate_genesis(self) -> eyre::Result<(Genesis, Option<ConsensusConfig>)> {
        println!("Generating {:?} accounts", self.accounts);

        let addresses: Vec<Address> = (0..self.accounts)
            .into_par_iter()
            .progress()
            .map(|worker_id| -> eyre::Result<Address> {
                let signer = MnemonicBuilder::from_phrase_nth(&self.mnemonic, worker_id);
                let address = secret_key_to_address(signer.credential());
                Ok(address)
            })
            .collect::<eyre::Result<Vec<Address>>>()?;

        // system contracts/precompiles must be initialized bottom up, if an init function (e.g. mint_pairwise_liquidity) uses another system contract/precompiles internally (tip403 registry), the registry must be initialized first.

        // Deploy TestUSD fee token
        let admin = addresses[0];
        let mut evm = setup_tempo_evm();

        println!("Initializing registry");
        initialize_registry(&mut evm)?;

        // Initialize TIP20Factory once before creating any tokens
        println!("Initializing TIP20Factory");
        initialize_tip20_factory(&mut evm)?;

        // Post-Allegretto: PathUSD is created through the factory as token_id=0 with address(0) as quote token
        println!("Creating PathUSD through factory");
        create_path_usd_token(admin, &addresses, &mut evm)?;

        println!("Initializing TIP20 tokens");
        let (_, alpha_token_address) = create_and_mint_token(
            "AlphaUSD",
            "AlphaUSD",
            "USD",
            PATH_USD_ADDRESS,
            admin,
            &addresses,
            U256::from(u64::MAX),
            &mut evm,
        )?;

        let (_, beta_token_address) = create_and_mint_token(
            "BetaUSD",
            "BetaUSD",
            "USD",
            PATH_USD_ADDRESS,
            admin,
            &addresses,
            U256::from(u64::MAX),
            &mut evm,
        )?;

        let (_, theta_token_address) = create_and_mint_token(
            "ThetaUSD",
            "ThetaUSD",
            "USD",
            PATH_USD_ADDRESS,
            admin,
            &addresses,
            U256::from(u64::MAX),
            &mut evm,
        )?;

        println!("Initializing TIP20RewardsRegistry");
        initialize_tip20_rewards_registry(&mut evm)?;

        println!("Initializing validator config");
        initialize_validator_config(admin, &mut evm)?;

        println!("Initializing fee manager");
        initialize_fee_manager(
            alpha_token_address,
            addresses.clone(),
            // TODO: also populate validators here, once the logic is back.
            vec![self.coinbase],
            &mut evm,
        );

        println!("Initializing stablecoin exchange");
        initialize_stablecoin_exchange(&mut evm)?;

        println!("Initializing nonce manager");
        initialize_nonce_manager(&mut evm)?;

        println!("Minting pairwise FeeAMM liquidity");
        mint_pairwise_liquidity(
            alpha_token_address,
            vec![PATH_USD_ADDRESS, beta_token_address, theta_token_address],
            U256::from(10u64.pow(10)),
            admin,
            &mut evm,
        );

        // Save EVM state to allocation
        println!("Saving EVM state to allocation");
        let evm_state = evm.ctx_mut().journaled_state.evm_state();
        let mut genesis_alloc: BTreeMap<Address, GenesisAccount> = evm_state
            .iter()
            .progress()
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
            SAFE_DEPLOYER_ADDRESS,
            GenesisAccount {
                code: Some(tempo_contracts::SafeDeployer::DEPLOYED_BYTECODE.clone()),
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

        genesis_alloc.insert(
            ARACHNID_CREATE2_FACTORY_ADDRESS,
            GenesisAccount {
                code: Some(ARACHNID_CREATE2_FACTORY_BYTECODE),
                nonce: Some(1),
                ..Default::default()
            },
        );

        println!(
            "generating consensus config for validators: {:?}",
            self.validators
        );
        let consensus_config = generate_consensus_config(&self.validators, self.seed);

        let mut chain_config = ChainConfig {
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
            osaka_time: Some(0),
            terminal_total_difficulty: Some(U256::from(0)),
            terminal_total_difficulty_passed: true,
            deposit_contract_address: Some(address!("0x00000000219ab540356cBB839Cbe05303d7705Fa")),
            ..Default::default()
        };

        // Add Tempo hardfork times to extra_fields
        chain_config.extra_fields.insert(
            "adagioTime".to_string(),
            serde_json::json!(self.adagio_time),
        );
        chain_config.extra_fields.insert(
            "moderatoTime".to_string(),
            serde_json::json!(self.moderato_time),
        );
        if let Some(allegretto_time) = self.allegretto_time {
            chain_config.extra_fields.insert(
                "allegrettoTime".to_string(),
                serde_json::json!(allegretto_time),
            );
        }

        chain_config
            .extra_fields
            .insert_value("epochLength".to_string(), self.epoch_length)?;
        if let Some(consensus_config) = &consensus_config {
            chain_config
                .extra_fields
                .insert_value("validators".to_string(), consensus_config.peers.clone())?;
            chain_config.extra_fields.insert_value(
                "publicPolynomial".to_string(),
                consensus_config.public_polynomial.clone(),
            )?;
        }

        let mut genesis = Genesis::default()
            .with_gas_limit(self.gas_limit)
            .with_base_fee(Some(self.base_fee_per_gas))
            .with_nonce(0x42)
            .with_extra_data(Bytes::from_static(b"tempo-genesis"))
            .with_coinbase(self.coinbase);

        genesis.alloc = genesis_alloc;
        genesis.config = chain_config;

        Ok((genesis, consensus_config))
    }
}

fn setup_tempo_evm() -> TempoEvm<CacheDB<EmptyDB>> {
    let db = CacheDB::default();
    let mut env = EvmEnv::default();
    // Configure EVM for Allegretto hardfork so factory uses correct token_id counter (starts at 0)
    // and accepts address(0) as quote token for the first token
    env.cfg_env = env.cfg_env.with_spec(TempoHardfork::Allegretto);
    let factory = TempoEvmFactory::default();
    factory.create_evm(db, env)
}

/// Initializes the TIP20Factory contract (should be called once before creating any tokens)
fn initialize_tip20_factory(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

    let mut factory = TIP20Factory::new(&mut provider);
    factory
        .initialize()
        .expect("Could not initialize tip20 factory");
    Ok(())
}

/// Creates PathUSD as the first TIP20 token (token_id=0) through the factory.
/// Post-Allegretto, the first token must have address(0) as quote token.
fn create_path_usd_token(
    admin: Address,
    recipients: &[Address],
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

    // Create PathUSD through factory with address(0) as quote token (required for first token post-Allegretto)
    let token_address = {
        let mut factory = TIP20Factory::new(&mut provider);
        factory
            .create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: "pathUSD".into(),
                    symbol: "pathUSD".into(),
                    currency: "USD".into(),
                    quoteToken: Address::ZERO, // First token must use address(0) as quote token
                    admin,
                },
            )
            .expect("Could not create PathUSD token")
    };

    // Verify it was created at the expected address (token_id=0)
    assert_eq!(
        token_address, PATH_USD_ADDRESS,
        "PathUSD should be created at token_id=0 address"
    );

    let mut token = TIP20Token::new(0, &mut provider);
    token.grant_role_internal(admin, *ISSUER_ROLE)?;

    // Mint to all recipients
    for recipient in recipients.iter().progress() {
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: *recipient,
                    amount: U256::from(u64::MAX),
                },
            )
            .expect("Could not mint pathUSD");
    }

    Ok(())
}

/// Creates a TIP20 token through the factory (factory must already be initialized)
#[expect(clippy::too_many_arguments)]
fn create_and_mint_token(
    symbol: &str,
    name: &str,
    currency: &str,
    quote_token: Address,
    admin: Address,
    recipients: &[Address],
    mint_amount: U256,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) -> eyre::Result<(u64, Address)> {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

    let token_id = {
        let mut factory = TIP20Factory::new(&mut provider);
        assert!(
            factory
                .is_initialized()
                .expect("Could not check factory initialization"),
            "TIP20Factory must be initialized before creating tokens"
        );
        let token_address = factory
            .create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: name.into(),
                    symbol: symbol.into(),
                    currency: currency.into(),
                    quoteToken: quote_token,
                    admin,
                },
            )
            .expect("Could not create token");

        address_to_token_id_unchecked(token_address)
    };

    let mut token = TIP20Token::new(token_id, &mut provider);
    token.grant_role_internal(admin, *ISSUER_ROLE)?;

    let result = token.set_supply_cap(
        admin,
        ITIP20::setSupplyCapCall {
            newSupplyCap: U256::from(u128::MAX),
        },
    );
    assert!(result.is_ok());

    token
        .mint(
            admin,
            ITIP20::mintCall {
                to: admin,
                amount: mint_amount,
            },
        )
        .expect("Token minting failed");

    for address in recipients.iter().progress() {
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: *address,
                    amount: U256::from(u64::MAX),
                },
            )
            .expect("Could not mint fee token");
    }

    Ok((token_id, token.address()))
}

fn initialize_tip20_rewards_registry(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);
    TIP20RewardsRegistry::new(&mut provider).initialize()?;

    Ok(())
}

fn initialize_fee_manager(
    default_fee_address: Address,
    initial_accounts: Vec<Address>,
    validators: Vec<Address>,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) {
    // Update the beneficiary since the validator can't set the validator fee token for themselves
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

    let mut fee_manager = TipFeeManager::new(&mut provider);
    fee_manager
        .initialize()
        .expect("Could not init fee manager");
    for address in initial_accounts.iter().progress() {
        fee_manager
            .set_user_token(
                *address,
                IFeeManager::setUserTokenCall {
                    token: default_fee_address,
                },
            )
            .expect("Could not set fee token");
    }

    // Set validator fee tokens to PathUSD
    for validator in validators {
        fee_manager
            .set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: PATH_USD_ADDRESS,
                },
                // use random address to avoid `CannotChangeWithinBlock` error
                Address::random(),
            )
            .expect("Could not set validator fee token");
    }
}

/// Initializes the [`TIP403Registry`] contract.
fn initialize_registry(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);
    TIP403Registry::new(&mut provider).initialize().unwrap();
    Ok(())
}

fn initialize_stablecoin_exchange(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

    let mut exchange = StablecoinExchange::new(&mut provider);
    exchange.initialize()?;

    Ok(())
}

fn initialize_nonce_manager(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);
    NonceManager::new(&mut provider).initialize()?;

    Ok(())
}

/// Initializes the initial validator config smart contract.
///
/// NOTE: Does not populate it at all because consensus does not read the
/// validators at genesis.
fn initialize_validator_config(
    admin: Address,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

    let mut validator_config = ValidatorConfig::new(&mut provider);
    validator_config
        .initialize(admin)
        .wrap_err("failed to initialize validator config contract")?;
    Ok(())
}

/// Generates the consensus configs of the validators.
fn generate_consensus_config(
    addresses: &[SocketAddr],
    seed: Option<u64>,
) -> Option<ConsensusConfig> {
    use commonware_cryptography::{PrivateKeyExt as _, Signer as _, ed25519::PrivateKey};
    use rand::SeedableRng as _;

    if addresses.is_empty() {
        println!("no validator socket addresses provided; not generating consensus config");
        return None;
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand::random::<u64>));
    let mut signers = (0..addresses.len())
        .map(|_| PrivateKey::from_rng(&mut rng))
        .collect::<Vec<_>>();

    // generate consensus key
    let threshold = commonware_utils::quorum(addresses.len() as u32);
    let (polynomial, shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<
        _,
        commonware_cryptography::bls12381::primitives::variant::MinSig,
    >(&mut rng, None, addresses.len() as u32, threshold);

    signers.sort_by_key(|signer| signer.public_key());
    let peers = addresses
        .iter()
        .zip(signers.iter())
        .map(|(addr, private_key)| (private_key.public_key(), *addr))
        .collect::<commonware_utils::set::OrderedAssociated<_, _>>();

    let mut validators = vec![];
    for (addr, (signer, share)) in peers.values().iter().zip(signers.into_iter().zip(shares)) {
        validators.push(Validator {
            addr: *addr,
            signing_key: SigningKey::from(signer),
            signing_share: SigningShare::from(share),
        });
    }
    Some(ConsensusConfig {
        peers: peers.into(),
        public_polynomial: polynomial.into(),
        validators,
    })
}

fn mint_pairwise_liquidity(
    a_token: Address,
    b_tokens: Vec<Address>,
    amount: U256,
    admin: Address,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) {
    let ctx = evm.ctx_mut();
    let evm_internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, &ctx.cfg);

    let mut fee_manager = TipFeeManager::new(&mut provider);

    for b_token_address in b_tokens {
        fee_manager
            .mint(admin, a_token, b_token_address, amount, amount, admin)
            .expect("Could not mint A -> B Liquidity pool");
    }
}
