use alloy::{
    genesis::{ChainConfig, Genesis, GenesisAccount},
    primitives::{Address, U256, address},
    signers::{local::MnemonicBuilder, utils::secret_key_to_address},
};
use alloy_primitives::Bytes;
use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::{self, Output},
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519::PublicKey,
};
use commonware_math::algebra::Random as _;
use commonware_utils::{TryFromIterator as _, ordered};
use eyre::{WrapErr as _, eyre};
use indicatif::{ParallelProgressIterator, ProgressIterator};
use itertools::Itertools;
use rayon::prelude::*;
use reth_evm::{
    Evm as _, EvmEnv, EvmFactory,
    revm::{
        DatabaseCommit,
        context_interface::JournalTr as _,
        database::{CacheDB, EmptyDB},
        inspector::JournalExt,
        state::{AccountInfo, Bytecode},
    },
};
use std::{
    collections::BTreeMap,
    iter::repeat_with,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_commonware_node_config::{SigningKey, SigningShare};
use tempo_contracts::{
    ARACHNID_CREATE2_FACTORY_ADDRESS, CREATEX_ADDRESS, MULTICALL3_ADDRESS, PERMIT2_ADDRESS,
    PERMIT2_SALT, SAFE_DEPLOYER_ADDRESS,
    contracts::{ARACHNID_CREATE2_FACTORY_BYTECODE, CreateX, Multicall3, SafeDeployer},
    precompiles::{ITIP20Factory, IValidatorConfig},
};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::evm::{TempoEvm, TempoEvmFactory};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    account_keychain::AccountKeychain,
    nonce::NonceManager,
    stablecoin_exchange::StablecoinExchange,
    storage::{ContractStorage, StorageCtx},
    tip_fee_manager::{IFeeManager, TipFeeManager},
    tip20::{ISSUER_ROLE, ITIP20, TIP20Token, address_to_token_id_unchecked},
    tip20_factory::TIP20Factory,
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
    #[arg(long, default_value_t = 500_000_000)]
    gas_limit: u64,

    /// The hard-coded length of an epoch in blocks.
    #[arg(long, default_value_t = 302_400)]
    epoch_length: u64,

    /// A comma-separated list of `<ip>:<port>`.
    #[arg(
        long,
        value_name = "<ip>:<port>",
        value_delimiter = ',',
        required_unless_present_all(["no_dkg_in_genesis"]),
    )]
    validators: Vec<SocketAddr>,

    /// Will not write the initial DKG outcome into the extra_data field of
    /// the genesis header.
    #[arg(long)]
    no_dkg_in_genesis: bool,

    /// A fixed seed to generate all signing keys and group shares. This is
    /// intended for use in development and testing. Use at your own peril.
    #[arg(long)]
    pub(crate) seed: Option<u64>,

    /// Custom admin address for PathUSD token.
    /// If not set, uses the first generated account.
    #[arg(long)]
    pathusd_admin: Option<Address>,

    /// Custom admin address for validator config.
    /// If not set, uses the first generated account.
    #[arg(long)]
    validator_admin: Option<Address>,

    /// Custom onchain addresses for validators.
    /// Must match the number of validators if provided.
    #[arg(long, value_delimiter = ',')]
    validator_addresses: Vec<Address>,

    /// Disable creating Alpha/Beta/ThetaUSD tokens.
    #[arg(long)]
    no_extra_tokens: bool,

    /// Disable minting pairwise FeeAMM liquidity.
    #[arg(long)]
    no_pairwise_liquidity: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ConsensusConfig {
    pub(crate) output: Output<MinSig, PublicKey>,
    pub(crate) validators: Vec<Validator>,
}
impl ConsensusConfig {
    pub(crate) fn to_genesis_dkg_outcome(&self) -> OnchainDkgOutcome {
        OnchainDkgOutcome {
            epoch: Epoch::zero(),
            output: self.output.clone(),
            next_players: ordered::Set::try_from_iter(
                self.validators.iter().map(Validator::public_key),
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Validator {
    pub(crate) addr: SocketAddr,
    pub(crate) signing_key: SigningKey,
    pub(crate) signing_share: SigningShare,
}

impl Validator {
    pub(crate) fn public_key(&self) -> PublicKey {
        self.signing_key.public_key()
    }

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
        let pathusd_admin = self.pathusd_admin.unwrap_or(addresses[0]);
        let validator_admin = self.validator_admin.unwrap_or(addresses[0]);
        let mut evm = setup_tempo_evm(self.chain_id);

        deploy_arachnid_create2_factory(&mut evm);
        deploy_permit2(&mut evm)?;

        println!("Initializing registry");
        initialize_registry(&mut evm)?;

        // Initialize TIP20Factory once before creating any tokens
        println!("Initializing TIP20Factory");
        initialize_tip20_factory(&mut evm)?;

        println!("Creating PathUSD through factory");
        create_path_usd_token(pathusd_admin, &addresses, &mut evm)?;

        let (alpha_token_address, beta_token_address, theta_token_address) =
            if !self.no_extra_tokens {
                println!("Initializing TIP20 tokens");
                let (_, alpha) = create_and_mint_token(
                    "AlphaUSD",
                    "AlphaUSD",
                    "USD",
                    PATH_USD_ADDRESS,
                    pathusd_admin,
                    &addresses,
                    U256::from(u64::MAX),
                    &mut evm,
                )?;

                let (_, beta) = create_and_mint_token(
                    "BetaUSD",
                    "BetaUSD",
                    "USD",
                    PATH_USD_ADDRESS,
                    pathusd_admin,
                    &addresses,
                    U256::from(u64::MAX),
                    &mut evm,
                )?;

                let (_, theta) = create_and_mint_token(
                    "ThetaUSD",
                    "ThetaUSD",
                    "USD",
                    PATH_USD_ADDRESS,
                    pathusd_admin,
                    &addresses,
                    U256::from(u64::MAX),
                    &mut evm,
                )?;

                (Some(alpha), Some(beta), Some(theta))
            } else {
                println!("Skipping extra token creation (--no-extra-tokens)");
                (None, None, None)
            };

        println!(
            "generating consensus config for validators: {:?}",
            self.validators
        );
        let consensus_config =
            generate_consensus_config(&self.validators, self.seed, self.no_dkg_in_genesis);

        println!("Initializing validator config");
        let validator_onchain_addresses = if self.validator_addresses.is_empty() {
            None
        } else {
            Some(&self.validator_addresses[..])
        };
        initialize_validator_config(
            validator_admin,
            &mut evm,
            &consensus_config,
            // Skip first address (used as default admin)
            &addresses[1..],
            validator_onchain_addresses,
            self.no_dkg_in_genesis,
        )?;

        println!("Initializing fee manager");
        let default_fee_token = alpha_token_address.unwrap_or(PATH_USD_ADDRESS);
        initialize_fee_manager(
            default_fee_token,
            addresses.clone(),
            // TODO: also populate validators here, once the logic is back.
            vec![self.coinbase],
            &mut evm,
        );

        println!("Initializing stablecoin exchange");
        initialize_stablecoin_exchange(&mut evm)?;

        println!("Initializing nonce manager");
        initialize_nonce_manager(&mut evm)?;

        println!("Initializing account keychain");
        initialize_account_keychain(&mut evm)?;

        if !self.no_pairwise_liquidity {
            if let (Some(alpha), Some(beta), Some(theta)) =
                (alpha_token_address, beta_token_address, theta_token_address)
            {
                println!("Minting pairwise FeeAMM liquidity");
                mint_pairwise_liquidity(
                    alpha,
                    vec![PATH_USD_ADDRESS, beta, theta],
                    U256::from(10u64.pow(10)),
                    pathusd_admin,
                    &mut evm,
                );
            } else {
                println!("Skipping pairwise liquidity (extra tokens not created)");
            }
        } else {
            println!("Skipping pairwise liquidity (--no-pairwise-liquidity)");
        }

        evm.ctx_mut()
            .journaled_state
            .load_account(ARACHNID_CREATE2_FACTORY_ADDRESS)?;
        evm.ctx_mut()
            .journaled_state
            .load_account(PERMIT2_ADDRESS)?;

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
            MULTICALL3_ADDRESS,
            GenesisAccount {
                code: Some(Bytes::from_static(&Multicall3::DEPLOYED_BYTECODE)),
                nonce: Some(1),
                ..Default::default()
            },
        );

        genesis_alloc.insert(
            CREATEX_ADDRESS,
            GenesisAccount {
                code: Some(Bytes::from_static(&CreateX::DEPLOYED_BYTECODE)),
                nonce: Some(1),
                ..Default::default()
            },
        );

        genesis_alloc.insert(
            SAFE_DEPLOYER_ADDRESS,
            GenesisAccount {
                code: Some(Bytes::from_static(&SafeDeployer::DEPLOYED_BYTECODE)),
                nonce: Some(1),
                ..Default::default()
            },
        );

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

        chain_config
            .extra_fields
            .insert_value("epochLength".to_string(), self.epoch_length)?;
        let mut extra_data = Bytes::from_static(b"tempo-genesis");

        if let Some(consensus_config) = &consensus_config {
            if self.no_dkg_in_genesis {
                println!("no-initial-dkg-in-genesis passed; not writing to header extra_data");
            } else {
                extra_data = consensus_config
                    .to_genesis_dkg_outcome()
                    .encode()
                    .freeze()
                    .to_vec()
                    .into();
            }
        }

        let mut genesis = Genesis::default()
            .with_gas_limit(self.gas_limit)
            .with_base_fee(Some(self.base_fee_per_gas))
            .with_nonce(0x42)
            .with_extra_data(extra_data)
            .with_coinbase(self.coinbase);

        genesis.alloc = genesis_alloc;
        genesis.config = chain_config;

        Ok((genesis, consensus_config))
    }
}

fn setup_tempo_evm(chain_id: u64) -> TempoEvm<CacheDB<EmptyDB>> {
    let db = CacheDB::default();
    // revm sets timestamp to 1 by default, override it to 0 for genesis initializations
    let mut env = EvmEnv::default().with_timestamp(U256::ZERO);
    env.cfg_env.chain_id = chain_id;

    let factory = TempoEvmFactory::default();
    factory.create_evm(db, env)
}

/// Deploys the Arachnid CREATE2 factory by directly inserting it into the EVM state.
fn deploy_arachnid_create2_factory(evm: &mut TempoEvm<CacheDB<EmptyDB>>) {
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

/// Deploys Permit2 contract via the Arachnid CREATE2 factory.
fn deploy_permit2(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    // Build calldata for Arachnid CREATE2 factory: salt (32 bytes) || creation bytecode
    let bytecode = &tempo_contracts::Permit2::BYTECODE;
    let calldata: Bytes = PERMIT2_SALT
        .as_slice()
        .iter()
        .chain(bytecode.iter())
        .copied()
        .collect();

    println!("Deploying Permit2 via CREATE2 to {PERMIT2_ADDRESS}");

    let result =
        evm.transact_system_call(Address::ZERO, ARACHNID_CREATE2_FACTORY_ADDRESS, calldata)?;

    if !result.result.is_success() {
        return Err(eyre!("Permit2 deployment failed: {:?}", result));
    }

    evm.db_mut().commit(result.state);

    println!("Permit2 deployed successfully at {PERMIT2_ADDRESS}");
    Ok(())
}

/// Initializes the TIP20Factory contract (should be called once before creating any tokens)
fn initialize_tip20_factory(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        TIP20Factory::new().initialize()
    })?;
    Ok(())
}

/// Creates PathUSD as the first TIP20 token (token_id=0) through the factory.
/// The first token must have address(0) as quote token.
fn create_path_usd_token(
    admin: Address,
    recipients: &[Address],
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        // Create PathUSD through factory with address(0) as quote token (required for first token)
        let token_address = TIP20Factory::new()
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
            .expect("Could not create PathUSD token");

        // Verify it was created at the expected address (token_id=0)
        assert_eq!(
            token_address, PATH_USD_ADDRESS,
            "PathUSD should be created at token_id=0 address"
        );

        let mut token = TIP20Token::new(0);
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
    })
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
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        let mut factory = TIP20Factory::new();
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

        let token_id = address_to_token_id_unchecked(token_address);

        let mut token = TIP20Token::new(token_id);
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
    })
}

fn initialize_fee_manager(
    default_fee_address: Address,
    initial_accounts: Vec<Address>,
    validators: Vec<Address>,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) {
    // Update the beneficiary since the validator can't set the validator fee token for themselves
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        let mut fee_manager = TipFeeManager::new();
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
    });
}

/// Initializes the [`TIP403Registry`] contract.
fn initialize_registry(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        TIP403Registry::new().initialize()
    })?;

    Ok(())
}

fn initialize_stablecoin_exchange(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        StablecoinExchange::new().initialize()
    })?;

    Ok(())
}

fn initialize_nonce_manager(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        NonceManager::new().initialize()
    })?;

    Ok(())
}

/// Initializes the [`AccountKeychain`] contract.
fn initialize_account_keychain(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        AccountKeychain::new().initialize()
    })?;

    Ok(())
}

/// Initializes the initial validator config smart contract.
///
/// NOTE: Does not populate it at all because consensus does not read the
/// validators at genesis.
fn initialize_validator_config(
    admin: Address,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
    consensus_config: &Option<ConsensusConfig>,
    fallback_addresses: &[Address],
    custom_validator_addresses: Option<&[Address]>,
    no_dkg_in_genesis: bool,
) -> eyre::Result<()> {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        let mut validator_config = ValidatorConfig::new();
        validator_config
            .initialize(admin)
            .wrap_err("failed to initialize validator config contract")?;

        if no_dkg_in_genesis {
            println!("no-dkg-in-genesis passed; not writing validators to genesis block");
            return Ok(());
        }

        if let Some(consensus_config) = consensus_config.clone() {
            let num_validators = consensus_config.validators.len();
            let addrs = custom_validator_addresses.unwrap_or(fallback_addresses);

            if addrs.len() < num_validators {
                return Err(eyre!(
                    "need {} addresses for all validators, but only {} were provided",
                    num_validators,
                    addrs.len()
                ));
            }

            println!("writing {num_validators} validators into contract");
            for (i, validator) in consensus_config.validators.iter().enumerate() {
                #[expect(non_snake_case, reason = "field of a snakeCase smart contract call")]
                let newValidatorAddress = addrs[i];
                let public_key = validator.public_key();
                let addr = validator.addr;
                validator_config
                    .add_validator(
                        admin,
                        IValidatorConfig::addValidatorCall {
                            newValidatorAddress,
                            publicKey: public_key.encode().freeze().as_ref().try_into().unwrap(),
                            active: true,
                            inboundAddress: addr.to_string(),
                            outboundAddress: addr.to_string(),
                        },
                    )
                    .wrap_err(
                        "failed to execute smart contract call to add validator to evm state",
                    )?;
                println!(
                    "added validator\
                \n\tpublic key: {public_key}\
                \n\tonchain address: {newValidatorAddress}\
                \n\tnet address: {addr}"
                );
            }
        } else {
            println!("no consensus config passed; no validators to write to contract");
        }

        Ok(())
    })
}

/// Generates the consensus configs of the validators.
fn generate_consensus_config(
    validators: &[SocketAddr],
    seed: Option<u64>,
    no_dkg_in_genesis: bool,
) -> Option<ConsensusConfig> {
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use rand::SeedableRng as _;

    match (validators.is_empty(), no_dkg_in_genesis) {
        (_, true) => {
            println!(
                "no-dkg-in-genesis passed; not generating any consensus config because I can't write it to the genesis block"
            );
            return None;
        }
        (true, false) => {
            panic!("no validators provided and no-dkg-in-genesis not set");
        }
        _ => {}
    }

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand::random::<u64>));

    let mut signer_keys = repeat_with(|| PrivateKey::random(&mut rng))
        .take(validators.len())
        .collect::<Vec<_>>();
    signer_keys.sort_by_key(|key| key.public_key());

    let (output, shares) = dkg::deal(
        &mut rng,
        Mode::NonZeroCounter,
        ordered::Set::try_from_iter(signer_keys.iter().map(|key| key.public_key())).unwrap(),
    )
    .unwrap();

    let validators = validators
        .iter()
        .copied()
        .zip_eq(signer_keys)
        .zip_eq(shares)
        .map(|((addr, signing_key), (verifying_key, signing_share))| {
            assert_eq!(signing_key.public_key(), verifying_key);
            Validator {
                addr,
                signing_key: SigningKey::from(signing_key),
                signing_share: SigningShare::from(signing_share),
            }
        })
        .collect();

    Some(ConsensusConfig { output, validators })
}

fn mint_pairwise_liquidity(
    a_token: Address,
    b_tokens: Vec<Address>,
    amount: U256,
    admin: Address,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) {
    let ctx = evm.ctx_mut();
    StorageCtx::enter_evm(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, || {
        let mut fee_manager = TipFeeManager::new();

        for b_token_address in b_tokens {
            fee_manager
                .mint(admin, a_token, b_token_address, amount, admin)
                .expect("Could not mint A -> B Liquidity pool");
        }
    });
}
