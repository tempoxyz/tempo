use alloy::{
    genesis::{Genesis, GenesisAccount},
    primitives::{Address, U256, address},
    signers::{local::MnemonicBuilder, utils::secret_key_to_address},
};
use alloy_eips::eip2935::{HISTORY_STORAGE_ADDRESS, HISTORY_STORAGE_CODE};
use alloy_primitives::{B256, Bytes};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::{self, feldman_desmedt::Output},
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519::PublicKey,
};
use commonware_math::algebra::Random as _;
use commonware_utils::{N3f1, TryFromIterator as _, ordered};
use eyre::{WrapErr as _, eyre};
use indicatif::{ParallelProgressIterator, ProgressIterator};
use itertools::Itertools;
use rand::SeedableRng as _;
use rand_08::SeedableRng as _;
use rayon::prelude::*;
use reth_evm::revm::context_interface::JournalTr as _;
use std::{
    collections::BTreeMap,
    iter::repeat_with,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tempo_chainspec::{
    TempoHardfork,
    cli::TempoHardforkArgs,
    spec::{TEMPO_T0_BASE_FEE, TEMPO_T1_BASE_FEE},
};
use tempo_consensus_config::{SigningKey, SigningShare};
use tempo_contracts::{
    ARACHNID_CREATE2_FACTORY_ADDRESS, CREATEX_ADDRESS, MULTICALL3_ADDRESS, PERMIT2_ADDRESS,
    SAFE_DEPLOYER_ADDRESS,
    contracts::{CreateX, Multicall3, SafeDeployer},
    precompiles::{
        INITIAL_FACTORY_OWNER, IValidatorConfigV2, createTokenCall, initial_zone_factory_state,
        t13_zone_factory_state,
    },
};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::genesis::{
    GenesisEvm, create_genesis_evm, deploy_arachnid_create2_factory, deploy_permit2,
    ethereum_chain_config, genesis_account, genesis_evm_env, predeployed_contract,
    with_genesis_storage,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS,
    account_keychain::AccountKeychain,
    address_registry::AddressRegistry,
    nonce::NonceManager,
    receive_policy_guard::ReceivePolicyGuard,
    signature_verifier::SignatureVerifier,
    stablecoin_dex::StablecoinDEX,
    storage::ContractStorage,
    tip_fee_manager::{IFeeManager, TipFeeManager},
    tip20::{ISSUER_ROLE, ITIP20, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
    validator_config_v2::ValidatorConfigV2,
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

    /// Read the account-generation mnemonic from a file.
    #[arg(long, value_name = "PATH", conflicts_with = "mnemonic")]
    mnemonic_file: Option<PathBuf>,

    /// Coinbase address
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
    coinbase: Address,

    /// Chain ID
    #[arg(long, short, default_value = "1337")]
    chain_id: u64,

    /// Genesis block gas limit
    #[arg(long, default_value_t = 500_000_000)]
    gas_limit: u64,

    /// Override the general (non-payment) gas limit
    #[arg(long)]
    general_gas_limit: Option<u64>,

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

    /// Custom admin address for pathUSD token.
    /// If not set, uses the first generated account.
    #[arg(long)]
    pathusd_admin: Option<Address>,

    #[arg(long, default_value_t = u64::MAX)]
    pathusd_amount: u64,

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

    /// Enable creating deployment gas token.
    #[arg(long)]
    deployment_gas_token: bool,

    /// Custom admin address for deployment gas token.
    #[arg(long)]
    deployment_gas_token_admin: Option<Address>,

    /// Disable minting pairwise FeeAMM liquidity.
    #[arg(long)]
    no_pairwise_liquidity: bool,

    /// Tempo hardfork schedule. Individual `--<fork>-time` flags default to genesis (0).
    #[command(flatten)]
    hardforks: TempoHardforkArgs,
}

#[derive(Clone, Debug)]
pub(crate) struct ConsensusConfig {
    pub(crate) output: Output<MinSig, PublicKey>,
    pub(crate) validators: Vec<Validator>,
}
impl ConsensusConfig {
    pub(crate) fn to_genesis_dkg_outcome(&self) -> OnchainDkgOutcome {
        OnchainDkgOutcome {
            epoch: 0,
            output: self.output.clone(),
            next_players: ordered::Set::try_from_iter(
                self.validators.iter().map(Validator::public_key),
            )
            .unwrap(),
            is_next_full_dkg: false,
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
    pub(crate) fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub(crate) fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = chain_id;
    }

    pub(crate) fn validator_onchain_addresses(&self) -> eyre::Result<Vec<Address>> {
        if self.validator_addresses.is_empty() {
            let validator_count = u32::try_from(self.validators.len())
                .map_err(|_| eyre!("too many validators to derive account addresses"))?;
            if self.accounts < validator_count.saturating_add(1) {
                return Err(eyre!("not enough accounts created for validators"));
            }

            let mnemonic = self.resolved_mnemonic()?;
            (1..=validator_count)
                .map(|worker_id| {
                    let signer = MnemonicBuilder::from_phrase_nth(&mnemonic, worker_id);
                    Ok(secret_key_to_address(signer.credential()))
                })
                .collect()
        } else {
            if self.validator_addresses.len() < self.validators.len() {
                return Err(eyre!("not enough addresses provided for validators"));
            }

            Ok(self.validator_addresses[0..self.validators.len()].to_vec())
        }
    }

    /// Generates a genesis json file.
    ///
    /// It creates a new genesis allocation for the configured accounts.
    /// And creates accounts for system contracts.
    pub(crate) async fn generate_genesis(self) -> eyre::Result<(Genesis, Option<ConsensusConfig>)> {
        let mnemonic = self.resolved_mnemonic()?;
        println!("Generating {:?} accounts", self.accounts);

        let addresses: Vec<Address> = (0..self.accounts)
            .into_par_iter()
            .progress()
            .map(|worker_id| -> eyre::Result<Address> {
                let signer = MnemonicBuilder::from_phrase_nth(&mnemonic, worker_id);
                let address = secret_key_to_address(signer.credential());
                Ok(address)
            })
            .collect::<eyre::Result<Vec<Address>>>()?;

        // system contracts/precompiles must be initialized bottom up, if an init function (e.g. mint_pairwise_liquidity) uses another system contract/precompiles internally (tip403 registry), the registry must be initialized first.

        let pathusd_admin = self.pathusd_admin.unwrap_or_else(|| addresses[0]);
        let validator_admin = self.validator_admin.unwrap_or_else(|| addresses[0]);
        let mut evm = create_genesis_evm(genesis_evm_env(self.chain_id));

        deploy_arachnid_create2_factory(&mut evm);
        deploy_permit2(&mut evm)?;

        println!("Initializing registry");
        with_genesis_storage(&mut evm, || TIP403Registry::new().initialize())?;

        // Initialize TIP20Factory once before creating any tokens
        println!("Initializing TIP20Factory");
        with_genesis_storage(&mut evm, || TIP20Factory::new().initialize())?;

        println!("Creating pathUSD through factory");
        create_path_usd_token(pathusd_admin, &addresses, self.pathusd_amount, &mut evm)?;

        let (alpha_token_address, beta_token_address, theta_token_address) =
            if !self.no_extra_tokens {
                println!("Initializing TIP20 tokens");
                let alpha = create_and_mint_token(
                    "AlphaUSD",
                    "AlphaUSD",
                    "USD",
                    PATH_USD_ADDRESS,
                    pathusd_admin,
                    &addresses,
                    U256::from(u64::MAX),
                    SaltOrAddress::Address(address!("20C0000000000000000000000000000000000001")),
                    &mut evm,
                )?;

                let beta = create_and_mint_token(
                    "BetaUSD",
                    "BetaUSD",
                    "USD",
                    PATH_USD_ADDRESS,
                    pathusd_admin,
                    &addresses,
                    U256::from(u64::MAX),
                    SaltOrAddress::Address(address!("20C0000000000000000000000000000000000002")),
                    &mut evm,
                )?;

                let theta = create_and_mint_token(
                    "ThetaUSD",
                    "ThetaUSD",
                    "USD",
                    PATH_USD_ADDRESS,
                    pathusd_admin,
                    &addresses,
                    U256::from(u64::MAX),
                    SaltOrAddress::Address(address!("20C0000000000000000000000000000000000003")),
                    &mut evm,
                )?;

                (Some(alpha), Some(beta), Some(theta))
            } else {
                println!("Skipping extra token creation (--no-extra-tokens)");
                (None, None, None)
            };

        if self.deployment_gas_token && self.deployment_gas_token_admin.is_none() {
            eyre::bail!(
                "--deployment-gas-token-admin is required when --deployment-gas-token is set"
            );
        }

        let deployment_gas_token = {
            if self.deployment_gas_token {
                let mut rng = rand_08::rngs::StdRng::seed_from_u64(
                    self.seed.unwrap_or_else(rand_08::random::<u64>),
                );

                let mut salt_bytes = [0u8; 32];
                rand_08::Rng::fill(&mut rng, &mut salt_bytes);

                let address = create_and_mint_token(
                    "DONOTUSE",
                    "DONOTUSE",
                    "USD",
                    PATH_USD_ADDRESS,
                    self.deployment_gas_token_admin.expect(
                        "Deployment gas token admin is required if you want to deploy the token",
                    ),
                    &addresses,
                    U256::from(u64::MAX),
                    SaltOrAddress::Salt(B256::from(salt_bytes)),
                    &mut evm,
                )?;

                println!("Deployment gas token address: {address}");
                Some(address)
            } else {
                None
            }
        };

        println!(
            "generating consensus config for validators: {:?}",
            self.validators
        );
        let consensus_config =
            generate_consensus_config(&self.validators, self.seed, self.no_dkg_in_genesis);

        let validator_onchain_addresses = self.validator_onchain_addresses()?;

        println!("Initializing validator config v2");
        initialize_validator_config_v2(
            validator_admin,
            &mut evm,
            &consensus_config,
            &validator_onchain_addresses,
            self.no_dkg_in_genesis,
            self.chain_id,
        )?;

        println!("Initializing fee manager");
        let default_user_fee_token = if let Some(address) = deployment_gas_token {
            address
        } else {
            alpha_token_address.unwrap_or(PATH_USD_ADDRESS)
        };

        let default_validator_fee_token = if let Some(address) = deployment_gas_token {
            address
        } else {
            PATH_USD_ADDRESS
        };

        initialize_fee_manager(
            default_validator_fee_token,
            default_user_fee_token,
            addresses.clone(),
            // TODO: also populate validators here, once the logic is back.
            vec![self.coinbase],
            &mut evm,
        );

        println!("Initializing stablecoin exchange");
        with_genesis_storage(&mut evm, || StablecoinDEX::new().initialize())?;

        println!("Initializing nonce manager");
        with_genesis_storage(&mut evm, || NonceManager::new().initialize())?;

        println!("Initializing account keychain");
        with_genesis_storage(&mut evm, || AccountKeychain::new().initialize())?;

        println!("Initializing TIP20 registry");
        with_genesis_storage(&mut evm, || AddressRegistry::new().initialize())?;

        if self.hardforks.active_at_genesis(TempoHardfork::T3) {
            println!("Initializing signature verifier (T3 active at genesis)");
            with_genesis_storage(&mut evm, || SignatureVerifier::new().initialize())?;
        }

        if self.hardforks.active_at_genesis(TempoHardfork::T6) {
            println!("Initializing TIP-1028 ReceivePolicyGuard (T6 active at genesis)");
            with_genesis_storage(&mut evm, || ReceivePolicyGuard::new().initialize())?;
        }

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
                let storage = account
                    .storage
                    .iter()
                    .map(|(key, val)| (*key, val.present_value));
                (*address, genesis_account(&account.info, storage))
            })
            .collect();

        for (address, code) in [
            (MULTICALL3_ADDRESS, &Multicall3::DEPLOYED_BYTECODE),
            (CREATEX_ADDRESS, &CreateX::DEPLOYED_BYTECODE),
            (SAFE_DEPLOYER_ADDRESS, &SafeDeployer::DEPLOYED_BYTECODE),
            (HISTORY_STORAGE_ADDRESS, &HISTORY_STORAGE_CODE),
        ] {
            genesis_alloc.insert(address, predeployed_contract(code));
        }
        insert_zone_state_at_genesis(&self.hardforks, &mut genesis_alloc);

        let mut chain_config = ethereum_chain_config(self.chain_id);
        chain_config
            .extra_fields
            .insert_value("epochLength".to_string(), self.epoch_length)?;
        if let Some(general_gas_limit) = self.general_gas_limit {
            chain_config
                .extra_fields
                .insert_value("generalGasLimit".to_string(), general_gas_limit)?;
        }
        self.hardforks.write_to(&mut chain_config);
        let mut extra_data = Bytes::from_static(b"tempo-genesis");

        if let Some(consensus_config) = &consensus_config {
            if self.no_dkg_in_genesis {
                println!("no-initial-dkg-in-genesis passed; not writing to header extra_data");
            } else {
                extra_data = consensus_config.to_genesis_dkg_outcome().encode().into();
            }
        }

        // Base fee determined by hardfork: T1 active at genesis uses T1 fee
        let base_fee: u128 = if self.hardforks.active_at_genesis(TempoHardfork::T1) {
            u128::from(TEMPO_T1_BASE_FEE)
        } else {
            u128::from(TEMPO_T0_BASE_FEE)
        };

        let mut genesis = Genesis::default()
            .with_gas_limit(self.gas_limit)
            .with_base_fee(Some(base_fee))
            .with_nonce(0x42)
            .with_extra_data(extra_data)
            .with_coinbase(self.coinbase);

        genesis.alloc = genesis_alloc;
        genesis.config = chain_config;

        Ok((genesis, consensus_config))
    }

    fn resolved_mnemonic(&self) -> eyre::Result<String> {
        let Some(path) = &self.mnemonic_file else {
            return Ok(self.mnemonic.clone());
        };
        let mnemonic = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("failed reading mnemonic file `{}`", path.display()))?;
        let mnemonic = mnemonic.trim();
        if mnemonic.is_empty() {
            return Err(eyre!("mnemonic file `{}` is empty", path.display()));
        }
        Ok(mnemonic.to_owned())
    }
}

fn insert_zone_state_at_genesis(
    hardforks: &TempoHardforkArgs,
    genesis_alloc: &mut BTreeMap<Address, GenesisAccount>,
) {
    if hardforks.active_at_genesis(TempoHardfork::T10) {
        println!("Initializing ZoneFactory and shared runtimes");
        let accounts = if hardforks.active_at_genesis(TempoHardfork::T13) {
            t13_zone_factory_state(INITIAL_FACTORY_OWNER)
        } else {
            initial_zone_factory_state(INITIAL_FACTORY_OWNER)
        };
        for account in accounts {
            genesis_alloc.insert(
                account.address,
                GenesisAccount {
                    code: Some(account.code),
                    storage: account.storage.map(|(slot, value)| {
                        BTreeMap::from([(B256::from(slot.to_be_bytes()), value.into())])
                    }),
                    ..Default::default()
                },
            );
        }
    }
}

/// Creates pathUSD as the first TIP20 token at a reserved address.
/// pathUSD is not created via factory since it's at a reserved address.
fn create_path_usd_token(
    admin: Address,
    recipients: &[Address],
    amount_per_recipient: u64,
    evm: &mut GenesisEvm,
) -> eyre::Result<()> {
    with_genesis_storage(evm, || {
        TIP20Factory::new().create_token_reserved_address(
            PATH_USD_ADDRESS,
            "pathUSD",
            "pathUSD",
            "USD",
            Address::ZERO,
            admin,
        )?;

        // Initialize pathUSD directly (not via factory) since it's at a reserved address.
        let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)
            .expect("Could not create pathUSD token instance");
        token.grant_role_internal(admin, ISSUER_ROLE)?;

        // Mint to all recipients
        for recipient in recipients.iter().progress() {
            token
                .mint(
                    admin,
                    ITIP20::mintCall {
                        to: *recipient,
                        amount: U256::from(amount_per_recipient),
                    },
                )
                .expect("Could not mint pathUSD");
        }

        Ok(())
    })
}

enum SaltOrAddress {
    Salt(B256),
    Address(Address),
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
    salt_or_address: SaltOrAddress,
    evm: &mut GenesisEvm,
) -> eyre::Result<Address> {
    with_genesis_storage(evm, || {
        let mut factory = TIP20Factory::new();
        assert!(
            factory
                .is_initialized()
                .expect("Could not check factory initialization"),
            "TIP20Factory must be initialized before creating tokens"
        );

        let token_address = match salt_or_address {
            SaltOrAddress::Salt(salt) => factory
                .create_token(
                    admin,
                    createTokenCall {
                        name: name.into(),
                        symbol: symbol.into(),
                        currency: currency.into(),
                        quoteToken: quote_token,
                        salt,
                        admin,
                    },
                )
                .expect("Could not create token"),
            SaltOrAddress::Address(address) => factory
                .create_token_reserved_address(address, name, symbol, currency, quote_token, admin)
                .expect("Could not create token"),
        };

        let mut token =
            TIP20Token::from_address(token_address).expect("Could not create token instance");
        token.grant_role_internal(admin, ISSUER_ROLE)?;

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

        Ok(token.address())
    })
}

fn initialize_fee_manager(
    validator_fee_token_address: Address,
    user_fee_token_address: Address,
    initial_accounts: Vec<Address>,
    validators: Vec<Address>,
    evm: &mut GenesisEvm,
) {
    // Update the beneficiary since the validator can't set the validator fee token for themselves
    with_genesis_storage(evm, || {
        let mut fee_manager = TipFeeManager::new();
        fee_manager
            .initialize()
            .expect("Could not init fee manager");
        println!(
            "Setting user fee token {user_fee_token_address} for {} accounts",
            initial_accounts.len()
        );
        for address in initial_accounts.iter().progress() {
            fee_manager
                .set_user_token(
                    *address,
                    IFeeManager::setUserTokenCall {
                        token: user_fee_token_address,
                    },
                )
                .expect("Could not set fee token");
        }

        // Set validator fee tokens to pathUSD
        for validator in validators {
            println!("Setting user token for {validator} {validator_fee_token_address}");
            fee_manager
                .set_validator_token(
                    validator,
                    IFeeManager::setValidatorTokenCall {
                        token: validator_fee_token_address,
                    },
                    // use random address to avoid `CannotChangeWithinBlock` error
                    Address::random(),
                )
                .expect("Could not set validator fee token");
        }
    });
}

/// Initializes the [`ValidatorConfigV2`] contract at genesis (T2 active at genesis).
///
/// Populates validators directly into V2 with `needs_migration = false`.
/// Each `add_validator` call requires an Ed25519 signature from the validator's signing key.
fn initialize_validator_config_v2(
    admin: Address,
    evm: &mut GenesisEvm,
    consensus_config: &Option<ConsensusConfig>,
    onchain_validator_addresses: &[Address],
    no_dkg_in_genesis: bool,
    chain_id: u64,
) -> eyre::Result<()> {
    with_genesis_storage(evm, || {
        let mut v2 = ValidatorConfigV2::new();
        v2.initialize(admin)
            .wrap_err("failed to initialize validator config v2")?;

        if no_dkg_in_genesis {
            println!("no-dkg-in-genesis passed; not writing validators to genesis block");
            return Ok(());
        }

        let Some(consensus_config) = consensus_config.clone() else {
            println!("no consensus config passed; no validators to write to contract");
            return Ok(());
        };

        let num_validators = consensus_config.validators.len();
        if onchain_validator_addresses.len() < num_validators {
            return Err(eyre!(
                "need {} addresses for all validators, but only {} were provided",
                num_validators,
                onchain_validator_addresses.len()
            ));
        }

        println!("writing {num_validators} validators into v2 contract");
        for (i, validator) in consensus_config.validators.iter().enumerate() {
            let validator_address = onchain_validator_addresses[i];
            let public_key = validator.public_key();
            let pubkey: B256 = public_key.encode().as_ref().try_into().unwrap();
            let addr = validator.addr;

            let config = tempo_validator_config::ValidatorConfig {
                chain_id,
                validator_address,
                public_key: pubkey,
                ingress: addr,
                egress: addr.ip(),
            };

            let message = config.add_validator_message_hash(validator_address);
            let private_key = validator.signing_key.clone().into_inner();
            let signature = private_key.sign(
                tempo_precompiles::validator_config_v2::VALIDATOR_NS_ADD,
                message.as_slice(),
            );

            v2.add_validator(
                admin,
                IValidatorConfigV2::addValidatorCall {
                    validatorAddress: validator_address,
                    publicKey: pubkey,
                    ingress: config.ingress.to_string(),
                    egress: config.egress.to_string(),
                    feeRecipient: validator_address,
                    signature: signature.encode().into(),
                },
            )
            .wrap_err("failed to add validator to V2")?;

            println!(
                "added validator (v2)\
                    \n\tpublic key: {public_key}\
                    \n\tonchain address: {validator_address}\
                    \n\tnet address: {addr}"
            );
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
    use commonware_cryptography::ed25519::PrivateKey;

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

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed.unwrap_or_else(rand_08::random::<u64>));

    let mut signer_keys = repeat_with(|| PrivateKey::random(&mut rng))
        .take(validators.len())
        .collect::<Vec<_>>();
    signer_keys.sort_by_key(|key| key.public_key());

    let (output, shares) = dkg::feldman_desmedt::deal::<_, _, N3f1>(
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
    evm: &mut GenesisEvm,
) {
    with_genesis_storage(evm, || {
        let mut fee_manager = TipFeeManager::new();

        for b_token_address in b_tokens {
            fee_manager
                .mint(admin, a_token, b_token_address, amount, admin)
                .expect("Could not mint A -> B Liquidity pool");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempo_contracts::{
        precompiles::{
            ZONE_FACTORY_ADDRESS, ZONE_MESSENGER_ADDRESS, ZONE_PORTAL_IMPL_ADDRESS,
            ZONE_VERIFIER_ADDRESS,
        },
        zones::{
            T13_ZONE_MESSENGER_RUNTIME, T13_ZONE_PORTAL_RUNTIME, T13_ZONE_VERIFIER_RUNTIME,
            ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME,
        },
    };

    #[derive(Debug, clap::Parser)]
    struct Cli {
        #[command(flatten)]
        genesis: GenesisArgs,
    }

    fn parse(args: &str) -> Result<GenesisArgs, clap::Error> {
        use clap::Parser as _;
        let base = "xtask --accounts 2 --no-dkg-in-genesis --seed 1";
        Cli::try_parse_from(format!("{base} {args}").split_whitespace()).map(|cli| cli.genesis)
    }

    async fn generate(args: &str) -> Genesis {
        parse(args).unwrap().generate_genesis().await.unwrap().0
    }

    #[tokio::test]
    async fn legacy_genesis_writes_every_fork_time() {
        let genesis = generate("--t3-time 100").await;

        for fork in TempoHardfork::VARIANTS.iter().skip(1) {
            let expected = if *fork == TempoHardfork::T3 { 100 } else { 0 };
            assert_eq!(
                genesis.config.extra_fields.get(fork.genesis_key().unwrap()),
                Some(&serde_json::json!(expected)),
                "{fork}"
            );
        }
        // T3 is not active at genesis, so the signature verifier is not initialized.
        assert!(
            !genesis
                .alloc
                .contains_key(&tempo_precompiles::SIGNATURE_VERIFIER_ADDRESS)
        );
    }

    #[tokio::test]
    async fn profile_genesis_disables_later_forks() {
        let genesis = generate("--hardfork T13").await;
        let chainspec = tempo_chainspec::TempoChainSpec::from_genesis(genesis.clone());

        assert_eq!(
            genesis.config.extra_fields.get("t13Time"),
            Some(&serde_json::json!(0))
        );
        assert_eq!(
            genesis.config.extra_fields.get("t14Time"),
            Some(&serde_json::Value::Null)
        );
        assert_eq!(
            tempo_chainspec::TempoHardforks::tempo_hardfork_at(&chainspec, u64::MAX),
            TempoHardfork::T13
        );
        assert_eq!(
            genesis.alloc[&ZONE_PORTAL_IMPL_ADDRESS].code.as_ref(),
            Some(&T13_ZONE_PORTAL_RUNTIME)
        );
    }

    #[test]
    fn t10_genesis_installs_factory_and_canonical_shared_runtimes() {
        let mut alloc = BTreeMap::new();
        let hardforks = TempoHardforkArgs {
            t13_time: Some(1),
            ..Default::default()
        };
        insert_zone_state_at_genesis(&hardforks, &mut alloc);
        let account = alloc.remove(&ZONE_FACTORY_ADDRESS).unwrap();
        let expected_config =
            U256::from(1) | (U256::from_be_slice(INITIAL_FACTORY_OWNER.as_slice()) << u32::BITS);

        assert_eq!(account.code, Some(Bytes::from_static(&[0xef])));
        assert_eq!(
            account.storage.unwrap().get(&B256::ZERO),
            Some(&expected_config.into())
        );
        for (destination, expected) in [
            (ZONE_PORTAL_IMPL_ADDRESS, ZONE_PORTAL_RUNTIME),
            (ZONE_VERIFIER_ADDRESS, ZONE_VERIFIER_RUNTIME),
            (ZONE_MESSENGER_ADDRESS, ZONE_MESSENGER_RUNTIME),
        ] {
            assert_eq!(alloc[&destination].code.as_ref(), Some(&expected));
        }
    }

    #[test]
    fn future_t10_does_not_install_zone_factory_at_genesis() {
        let mut alloc = BTreeMap::new();
        let hardforks = TempoHardforkArgs {
            t10_time: Some(1),
            ..Default::default()
        };
        insert_zone_state_at_genesis(&hardforks, &mut alloc);

        assert!(!alloc.contains_key(&ZONE_FACTORY_ADDRESS));
    }

    #[test]
    fn t13_genesis_installs_t13_shared_runtimes() {
        let mut alloc = BTreeMap::new();
        let hardforks = TempoHardforkArgs::default();
        insert_zone_state_at_genesis(&hardforks, &mut alloc);

        for (destination, expected) in [
            (ZONE_PORTAL_IMPL_ADDRESS, T13_ZONE_PORTAL_RUNTIME),
            (ZONE_VERIFIER_ADDRESS, T13_ZONE_VERIFIER_RUNTIME),
            (ZONE_MESSENGER_ADDRESS, T13_ZONE_MESSENGER_RUNTIME),
        ] {
            assert_eq!(alloc[&destination].code.as_ref(), Some(&expected));
        }
    }

    #[derive(Parser)]
    struct GenesisCli {
        #[command(flatten)]
        args: GenesisArgs,
    }

    #[test]
    fn mnemonic_file_matches_inline_validator_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mnemonic");
        std::fs::write(&path, format!("{mnemonic}\n")).unwrap();
        let args = [
            "genesis",
            "--validators",
            "127.0.0.1:8000",
            "--accounts",
            "2",
        ];
        let inline = GenesisCli::parse_from(args.into_iter().chain(["--mnemonic", mnemonic])).args;
        let from_file = GenesisCli::parse_from(
            args.into_iter()
                .chain(["--mnemonic-file", path.to_str().unwrap()]),
        )
        .args;
        assert_eq!(from_file.resolved_mnemonic().unwrap(), mnemonic);
        assert_eq!(
            from_file.validator_onchain_addresses().unwrap(),
            inline.validator_onchain_addresses().unwrap()
        );
        assert!(
            GenesisCli::try_parse_from(args.into_iter().chain([
                "--mnemonic",
                mnemonic,
                "--mnemonic-file",
                path.to_str().unwrap(),
            ]))
            .is_err()
        );
        std::fs::write(&path, " \n").unwrap();
        assert!(from_file.resolved_mnemonic().is_err());
        std::fs::remove_file(path).unwrap();
        assert!(from_file.validator_onchain_addresses().is_err());
    }
}
