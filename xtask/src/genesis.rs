use alloy::{
    genesis::{ChainConfig, Genesis, GenesisAccount},
    primitives::{Address, U256, address},
    signers::{
        local::{MnemonicBuilder, coins_bip39::English},
        utils::secret_key_to_address,
    },
};
use alloy_primitives::Bytes;
use clap::Parser;
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
use commonware_cryptography::{
    bls12381::primitives::{poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_utils::quorum;
use eyre::WrapErr as _;
use rayon::prelude::*;
use reth_evm::{
    Evm, EvmEnv, EvmFactory, EvmInternals,
    revm::{
        context::ContextTr,
        database::{CacheDB, EmptyDB},
        inspector::JournalExt,
    },
};
use simple_tqdm::{ParTqdm, Tqdm};
use std::{collections::BTreeMap, fs, path::PathBuf};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::{
    ARACHNID_CREATE2_FACTORY_ADDRESS, CREATEX_ADDRESS, DEFAULT_7702_DELEGATE_ADDRESS,
    MULTICALL_ADDRESS, PERMIT2_ADDRESS, SAFE_DEPLOYER_ADDRESS,
    contracts::ARACHNID_CREATE2_FACTORY_BYTECODE,
};
use tempo_dkg_onchain_artifacts::PublicOutcome;
use tempo_evm::evm::{TempoEvm, TempoEvmFactory};
use tempo_precompiles::{
    LINKING_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, VALIDATOR_CONFIG_ADDRESS,
    linking_usd::{LinkingUSD, TRANSFER_ROLE},
    nonce::NonceManager,
    stablecoin_exchange::StablecoinExchange,
    storage::evm::EvmPrecompileStorageProvider,
    tip_fee_manager::{IFeeManager, ITIPFeeAMM, TipFeeManager},
    tip20::{ISSUER_ROLE, ITIP20, TIP20Token, address_to_token_id_unchecked},
    tip20_factory::{ITIP20Factory, TIP20Factory},
    tip20_rewards_registry::TIP20RewardsRegistry,
    tip403_registry::TIP403Registry,
    validator_config::{IValidatorConfig, ValidatorConfig},
};

/// Generate genesis allocation file for testing
#[derive(Parser, Debug)]
pub(crate) struct GenesisArgs {
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

    /// Coinbase address
    #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
    pub coinbase: Address,

    /// Chain ID
    #[arg(long, short, default_value = "1337")]
    pub chain_id: u64,

    /// Base fee
    #[arg(long, default_value_t = TEMPO_BASE_FEE.into())]
    pub base_fee_per_gas: u128,

    /// Genesis block gas limit
    #[arg(long, default_value_t = 17000000000000)]
    pub gas_limit: u64,

    /// Adagio hardfork activation timestamp (defaults to 0 = active at genesis)
    #[arg(long, default_value_t = 0)]
    pub adagio_time: u64,

    /// A list of comma-separated socket addresses or host names with port.
    /// Example: 127.0.0.1:8000,network-service:9000,0.0.0.0:1024
    ///
    /// The addresses listed here are mapped to the respective entries in
    /// `validator_pubkeys`.
    #[arg(long, default_value = "")]
    pub validator_addresses: String,

    /// A list of comma-separated ed25519 public keys.
    ///
    /// The keys listed here are mapped to the respective entry in
    /// `validator_addresses`.
    #[arg(long, default_value = "")]
    pub validator_pubkeys: String,

    /// The public polynomial that will be written to genesis.
    #[arg(long, default_value = "")]
    pub public_polynomial: String,

    /// The length of an epoch. The default value of 302_400 blocks is about
    /// 1 week of blocks, assuming a block time of 2s.
    #[arg(long, default_value_t = 302_400)]
    pub epoch_length: u64,
}

impl GenesisArgs {
    /// Generates a genesis json file.
    ///
    /// It creates a new genesis allocation for the configured accounts.
    /// And creates accounts for system contracts.
    pub(crate) async fn run(self) -> eyre::Result<()> {
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

        // system contracts/precompiles must be initialized bottom up, if an init function (e.g. mint_pairwise_liquidity) uses another system contract/precompiles internally (tip403 registry), the registry must be initialized first.

        // Deploy TestUSD fee token
        // TODO: admin should be updated to be a cli arg so we can specify that
        // linkingUSD admin for persistent testnet deployments
        let admin = addresses[0];
        let mut evm = setup_tempo_evm();

        println!("Initializing registry");
        initialize_registry(&mut evm)?;

        println!("Initializing LinkingUSD");
        initialize_linking_usd(admin, &addresses, &mut evm)?;

        let (_, alpha_token_address) = create_and_mint_token(
            "AlphaUSD",
            "AlphaUSD",
            "USD",
            admin,
            &addresses,
            U256::from(u64::MAX),
            &mut evm,
        )?;

        let (_, beta_token_address) = create_and_mint_token(
            "BetaUSD",
            "BetaUSD",
            "USD",
            admin,
            &addresses,
            U256::from(u64::MAX),
            &mut evm,
        )?;

        let (_, theta_token_address) = create_and_mint_token(
            "ThetaUSD",
            "ThetaUSD",
            "USD",
            admin,
            &addresses,
            U256::from(u64::MAX),
            &mut evm,
        )?;

        println!("Initializing TIP20RewardsRegistry");
        initialize_tip20_rewards_registry(&mut evm)?;

        println!("Initializing validator config");
        let (initial_dkg, validators) = initialize_validator_config(
            admin,
            self.validator_addresses,
            self.validator_pubkeys,
            self.public_polynomial,
            self.mnemonic,
            &mut evm,
        )?;

        println!("Initializing fee manager");
        initialize_fee_manager(alpha_token_address, addresses.clone(), validators, &mut evm);

        println!("Initializing stablecoin exchange");
        initialize_stablecoin_exchange(&mut evm)?;

        println!("Initializing nonce manager");
        initialize_nonce_manager(&mut evm)?;

        println!("Minting pairwise FeeAMM liquidity");
        mint_pairwise_liquidity(
            alpha_token_address,
            vec![LINKING_USD_ADDRESS, beta_token_address, theta_token_address],
            U256::from(10u64.pow(10)),
            admin,
            &mut evm,
        );

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
            "epochLength".to_string(),
            serde_json::json!(self.epoch_length),
        );

        let mut genesis = Genesis::default()
            .with_gas_limit(self.gas_limit)
            .with_base_fee(Some(self.base_fee_per_gas))
            .with_nonce(0x42)
            .with_extra_data(initial_dkg.map_or_else(
                || Bytes::from_static(b"tempo-genesis"),
                |dkg| dkg.encode().freeze().to_vec().into(),
            ))
            .with_coinbase(self.coinbase);

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
    recipients: &[Address],
    mint_amount: U256,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) -> eyre::Result<(u64, Address)> {
    let chain_id = evm.chain_id();
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, chain_id);

    let token_id = {
        let mut factory = TIP20Factory::new(&mut provider);
        factory
            .initialize()
            .expect("Could not initialize tip20 factory");
        let token_address = factory
            .create_token(
                admin,
                ITIP20Factory::createTokenCall {
                    name: name.into(),
                    symbol: symbol.into(),
                    currency: currency.into(),
                    quoteToken: LINKING_USD_ADDRESS,
                    admin,
                },
            )
            .expect("Could not create token");

        address_to_token_id_unchecked(token_address)
    };

    let mut token = TIP20Token::new(token_id, &mut provider);
    token
        .get_roles_contract()
        .grant_role_internal(admin, *ISSUER_ROLE)?;

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

    for address in recipients.iter().tqdm() {
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

    Ok((token_id, token.token_address))
}

fn initialize_linking_usd(
    admin: Address,
    recipients: &[Address],
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) -> eyre::Result<()> {
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, 1);

    let mut linking_usd = LinkingUSD::new(&mut provider);
    linking_usd
        .initialize(admin)
        .expect("LinkingUSD initialization should succeed");

    let mut roles = linking_usd.get_roles_contract();
    roles.grant_role_internal(admin, *ISSUER_ROLE)?;
    roles.grant_role_internal(admin, *TRANSFER_ROLE)?;
    for recipient in recipients.iter().tqdm() {
        roles.grant_role_internal(*recipient, *TRANSFER_ROLE)?;
    }

    for recipient in recipients.iter().tqdm() {
        linking_usd
            .mint(
                admin,
                ITIP20::mintCall {
                    to: *recipient,
                    amount: U256::from(u64::MAX),
                },
            )
            .expect("Could not mint linkingUSD");
    }

    Ok(())
}

fn initialize_tip20_rewards_registry(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, 1);
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
    let block = evm.block.clone();

    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, 1);

    let mut fee_manager =
        TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut provider);
    fee_manager
        .initialize()
        .expect("Could not init fee manager");
    for address in initial_accounts.iter().tqdm() {
        fee_manager
            .set_user_token(
                *address,
                IFeeManager::setUserTokenCall {
                    token: default_fee_address,
                },
            )
            .expect("Could not set fee token");
    }

    fee_manager
        .set_validator_token(
            Address::ZERO,
            IFeeManager::setValidatorTokenCall {
                token: default_fee_address,
            },
        )
        .expect("Could not set 0x00 validator fee token");

    // Set validator fee tokens to linking USD
    for validator in validators {
        fee_manager
            .set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: LINKING_USD_ADDRESS,
                },
            )
            .expect("Could not set validator fee token");
    }
}

/// Initializes the [`TIP403Registry`] contract.
fn initialize_registry(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, 1);
    TIP403Registry::new(&mut provider).initialize().unwrap();
    Ok(())
}

fn initialize_stablecoin_exchange(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, 1);

    let mut exchange = StablecoinExchange::new(&mut provider);
    exchange.initialize()?;

    Ok(())
}

fn initialize_nonce_manager(evm: &mut TempoEvm<CacheDB<EmptyDB>>) -> eyre::Result<()> {
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, 1);
    NonceManager::new(&mut provider).initialize()?;

    Ok(())
}

/// Initializes the initial set of validators with the specified validator config.
/// Returns a vec of the validator public keys
fn initialize_validator_config(
    owner: Address,
    addresses: String,
    public_keys: String,
    polynomial: String,
    mnemonic: String,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) -> eyre::Result<(Option<PublicOutcome>, Vec<Address>)> {
    if addresses.is_empty() && public_keys.is_empty() && polynomial.is_empty() {
        return Ok((None, vec![]));
    }
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, 1);

    let mut validator_config = ValidatorConfig::new(VALIDATOR_CONFIG_ADDRESS, &mut provider);
    validator_config
        .initialize(owner)
        .wrap_err("Failed to initialize validator config")?;

    let privkey_builder = MnemonicBuilder::<English>::default().phrase(mnemonic);

    let addresses = addresses.trim().split(',');
    let public_keys = public_keys.trim().split(',');

    let mut n_validators = 0u32;
    let mut validator_addresses = vec![];
    let mut participants = vec![];

    for (i, (addr, key)) in addresses.zip(public_keys).enumerate() {
        let signer = privkey_builder.clone().index(i as u32)?.build()?;
        let address = secret_key_to_address(signer.credential());

        let key_bytes =
            const_hex::decode(key).wrap_err_with(|| format!("failed decoding `{key}` as hex"))?;
        let key = PublicKey::decode(&key_bytes[..])
            .wrap_err_with(|| format!("failed decoding `{key}` as public ed25519 key"))?;
        participants.push(key.clone());

        validator_config
            .add_validator(
                &owner,
                IValidatorConfig::addValidatorCall {
                    newValidatorAddress: address,
                    publicKey: key_bytes
                        .as_slice()
                        .try_into()
                        .expect("we just decoded it; it fits"),
                    active: true,
                    inboundAddress: addr.to_string(),
                    outboundAddress: addr.to_string(),
                },
            )
            .wrap_err("failed to call addValidator smart contract")?;
        println!("added validator {i}; pubkey: `{key}`, address: `{address}`");
        n_validators += 1;

        validator_addresses.push(address);
    }
    let polynomial_bytes = const_hex::decode(&polynomial)
        .wrap_err_with(|| format!("failed decoding `{polynomial}` as bytes"))?;
    let quorum = quorum(n_validators);
    let polynomial_decoded =
        Public::<MinSig>::decode_cfg(polynomial_bytes.as_slice(), &(quorum as usize))
            .wrap_err_with(|| {
                format!(
                    "failed decoding provided public polynomial with a quorum of \
        `{quorum}` for `{n_validators}` validators"
                )
            })?;

    let initial_dkg_outcome = PublicOutcome {
        epoch: 0,
        participants: participants.into(),
        public: polynomial_decoded,
    };

    Ok((Some(initial_dkg_outcome), validator_addresses))
}

fn mint_pairwise_liquidity(
    a_token: Address,
    b_tokens: Vec<Address>,
    amount: U256,
    admin: Address,
    evm: &mut TempoEvm<CacheDB<EmptyDB>>,
) {
    let block = evm.block.clone();
    let evm_internals = EvmInternals::new(evm.journal_mut(), &block);
    let mut provider = EvmPrecompileStorageProvider::new_max_gas(evm_internals, 1);

    let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::ZERO, &mut provider);

    for b_token_address in b_tokens {
        fee_manager
            .mint(
                admin,
                ITIPFeeAMM::mintCall {
                    userToken: a_token,
                    validatorToken: b_token_address,
                    amountUserToken: amount,
                    amountValidatorToken: amount,
                    to: admin,
                },
            )
            .expect("Could not mint A -> B Liquidity pool");
    }
}
