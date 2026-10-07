use alloy::{
    consensus::BlockHeader as _,
    genesis::{Genesis, GenesisAccount},
    primitives::{Address, B256, Bytes, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
};
use alloy_eips::BlockNumberOrTag;
use alloy_rpc_types_eth::BlockId;
use eyre::{WrapErr as _, ensure, eyre};
use reth_evm::{
    Evm as _,
    revm::{DatabaseCommit, context::JournalTr, state::AccountInfo},
};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::{cli::TempoHardforkArgs, spec::TEMPO_T0_BASE_FEE};
use tempo_contracts::{
    ARACHNID_CREATE2_FACTORY_ADDRESS, CREATEX_ADDRESS, MULTICALL3_ADDRESS, SAFE_DEPLOYER_ADDRESS,
    contracts::{CreateX, Multicall3, SafeDeployer},
};
use tempo_evm::genesis::{
    GenesisEvm, create_genesis_evm, deploy_arachnid_create2_factory, deploy_permit2,
    ethereum_chain_config, genesis_account, genesis_evm_env, predeployed_contract,
    with_genesis_storage,
};
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS,
    account_keychain::AccountKeychain,
    nonce::NonceManager,
    receive_policy_guard::ReceivePolicyGuard,
    stablecoin_dex::StablecoinDEX,
    storage_credits::StorageCredits,
    tip20::{ISSUER_ROLE, ITIP20, TIP20Token},
    tip20_factory::TIP20Factory,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::TempoHeader;
use tempo_zone_contracts::{
    TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, ZonePortal,
};
use zone_precompiles::{
    TempoState as NativeTempoState, ZoneFeeManager, ZoneInbox as NativeZoneInbox,
    ZoneOutbox as NativeZoneOutbox,
};

use crate::zone_utils::find_zone_deployment_block;

const DEPLOYER: Address = address!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

#[derive(Debug, clap::Parser)]
pub(crate) struct GenerateZoneGenesis {
    #[arg(short, long)]
    pub(crate) output: PathBuf,

    #[arg(long)]
    pub(crate) chain_id: u64,

    #[arg(long, default_value_t = TEMPO_T0_BASE_FEE.into())]
    pub(crate) base_fee_per_gas: u128,

    #[arg(long, default_value_t = 30_000_000)]
    pub(crate) gas_limit: u64,

    /// Existing ZonePortal used to derive the pre-creation genesis anchor.
    #[arg(
        long,
        requires = "l1_rpc_url",
        conflicts_with = "tempo_genesis_header_rlp"
    )]
    pub(crate) tempo_portal: Option<Address>,

    /// Tempo L1 HTTP RPC URL used to derive the pre-creation genesis anchor.
    #[arg(
        long,
        requires = "tempo_portal",
        conflicts_with = "tempo_genesis_header_rlp"
    )]
    pub(crate) l1_rpc_url: Option<String>,

    /// Canonical fee token used when a zone transaction omits `fee_token`.
    #[arg(long, default_value_t = PATH_USD_ADDRESS)]
    pub(crate) default_fee_token: Address,

    /// RLP-encoded Tempo genesis header. When omitted, `--tempo-portal` derives its pre-creation
    /// anchor from L1; otherwise the development genesis uses `TempoHeader::default()`.
    #[arg(long)]
    pub(crate) tempo_genesis_header_rlp: Option<String>,

    #[arg(long)]
    pub(crate) admin: Address,

    #[arg(long)]
    pub(crate) sequencer: Option<Address>,

    /// Include CreateX factory in genesis.
    #[arg(long)]
    pub(crate) with_createx: bool,

    /// Include Safe Singleton Factory in genesis.
    #[arg(long)]
    pub(crate) with_safe_deployer: bool,

    /// Include Arachnid CREATE2 factory in genesis.
    /// The factory is always used internally to deploy Permit2; this flag
    /// controls whether it remains in the final genesis state.
    #[arg(long)]
    pub(crate) with_create2_factory: bool,

    #[command(flatten)]
    pub(crate) forks: TempoHardforkArgs,
}

impl GenerateZoneGenesis {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        if self.admin.is_zero() {
            return Err(eyre!("--admin must not be the zero address"));
        }

        let header_rlp = match (
            &self.tempo_genesis_header_rlp,
            self.tempo_portal,
            self.l1_rpc_url.as_deref(),
        ) {
            (Some(header_rlp), None, None) => {
                const_hex::decode(header_rlp).wrap_err("failed to decode hex string")?
            }
            (None, Some(portal), Some(l1_rpc_url)) => {
                derive_pre_creation_anchor(l1_rpc_url, portal).await?.rlp
            }
            (None, None, None) => alloy_rlp::encode(TempoHeader::default()),
            _ => unreachable!("clap validates genesis anchor arguments"),
        };

        let mut evm = setup_zone_evm(self.chain_id, self.gas_limit);

        evm.db_mut().insert_account_info(
            DEPLOYER,
            AccountInfo::from_balance(U256::from(1_000_000_000_000_000_000_000u128)),
        );

        // Initialize all precompiles and deploy standard contracts to match the
        // L1 genesis setup. The zone EVM uses the same TempoEvmFactory, so all
        // precompiles must be initialized for user transactions to work correctly.
        deploy_arachnid_create2_factory(&mut evm);
        deploy_permit2(&mut evm)?;

        with_genesis_storage(&mut evm, || {
            // Required for fee token transfer checks.
            println!("Initializing TIP403 registry");
            TIP403Registry::new().initialize()?;

            println!("Creating pathUSD fee token at {PATH_USD_ADDRESS}");
            create_path_usd_token()?;

            let default_fee_token = self.default_fee_token;
            println!("Initializing fee manager with default fee token {default_fee_token}");
            ZoneFeeManager::new().initialize(default_fee_token)?;

            println!("Initializing stablecoin exchange");
            StablecoinDEX::new().initialize()?;

            println!("Initializing nonce manager");
            NonceManager::new().initialize()?;

            println!("Initializing account keychain");
            AccountKeychain::new().initialize()?;

            println!("Initializing TIP-1028 ReceivePolicyGuard");
            ReceivePolicyGuard::new().initialize()?;

            // TIP-1060 bookkeeping writes StorageCredits from the EVM handler even when no
            // transaction calls it. Keeping the account non-empty prevents EIP-161 from dropping
            // the sequential transition while the sparse-trie state hook observes its storage.
            println!("Initializing TIP-1060 StorageCredits");
            StorageCredits::new().initialize()?;

            println!("Initializing native TempoState at {TEMPO_STATE_ADDRESS}");
            NativeTempoState::new().initialize(&header_rlp)?;

            println!("Initializing native ZoneInbox at {ZONE_INBOX_ADDRESS}");
            NativeZoneInbox::new().initialize()?;

            println!("Initializing native ZoneOutbox at {ZONE_OUTBOX_ADDRESS}");
            NativeZoneOutbox::new().initialize()
        })?;

        let native_state = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(native_state);

        let db = evm.db_mut();
        for (name, addr) in [
            ("TempoState", TEMPO_STATE_ADDRESS),
            ("ZoneInbox", ZONE_INBOX_ADDRESS),
            ("ZoneOutbox", ZONE_OUTBOX_ADDRESS),
        ] {
            let account = db
                .cache
                .accounts
                .get(&addr)
                .ok_or_else(|| eyre!("{name} not found at {addr}"))?;
            let has_code = account.info.code.as_ref().is_some_and(|c| !c.is_empty());
            if !has_code {
                return Err(eyre!("{name} has no code at {addr}"));
            }
        }

        let mut genesis_alloc: BTreeMap<Address, GenesisAccount> = db
            .cache
            .accounts
            .iter()
            .filter(|(addr, _)| **addr != DEPLOYER && **addr != TIP20_FACTORY_ADDRESS)
            .filter(|(addr, _)| {
                self.with_create2_factory || **addr != ARACHNID_CREATE2_FACTORY_ADDRESS
            })
            .map(|(address, account)| {
                let storage = account.storage.iter().map(|(key, val)| (*key, *val));
                (*address, genesis_account(&account.info, storage))
            })
            .collect();

        // Include Address::ZERO in genesis so it exists in the state trie.
        // System transactions use this address as the sender, and TIP-20 burn
        // transfers to it. Without a trie entry, the parallel state root task
        // (sparse trie) can diverge when this account is touched and then
        // cleared under EIP-161 state-clear rules.
        genesis_alloc.entry(Address::ZERO).or_default().nonce = Some(1);

        // Deploy standard utility contracts matching L1 genesis.
        for (address, code, enabled) in [
            (MULTICALL3_ADDRESS, &Multicall3::DEPLOYED_BYTECODE, true),
            (
                CREATEX_ADDRESS,
                &CreateX::DEPLOYED_BYTECODE,
                self.with_createx,
            ),
            (
                SAFE_DEPLOYER_ADDRESS,
                &SafeDeployer::DEPLOYED_BYTECODE,
                self.with_safe_deployer,
            ),
        ] {
            if enabled {
                genesis_alloc.insert(address, predeployed_contract(code));
            }
        }

        let mut chain_config = ethereum_chain_config(self.chain_id);
        self.forks.write_to(&mut chain_config);

        let mut genesis = Genesis::default()
            .with_gas_limit(self.gas_limit)
            .with_base_fee(Some(self.base_fee_per_gas))
            .with_nonce(0x42)
            .with_extra_data(Bytes::from_static(b"tempo-zone-genesis"));

        genesis.alloc = genesis_alloc;
        genesis.config = chain_config;

        let genesis_json =
            serde_json::to_value(&genesis).wrap_err("failed encoding genesis as JSON")?;
        let mut json = serde_json::to_string_pretty(&genesis_json)
            .wrap_err("failed encoding genesis as JSON")?;
        json.push('\n');

        std::fs::create_dir_all(&self.output).wrap_err_with(|| {
            format!(
                "failed to create directory and parents for `{}`",
                self.output.display()
            )
        })?;
        let genesis_dst = self.output.join("genesis.json");
        std::fs::write(&genesis_dst, json).wrap_err_with(|| {
            format!("failed writing genesis to file `{}`", genesis_dst.display())
        })?;

        println!("Zone genesis written to {}", genesis_dst.display());

        Ok(())
    }
}

pub(crate) struct PreCreationAnchor {
    pub(crate) block_number: u64,
    pub(crate) hash: B256,
    pub(crate) rlp: Vec<u8>,
}

async fn derive_pre_creation_anchor(
    l1_rpc_url: &str,
    portal: Address,
) -> eyre::Result<PreCreationAnchor> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(l1_rpc_url)
        .await
        .wrap_err_with(|| format!("failed to connect to Tempo L1 RPC {l1_rpc_url}"))?;
    finalized_pre_creation_anchor(&provider, portal, None).await
}

pub(crate) async fn finalized_pre_creation_anchor<P: Provider<TempoNetwork>>(
    provider: &P,
    portal: Address,
    expected_creation_block: Option<u64>,
) -> eyre::Result<PreCreationAnchor> {
    let finalized_header = provider
        .get_header_by_number(BlockNumberOrTag::Finalized)
        .await
        .wrap_err("failed to fetch finalized Tempo L1 block")?
        .ok_or_else(|| eyre!("Tempo L1 returned no finalized block"))?;
    let finalized_block = finalized_header.number();
    if let Some(expected) = expected_creation_block {
        ensure!(
            expected <= finalized_block,
            "ZonePortal creation block {expected} is not finalized yet (finalized Tempo block: {finalized_block})"
        );
    }
    let finalized_block_id = BlockId::number(finalized_block);

    ensure!(
        !provider
            .get_code_at(portal)
            .block_id(finalized_block_id)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to fetch code for portal {portal} at finalized block {finalized_block}"
                )
            })?
            .is_empty(),
        "portal {portal} has no code at finalized Tempo block {finalized_block}; check --tempo-portal and --l1-rpc-url"
    );

    let zone_id = ZonePortal::new(portal, provider)
        .zoneId()
        .block(finalized_block_id)
        .call()
        .await
        .wrap_err_with(|| {
            format!("failed to read Zone ID from portal {portal} at block {finalized_block}")
        })?;
    // A known creation block bounds the scan; the code checks below still prove that the
    // portal was deployed in exactly that block.
    let creation_block = find_zone_deployment_block(
        provider,
        zone_id,
        portal,
        expected_creation_block.unwrap_or(0),
        finalized_block,
    )
    .await?;
    if let Some(expected) = expected_creation_block {
        ensure!(
            creation_block == expected,
            "ZoneCreated event is in block {creation_block}, but the creation receipt reported block {expected}"
        );
    }
    let anchor_block = creation_block.checked_sub(1).ok_or_else(|| {
        eyre!("portal {portal} exists at genesis, so no pre-creation anchor is available")
    })?;
    ensure!(
        provider
            .get_code_at(portal)
            .number(anchor_block)
            .await
            .wrap_err_with(|| {
                format!("failed to fetch portal code at Tempo anchor block {anchor_block}")
            })?
            .is_empty(),
        "portal {portal} already has code at proposed pre-creation anchor block {anchor_block}"
    );
    ensure!(
        !provider
            .get_code_at(portal)
            .number(creation_block)
            .await
            .wrap_err_with(|| {
                format!("failed to fetch portal code at creation block {creation_block}")
            })?
            .is_empty(),
        "portal {portal} has no code at ZoneCreated block {creation_block}"
    );

    let anchor_header_response = provider
        .get_header_by_number(anchor_block.into())
        .await
        .wrap_err_with(|| format!("failed to fetch Tempo anchor header {anchor_block}"))?
        .ok_or_else(|| eyre!("Tempo anchor header {anchor_block} was not found"))?;
    ensure!(
        anchor_header_response.number() == anchor_block,
        "Tempo RPC returned header {} for requested anchor block {anchor_block}",
        anchor_header_response.number()
    );
    let response_hash = anchor_header_response.hash;
    let header_rlp = alloy_rlp::encode(anchor_header_response.inner.inner);
    let anchor_hash = keccak256(&header_rlp);
    ensure!(
        anchor_hash == response_hash,
        "Tempo anchor header RLP hash {anchor_hash} does not match RPC block hash {response_hash}"
    );
    println!(
        "Derived pre-creation Tempo anchor block {anchor_block} (hash: {anchor_hash}) for portal {portal}"
    );
    Ok(PreCreationAnchor {
        block_number: anchor_block,
        hash: anchor_hash,
        rlp: header_rlp,
    })
}

pub(crate) async fn wait_for_finalized_pre_creation_anchor<P: Provider<TempoNetwork>>(
    provider: &P,
    portal: Address,
    creation_block: u64,
) -> eyre::Result<PreCreationAnchor> {
    const ATTEMPTS: usize = 600;
    const POLL_INTERVAL: Duration = Duration::from_millis(500);

    for _ in 0..ATTEMPTS {
        let finalized = provider
            .get_header_by_number(BlockNumberOrTag::Finalized)
            .await
            .wrap_err("failed to fetch finalized Tempo L1 block")?
            .ok_or_else(|| eyre!("Tempo L1 returned no finalized block"))?;
        if finalized.number() >= creation_block {
            return finalized_pre_creation_anchor(provider, portal, Some(creation_block)).await;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    Err(eyre!(
        "ZonePortal creation block {creation_block} was not finalized within {} seconds",
        ATTEMPTS as u128 * POLL_INTERVAL.as_millis() / 1_000
    ))
}

fn setup_zone_evm(chain_id: u64, gas_limit: u64) -> GenesisEvm {
    let mut env = genesis_evm_env(chain_id);
    env.cfg_env.tx_gas_limit_cap = Some(u64::MAX);
    env.block_env.inner.gas_limit = gas_limit;
    create_genesis_evm(env)
}

/// Create pathUSD as the default fee token at its reserved TIP20 address.
///
/// This mirrors the L1 genesis setup: the Tempo EVM handler defaults to pathUSD
/// (`0x20C0...`) as the fee token and validates its `currency == "USD"` storage.
/// Without this, user transactions on the zone revert with `InvalidFeeToken`.
/// ZoneInbox is the fixed token admin; the configured zone admin receives no token roles.
fn create_path_usd_token() -> tempo_precompiles::error::Result<()> {
    TIP20Factory::new().create_token_reserved_address(
        PATH_USD_ADDRESS,
        "pathUSD",
        "pathUSD",
        "USD",
        Address::ZERO,
        ZONE_INBOX_ADDRESS,
    )?;

    let mut token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
    // Allow address(0) to mint (system transactions use sender=0)
    token.grant_role_internal(Address::ZERO, ISSUER_ROLE)?;
    // Grant ISSUER_ROLE to ZoneInbox so it can mint pathUSD on deposits
    token.grant_role_internal(ZONE_INBOX_ADDRESS, ISSUER_ROLE)?;
    // Grant ISSUER_ROLE to ZoneOutbox so it can burn pathUSD on withdrawals
    token.grant_role_internal(ZONE_OUTBOX_ADDRESS, ISSUER_ROLE)?;

    // Set a large supply cap
    token.set_supply_cap(
        ZONE_INBOX_ADDRESS,
        ITIP20::setSupplyCapCall {
            newSupplyCap: U256::from(u128::MAX),
        },
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempo_chainspec::{TempoHardfork, TempoHardforks};
    use zone_chainspec::ZoneChainSpec;

    #[tokio::test]
    async fn genesis_preserves_explicit_fork_timestamps() {
        for (t12, t13, t14) in [
            (None, None, None),
            (Some(0), Some(0), Some(0)),
            (Some(0), Some(u64::MAX), Some(u64::MAX)),
            (Some(1789463700), None, None),
            (None, Some(1789467300), None),
            (Some(u64::MAX), Some(u64::MAX), Some(u64::MAX)),
        ] {
            let output = tempfile::tempdir().unwrap();
            let mut args = vec![
                "generate-zone-genesis".to_owned(),
                "--output".to_owned(),
                output.path().display().to_string(),
                "--chain-id".to_owned(),
                "134509785776129".to_owned(),
                "--admin".to_owned(),
                "0x1000000000000000000000000000000000000001".to_owned(),
            ];
            for (flag, timestamp) in [
                ("--t12-time", t12),
                ("--t13-time", t13),
                ("--t14-time", t14),
            ] {
                if let Some(timestamp) = timestamp {
                    args.extend([flag.to_owned(), timestamp.to_string()]);
                }
            }
            GenerateZoneGenesis::try_parse_from(args)
                .unwrap()
                .run()
                .await
                .unwrap();
            let genesis = serde_json::from_slice::<Genesis>(
                &std::fs::read(output.path().join("genesis.json")).unwrap(),
            )
            .unwrap();
            let config = serde_json::to_value(&genesis.config).unwrap();
            assert_eq!(genesis.config.chain_id, 134509785776129);
            assert!(!genesis.alloc.is_empty());

            let spec = ZoneChainSpec::from_genesis(genesis).unwrap();
            // Check each fork: the highest active fork can hide missing earlier ones.
            for &fork in TempoHardfork::VARIANTS {
                if fork == TempoHardfork::Genesis {
                    continue;
                }
                let activation = match fork {
                    TempoHardfork::T12 => t12.unwrap_or(0),
                    TempoHardfork::T13 => t13.unwrap_or(0),
                    TempoHardfork::T14 => t14.unwrap_or(0),
                    _ => 0,
                };
                let field = format!("{}Time", fork.to_string().to_lowercase());
                assert_eq!(config[&field], serde_json::json!(activation));
                for timestamp in [0, activation.saturating_sub(1), activation, u64::MAX] {
                    assert_eq!(
                        spec.tempo_fork_activation(fork)
                            .active_at_timestamp(timestamp),
                        timestamp >= activation,
                        "{fork} at {timestamp}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_tempo_fork_has_an_independent_timestamp_override() {
        for &overridden in TempoHardfork::VARIANTS {
            if overridden == TempoHardfork::Genesis {
                continue;
            }
            let flag = format!("--{}-time", overridden.to_string().to_lowercase());
            let command = GenerateZoneGenesis::try_parse_from([
                "generate-zone-genesis",
                "--output",
                "/tmp/zone",
                "--chain-id",
                "134509785776129",
                "--admin",
                "0x1000000000000000000000000000000000000001",
                &flag,
                "12345",
            ])
            .unwrap();
            let mut genesis = Genesis::default();
            genesis.config.chain_id = command.chain_id;
            command.forks.write_to(&mut genesis.config);
            let spec = ZoneChainSpec::from_genesis(genesis).unwrap();
            for &fork in TempoHardfork::VARIANTS {
                for timestamp in [0, 12344, 12345] {
                    assert_eq!(
                        spec.tempo_fork_activation(fork)
                            .active_at_timestamp(timestamp),
                        fork != overridden || timestamp >= 12345,
                        "{fork} at {timestamp} with {overridden} overridden"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn genesis_writes_explicit_hardfork_profile() {
        let output = tempfile::tempdir().unwrap();
        GenerateZoneGenesis::try_parse_from([
            "generate-zone-genesis",
            "--output",
            output.path().to_str().unwrap(),
            "--chain-id",
            "134509785776129",
            "--admin",
            "0x1000000000000000000000000000000000000001",
            "--hardfork",
            "T13",
            "--t13-time",
            "100",
        ])
        .unwrap()
        .run()
        .await
        .unwrap();
        let genesis = serde_json::from_slice::<Genesis>(
            &std::fs::read(output.path().join("genesis.json")).unwrap(),
        )
        .unwrap();
        let config = serde_json::to_value(&genesis.config).unwrap();

        assert_eq!(config["t12Time"], serde_json::json!(0));
        assert_eq!(config["t13Time"], serde_json::json!(100));
        assert_eq!(config["t14Time"], serde_json::Value::Null);
        let spec = ZoneChainSpec::from_genesis(genesis).unwrap();
        assert_eq!(spec.tempo_hardfork_at(99), TempoHardfork::T12);
        assert_eq!(spec.tempo_hardfork_at(u64::MAX), TempoHardfork::T13);
    }
}
