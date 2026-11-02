//! Deploy and configure the non-secret L1 fixtures used by the private-Zone benchmark.

use alloy::{
    network::{TransactionBuilder, primitives::ReceiptResponse},
    primitives::{Address, B256, Uint, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol_types::{SolCall, SolConstructor},
};
use eyre::{Context as _, ensure, eyre};
use serde::Serialize;
use std::{fs, path::PathBuf};
use tempo_alloy::{
    TempoNetwork,
    primitives::transaction::Call,
    provider::TempoProviderBuilderExt as _,
    rpc::{TempoCallBuilderExt as _, TempoTransactionRequest},
};
use tempo_contracts::{
    precompiles::{IRolesAuth, ITIP20},
    zones::{ZonePortal, ZonePortal::Role as PortalRole},
};
use tempo_precompiles::TIP20_FACTORY_ADDRESS;

use crate::zone_utils::{check, parse_private_key};

alloy::sol! {
    #[sol(rpc)]
    contract FixtureEarnFactory {
        struct FixedFeeRecipient {
            address account;
            uint16 rateBps;
        }

        struct ExcessReturnFee {
            bool enabled;
            address account;
            uint16 annualTargetRateBps;
            uint16 excessFeeRateBps;
        }

        struct FeeConfig {
            uint8 fixedFeeCount;
            FixedFeeRecipient[4] fixedFees;
            ExcessReturnFee excess;
        }

        struct EarnVaultControls {
            address emergencyGuardian;
            address asyncJanitor;
            uint256 maxManagedAssets;
            uint8 migrationMode;
        }

        struct DistributorConfig {
            address distributor;
            uint40 updateDelay;
        }

        struct DeployParams {
            bytes32 deploymentId;
            address engine;
            address owner;
            EarnVaultControls controls;
            DistributorConfig distributorConfig;
            FeeConfig fees;
            uint64 transferPolicyId;
        }

        function deploy(DeployParams calldata params)
            external
            returns (address earnShare, address earnVault, address earnFees);
    }

    #[sol(rpc)]
    interface ERC4626EngineInitializer {
        function initializeEarnVault(address earnVault) external;
    }

    /// Earn's public test-only stand-in for the DirectPropAMM par pool behind the router.
    #[sol(rpc)]
    interface DemoParPool {
        function setTakerAllowed(address taker, bool allowed) external;
        function setRecipientAllowed(address recipient, bool allowed) external;
    }

    #[sol(rpc)]
    interface EarnRouterPoolView {
        function pool() external view returns (address);
        function customerId() external view returns (bytes32);
        function liquidityStatus()
            external
            view
            returns (
                bool paused,
                bool admitted,
                bool atPar,
                uint256 depositLiquidity,
                uint256 redeemLiquidity
            );
    }

    contract FixtureSimple4626Vault {
        constructor(address asset_, string name_, string symbol_, uint8 decimals_);
    }

    contract FixtureERC4626Engine {
        constructor(address vault_, address owner_, string nameOverride_, string symbolOverride_);
    }

    contract FixtureDemoParPool {
        constructor(address baseToken_, address quoteToken_, address owner_);
    }

    contract FixtureSingleZoneEarnRouter {
        constructor(
            uint32 allowedZoneId_,
            address earnVault_,
            address privateAsset_,
            address pool_,
            bytes32 customerId_
        );
    }

    contract FixtureEarnFactoryConstructor {
        constructor(
            address tip20Factory_,
            address earnVaultImplementation_,
            address earnFeesImplementation_
        );
    }

    contract FixtureEarnContributionController {
        constructor(address earnVault_, address owner_);
    }
}

const DEFAULT_DEPLOYMENT_GAS_LIMIT: u64 = 30_000_000;
// The router's pool rounding route and trade-memo customer; the demo pool accepts any nonzero ID.
const ROUTER_CUSTOMER_ID: B256 = B256::with_last_byte(0xBE);
// Tempo's transaction pool rejects AA transactions containing more than 32 calls.
const MAX_PORTAL_ROLE_CALLS_PER_TX: usize = 32;

#[derive(Debug, clap::Parser)]
pub(crate) struct DeployNeobankFixtures {
    /// Tempo L1 HTTP RPC URL. This command never defaults to a public endpoint.
    #[arg(long, env = "L1_RPC_URL")]
    l1_rpc_url: String,

    /// ZonePortal address created for this benchmark topology.
    #[arg(long, env = "L1_PORTAL_ADDRESS")]
    portal: Address,

    /// Native TIP-20 used for Zone deposits, transfer fees, and off-ramp.
    #[arg(long, env = "ZONES_BENCH_DLUSD")]
    dlusd: Address,

    /// Native TIP-20 used as the vault asset on L1.
    #[arg(long, env = "ZONES_BENCH_PATHUSD")]
    pathusd: Address,

    /// Native TIP-20 used as the private asset for this benchmark preset.
    #[arg(long, env = "ZONES_BENCH_PRIVATE_ASSET")]
    private_asset: Address,

    /// Directory containing Foundry artifacts from the external Earn checkout and local fixtures.
    #[arg(long, default_value = "crates/zones/contracts/benchmark-out")]
    specs_out: PathBuf,

    /// Exact revision of the external Earn checkout used to build the Foundry artifacts.
    #[arg(long, env = "ZONES_BENCH_EARN_REVISION")]
    earn_revision: String,

    /// Non-secret fixture metadata written for rendering the runtime scenario.
    #[arg(long)]
    output: PathBuf,

    /// Mode-0600 newline-delimited benchmark account allowlist.
    #[arg(long)]
    allowed_accounts_file: PathBuf,

    /// Untimed per-side inventory seeded into the router's par pool.
    #[arg(long, default_value_t = 10_000_000_000_u128)]
    liquidity: u128,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FixtureMetadata {
    portal: String,
    messenger: String,
    zone_id: u32,
    dlusd: String,
    pathusd: String,
    private_asset: String,
    earn_token: String,
    earn_share: String,
    route_swapper: Option<String>,
    route_override: bool,
    par_pool: String,
    customer_id: String,
    tip20_handler: Option<String>,
    auth_registry: Option<String>,
    liquidity: u128,
    earn_fixture_revision: String,
    vault: String,
    engine: String,
    earn_factory: String,
    earn_vault: String,
    earn_fees: String,
    earn_router: String,
    contribution_controller: String,
    // Compatibility aliases consumed by the benchmark runtime while its environment variable
    // names remain stable. Each points at the corresponding canonical v1 contract above.
    vault_adapter: String,
    rewards: String,
    gateway: String,
    bridge_wallet: String,
}

impl DeployNeobankFixtures {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        validate_earn_revision(&self.earn_revision)?;
        validate_liquidity(self.liquidity)?;
        ensure!(
            self.private_asset == self.dlusd,
            "current Earn requires --private-asset to differ from the pathUSD vault asset"
        );
        let deployer = signer_from_env("FIXTURE_DEPLOYER_KEY")?;
        let deployer_address = deployer.address();
        let portal_admin = signer_from_env("PORTAL_ADMIN_KEY")?;
        let portal_admin_address = portal_admin.address();
        let deployer_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(deployer)
            .connect(&self.l1_rpc_url)
            .await
            .wrap_err("failed connecting fixture deployer to Tempo L1")?;
        let admin_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .with_expiring_nonces()
            .wallet(portal_admin)
            .connect(&self.l1_rpc_url)
            .await
            .wrap_err("failed connecting portal admin to Tempo L1")?;

        let portal = ZonePortal::new(self.portal, &deployer_provider);
        let messenger = portal
            .messenger()
            .call()
            .await
            .wrap_err("failed querying ZonePortal messenger")?;
        let zone_id = portal
            .zoneId()
            .call()
            .await
            .wrap_err("failed querying ZonePortal zone ID")?;
        ensure!(!messenger.is_zero(), "ZonePortal messenger is zero");
        let mut allowed_accounts = read_private_address_file(&self.allowed_accounts_file)?;
        allowed_accounts.sort_unstable();
        allowed_accounts.dedup();
        ensure!(
            !allowed_accounts.is_empty(),
            "benchmark account allowlist must not be empty"
        );
        let admin_portal = ZonePortal::new(self.portal, &admin_provider);
        ensure!(
            admin_portal
                .admin()
                .call()
                .await
                .wrap_err("failed querying ZonePortal admin")?
                == portal_admin_address,
            "PORTAL_ADMIN_KEY does not control the configured ZonePortal"
        );
        ensure!(
            admin_portal
                .isAccessEnforced()
                .call()
                .await
                .wrap_err("failed querying ZonePortal access mode")?,
            "ZonePortal access enforcement must be enabled before deploying fixtures"
        );
        ensure!(
            admin_portal
                .isGatewayOpen()
                .call()
                .await
                .wrap_err("failed querying ZonePortal gateway mode")?,
            "ZonePortal gateway enforcement must remain disabled until fixture roles are configured"
        );

        let par_pool = deploy_par_pool(
            &deployer_provider,
            &self.specs_out,
            deployer_address,
            self.private_asset,
            self.pathusd,
            self.liquidity,
        )
        .await?;
        let vault = deploy(
            &deployer_provider,
            with_constructor(
                load_bytecode(&self.specs_out, "Simple4626Vault.sol/Simple4626Vault")?,
                FixtureSimple4626Vault::constructorCall {
                    asset_: self.pathusd,
                    name_: "Neobank benchmark vault".to_owned(),
                    symbol_: "nbVAULT".to_owned(),
                    decimals_: 6,
                }
                .abi_encode(),
            ),
            "Simple4626Vault",
        )
        .await?;
        let engine = deploy(
            &deployer_provider,
            with_constructor(
                load_bytecode(&self.specs_out, "ERC4626Engine.sol/ERC4626Engine")?,
                FixtureERC4626Engine::constructorCall {
                    vault_: vault,
                    owner_: deployer_address,
                    nameOverride_: String::new(),
                    symbolOverride_: String::new(),
                }
                .abi_encode(),
            ),
            "ERC4626Engine",
        )
        .await?;
        let earn_vault_implementation = deploy(
            &deployer_provider,
            load_bytecode(&self.specs_out, "EarnVault.sol/EarnVault")?,
            "EarnVault implementation",
        )
        .await?;
        let earn_fees_implementation = deploy(
            &deployer_provider,
            load_bytecode(&self.specs_out, "EarnFees.sol/EarnFees")?,
            "EarnFees implementation",
        )
        .await?;
        let earn_factory = deploy(
            &deployer_provider,
            with_constructor(
                load_bytecode(&self.specs_out, "EarnFactory.sol/EarnFactory")?,
                FixtureEarnFactoryConstructor::constructorCall {
                    tip20Factory_: TIP20_FACTORY_ADDRESS,
                    earnVaultImplementation_: earn_vault_implementation,
                    earnFeesImplementation_: earn_fees_implementation,
                }
                .abi_encode(),
            ),
            "EarnFactory",
        )
        .await?;
        let factory = FixtureEarnFactory::new(earn_factory, &deployer_provider);
        let deploy_params = FixtureEarnFactory::DeployParams {
            deploymentId: keccak256("zones-neobank-benchmark-earn-v1"),
            engine,
            owner: deployer_address,
            controls: FixtureEarnFactory::EarnVaultControls {
                emergencyGuardian: deployer_address,
                asyncJanitor: deployer_address,
                maxManagedAssets: Uint::<256, 4>::ZERO,
                migrationMode: 0,
            },
            distributorConfig: FixtureEarnFactory::DistributorConfig {
                distributor: Address::ZERO,
                updateDelay: Uint::<40, 1>::ZERO,
            },
            fees: zero_fee_config(),
            transferPolicyId: 0,
        };
        let predicted = factory
            .deploy_call(deploy_params.clone())
            .call()
            .await
            .wrap_err("failed simulating canonical Earn stack deployment")?;
        let receipt = factory
            .deploy_call(deploy_params)
            .gas(DEFAULT_DEPLOYMENT_GAS_LIMIT)
            .fee_token(self.pathusd)
            .send()
            .await
            .wrap_err("failed deploying canonical Earn stack")?
            .get_receipt()
            .await
            .wrap_err("failed waiting for canonical Earn stack deployment")?;
        check(&receipt, "deploy canonical Earn stack")?;
        let earn_share = predicted.earnShare;
        let earn_vault = predicted.earnVault;
        let earn_fees = predicted.earnFees;
        for (label, address) in [
            ("EarnShare", earn_share),
            ("EarnVault", earn_vault),
            ("EarnFees", earn_fees),
        ] {
            ensure!(!address.is_zero(), "{label} address is zero");
        }

        let receipt = ERC4626EngineInitializer::new(engine, &deployer_provider)
            .initializeEarnVault(earn_vault)
            .fee_token(self.pathusd)
            .send()
            .await
            .wrap_err("failed initializing the canonical ERC4626 engine")?
            .get_receipt()
            .await
            .wrap_err("failed waiting for canonical ERC4626 engine initialization")?;
        check(&receipt, "initialize canonical ERC4626 engine")?;

        let earn_router = deploy(
            &deployer_provider,
            with_constructor(
                load_bytecode(
                    &self.specs_out,
                    "SingleZoneEarnRouter.sol/SingleZoneEarnRouter",
                )?,
                FixtureSingleZoneEarnRouter::constructorCall {
                    allowedZoneId_: zone_id,
                    earnVault_: earn_vault,
                    privateAsset_: self.private_asset,
                    pool_: par_pool,
                    customerId_: ROUTER_CUSTOMER_ID,
                }
                .abi_encode(),
            ),
            "SingleZoneEarnRouter",
        )
        .await?;
        admit_router_on_par_pool(
            &deployer_provider,
            par_pool,
            earn_router,
            self.pathusd,
            self.liquidity,
        )
        .await?;

        let contribution_controller = deploy(
            &deployer_provider,
            with_constructor(
                load_bytecode(
                    &self.specs_out,
                    "EarnContributionController.sol/EarnContributionController",
                )?,
                FixtureEarnContributionController::constructorCall {
                    earnVault_: earn_vault,
                    owner_: deployer_address,
                }
                .abi_encode(),
            ),
            "EarnContributionController",
        )
        .await?;
        let bridge_wallet = deploy(
            &deployer_provider,
            load_bytecode(
                &self.specs_out,
                "BridgeWalletFixture.sol/BridgeWalletFixture",
            )?,
            "BridgeWalletFixture",
        )
        .await?;
        let role_assignments =
            portal_role_assignments(&allowed_accounts, bridge_wallet, earn_router, messenger)?;

        if !admin_portal
            .isTokenEnabled(earn_share)
            .call()
            .await
            .wrap_err("failed querying EarnShare ZonePortal enablement")?
        {
            let receipt = admin_portal
                .enableToken(earn_share)
                .fee_token(self.pathusd)
                .send()
                .await
                .wrap_err("failed enabling EarnShare on ZonePortal")?
                .get_receipt()
                .await
                .wrap_err("failed waiting for EarnShare enablement receipt")?;
            check(&receipt, "enable EarnShare on ZonePortal")?;
        }
        configure_closed_loop_portal(
            &admin_provider,
            self.portal,
            self.pathusd,
            &role_assignments,
        )
        .await?;

        let metadata = FixtureMetadata {
            portal: self.portal.to_string(),
            messenger: messenger.to_string(),
            zone_id,
            dlusd: self.dlusd.to_string(),
            pathusd: self.pathusd.to_string(),
            private_asset: self.private_asset.to_string(),
            earn_token: earn_share.to_string(),
            earn_share: earn_share.to_string(),
            route_swapper: Some(earn_router.to_string()),
            route_override: true,
            par_pool: par_pool.to_string(),
            customer_id: ROUTER_CUSTOMER_ID.to_string(),
            tip20_handler: None,
            auth_registry: None,
            liquidity: self.liquidity,
            earn_fixture_revision: self.earn_revision.clone(),
            vault: vault.to_string(),
            engine: engine.to_string(),
            earn_factory: earn_factory.to_string(),
            earn_vault: earn_vault.to_string(),
            earn_fees: earn_fees.to_string(),
            earn_router: earn_router.to_string(),
            contribution_controller: contribution_controller.to_string(),
            vault_adapter: earn_vault.to_string(),
            rewards: contribution_controller.to_string(),
            gateway: earn_router.to_string(),
            bridge_wallet: bridge_wallet.to_string(),
        };
        if let Some(parent) = self.output.parent() {
            fs::create_dir_all(parent)
                .wrap_err_with(|| format!("failed creating {}", parent.display()))?;
        }
        fs::write(&self.output, serde_json::to_string_pretty(&metadata)?)
            .wrap_err_with(|| format!("failed writing {}", self.output.display()))?;
        println!("Private-Zone benchmark fixtures deployed");
        println!("  Earn router:             {earn_router}");
        println!("  Par pool:                {par_pool}");
        println!("  Earn vault:              {earn_vault}");
        println!("  Earn share:              {earn_share}");
        println!("  Earn fees:               {earn_fees}");
        println!("  Contribution controller: {contribution_controller}");
        println!("  Bridge wallet:           {bridge_wallet}");
        println!("  Portal policy:           closed-loop enforcement enabled");
        println!("  Metadata:                {}", self.output.display());
        Ok(())
    }
}

fn portal_role_assignments(
    allowed_accounts: &[Address],
    bridge_wallet: Address,
    earn_router: Address,
    messenger: Address,
) -> eyre::Result<Vec<(Address, PortalRole)>> {
    ensure!(!bridge_wallet.is_zero(), "Bridge wallet address is zero");
    ensure!(!earn_router.is_zero(), "EarnRouter address is zero");
    ensure!(
        bridge_wallet != earn_router,
        "Bridge wallet and EarnRouter addresses must be distinct"
    );
    ensure!(
        bridge_wallet != messenger,
        "the ZonePortal messenger cannot be assigned the Bridge wallet account role"
    );
    ensure!(
        earn_router != messenger,
        "the ZonePortal messenger cannot be assigned the EarnRouter gateway role"
    );
    let mut assignments = Vec::with_capacity(allowed_accounts.len() + 2);
    for account in allowed_accounts {
        ensure!(
            !account.is_zero(),
            "the benchmark account allowlist contains the zero address"
        );
        ensure!(
            *account != messenger,
            "the ZonePortal messenger cannot be assigned the benchmark account role"
        );
        ensure!(
            *account != bridge_wallet && *account != earn_router,
            "a benchmark account conflicts with a closed-loop fixture role"
        );
        assignments.push((*account, PortalRole::Account));
    }
    assignments.push((bridge_wallet, PortalRole::Account));
    assignments.push((earn_router, PortalRole::CallbackGateway));
    Ok(assignments)
}

async fn configure_closed_loop_portal<P: Provider<TempoNetwork>>(
    provider: &P,
    portal_address: Address,
    fee_token: Address,
    assignments: &[(Address, PortalRole)],
) -> eyre::Result<()> {
    let portal = ZonePortal::new(portal_address, provider);
    println!(
        "Configuring {} closed-loop ZonePortal roles...",
        assignments.len()
    );
    let mut missing_role_calls = Vec::new();
    for (index, (account, expected_role)) in assignments.iter().enumerate() {
        if !portal
            .hasRole(*account, *expected_role)
            .call()
            .await
            .wrap_err_with(|| format!("failed querying ZonePortal role at index {index}"))?
        {
            let input = match expected_role {
                PortalRole::Account => ZonePortal::setAllowedAccountCall {
                    account: *account,
                    allowed: true,
                }
                .abi_encode(),
                PortalRole::CallbackGateway => ZonePortal::setGatewayCall {
                    account: *account,
                    allowed: true,
                }
                .abi_encode(),
                unsupported => {
                    eyre::bail!(
                        "unsupported benchmark ZonePortal role {unsupported:?} at index {index}"
                    );
                }
            };
            missing_role_calls.push(Call {
                to: portal_address.into(),
                value: Uint::<256, 4>::ZERO,
                input: input.into(),
            });
        }
        if (index + 1) % 10 == 0 || index + 1 == assignments.len() {
            println!(
                "ZonePortal role discovery progress: {}/{}",
                index + 1,
                assignments.len()
            );
        }
    }

    let batch_count = missing_role_calls
        .len()
        .div_ceil(MAX_PORTAL_ROLE_CALLS_PER_TX);
    println!(
        "Assigning {} missing ZonePortal roles in {} Tempo AA batches...",
        missing_role_calls.len(),
        batch_count
    );
    let receipt_results = futures::future::join_all(
        missing_role_calls
            .chunks(MAX_PORTAL_ROLE_CALLS_PER_TX)
            .enumerate()
            .map(|(batch_index, calls)| {
                let request = TempoTransactionRequest {
                    calls: calls.to_vec(),
                    fee_token: Some(fee_token),
                    ..Default::default()
                };
                async move {
                    provider
                        .send_transaction(request)
                        .await
                        .wrap_err_with(|| {
                            format!(
                                "failed submitting ZonePortal role batch {}/{batch_count}",
                                batch_index + 1
                            )
                        })?
                        .get_receipt()
                        .await
                        .wrap_err_with(|| {
                            format!(
                                "failed waiting for ZonePortal role batch {}/{batch_count}",
                                batch_index + 1
                            )
                        })
                }
            }),
    )
    .await;
    for (batch_index, receipt) in receipt_results.into_iter().enumerate() {
        let receipt = receipt?;
        check(
            &receipt,
            &format!(
                "assign ZonePortal benchmark role batch {}/{batch_count}",
                batch_index + 1
            ),
        )?;
        println!(
            "ZonePortal role batch progress: {}/{}",
            batch_index + 1,
            batch_count
        );
    }

    for (index, (account, expected_role)) in assignments.iter().enumerate() {
        ensure!(
            portal
                .hasRole(*account, *expected_role)
                .call()
                .await
                .wrap_err_with(|| {
                    format!("failed verifying ZonePortal role at index {index}")
                })?,
            "ZonePortal role verification failed at index {index}"
        );
    }

    if portal
        .isGatewayOpen()
        .call()
        .await
        .wrap_err("failed querying ZonePortal gateway mode")?
    {
        let receipt = portal
            .setGatewayMode(true)
            .fee_token(fee_token)
            .send()
            .await
            .wrap_err("failed enabling ZonePortal gateway enforcement")?
            .get_receipt()
            .await
            .wrap_err("failed waiting for ZonePortal gateway enforcement receipt")?;
        check(&receipt, "enable ZonePortal gateway enforcement")?;
    }
    ensure!(
        !portal
            .isGatewayOpen()
            .call()
            .await
            .wrap_err("failed verifying ZonePortal gateway mode")?,
        "ZonePortal gateway enforcement did not activate"
    );

    ensure!(
        portal
            .isAccessEnforced()
            .call()
            .await
            .wrap_err("failed verifying ZonePortal access mode")?,
        "ZonePortal access enforcement was disabled while configuring fixture roles"
    );
    Ok(())
}

fn validate_liquidity(liquidity: u128) -> eyre::Result<()> {
    ensure!(liquidity > 0, "--liquidity must be greater than zero");
    Ok(())
}

fn validate_earn_revision(revision: &str) -> eyre::Result<()> {
    ensure!(
        revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "ZONES_BENCH_EARN_REVISION must be the exact 40-character commit SHA of the external Earn checkout"
    );
    Ok(())
}

/// Deploys Earn's public par pool for the private asset and pathUSD and seeds both sides.
async fn deploy_par_pool<P: Provider<TempoNetwork>>(
    provider: &P,
    specs_out: &std::path::Path,
    deployer: Address,
    private_asset: Address,
    pathusd: Address,
    liquidity: u128,
) -> eyre::Result<Address> {
    let pool = deploy(
        provider,
        with_constructor(
            load_bytecode(specs_out, "DemoParPool.sol/DemoParPool")?,
            FixtureDemoParPool::constructorCall {
                baseToken_: private_asset,
                quoteToken_: pathusd,
                owner_: deployer,
            }
            .abi_encode(),
        ),
        "Earn DemoParPool",
    )
    .await?;

    let inventory = Uint::<256, 4>::from(liquidity);
    for (token, label) in [(private_asset, "private asset"), (pathusd, "pathUSD")] {
        let issuer_role = ITIP20::new(token, provider)
            .ISSUER_ROLE()
            .call()
            .await
            .wrap_err_with(|| format!("failed querying {label} issuer role"))?;
        let roles = IRolesAuth::new(token, provider);
        if !roles
            .hasRole(deployer, issuer_role)
            .call()
            .await
            .wrap_err_with(|| format!("failed querying deployer {label} issuer role"))?
        {
            let receipt = roles
                .grantRole(issuer_role, deployer)
                .fee_token(pathusd)
                .send()
                .await
                .wrap_err_with(|| format!("failed granting deployer {label} issuer role"))?
                .get_receipt()
                .await
                .wrap_err_with(|| format!("failed waiting for deployer {label} issuer role"))?;
            check(&receipt, &format!("grant deployer {label} issuer role"))?;
        }
        let receipt = ITIP20::new(token, provider)
            .mint(pool, inventory)
            .fee_token(pathusd)
            .send()
            .await
            .wrap_err_with(|| format!("failed seeding {label} par pool inventory"))?
            .get_receipt()
            .await
            .wrap_err_with(|| format!("failed waiting to seed {label} par pool inventory"))?;
        check(&receipt, &format!("seed {label} par pool inventory"))?;
    }
    Ok(pool)
}

/// Admits the router as the par pool's taker and recipient, then checks the router's own view.
async fn admit_router_on_par_pool<P: Provider<TempoNetwork>>(
    provider: &P,
    pool: Address,
    router: Address,
    pathusd: Address,
    liquidity: u128,
) -> eyre::Result<()> {
    let pool_contract = DemoParPool::new(pool, provider);
    let receipt = pool_contract
        .setTakerAllowed(router, true)
        .fee_token(pathusd)
        .send()
        .await
        .wrap_err("failed admitting EarnRouter as par pool taker")?
        .get_receipt()
        .await
        .wrap_err("failed waiting to admit EarnRouter as par pool taker")?;
    check(&receipt, "admit EarnRouter as par pool taker")?;
    let receipt = pool_contract
        .setRecipientAllowed(router, true)
        .fee_token(pathusd)
        .send()
        .await
        .wrap_err("failed admitting EarnRouter as par pool recipient")?
        .get_receipt()
        .await
        .wrap_err("failed waiting to admit EarnRouter as par pool recipient")?;
    check(&receipt, "admit EarnRouter as par pool recipient")?;

    let router_view = EarnRouterPoolView::new(router, provider);
    ensure!(
        router_view
            .pool()
            .call()
            .await
            .wrap_err("failed querying EarnRouter pool")?
            == pool,
        "EarnRouter is not bound to the deployed par pool"
    );
    let status = router_view
        .liquidityStatus()
        .call()
        .await
        .wrap_err("failed querying EarnRouter liquidity status")?;
    let inventory = Uint::<256, 4>::from(liquidity);
    ensure!(
        !status.paused && status.admitted && status.atPar,
        "par pool is not ready for EarnRouter: paused={}, admitted={}, atPar={}",
        status.paused,
        status.admitted,
        status.atPar
    );
    ensure!(
        status.depositLiquidity == inventory && status.redeemLiquidity == inventory,
        "par pool inventory does not match --liquidity: deposit={}, redeem={}",
        status.depositLiquidity,
        status.redeemLiquidity
    );
    Ok(())
}

fn signer_from_env(name: &str) -> eyre::Result<PrivateKeySigner> {
    let key =
        std::env::var(name).wrap_err_with(|| format!("{name} must be set in the environment"))?;
    parse_private_key(&key).wrap_err_with(|| format!("{name} is not a valid private key"))
}

async fn deploy<P: Provider<TempoNetwork>>(
    provider: &P,
    bytecode: Vec<u8>,
    label: &str,
) -> eyre::Result<Address> {
    let general_gas_limit = std::env::var("ZONES_BENCH_L1_GENERAL_GAS_LIMIT")
        .unwrap_or_else(|_| DEFAULT_DEPLOYMENT_GAS_LIMIT.to_string())
        .parse::<u64>()
        .wrap_err("ZONES_BENCH_L1_GENERAL_GAS_LIMIT must be an unsigned integer")?;
    ensure!(
        general_gas_limit > 0,
        "ZONES_BENCH_L1_GENERAL_GAS_LIMIT must be greater than zero"
    );
    // The configured value is the aggregate general-transaction budget for an L1 block. Keep
    // this individual deployment transaction within Tempo's protocol transaction gas cap.
    let gas_limit = general_gas_limit.min(DEFAULT_DEPLOYMENT_GAS_LIMIT);
    let receipt = provider
        .send_transaction(
            TransactionRequest::default()
                .with_deploy_code(bytecode)
                // Fixture constructors can make contract calls that Tempo's generic
                // estimator underestimates. Use as much of the configured general-transaction
                // budget as Tempo's per-transaction cap allows.
                .with_gas_limit(gas_limit)
                .into(),
        )
        .await
        .wrap_err_with(|| format!("failed deploying {label}"))?
        .get_receipt()
        .await
        .wrap_err_with(|| format!("failed waiting for {label} deployment receipt"))?;
    if !receipt.status() {
        return Err(eyre!(
            "{label} reverted after using {} gas (transaction {})",
            receipt.gas_used(),
            receipt.transaction_hash(),
        ));
    }
    let contract = receipt
        .contract_address
        .ok_or_else(|| eyre!("{label} deployment receipt did not contain a contract address"))?;
    println!(
        "Deployed {label}: {contract} (gas used: {})",
        receipt.gas_used()
    );
    Ok(contract)
}

fn with_constructor(mut bytecode: Vec<u8>, constructor: Vec<u8>) -> Vec<u8> {
    bytecode.extend_from_slice(&constructor);
    bytecode
}

fn zero_fee_config() -> FixtureEarnFactory::FeeConfig {
    let zero_fee_recipient = FixtureEarnFactory::FixedFeeRecipient {
        account: Address::ZERO,
        rateBps: 0,
    };
    FixtureEarnFactory::FeeConfig {
        fixedFeeCount: 0,
        fixedFees: std::array::from_fn(|_| zero_fee_recipient.clone()),
        excess: FixtureEarnFactory::ExcessReturnFee {
            enabled: false,
            account: Address::ZERO,
            annualTargetRateBps: 0,
            excessFeeRateBps: 0,
        },
    }
}

fn load_bytecode(artifacts: &std::path::Path, contract: &str) -> eyre::Result<Vec<u8>> {
    let artifact_path = artifact_path(artifacts, contract);
    let artifact = fs::read_to_string(&artifact_path).wrap_err_with(|| {
        format!(
            "{contract} artifact not found at {}",
            artifact_path.display()
        )
    })?;
    let artifact: serde_json::Value = serde_json::from_str(&artifact)
        .wrap_err_with(|| format!("failed parsing {}", artifact_path.display()))?;
    let bytecode = artifact["bytecode"]["object"]
        .as_str()
        .ok_or_else(|| eyre!("missing bytecode in {}", artifact_path.display()))?;
    alloy::primitives::hex::decode(bytecode)
        .wrap_err_with(|| format!("invalid bytecode in {}", artifact_path.display()))
}

fn artifact_path(artifacts: &std::path::Path, contract: &str) -> PathBuf {
    artifacts.join(format!("{contract}.json"))
}

fn read_private_address_file(path: &std::path::Path) -> eyre::Result<Vec<Address>> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path).wrap_err_with(|| {
        format!(
            "failed reading allowed-accounts metadata from {}",
            path.display()
        )
    })?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "allowed-accounts file must be a regular, non-symlink file: {}",
        path.display()
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "allowed-accounts file must not be accessible by group or other users: {}",
        path.display()
    );

    let contents = fs::read_to_string(path)
        .wrap_err_with(|| format!("failed reading allowed accounts from {}", path.display()))?;
    contents
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let value = line.trim();
            (!value.is_empty() && !value.starts_with('#')).then_some((index + 1, value))
        })
        .map(|(line, value)| {
            value.parse::<Address>().wrap_err_with(|| {
                format!(
                    "invalid allowed account in {} at line {line}",
                    path.display()
                )
            })
        })
        .collect()
}
