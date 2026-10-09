//! Tempo Earn scenarios that cross the public L1 / private Zone boundary.
//!
//! CI builds the Solidity artifacts from the Tempo Earn `main` branch. These tests deliberately
//! exercise the complete callback path: a private withdrawal settles on L1, the Earn router
//! deposits or redeems through the vault stack, and the output is encrypted back into the
//! originating Zone.

use crate::utils::{
    Check403Registry, L1TestNode, WithdrawalArgs, ZoneAccount, ZoneTestNode, forge_bytecode,
    spawn_sequencer,
};
use alloy::{
    primitives::{Address, B256, Bytes, TxKind, U256, keccak256},
    providers::{Provider, ProviderBuilder},
};
use alloy_network::{ReceiptResponse, TransactionBuilder as _};
use alloy_rpc_types_eth::{Filter, TransactionRequest};
use alloy_sol_types::{SolCall, SolConstructor, SolValue};
use eyre::WrapErr;
use std::time::Duration;
use tempo_alloy::{TempoNetwork, rpc::TempoTransactionRequest};
use tempo_contracts::precompiles::{IRolesAuth, ITIP20, ITIP403Registry};
use tempo_precompiles::{
    PATH_USD_ADDRESS, TIP20_FACTORY_ADDRESS, TIP403_REGISTRY_ADDRESS, tip20::ISSUER_ROLE,
    tip403_registry::AuthRole,
};
use tempo_primitives::transaction::Call;
use tempo_zone_contracts::{DepositPayload, ZONE_OUTBOX_ADDRESS, ZonePortal};

const AMOUNT: u128 = 1_000_000;
const REWARD_AMOUNT: u128 = AMOUNT / 10;
const PUBLIC_USER_BALANCE: u128 = 50_000_000;
const PRIVATE_FEE_BALANCE: u128 = 10_000_000;
const TOKEN_SUPPLY: u128 = 1_000_000_000;
// Match Earn's current callback budget.
const CALLBACK_GAS_LIMIT: u64 = 10_000_000;
const REWARD_FUNDING_TX_GAS_LIMIT: u64 = 5_000_000;
const MIGRATION_TX_GAS_LIMIT: u64 = 10_000_000;
// Tempo's transaction cap is 30M.
const CONTRACT_DEPLOYMENT_TX_GAS_LIMIT: u64 = 30_000_000;
const MIN_GAS_HEADROOM_PERCENT: u64 = 15;
const E2E_TIMEOUT: Duration = Duration::from_secs(90);
const BOUNCE_TIMEOUT: Duration = Duration::from_secs(180);

alloy_sol_types::sol! {
    enum EarnFlow {
        Deposit,
        Redeem
    }

    enum EngineMigrationMode {
        UserOnly,
        OperatorEnabled
    }

    struct EarnVaultControls {
        address emergencyGuardian;
        address asyncJanitor;
        uint256 maxManagedAssets;
        EngineMigrationMode migrationMode;
    }

    struct DistributorConfig {
        address distributor;
        uint40 updateDelay;
    }

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

    struct EarnDepositPayload {
        bytes32 ephemeralPubkeyX;
        uint8 ephemeralPubkeyYParity;
        bytes ciphertext;
        bytes12 nonce;
        bytes16 tag;
    }

    struct EarnZoneReturn {
        uint256 keyIndex;
        EarnDepositPayload encrypted;
        address refundRecipient;
    }

    struct EarnCallbackData {
        EarnFlow flow;
        uint128 minVaultAssets;
        uint128 minEarnShares;
        uint128 minOutputAmount;
        bytes32 actionId;
        EarnZoneReturn zoneReturn;
    }

    enum LegacyEarnDestination {
        Zone,
        Public
    }

    struct LegacyEarnZoneDelivery {
        address portal;
        uint256 keyIndex;
        EarnDepositPayload encrypted;
        address refundRecipient;
    }

    struct LegacyEarnCallbackData {
        EarnFlow flow;
        address earnVault;
        LegacyEarnDestination destination;
        address outputToken;
        uint128 minVaultAssets;
        uint128 minEarnShares;
        uint128 minOutputAmount;
        bytes32 actionId;
        bytes destinationData;
    }

    struct EarnDeployParams {
        bytes32 deploymentId;
        address engine;
        address owner;
        EarnVaultControls controls;
        DistributorConfig distributorConfig;
        FeeConfig fees;
        uint64 transferPolicyId;
    }

    #[sol(rpc)]
    contract VenueVault {
        constructor(address asset_, string name_, string symbol_, uint8 decimals_);
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function deposit(uint256 assets, address receiver) external returns (uint256 shares);
        function totalAssets() external view returns (uint256);
    }

    #[sol(rpc)]
    contract EarnEngine {
        constructor(address vault_, address owner_, string nameOverride_, string symbolOverride_);
        function initializeEarnVault(address earnVault) external;
    }

    #[sol(rpc)]
    contract EarnFactory {
        constructor(
            address tip20Factory_,
            address earnVaultImplementation_,
            address earnFeesImplementation_
        );
        function deploy(EarnDeployParams params)
            external
            returns (address earnShare, address earnVault, address earnFees);
    }

    #[sol(rpc)]
    contract EarnVault {
        function deposit(uint256 assets, address receiver, uint256 minEarnShares)
            external
            returns (uint256 earnShares);
        function depositVenueShares(uint256 venueShares, address receiver, uint256 minEarnShares)
            external
            returns (uint256 earnShares);
        function depositsPaused() external view returns (bool);
        function engine() external view returns (address);
        function engineShares() external view returns (uint256);
        function migrateEngine(address newEngine, uint256 minNewShares, uint256 minAssetsRetained)
            external
            returns (uint256 newShares);
        function previewRedeem(uint256 shares) external view returns (uint256 assets);
        function redeem(uint256 earnShares, address receiver, uint256 minAssets)
            external
            returns (uint256 assets);
        function setDepositsPaused(bool paused) external;
        function convertEngineSharesToEarnShares(uint256 shares) external view returns (uint256);
        function totalEarnShares() external view returns (uint256);
        function anchorEngineShares() external view returns (uint256);
        function anchorEarnShares() external view returns (uint256);
    }

    #[sol(rpc)]
    contract SingleZoneEarnRouter {
        constructor(uint32 allowedZoneId_, address earnVault_, address privateAsset_, address tokenAuthority_);
    }

    #[sol(rpc)]
    contract LegacyUniversalEarnRouter {
        function depositToZone(
            address earnVault,
            uint256 assets,
            uint256 minEarnShares,
            LegacyEarnZoneDelivery delivery
        ) external returns (uint256 earnShares, bytes32 zoneDepositHash);
        function redeemToZone(
            address earnVault,
            uint256 earnShares,
            uint256 minAssets,
            LegacyEarnZoneDelivery delivery
        ) external returns (uint256 assets, bytes32 zoneDepositHash);
    }

    #[sol(rpc)]
    contract DemoTokenAuthority {
        constructor(address reserveToken, address administrator);
        function BRIDGE_ECOSYSTEM_CONTRACT_ROLE() external view returns (bytes32);
        function UNWRAPPER_ROLE() external view returns (bytes32);
        function grantRole(bytes32 role, address account) external;
        function setTxnMintLimit(address stablecoin, uint256 limit) external;
        function mintBridgeEcosystem(address stablecoin, address receiver, uint256 amount) external;
    }

    #[sol(rpc)]
    contract EarnContributionController {
        function fund(address funder, uint256 requested, uint256 maxEarnShareSupply)
            external
            returns (uint256 funded);
        function executeFunding(address funder, uint256 requested, uint256 maxEarnShareSupply)
            external
            returns (uint256 funded);
    }
}

#[derive(Clone, Copy)]
struct EarnLimits {
    min_vault_assets: u128,
    min_earn_shares: u128,
    min_output_amount: u128,
}

impl Default for EarnLimits {
    fn default() -> Self {
        Self {
            min_vault_assets: 1,
            min_earn_shares: 1,
            min_output_amount: 1,
        }
    }
}

#[derive(Clone, Copy)]
struct EarnAccessPolicy {
    policy_id: u64,
}

struct EarnZoneFixture {
    l1: L1TestNode,
    zone: ZoneTestNode,
    portal: Address,
    vault_asset: Address,
    alternate_asset: Address,
    venue_vault: Address,
    engine: Address,
    earn_share: Address,
    earn_vault: Address,
    router: Address,
    contribution_controller: Address,
    access_policy: Option<EarnAccessPolicy>,
    user: ZoneAccount,
    _sequencer: zone_sequencer::ZoneSequencerHandle,
}

impl EarnZoneFixture {
    async fn start() -> eyre::Result<Self> {
        Self::start_with_access_policy(false).await
    }

    async fn start_protected() -> eyre::Result<Self> {
        Self::start_with_access_policy(true).await
    }

    async fn start_with_access_policy(protected: bool) -> eyre::Result<Self> {
        reth_tracing::init_test_tracing();

        let l1 = L1TestNode::start().await?;
        let vault_asset = l1
            .create_tip20("Earn Vault USD", "evUSD", B256::with_last_byte(0xE1))
            .await?;
        let alternate_asset = l1
            .create_tip20("Earn Alternate USD", "eaUSD", B256::with_last_byte(0xE2))
            .await?;
        l1.mint_tip20(vault_asset, l1.dev_address(), TOKEN_SUPPLY)
            .await?;
        l1.mint_tip20(alternate_asset, l1.dev_address(), TOKEN_SUPPLY)
            .await?;

        let portal = l1.deploy_zone().await?;
        let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal).await?;
        zone.wait_for_l2_tempo_finalized(0, E2E_TIMEOUT).await?;

        let messenger = ZonePortal::new(portal, l1.provider())
            .messenger()
            .call()
            .await?;
        let owner = l1.dev_address();
        let user_address = l1.user_signer().address();

        let venue_vault = deploy_contract(
            &l1,
            "Simple4626Vault",
            VenueVault::constructorCall {
                asset_: vault_asset,
                name_: "Tempo Earn Zone Vault".to_string(),
                symbol_: "teZONE".to_string(),
                decimals_: 6,
            }
            .abi_encode(),
        )
        .await?;
        let engine = deploy_contract(
            &l1,
            "ERC4626Engine",
            EarnEngine::constructorCall {
                vault_: venue_vault,
                owner_: owner,
                nameOverride_: String::new(),
                symbolOverride_: String::new(),
            }
            .abi_encode(),
        )
        .await?;
        let earn_vault_implementation = deploy_contract(&l1, "EarnVault", Vec::new()).await?;
        let earn_fees_implementation = deploy_contract(&l1, "EarnFees", Vec::new()).await?;
        let factory = deploy_contract(
            &l1,
            "EarnFactory",
            EarnFactory::constructorCall {
                tip20Factory_: TIP20_FACTORY_ADDRESS,
                earnVaultImplementation_: earn_vault_implementation,
                earnFeesImplementation_: earn_fees_implementation,
            }
            .abi_encode(),
        )
        .await?;

        let fees = FeeConfig {
            fixedFeeCount: 0,
            fixedFees: std::array::from_fn(|_| FixedFeeRecipient {
                account: Address::ZERO,
                rateBps: Default::default(),
            }),
            excess: ExcessReturnFee {
                enabled: false,
                account: Address::ZERO,
                annualTargetRateBps: Default::default(),
                excessFeeRateBps: Default::default(),
            },
        };
        let access_policy = if protected {
            Some(EarnAccessPolicy {
                policy_id: l1.create_whitelist_policy().await?,
            })
        } else {
            None
        };
        let params = EarnDeployParams {
            deploymentId: keccak256("zones-earn-e2e-v1"),
            engine,
            owner,
            controls: EarnVaultControls {
                emergencyGuardian: Address::ZERO,
                asyncJanitor: Address::ZERO,
                maxManagedAssets: U256::ZERO,
                migrationMode: EngineMigrationMode::OperatorEnabled,
            },
            distributorConfig: DistributorConfig {
                distributor: Address::ZERO,
                updateDelay: Default::default(),
            },
            fees,
            transferPolicyId: access_policy.map_or(0, |policy| policy.policy_id),
        };

        let provider = l1.dev_provider();
        let factory_contract = EarnFactory::new(factory, &provider);
        let predicted = factory_contract.deploy_call(params.clone()).call().await?;
        let receipt = factory_contract
            .deploy_call(params)
            .gas(CONTRACT_DEPLOYMENT_TX_GAS_LIMIT)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "deploying the Earn stack failed");
        ensure_gas_headroom(
            receipt.gas_used,
            CONTRACT_DEPLOYMENT_TX_GAS_LIMIT,
            "Earn stack deployment",
        )?;
        let earn_share = predicted.earnShare;
        let earn_vault = predicted.earnVault;

        let receipt = EarnEngine::new(engine, &provider)
            .initializeEarnVault(earn_vault)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "initializing the Earn engine failed");

        let authority = deploy_contract(
            &l1,
            "DemoTokenAuthority",
            DemoTokenAuthority::constructorCall {
                reserveToken: PATH_USD_ADDRESS,
                administrator: owner,
            }
            .abi_encode(),
        )
        .await?;
        let provider = l1.dev_provider();
        let authority_contract = DemoTokenAuthority::new(authority, &provider);
        let receipt = IRolesAuth::new(PATH_USD_ADDRESS, &provider)
            .grantRole(ISSUER_ROLE, authority)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "granting reserve issuer role failed");
        for token in [vault_asset, alternate_asset] {
            let receipt = IRolesAuth::new(token, &provider)
                .grantRole(ISSUER_ROLE, authority)
                .send()
                .await?
                .get_receipt()
                .await?;
            eyre::ensure!(
                receipt.status(),
                "granting TokenAuthority issuer role failed"
            );
            let receipt = authority_contract
                .setTxnMintLimit(token, U256::from(TOKEN_SUPPLY))
                .send()
                .await?
                .get_receipt()
                .await?;
            eyre::ensure!(
                receipt.status(),
                "setting TokenAuthority transaction limit failed"
            );
        }
        let zone_id = ZonePortal::new(portal, l1.provider())
            .zoneId()
            .call()
            .await?;
        let router = deploy_contract(
            &l1,
            "SingleZoneEarnRouter",
            SingleZoneEarnRouter::constructorCall {
                allowedZoneId_: zone_id,
                earnVault_: earn_vault,
                privateAsset_: alternate_asset,
                tokenAuthority_: authority,
            }
            .abi_encode(),
        )
        .await?;
        let provider = l1.dev_provider();
        let authority_contract = DemoTokenAuthority::new(authority, &provider);
        let unwrap_role = authority_contract.UNWRAPPER_ROLE().call().await?;
        let receipt = authority_contract
            .grantRole(unwrap_role, router)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "granting router unwrap role failed");
        let bridge_role = authority_contract
            .BRIDGE_ECOSYSTEM_CONTRACT_ROLE()
            .call()
            .await?;
        let receipt = authority_contract
            .grantRole(bridge_role, owner)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "granting fixture funding role failed");
        for token in [vault_asset, alternate_asset] {
            let receipt = authority_contract
                .mintBridgeEcosystem(token, user_address, U256::from(PUBLIC_USER_BALANCE))
                .send()
                .await?
                .get_receipt()
                .await?;
            eyre::ensure!(receipt.status(), "funding TokenAuthority fixture failed");
        }
        let router_block = l1.set_zone_gateway_on_portal(portal, router, true).await?;
        zone.wait_for_l2_tempo_finalized(router_block, E2E_TIMEOUT)
            .await?;
        zone.assert_zone_gateway(router, true).await?;
        let contribution_controller = deploy_contract(
            &l1,
            "EarnContributionController",
            (earn_vault, user_address).abi_encode(),
        )
        .await?;

        if let Some(policy) = access_policy {
            let outsider = l1.signer_at(3).address();
            for account in [
                earn_vault,
                router,
                portal,
                messenger,
                ZONE_OUTBOX_ADDRESS,
                owner,
                user_address,
                outsider,
            ] {
                l1.whitelist_address(policy.policy_id, account).await?;
            }
        }

        l1.enable_token_on_portal(portal, vault_asset).await?;
        l1.enable_token_on_portal(portal, alternate_asset).await?;
        l1.enable_token_on_portal(portal, earn_share).await?;

        let configured_at = l1.provider().get_block_number().await?;
        zone.wait_for_l2_tempo_finalized(configured_at, E2E_TIMEOUT)
            .await?;

        l1.fund_user(user_address, PUBLIC_USER_BALANCE).await?;
        l1.fund_user_token(vault_asset, user_address, PUBLIC_USER_BALANCE)
            .await?;
        l1.fund_user_token(alternate_asset, user_address, PUBLIC_USER_BALANCE)
            .await?;

        let mut user = ZoneAccount::from_l1_and_zone(&l1, &zone, portal);
        user.deposit(PRIVATE_FEE_BALANCE, E2E_TIMEOUT, &zone)
            .await?;

        let sequencer = spawn_sequencer(&l1, &zone, portal, l1.dev_signer()).await;

        Ok(Self {
            l1,
            zone,
            portal,
            vault_asset,
            alternate_asset,
            venue_vault,
            engine,
            earn_share,
            earn_vault,
            router,
            contribution_controller,
            access_policy,
            user,
            _sequencer: sequencer,
        })
    }

    async fn set_access_eligibility(&self, account: Address, eligible: bool) -> eyre::Result<()> {
        let policy = self
            .access_policy
            .ok_or_else(|| eyre::eyre!("Earn access policy is not configured"))?;
        let provider = self.l1.dev_provider();
        let receipt = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider)
            .modifyPolicyWhitelist(policy.policy_id, account, eligible)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "updating Earn eligibility failed");

        let policy_block = self.l1.provider().get_block_number().await?;
        self.zone
            .wait_for_l2_tempo_finalized(policy_block, E2E_TIMEOUT)
            .await?;
        let provider = self.zone.provider();
        let registry = Check403Registry {
            provider,
            token: self.earn_share,
        };
        let recipient_authorized = registry.is_auth_as(account, AuthRole::Recipient).await;
        eyre::ensure!(
            recipient_authorized == eligible,
            "Zone did not mirror Earn recipient eligibility for policy {} and {account}: actual={recipient_authorized}, expected={eligible}",
            policy.policy_id
        );
        Ok(())
    }

    async fn allow_zone_account(&self, account: Address) -> eyre::Result<()> {
        let block = self
            .l1
            .set_allowed_account_on_portal(self.portal, account, true)
            .await?;
        self.zone
            .wait_for_l2_tempo_finalized(block, E2E_TIMEOUT)
            .await?;
        self.zone.assert_allowed_account(account, true).await
    }

    async fn set_deposits_paused(&self, paused: bool) -> eyre::Result<()> {
        let provider = self.l1.dev_provider();
        let earn_vault = EarnVault::new(self.earn_vault, &provider);
        let receipt = earn_vault
            .setDepositsPaused(paused)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "setting Earn deposit pause failed");
        eyre::ensure!(
            earn_vault.depositsPaused().call().await? == paused,
            "Earn deposit pause state did not update"
        );
        Ok(())
    }

    async fn assert_engine_migration_guardrails(&self) -> eyre::Result<()> {
        let earn_vault = EarnVault::new(self.earn_vault, self.l1.provider());
        let engine_before = earn_vault.engine().call().await?;
        let engine_shares_before = earn_vault.engineShares().call().await?;
        let supply_before = earn_vault.totalEarnShares().call().await?;

        let unauthorized = EarnVault::new(self.earn_vault, self.user.l1_provider())
            .migrateEngine(Address::ZERO, U256::ONE, U256::ONE)
            .from(self.user.address())
            .call()
            .await;
        eyre::ensure!(
            unauthorized.is_err(),
            "non-operator unexpectedly passed the engine migration guard"
        );

        let provider = self.l1.dev_provider();
        let operator_vault = EarnVault::new(self.earn_vault, &provider);
        eyre::ensure!(
            operator_vault
                .migrateEngine(Address::ZERO, U256::ONE, U256::ONE)
                .call()
                .await
                .is_err(),
            "operator unexpectedly migrated to the zero engine"
        );
        eyre::ensure!(
            operator_vault
                .migrateEngine(engine_before, U256::ONE, U256::ONE)
                .call()
                .await
                .is_err(),
            "operator unexpectedly migrated to the active engine"
        );

        assert_eq!(earn_vault.engine().call().await?, engine_before);
        assert_eq!(
            earn_vault.engineShares().call().await?,
            engine_shares_before
        );
        assert_eq!(earn_vault.totalEarnShares().call().await?, supply_before);
        Ok(())
    }

    async fn deposit_entry(&mut self, token: Address, amount: u128) -> eyre::Result<()> {
        let recipient = self.user.address();
        let provider = self.user.l1_provider();
        let receipt = ITIP20::new(token, provider)
            .approve(self.portal, U256::MAX)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "encrypted entry approval failed");

        let (key_index, encrypted) = self
            .l1
            .encrypt_deposit_for_portal(self.portal, self.user.address(), recipient, B256::ZERO)
            .await?;
        let balance_before = self.zone.balance_of(token, recipient).await?;
        let receipt = ZonePortal::new(self.portal, provider)
            .deposit(token, amount, key_index, encrypted, recipient)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "encrypted Zone entry failed");

        self.zone
            .wait_for_balance(
                token,
                recipient,
                balance_before + U256::from(amount),
                E2E_TIMEOUT,
            )
            .await?;
        Ok(())
    }

    async fn callback_data(
        &self,
        flow: EarnFlow,
        _output_token: Address,
        recipient: Address,
        refund_recipient: Address,
        limits: EarnLimits,
    ) -> eyre::Result<Bytes> {
        let (key_index, encrypted) = self
            .l1
            .encrypt_deposit_for_portal(self.portal, self.router, recipient, B256::ZERO)
            .await?;
        let action_id = keccak256(encrypted.ciphertext.as_ref());
        let zone_return = EarnZoneReturn {
            keyIndex: key_index,
            encrypted: map_deposit_payload(encrypted),
            refundRecipient: refund_recipient,
        };
        Ok(EarnCallbackData {
            flow,
            minVaultAssets: limits.min_vault_assets,
            minEarnShares: limits.min_earn_shares,
            minOutputAmount: limits.min_output_amount,
            actionId: action_id,
            zoneReturn: zone_return,
        }
        .abi_encode()
        .into())
    }

    async fn deposit_limits(&self, input_token: Address, amount: u128) -> eyre::Result<EarnLimits> {
        eyre::ensure!(
            input_token == self.alternate_asset,
            "unsupported private Earn input"
        );
        let expected_vault_assets = amount;
        let min_vault_assets = minimum_output(expected_vault_assets);
        let expected_earn_shares = EarnVault::new(self.earn_vault, self.l1.provider())
            .convertEngineSharesToEarnShares(U256::from(min_vault_assets))
            .call()
            .await?;
        Ok(EarnLimits {
            min_vault_assets,
            min_earn_shares: minimum_output(u256_to_u128(
                expected_earn_shares,
                "Earn deposit preview",
            )?),
            min_output_amount: 0,
        })
    }

    async fn redeem_limits(
        &self,
        earn_shares: u128,
        output_token: Address,
    ) -> eyre::Result<EarnLimits> {
        let expected_vault_assets = EarnVault::new(self.earn_vault, self.l1.provider())
            .previewRedeem(U256::from(earn_shares))
            .call()
            .await?;
        let min_vault_assets =
            minimum_output(u256_to_u128(expected_vault_assets, "Earn redeem preview")?);
        eyre::ensure!(
            output_token == self.alternate_asset,
            "unsupported private Earn output"
        );
        let min_output_amount = min_vault_assets;
        Ok(EarnLimits {
            min_vault_assets,
            min_earn_shares: 0,
            min_output_amount,
        })
    }

    async fn assert_private_return(
        &self,
        token: Address,
        recipient: Address,
        public_recipient_before: U256,
        portal_before: U256,
        private_delta: U256,
        description: &str,
    ) -> eyre::Result<()> {
        let public_recipient_after = self.l1.balance_of(token, recipient).await?;
        eyre::ensure!(
            public_recipient_after == public_recipient_before,
            "{description} leaked to the recipient's public L1 balance: before={public_recipient_before}, after={public_recipient_after}"
        );

        let portal_after = self.l1.balance_of(token, self.portal).await?;
        eyre::ensure!(
            portal_after >= portal_before,
            "{description} reduced the portal escrow balance: before={portal_before}, after={portal_after}"
        );
        eyre::ensure!(
            portal_after - portal_before == private_delta,
            "{description} did not conserve the encrypted return: private={private_delta}, L1 escrow={}",
            portal_after - portal_before
        );
        eyre::ensure!(
            self.l1.balance_of(token, self.router).await?.is_zero(),
            "{description} left tokens on the closed-loop router"
        );
        Ok(())
    }

    async fn assert_router_event_privacy(
        &self,
        withdrawal_token: Address,
        withdrawal_amount: u128,
        flow: EarnFlow,
        private_user: Address,
    ) -> eyre::Result<()> {
        let portal = ZonePortal::new(self.portal, self.l1.provider());
        let events = portal
            .WithdrawalProcessed_filter()
            .from_block(0)
            .query()
            .await?;
        let signature = match flow {
            EarnFlow::Deposit => {
                keccak256("EarnDeposit(bytes32,address,address,uint256,uint256,uint256,bytes32)")
            }
            EarnFlow::Redeem => {
                keccak256("EarnRedeem(bytes32,address,address,uint256,uint256,uint256,bytes32)")
            }
            _ => unreachable!("EarnFlow contains only synchronous deposit and redeem"),
        };
        let private_user_topic = private_user.into_word();
        let filter = Filter::new()
            .address(self.router)
            .from_block(0)
            .event_signature(signature);
        let router_logs = self.l1.provider().get_logs(&filter).await?;
        let router_log = router_logs
            .last()
            .ok_or_else(|| eyre::eyre!("Earn router event not found"))?;
        let transaction_hash = router_log
            .transaction_hash
            .ok_or_else(|| eyre::eyre!("Earn router log has no transaction hash"))?;
        let (processed, _) = events
            .iter()
            .find(|(event, log)| {
                log.transaction_hash == Some(transaction_hash)
                    && event.to == self.router
                    && event.token == withdrawal_token
                    && event.amount == withdrawal_amount
                    && event.callbackSuccess
            })
            .ok_or_else(|| {
                eyre::eyre!("matching Earn WithdrawalProcessed event not found for router event")
            })?;
        eyre::ensure!(
            router_log.inner.topics().len() == 4,
            "Earn router event has an unexpected indexed-field layout"
        );
        eyre::ensure!(
            router_log
                .inner
                .topics()
                .iter()
                .all(|topic| *topic != processed.senderTag && *topic != private_user_topic),
            "Earn router event exposed the withdrawal sender tag or private user address"
        );
        Ok(())
    }

    async fn zone_deposit(
        &mut self,
        input_token: Address,
        recipient: Address,
    ) -> eyre::Result<u128> {
        self.deposit_entry(input_token, AMOUNT).await?;
        let before = self.zone.balance_of(self.earn_share, recipient).await?;
        let public_recipient_before = self.l1.balance_of(self.earn_share, recipient).await?;
        let portal_before = self.l1.balance_of(self.earn_share, self.portal).await?;
        let limits = self.deposit_limits(input_token, AMOUNT).await?;
        let data = self
            .callback_data(
                EarnFlow::Deposit,
                self.earn_share,
                recipient,
                self.user.address(),
                limits,
            )
            .await?;
        self.user
            .withdraw_token_with(
                input_token,
                WithdrawalArgs {
                    amount: AMOUNT,
                    to: Some(self.router),
                    memo: B256::ZERO,
                    gas_limit: CALLBACK_GAS_LIMIT,
                    zone_fallback_recipient: Some(self.user.address()),
                    data,
                    reveal_to: Bytes::new(),
                },
            )
            .await?;

        let callback_success = self
            .l1
            .wait_for_withdrawal_processed_status(
                self.portal,
                self.router,
                input_token,
                AMOUNT,
                E2E_TIMEOUT,
            )
            .await?;
        eyre::ensure!(callback_success, "Earn deposit callback failed");
        let after = self
            .zone
            .wait_for_balance(self.earn_share, recipient, before + U256::ONE, E2E_TIMEOUT)
            .await?;
        let minted = after - before;
        self.assert_private_return(
            self.earn_share,
            recipient,
            public_recipient_before,
            portal_before,
            minted,
            "Earn deposit",
        )
        .await?;
        self.assert_router_event_privacy(
            input_token,
            AMOUNT,
            EarnFlow::Deposit,
            self.user.address(),
        )
        .await?;
        u256_to_u128(minted, "EarnShare minted by Zone deposit")
    }

    async fn zone_deposit_expect_callback_bounce(
        &mut self,
        input_token: Address,
        recipient: Address,
        limits: EarnLimits,
    ) -> eyre::Result<()> {
        let data = self
            .callback_data(
                EarnFlow::Deposit,
                self.earn_share,
                recipient,
                self.user.address(),
                limits,
            )
            .await?;
        self.zone_deposit_with_data_expect_callback_bounce(input_token, recipient, data)
            .await
    }

    async fn zone_deposit_with_data_expect_callback_bounce(
        &mut self,
        input_token: Address,
        recipient: Address,
        data: Bytes,
    ) -> eyre::Result<()> {
        self.deposit_entry(input_token, AMOUNT).await?;
        let private_input_before = self
            .zone
            .balance_of(input_token, self.user.address())
            .await?;
        let recipient_earn_before = self.zone.balance_of(self.earn_share, recipient).await?;
        let share_supply_before = ITIP20::new(self.earn_share, self.l1.provider())
            .totalSupply()
            .call()
            .await?;
        let backing_before = VenueVault::new(self.venue_vault, self.l1.provider())
            .balanceOf(self.engine)
            .call()
            .await?;
        let callback_gas_limit = CALLBACK_GAS_LIMIT;
        self.user
            .withdraw_token_with(
                input_token,
                WithdrawalArgs {
                    amount: AMOUNT,
                    to: Some(self.router),
                    memo: B256::ZERO,
                    gas_limit: callback_gas_limit,
                    zone_fallback_recipient: Some(self.user.address()),
                    data,
                    reveal_to: Bytes::new(),
                },
            )
            .await?;

        let private_input_after = self
            .zone
            .wait_for_balance(
                input_token,
                self.user.address(),
                private_input_before,
                BOUNCE_TIMEOUT,
            )
            .await?;
        assert_eq!(
            private_input_after, private_input_before,
            "failed Earn callback did not restore the private input"
        );
        assert_eq!(
            self.zone.balance_of(self.earn_share, recipient).await?,
            recipient_earn_before,
            "failed Earn callback credited private EarnShare"
        );
        assert_eq!(
            ITIP20::new(self.earn_share, self.l1.provider())
                .totalSupply()
                .call()
                .await?,
            share_supply_before,
            "failed Earn callback changed share supply"
        );
        assert_eq!(
            VenueVault::new(self.venue_vault, self.l1.provider())
                .balanceOf(self.engine)
                .call()
                .await?,
            backing_before,
            "failed Earn callback changed engine backing"
        );
        self.l1
            .assert_withdrawal_processed_with_status(
                self.portal,
                self.router,
                input_token,
                AMOUNT,
                false,
            )
            .await?;
        assert_eq!(
            self.l1.balance_of(input_token, self.router).await?,
            U256::ZERO,
            "failed Earn callback left input on the router"
        );
        assert_eq!(
            self.l1.balance_of(self.earn_share, self.router).await?,
            U256::ZERO,
            "failed Earn callback left shares on the router"
        );
        Ok(())
    }

    async fn zone_deposit_expect_recipient_bounce(
        &mut self,
        input_token: Address,
        recipient: Address,
    ) -> eyre::Result<()> {
        self.deposit_entry(input_token, AMOUNT).await?;
        let recipient_earn_before = self.zone.balance_of(self.earn_share, recipient).await?;
        let public_refund_before = self
            .l1
            .balance_of(self.earn_share, self.user.address())
            .await?;
        let share_supply_before = ITIP20::new(self.earn_share, self.l1.provider())
            .totalSupply()
            .call()
            .await?;
        let backing_before = VenueVault::new(self.venue_vault, self.l1.provider())
            .balanceOf(self.engine)
            .call()
            .await?;
        let data = self
            .callback_data(
                EarnFlow::Deposit,
                self.earn_share,
                recipient,
                self.user.address(),
                EarnLimits::default(),
            )
            .await?;
        self.user
            .withdraw_token_with(
                input_token,
                WithdrawalArgs {
                    amount: AMOUNT,
                    to: Some(self.router),
                    memo: B256::ZERO,
                    gas_limit: CALLBACK_GAS_LIMIT,
                    zone_fallback_recipient: Some(self.user.address()),
                    data,
                    reveal_to: Bytes::new(),
                },
            )
            .await?;

        let public_refund_after = self
            .l1
            .wait_for_balance(
                self.earn_share,
                self.user.address(),
                public_refund_before + U256::ONE,
                BOUNCE_TIMEOUT,
            )
            .await?;
        let share_supply_after = ITIP20::new(self.earn_share, self.l1.provider())
            .totalSupply()
            .call()
            .await?;
        let backing_after = VenueVault::new(self.venue_vault, self.l1.provider())
            .balanceOf(self.engine)
            .call()
            .await?;
        let minted = share_supply_after - share_supply_before;
        let refunded = public_refund_after - public_refund_before;
        assert_eq!(
            self.zone.balance_of(self.earn_share, recipient).await?,
            recipient_earn_before,
            "ineligible recipient received private EarnShare"
        );
        assert!(
            refunded > U256::ZERO && refunded <= minted,
            "invalid ineligible-recipient refund: refunded={refunded}, minted={minted}"
        );
        assert!(minted > U256::ZERO, "recipient bounce minted no EarnShare");
        assert!(
            backing_after > backing_before,
            "successful router deposit added no engine backing"
        );
        self.l1
            .assert_withdrawal_processed_with_status(
                self.portal,
                self.router,
                input_token,
                AMOUNT,
                true,
            )
            .await?;
        self.assert_router_event_privacy(
            input_token,
            AMOUNT,
            EarnFlow::Deposit,
            self.user.address(),
        )
        .await?;
        assert_eq!(
            self.l1.balance_of(self.earn_share, self.router).await?,
            U256::ZERO,
            "recipient bounce left shares on the router"
        );
        Ok(())
    }

    async fn zone_redeem(
        &self,
        shares: u128,
        output_token: Address,
        recipient: Address,
    ) -> eyre::Result<u128> {
        let mut user = ZoneAccount::from_l1_and_zone(&self.l1, &self.zone, self.portal);
        self.zone_redeem_as(&mut user, shares, output_token, recipient)
            .await
    }

    async fn zone_redeem_as(
        &self,
        account: &mut ZoneAccount,
        shares: u128,
        output_token: Address,
        recipient: Address,
    ) -> eyre::Result<u128> {
        let before = self.zone.balance_of(output_token, recipient).await?;
        let public_recipient_before = self.l1.balance_of(output_token, recipient).await?;
        let portal_before = self.l1.balance_of(output_token, self.portal).await?;
        let limits = self.redeem_limits(shares, output_token).await?;
        let data = self
            .callback_data(
                EarnFlow::Redeem,
                output_token,
                recipient,
                account.address(),
                limits,
            )
            .await?;
        account
            .withdraw_token_with(
                self.earn_share,
                WithdrawalArgs {
                    amount: shares,
                    to: Some(self.router),
                    memo: B256::ZERO,
                    gas_limit: CALLBACK_GAS_LIMIT,
                    zone_fallback_recipient: Some(account.address()),
                    data,
                    reveal_to: Bytes::new(),
                },
            )
            .await?;

        let after = self
            .zone
            .wait_for_balance(output_token, recipient, before + U256::ONE, E2E_TIMEOUT)
            .await?;
        let returned = after - before;
        self.assert_private_return(
            output_token,
            recipient,
            public_recipient_before,
            portal_before,
            returned,
            "Earn redemption",
        )
        .await?;
        self.l1
            .assert_withdrawal_processed_with_status(
                self.portal,
                self.router,
                self.earn_share,
                shares,
                true,
            )
            .await?;
        self.assert_router_event_privacy(
            self.earn_share,
            shares,
            EarnFlow::Redeem,
            account.address(),
        )
        .await?;
        u256_to_u128(returned, "assets returned by Zone redemption")
    }

    async fn simulate_zone_redeem_as(
        &self,
        account: &mut ZoneAccount,
        shares: u128,
        output_token: Address,
        recipient: Address,
    ) -> eyre::Result<()> {
        let limits = self.redeem_limits(shares, output_token).await?;
        let data = self
            .callback_data(
                EarnFlow::Redeem,
                output_token,
                recipient,
                account.address(),
                limits,
            )
            .await?;
        account
            .simulate_withdraw_token_with(
                self.earn_share,
                WithdrawalArgs {
                    amount: shares,
                    to: Some(self.router),
                    memo: B256::ZERO,
                    gas_limit: CALLBACK_GAS_LIMIT,
                    zone_fallback_recipient: Some(account.address()),
                    data,
                    reveal_to: Bytes::new(),
                },
            )
            .await
    }

    async fn migrate_existing_vault_shares(&mut self) -> eyre::Result<u128> {
        let user = self.user.address();
        let provider = self.user.l1_provider();
        let asset = ITIP20::new(self.vault_asset, provider);
        let receipt = asset
            .approve(self.venue_vault, U256::from(AMOUNT))
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "vault asset approval failed");

        let vault = VenueVault::new(self.venue_vault, provider);
        let venue_before = vault.balanceOf(user).call().await?;
        let receipt = vault
            .deposit(U256::from(AMOUNT), user)
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "creating existing venue shares failed");
        let venue_after = vault.balanceOf(user).call().await?;
        let venue_shares = venue_after - venue_before;
        eyre::ensure!(
            venue_shares > U256::ZERO,
            "migration setup minted no venue shares"
        );

        let earn_vault = EarnVault::new(self.earn_vault, self.l1.provider());
        let earn_shares = earn_vault
            .convertEngineSharesToEarnShares(venue_shares)
            .call()
            .await?;
        let earn_shares_u128 = u256_to_u128(earn_shares, "migration EarnShare quote")?;
        eyre::ensure!(
            earn_shares_u128 > 0,
            "migration quote returned no EarnShare"
        );

        let (key_index, encrypted) = self
            .l1
            .encrypt_deposit_for_portal(self.portal, user, user, B256::ZERO)
            .await?;
        let private_before = self.zone.balance_of(self.earn_share, user).await?;
        let public_before = self.l1.balance_of(self.earn_share, user).await?;
        let supply_before = ITIP20::new(self.earn_share, self.l1.provider())
            .totalSupply()
            .call()
            .await?;
        let engine_venue_before = VenueVault::new(self.venue_vault, self.l1.provider())
            .balanceOf(self.engine)
            .call()
            .await?;

        let calls = vec![
            Call {
                to: TxKind::Call(self.venue_vault),
                value: U256::ZERO,
                input: VenueVault::approveCall {
                    spender: self.engine,
                    amount: venue_shares,
                }
                .abi_encode()
                .into(),
            },
            Call {
                to: TxKind::Call(self.earn_vault),
                value: U256::ZERO,
                input: EarnVault::depositVenueSharesCall {
                    venueShares: venue_shares,
                    receiver: user,
                    minEarnShares: earn_shares,
                }
                .abi_encode()
                .into(),
            },
            Call {
                to: TxKind::Call(self.earn_share),
                value: U256::ZERO,
                input: ITIP20::approveCall {
                    spender: self.portal,
                    amount: earn_shares,
                }
                .abi_encode()
                .into(),
            },
            Call {
                to: TxKind::Call(self.portal),
                value: U256::ZERO,
                input: ZonePortal::depositCall {
                    token: self.earn_share,
                    amount: earn_shares_u128,
                    keyIndex: key_index,
                    encrypted,
                    tempoRefundRecipient: user,
                }
                .abi_encode()
                .into(),
            },
        ];
        let tempo_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(self.l1.user_signer())
            .connect_http(self.l1.http_url().clone());
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(user),
                gas: Some(MIGRATION_TX_GAS_LIMIT),
                ..Default::default()
            },
            calls,
            fee_token: Some(PATH_USD_ADDRESS),
            ..Default::default()
        };
        let receipt = tempo_provider
            .send_transaction(request)
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "atomic venue-share migration failed");
        ensure_gas_headroom(
            receipt.gas_used,
            MIGRATION_TX_GAS_LIMIT,
            "atomic venue-share migration",
        )?;

        let private_after = self
            .zone
            .wait_for_balance(
                self.earn_share,
                user,
                private_before + earn_shares,
                E2E_TIMEOUT,
            )
            .await?;
        let user_venue_after = VenueVault::new(self.venue_vault, self.l1.provider())
            .balanceOf(user)
            .call()
            .await?;
        let engine_venue_after = VenueVault::new(self.venue_vault, self.l1.provider())
            .balanceOf(self.engine)
            .call()
            .await?;
        let public_after = self.l1.balance_of(self.earn_share, user).await?;
        let supply_after = ITIP20::new(self.earn_share, self.l1.provider())
            .totalSupply()
            .call()
            .await?;

        assert_eq!(venue_after - user_venue_after, venue_shares);
        assert_eq!(engine_venue_after - engine_venue_before, venue_shares);
        assert_eq!(
            public_after, public_before,
            "migrated EarnShare remained public"
        );
        assert_eq!(supply_after - supply_before, earn_shares);
        assert_eq!(private_after - private_before, earn_shares);

        Ok(earn_shares_u128)
    }
}

async fn deploy_contract(
    l1: &L1TestNode,
    contract: &str,
    constructor_args: Vec<u8>,
) -> eyre::Result<Address> {
    let mut deployment = forge_bytecode(contract)?.to_vec();
    deployment.extend_from_slice(&constructor_args);
    // Contract-to-contract constructor calls are valid on Tempo but can be under-estimated by the
    // generic Ethereum gas estimator. Earn's local deployer likewise applies explicit headroom.
    let request = TransactionRequest::default()
        .with_deploy_code(deployment)
        .gas_limit(CONTRACT_DEPLOYMENT_TX_GAS_LIMIT);
    let receipt = l1
        .dev_provider()
        .send_transaction(request)
        .await
        .wrap_err_with(|| format!("submitting {contract} deployment"))?
        .get_receipt()
        .await
        .wrap_err_with(|| format!("waiting for {contract} deployment receipt"))?;
    eyre::ensure!(
        receipt.status(),
        "{contract} deployment failed after using {} gas",
        receipt.gas_used
    );
    ensure_gas_headroom(
        receipt.gas_used,
        CONTRACT_DEPLOYMENT_TX_GAS_LIMIT,
        &format!("{contract} deployment"),
    )?;
    receipt
        .contract_address
        .ok_or_else(|| eyre::eyre!("{contract} deployment returned no contract address"))
}

fn map_deposit_payload(payload: DepositPayload) -> EarnDepositPayload {
    EarnDepositPayload {
        ephemeralPubkeyX: payload.ephemeralPubkeyX,
        ephemeralPubkeyYParity: payload.ephemeralPubkeyYParity,
        ciphertext: payload.ciphertext,
        nonce: payload.nonce,
        tag: payload.tag,
    }
}

fn legacy_delivery(portal: Address, refund_recipient: Address) -> LegacyEarnZoneDelivery {
    LegacyEarnZoneDelivery {
        portal,
        keyIndex: U256::ZERO,
        encrypted: EarnDepositPayload {
            ephemeralPubkeyX: B256::ZERO,
            ephemeralPubkeyYParity: 0,
            ciphertext: Bytes::new(),
            nonce: Default::default(),
            tag: Default::default(),
        },
        refundRecipient: refund_recipient,
    }
}

fn u256_to_u128(value: U256, description: &str) -> eyre::Result<u128> {
    value
        .try_into()
        .map_err(|_| eyre::eyre!("{description} does not fit into uint128: {value}"))
}

fn minimum_output(expected: u128) -> u128 {
    expected - expected * 50 / 10_000
}

fn ensure_gas_headroom(gas_used: u64, gas_limit: u64, operation: &str) -> eyre::Result<()> {
    let minimum_headroom = gas_limit * MIN_GAS_HEADROOM_PERCENT / 100;
    eyre::ensure!(
        gas_used <= gas_limit - minimum_headroom,
        "{operation} used {gas_used} of {gas_limit} gas, leaving less than {MIN_GAS_HEADROOM_PERCENT}% headroom"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn matrix_deposit_private_private_succeeds() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let shares = fixture.zone_deposit(fixture.alternate_asset, user).await?;
    assert_eq!(shares, AMOUNT, "direct Zone deposit was not 1:1");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_deposit_third_party_recipient() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let recipient = fixture.l1.signer_at(3).address();
    let shares = fixture
        .zone_deposit(fixture.alternate_asset, recipient)
        .await?;
    assert_eq!(shares, AMOUNT, "third-party Zone deposit was not 1:1");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn matrix_redeem_private_private_succeeds() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let shares = fixture.zone_deposit(fixture.alternate_asset, user).await?;
    let output = fixture
        .zone_redeem(shares, fixture.alternate_asset, user)
        .await?;
    assert_eq!(output, AMOUNT, "direct Zone lifecycle was not 1:1");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_redeem_third_party_recipient() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let recipient = fixture.l1.signer_at(3).address();
    let shares = fixture.zone_deposit(fixture.alternate_asset, user).await?;
    let output = fixture
        .zone_redeem(shares, fixture.alternate_asset, recipient)
        .await?;
    assert_eq!(output, AMOUNT, "third-party Zone lifecycle was not 1:1");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_lifecycle_swapped() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let shares = fixture.zone_deposit(fixture.alternate_asset, user).await?;
    assert_eq!(shares, AMOUNT, "swapped Zone deposit was not 1:1");
    let output = fixture
        .zone_redeem(shares, fixture.alternate_asset, user)
        .await?;
    assert_eq!(output, AMOUNT, "swapped Zone lifecycle was not 1:1");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_swap_slippage_bounces() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();

    fixture
        .zone_deposit_expect_callback_bounce(
            fixture.alternate_asset,
            user,
            EarnLimits {
                min_vault_assets: u128::MAX,
                ..EarnLimits::default()
            },
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn controls_pause_blocks_entry_but_preserves_exits() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let shares = fixture.zone_deposit(fixture.alternate_asset, user).await?;
    fixture.set_deposits_paused(true).await?;
    fixture
        .zone_deposit_expect_callback_bounce(fixture.alternate_asset, user, EarnLimits::default())
        .await?;
    let output = fixture
        .zone_redeem(shares, fixture.alternate_asset, user)
        .await?;
    assert_eq!(output, AMOUNT, "deposit pause blocked a private exit");
    fixture.set_deposits_paused(false).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_ineligible_private_deposit_bounces() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start_protected().await?;
    let outsider = fixture.l1.signer_at(3).address();
    fixture.allow_zone_account(outsider).await?;
    fixture.set_access_eligibility(outsider, false).await?;
    fixture
        .zone_deposit_expect_recipient_bounce(fixture.alternate_asset, outsider)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_ineligible_private_transfer_blocked() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start_protected().await?;
    let user = fixture.user.address();
    let outsider = fixture.l1.signer_at(3).address();
    fixture.allow_zone_account(outsider).await?;
    fixture.set_access_eligibility(outsider, false).await?;
    let user_shares = fixture.zone_deposit(fixture.alternate_asset, user).await?;
    let user_before = fixture.zone.balance_of(fixture.earn_share, user).await?;
    let outsider_before = fixture
        .zone
        .balance_of(fixture.earn_share, outsider)
        .await?;
    let user_provider = ProviderBuilder::new()
        .wallet(fixture.l1.user_signer())
        .connect_http(fixture.zone.http_url().clone());
    let transfer = ITIP20::new(fixture.earn_share, &user_provider)
        .transfer(outsider, U256::ONE)
        .from(user)
        .call()
        .await;
    eyre::ensure!(
        transfer.is_err(),
        "private EarnShare transfer to an ineligible recipient unexpectedly succeeded"
    );
    assert_eq!(
        fixture.zone.balance_of(fixture.earn_share, user).await?,
        user_before,
        "rejected private transfer changed the sender balance"
    );
    assert_eq!(
        fixture
            .zone
            .balance_of(fixture.earn_share, outsider)
            .await?,
        outsider_before,
        "rejected private transfer changed the recipient balance"
    );
    let output = fixture
        .zone_redeem(user_shares, fixture.alternate_asset, user)
        .await?;
    assert_eq!(output, AMOUNT, "eligible holder cleanup was not 1:1");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_removed_private_holder_is_blocked_until_reauthorized() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start_protected().await?;
    let outsider_signer = fixture.l1.signer_at(3);
    let outsider = outsider_signer.address();
    fixture.l1.fund_user(outsider, PUBLIC_USER_BALANCE).await?;
    fixture.allow_zone_account(outsider).await?;
    let mut outsider_account =
        ZoneAccount::with_signer(outsider_signer, &fixture.l1, &fixture.zone, fixture.portal);
    outsider_account
        .deposit(PRIVATE_FEE_BALANCE, E2E_TIMEOUT, &fixture.zone)
        .await?;
    fixture.set_access_eligibility(outsider, true).await?;
    let outsider_shares = fixture
        .zone_deposit(fixture.alternate_asset, outsider)
        .await?;
    assert!(
        outsider_shares > 0,
        "eligible private outsider received no EarnShare"
    );
    fixture.set_access_eligibility(outsider, false).await?;
    let redeem = fixture
        .simulate_zone_redeem_as(
            &mut outsider_account,
            outsider_shares,
            fixture.alternate_asset,
            outsider,
        )
        .await;
    eyre::ensure!(
        redeem.is_err(),
        "removed private holder unexpectedly exited while ineligible"
    );
    assert_eq!(
        fixture
            .zone
            .balance_of(fixture.earn_share, outsider)
            .await?,
        U256::from(outsider_shares),
        "rejected exit changed the removed holder's EarnShare balance"
    );

    fixture.set_access_eligibility(outsider, true).await?;
    let outsider_output = fixture
        .zone_redeem_as(
            &mut outsider_account,
            outsider_shares,
            fixture.alternate_asset,
            outsider,
        )
        .await?;
    assert_eq!(
        outsider_output, AMOUNT,
        "re-authorized private holder did not exit 1:1"
    );
    assert_eq!(
        fixture
            .zone
            .balance_of(fixture.earn_share, outsider)
            .await?,
        U256::ZERO,
        "removed private holder retained EarnShare after exit"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_rewards_private_holder() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let shares = fixture.zone_deposit(fixture.alternate_asset, user).await?;
    assert!(shares > 1, "private reward setup minted too few shares");

    let private_after_entry = fixture.zone.balance_of(fixture.earn_share, user).await?;
    let value_before = EarnVault::new(fixture.earn_vault, fixture.l1.provider())
        .previewRedeem(U256::from(shares))
        .call()
        .await?;
    let user_assets_before = fixture.l1.balance_of(fixture.vault_asset, user).await?;
    let vault_assets_before = VenueVault::new(fixture.venue_vault, fixture.l1.provider())
        .totalAssets()
        .call()
        .await?;

    let provider = fixture.user.l1_provider();
    let receipt = ITIP20::new(fixture.vault_asset, provider)
        .approve(fixture.contribution_controller, U256::from(REWARD_AMOUNT))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "reward asset approval failed");
    let rewards = EarnContributionController::new(fixture.contribution_controller, provider);
    let max_earn_share_supply = EarnVault::new(fixture.earn_vault, fixture.l1.provider())
        .totalEarnShares()
        .call()
        .await?;
    let simulated_funding = rewards
        .fund(user, U256::from(REWARD_AMOUNT), max_earn_share_supply)
        .gas(REWARD_FUNDING_TX_GAS_LIMIT)
        .call()
        .await?;
    if simulated_funding != U256::from(REWARD_AMOUNT) {
        // `fund` intentionally catches provider failures. Re-run its isolated leg as the rewards
        // contract so a failing E2E reports the underlying revert instead of only "funded = 0".
        EarnContributionController::new(fixture.contribution_controller, fixture.l1.provider())
            .executeFunding(user, U256::from(REWARD_AMOUNT), max_earn_share_supply)
            .from(fixture.contribution_controller)
            .call()
            .await
            .wrap_err("diagnosing zero Earn contribution funding")?;
        eyre::bail!("Earn contribution simulated zero funding without an underlying revert");
    }
    let receipt = rewards
        .fund(user, U256::from(REWARD_AMOUNT), max_earn_share_supply)
        .gas(REWARD_FUNDING_TX_GAS_LIMIT)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "funding private-holder rewards failed");
    ensure_gas_headroom(
        receipt.gas_used,
        REWARD_FUNDING_TX_GAS_LIMIT,
        "private-holder reward funding",
    )?;

    let earn_vault = EarnVault::new(fixture.earn_vault, fixture.l1.provider());
    let value_after = earn_vault.previewRedeem(U256::from(shares)).call().await?;
    let user_assets_after = fixture.l1.balance_of(fixture.vault_asset, user).await?;
    let vault_assets_after = VenueVault::new(fixture.venue_vault, fixture.l1.provider())
        .totalAssets()
        .call()
        .await?;
    let anchor_engine_shares = earn_vault.anchorEngineShares().call().await?;
    let anchor_supply = earn_vault.anchorEarnShares().call().await?;
    assert_eq!(
        user_assets_before - user_assets_after,
        U256::from(REWARD_AMOUNT),
        "EarnContributionController did not pull the requested provider assets"
    );
    assert_eq!(
        vault_assets_after - vault_assets_before,
        U256::from(REWARD_AMOUNT),
        "EarnContributionController did not invest the requested provider assets"
    );
    assert!(
        value_after > value_before,
        "private EarnShare received no reward value: before={value_before}, after={value_after}, anchorEngineShares={anchor_engine_shares}, anchorEarnShares={anchor_supply}"
    );

    let first_shares = shares / 2;
    let second_shares = shares - first_shares;
    let first_output = fixture
        .zone_redeem(first_shares, fixture.alternate_asset, user)
        .await?;
    assert!(
        first_output > 0,
        "partial private redemption returned no assets"
    );
    let private_after_partial = fixture.zone.balance_of(fixture.earn_share, user).await?;
    assert_eq!(
        private_after_partial,
        private_after_entry - U256::from(first_shares),
        "partial redemption changed the wrong private share amount"
    );

    let second_output = fixture
        .zone_redeem(second_shares, fixture.alternate_asset, user)
        .await?;
    assert_eq!(
        first_output + second_output,
        AMOUNT + REWARD_AMOUNT,
        "private reward lifecycle did not return all principal and rewards"
    );
    assert_eq!(
        fixture.zone.balance_of(fixture.earn_share, user).await?,
        U256::ZERO,
        "private reward lifecycle left EarnShare behind"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn matrix_deposit_public_public_succeeds() -> eyre::Result<()> {
    let fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let provider = fixture.user.l1_provider();
    let shares_before = fixture.l1.balance_of(fixture.earn_share, user).await?;

    let receipt = ITIP20::new(fixture.vault_asset, provider)
        .approve(fixture.earn_vault, U256::from(AMOUNT))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "public EarnVault approval failed");
    let receipt = EarnVault::new(fixture.earn_vault, provider)
        .deposit(U256::from(AMOUNT), user, U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "public EarnVault deposit failed");
    assert_eq!(
        fixture.l1.balance_of(fixture.earn_share, user).await? - shares_before,
        U256::from(AMOUNT),
        "public-to-public deposit was not 1:1"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn matrix_redeem_public_public_succeeds() -> eyre::Result<()> {
    let fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let provider = fixture.user.l1_provider();
    let assets_before = fixture.l1.balance_of(fixture.vault_asset, user).await?;

    ITIP20::new(fixture.vault_asset, provider)
        .approve(fixture.earn_vault, U256::from(AMOUNT))
        .send()
        .await?
        .get_receipt()
        .await?;
    EarnVault::new(fixture.earn_vault, provider)
        .deposit(U256::from(AMOUNT), user, U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    let earn_shares = fixture.l1.balance_of(fixture.earn_share, user).await?;

    let receipt = ITIP20::new(fixture.earn_share, provider)
        .approve(fixture.earn_vault, earn_shares)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "public EarnShare approval failed");
    let receipt = EarnVault::new(fixture.earn_vault, provider)
        .redeem(earn_shares, user, U256::ONE)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "public EarnVault redeem failed");
    assert_eq!(
        fixture.l1.balance_of(fixture.vault_asset, user).await?,
        assets_before,
        "direct public EarnVault lifecycle did not return the deposited assets"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn matrix_deposit_public_private_rejects_retired_router_surface() -> eyre::Result<()> {
    let fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let result = LegacyUniversalEarnRouter::new(fixture.router, fixture.user.l1_provider())
        .depositToZone(
            fixture.earn_vault,
            U256::from(AMOUNT),
            U256::ONE,
            legacy_delivery(fixture.portal, user),
        )
        .call()
        .await;
    eyre::ensure!(
        result.is_err(),
        "retired public-to-private deposit surface remained callable"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn matrix_redeem_public_private_rejects_retired_router_surface() -> eyre::Result<()> {
    let fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let result = LegacyUniversalEarnRouter::new(fixture.router, fixture.user.l1_provider())
        .redeemToZone(
            fixture.earn_vault,
            U256::from(AMOUNT),
            U256::ONE,
            legacy_delivery(fixture.portal, user),
        )
        .call()
        .await;
    eyre::ensure!(
        result.is_err(),
        "retired public-to-private redeem surface remained callable"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn matrix_deposit_private_public_rejects_legacy_destination() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let data: Bytes = LegacyEarnCallbackData {
        flow: EarnFlow::Deposit,
        earnVault: fixture.earn_vault,
        destination: LegacyEarnDestination::Public,
        outputToken: fixture.earn_share,
        minVaultAssets: 1,
        minEarnShares: 1,
        minOutputAmount: 0,
        actionId: keccak256("legacy-public-destination"),
        destinationData: user.abi_encode().into(),
    }
    .abi_encode()
    .into();
    fixture
        .zone_deposit_with_data_expect_callback_bounce(fixture.alternate_asset, user, data)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn matrix_redeem_private_public_rejects_legacy_destination() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let earn_shares = fixture.zone_deposit(fixture.alternate_asset, user).await?;
    let private_before = fixture.zone.balance_of(fixture.earn_share, user).await?;
    let supply_before = ITIP20::new(fixture.earn_share, fixture.l1.provider())
        .totalSupply()
        .call()
        .await?;
    let data: Bytes = LegacyEarnCallbackData {
        flow: EarnFlow::Redeem,
        earnVault: fixture.earn_vault,
        destination: LegacyEarnDestination::Public,
        outputToken: fixture.alternate_asset,
        minVaultAssets: 1,
        minEarnShares: 0,
        minOutputAmount: 1,
        actionId: keccak256("legacy-public-redeem-destination"),
        destinationData: user.abi_encode().into(),
    }
    .abi_encode()
    .into();
    fixture
        .user
        .withdraw_token_with(
            fixture.earn_share,
            WithdrawalArgs {
                amount: earn_shares,
                to: Some(fixture.router),
                memo: B256::ZERO,
                gas_limit: CALLBACK_GAS_LIMIT,
                zone_fallback_recipient: Some(user),
                data,
                reveal_to: Bytes::new(),
            },
        )
        .await?;
    fixture
        .zone
        .wait_for_balance(fixture.earn_share, user, private_before, BOUNCE_TIMEOUT)
        .await?;
    fixture
        .l1
        .assert_withdrawal_processed_with_status(
            fixture.portal,
            fixture.router,
            fixture.earn_share,
            earn_shares,
            false,
        )
        .await?;
    assert_eq!(
        ITIP20::new(fixture.earn_share, fixture.l1.provider())
            .totalSupply()
            .call()
            .await?,
        supply_before,
        "rejected private-to-public redeem changed EarnShare supply"
    );
    assert_eq!(
        fixture
            .l1
            .balance_of(fixture.earn_share, fixture.router)
            .await?,
        U256::ZERO,
        "rejected private-to-public redeem left shares on the router"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_cross_zone_destination_callback_bounces() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    let delivery = legacy_delivery(Address::with_last_byte(0x42), user);
    let data: Bytes = LegacyEarnCallbackData {
        flow: EarnFlow::Deposit,
        earnVault: fixture.earn_vault,
        destination: LegacyEarnDestination::Zone,
        outputToken: fixture.earn_share,
        minVaultAssets: 1,
        minEarnShares: 1,
        minOutputAmount: 0,
        actionId: keccak256("legacy-cross-zone-destination"),
        destinationData: delivery.abi_encode().into(),
    }
    .abi_encode()
    .into();
    fixture
        .zone_deposit_with_data_expect_callback_bounce(fixture.alternate_asset, user, data)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_existing_vault_shares_to_zone() -> eyre::Result<()> {
    let mut fixture = EarnZoneFixture::start().await?;
    let user = fixture.user.address();
    fixture.assert_engine_migration_guardrails().await?;
    let earn_shares = fixture.migrate_existing_vault_shares().await?;
    assert_eq!(earn_shares, AMOUNT, "venue-share migration was not 1:1");
    let output = fixture
        .zone_redeem(earn_shares, fixture.alternate_asset, user)
        .await?;
    assert_eq!(output, AMOUNT, "migrated EarnShare did not redeem 1:1");
    Ok(())
}
