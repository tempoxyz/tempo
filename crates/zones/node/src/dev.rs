//! Local dev mode.
//!
//! Provisions a self-contained zone against a Tempo dev L1: funds the dev account,
//! uses TIP-1091's protocol-managed `ZoneFactory`, calls `createZone`, registers the
//! sequencer encryption key, and builds an L1-anchored genesis. The `tempo-zone dev`
//! command wraps [`provision_zone`] and then runs the zone node.

use alloy_consensus::Sealable;
use alloy_genesis::Genesis;
use alloy_network::{EthereumWallet, ReceiptResponse as _};
use alloy_primitives::{Address, B256};
use alloy_provider::{PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy_signer_local::PrivateKeySigner;
use tempo_alloy::TempoNetwork;
use tempo_contracts::precompiles::{ITIP20, PATH_USD_ADDRESS};
use tempo_zone_contracts::{ZONE_FACTORY_ADDRESS, ZoneFactory};
use zone_primitives::constants::zone_chain_id;
use zone_sequencer::register_encryption_key;

/// Provisioning options for [`provision_zone`].
#[derive(Debug)]
pub struct ProvisionConfig {
    /// Tempo L1 RPC URL (http(s) or ws(s)).
    pub l1_rpc_url: String,
    /// Dev key: factory owner, L1 fee payer, portal admin, and zone sequencer.
    pub dev_key: PrivateKeySigner,
    /// Optional factory override, which must equal TIP-1091's protocol address.
    pub factory: Option<Address>,
    /// Initial TIP-20 enabled on the portal.
    pub initial_token: Address,
    /// Whether account access starts open.
    pub is_access_open: bool,
    /// Whether callback gateway registration enforcement starts enabled.
    pub is_gateway_enforced: bool,
    /// Initial callback-only ZoneGateway implementations.
    pub zone_gateways: Vec<Address>,
    /// Initial portal membership (required for closed mode, retained but unenforced in open mode).
    pub allowed_accounts: Vec<Address>,
    /// Operator zone RPC URL registered on the portal.
    pub rpc_url: String,
}

/// A zone provisioned by [`provision_zone`].
#[derive(Debug)]
pub struct ProvisionedZone {
    /// Zone ID assigned by the factory.
    pub zone_id: u32,
    /// Zone chain ID derived from the parent and zone IDs.
    pub chain_id: u64,
    /// `ZoneFactory` address on L1.
    pub factory: Address,
    /// `ZonePortal` address on L1.
    pub portal: Address,
    /// L1 anchor block number immediately before `createZone`.
    pub anchor_block_number: u64,
    /// Zone genesis anchored to the L1.
    pub genesis: Genesis,
}

/// Provisions a fresh zone on a Tempo dev L1.
///
/// Funds the dev account via `tempo_fundAddress` when needed, verifies TIP-1091's
/// `ZoneFactory`, calls `createZone` with the dev account as both admin and sequencer,
/// registers the sequencer encryption key on the portal, and
/// builds a genesis anchored immediately before `createZone` so the zone replays the
/// portal's initial `TokenEnabled` event.
pub async fn provision_zone(config: ProvisionConfig) -> eyre::Result<ProvisionedZone> {
    let ProvisionConfig {
        l1_rpc_url,
        dev_key,
        factory,
        initial_token,
        is_access_open,
        is_gateway_enforced,
        zone_gateways,
        allowed_accounts,
        rpc_url,
    } = config;
    let dev_address = dev_key.address();
    let wallet = EthereumWallet::from(dev_key.clone());

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(wallet.clone())
        .connect(&l1_rpc_url)
        .await?;

    ensure_canonical_tempo_header_hash(&provider).await?;
    fund_dev_account(&provider, dev_address).await?;

    if let Some(address) = factory {
        eyre::ensure!(
            address == ZONE_FACTORY_ADDRESS,
            "ZoneFactory must use TIP-1091 address {ZONE_FACTORY_ADDRESS}, got {address}"
        );
    }
    let factory_address = native_zone_factory(&l1_rpc_url, wallet).await?;

    let factory = ZoneFactory::new(factory_address, &provider);
    let factory_owner = factory.owner().call().await?;
    eyre::ensure!(
        factory_owner == dev_address,
        "ZoneFactory owner is {factory_owner}, but the configured dev key resolves to \
         {dev_address}; use the standard Tempo dev key or transfer factory ownership before \
         provisioning"
    );
    // Anchor before createZone so the L1 subscriber replays the creation block,
    // including the initial TokenEnabled event emitted by the portal constructor.
    let anchor_block_number = provider.get_block_number().await?;
    let anchor_header = provider
        .get_header_by_number(anchor_block_number.into())
        .await?
        .ok_or_else(|| eyre::eyre!("anchor header {anchor_block_number} not found"))?
        .inner
        .inner;

    let receipt = factory
        .createZone(ZoneFactory::CreateZoneParams {
            initialToken: initial_token,
            accessMode: !is_access_open,
            gatewayMode: is_gateway_enforced,
            allowedAccounts: allowed_accounts,
            zoneGateways: zone_gateways,
            admin: dev_address,
            sequencers: vec![dev_address],
            threshold: 1,
            rpcUrl: rpc_url,
        })
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "createZone reverted");

    let zone_created = receipt
        .decoded_log::<ZoneFactory::ZoneCreated>()
        .ok_or_else(|| eyre::eyre!("ZoneCreated event not found"))?;
    let zone_id = zone_created.zoneId;
    let portal = zone_created.portal;
    let parent_chain_id = provider.get_chain_id().await?;
    let chain_id = zone_chain_id(parent_chain_id, zone_id)?;

    register_encryption_key(&provider, portal, &dev_key).await?;

    let (mut genesis, anchor_block_number) =
        crate::genesis::l1_anchored_genesis(&anchor_header, initial_token)?;
    genesis.config.chain_id = chain_id;

    Ok(ProvisionedZone {
        zone_id,
        chain_id,
        factory: factory_address,
        portal,
        anchor_block_number,
        genesis,
    })
}

/// Ensures the L1 reports the canonical hash of its Tempo header.
///
/// A client that mines Ethereum headers and only adds Tempo fields at the RPC layer
/// produces a different hash from the header that Zones submits to `finalizeTempo`.
async fn ensure_canonical_tempo_header_hash<P: Provider<TempoNetwork>>(
    provider: &P,
) -> eyre::Result<()> {
    let block_number = provider.get_block_number().await?;
    let response = provider
        .get_header_by_number(block_number.into())
        .await?
        .ok_or_else(|| eyre::eyre!("L1 header not found for block {block_number}"))?;
    let rpc_hash = response.inner.hash;
    let canonical_hash = response.inner.inner.hash_slow();

    eyre::ensure!(
        rpc_hash == canonical_hash,
        "L1 block {block_number} reports hash {rpc_hash}, but its canonical Tempo header hash is \
         {canonical_hash}; use an L1 that mines canonically hashed Tempo headers"
    );
    Ok(())
}

async fn fund_dev_account<P: Provider<TempoNetwork>>(
    provider: &P,
    dev_address: Address,
) -> eyre::Result<()> {
    let funding = provider
        .raw_request::<_, Vec<B256>>("tempo_fundAddress".into(), (dev_address,))
        .await;

    match funding {
        Ok(tx_hashes) => {
            for tx_hash in tx_hashes {
                let receipt = PendingTransactionBuilder::new(provider.root().clone(), tx_hash)
                    .get_receipt()
                    .await?;
                eyre::ensure!(receipt.status(), "tempo_fundAddress transaction reverted");
            }
        }
        Err(err) => {
            tracing::debug!(%err, %dev_address, "tempo_fundAddress unavailable");
        }
    }

    let fee_balance = ITIP20::new(PATH_USD_ADDRESS, provider)
        .balanceOf(dev_address)
        .call()
        .await?;
    eyre::ensure!(
        !fee_balance.is_zero(),
        "dev account {dev_address} has no pathUSD for L1 fees; enable tempo_fundAddress, pre-fund the account, or use the default Anvil dev key"
    );
    Ok(())
}

/// Returns TIP-1091's fixed `ZoneFactory` address after verifying it is installed on L1.
pub async fn native_zone_factory(
    l1_rpc_url: &str,
    wallet: EthereumWallet,
) -> eyre::Result<Address> {
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(l1_rpc_url)
        .await?;

    eyre::ensure!(
        !provider.get_code_at(ZONE_FACTORY_ADDRESS).await?.is_empty(),
        "ZoneFactory is not installed at TIP-1091 address {ZONE_FACTORY_ADDRESS}"
    );
    Ok(ZONE_FACTORY_ADDRESS)
}

#[cfg(feature = "cli")]
pub use command::DevCommand;

#[cfg(feature = "cli")]
mod command {
    use std::path::{Path, PathBuf};

    use alloy_primitives::Address;
    use alloy_signer_local::PrivateKeySigner;

    use super::{ProvisionConfig, provision_zone};
    use crate::cli::ZoneCli;
    use tempo_contracts::precompiles::PATH_USD_ADDRESS;

    /// Default dev private key (account #0 of the standard `test test ... junk` mnemonic).
    const DEFAULT_DEV_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    /// Provisions a fresh zone against a Tempo dev L1 and runs the zone node.
    #[derive(Debug, clap::Parser)]
    #[command(
        name = "dev",
        about = "Provision a fresh zone against a Tempo dev L1 and run the zone node"
    )]
    pub struct DevCommand {
        /// Tempo L1 WebSocket RPC URL.
        #[arg(
            long = "l1.rpc-url",
            env = "L1_RPC_URL",
            default_value = "ws://localhost:8546"
        )]
        l1_rpc_url: String,

        /// Optional ZoneFactory override; must equal TIP-1091's protocol address.
        #[arg(long = "l1.factory-address", env = "ZONE_FACTORY")]
        factory_address: Option<Address>,

        /// Dev private key (hex): L1 fee payer, portal admin, and zone sequencer. Funded via
        /// `tempo_fundAddress` when the L1 supports it.
        #[arg(
            long = "dev.key",
            env = "DEV_KEY",
            hide_env_values = true,
            default_value = DEFAULT_DEV_KEY
        )]
        dev_key: String,

        /// Initial TIP-20 token enabled on the portal. Defaults to pathUSD.
        #[arg(long = "dev.token", default_value_t = PATH_USD_ADDRESS)]
        initial_token: Address,

        /// Enable account allowlist enforcement.
        #[arg(long = "dev.access-mode")]
        access_mode: bool,

        /// Enable callback gateway registration enforcement.
        #[arg(long = "dev.gateway-mode")]
        gateway_mode: bool,

        /// Callback-only ZoneGateway implementation. Repeat for legacy/replacement support.
        #[arg(long = "dev.zone-gateway")]
        zone_gateways: Vec<Address>,

        /// Additional allowed portal account. Repeat for each account.
        #[arg(long = "dev.allowed-account")]
        allowed_accounts: Vec<Address>,

        /// Directory for genesis.json, zone.json, node data, and logs. Wiped on start.
        #[arg(long, default_value_os_t = default_datadir())]
        datadir: PathBuf,

        /// Zone RPC listener address.
        #[arg(long = "http.addr", default_value = "127.0.0.1")]
        http_addr: String,

        /// Zone HTTP RPC port. The WebSocket RPC listens on the next port and the
        /// P2P listener on the one after.
        #[arg(long = "http.port", default_value_t = 9545)]
        http_port: u16,

        /// Zone redacted RPC port.
        #[arg(
            long = "redacted-rpc.port",
            alias = "private-rpc.port",
            default_value_t = 8544
        )]
        redacted_rpc_port: u16,

        /// Extra arguments forwarded to `tempo-zone node`.
        #[arg(last = true)]
        node_args: Vec<String>,
    }

    impl DevCommand {
        /// Provisions the zone, writes `genesis.json` and `zone.json` to the datadir,
        /// and runs the zone node.
        pub fn run(self) -> eyre::Result<()> {
            ensure_ws_url(&self.l1_rpc_url)?;
            let dev_key: PrivateKeySigner = self
                .dev_key
                .strip_prefix("0x")
                .unwrap_or(&self.dev_key)
                .parse()
                .map_err(|err| eyre::eyre!("invalid --dev.key: {err}"))?;
            let ws_port = self
                .http_port
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("--http.port too large for the WS port"))?;
            let p2p_port = self
                .http_port
                .checked_add(2)
                .ok_or_else(|| eyre::eyre!("--http.port too large for the P2P port"))?;

            prepare_datadir(&self.datadir)?;

            let allowed_accounts = self.allowed_accounts.clone();

            // Provision on a scoped runtime; the node builds its own afterwards.
            let provisioned = {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(provision_zone(ProvisionConfig {
                    l1_rpc_url: self.l1_rpc_url.clone(),
                    dev_key: dev_key.clone(),
                    factory: self.factory_address,
                    initial_token: self.initial_token,
                    is_access_open: !self.access_mode,
                    is_gateway_enforced: self.gateway_mode,
                    zone_gateways: self.zone_gateways.clone(),
                    allowed_accounts: allowed_accounts.clone(),
                    rpc_url: format!("http://{}:{}", self.http_addr, self.http_port),
                }))?
            };

            let genesis_path = self.datadir.join("genesis.json");
            std::fs::write(
                &genesis_path,
                serde_json::to_string_pretty(&provisioned.genesis)?,
            )?;

            // zone.json metadata for downstream tooling, matching `create-zone`.
            // `sequencerKey` is a well-known dev key; `just zone-up` reads it.
            let zone_json = serde_json::json!({
                "zoneId": provisioned.zone_id,
                "chainId": provisioned.chain_id,
                "portal": format!("{}", provisioned.portal),
                "initialToken": format!("{}", self.initial_token),
                "accessMode": self.access_mode,
                "gatewayMode": self.gateway_mode,
                "zoneGateways": self.zone_gateways.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "allowedAccounts": allowed_accounts.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "admin": format!("{}", dev_key.address()),
                "sequencer": format!("{}", dev_key.address()),
                "sequencerKey": self.dev_key,
                "tempoAnchorBlock": provisioned.anchor_block_number,
                "zoneFactory": format!("{}", provisioned.factory),
                "rpcUrl": format!("http://{}:{}", self.http_addr, self.http_port),
            });
            super::write_owner_only(
                &self.datadir.join("zone.json"),
                serde_json::to_string_pretty(&zone_json)?.as_bytes(),
            )?;
            let sequencer_key_path = self.datadir.join("sequencer.key");
            super::write_owner_only(&sequencer_key_path, self.dev_key.as_bytes())?;

            println!("Zone provisioned!");
            println!("  Zone ID:      {}", provisioned.zone_id);
            println!("  Chain ID:     {}", provisioned.chain_id);
            println!("  ZoneFactory:  {}", provisioned.factory);
            println!("  Portal:       {}", provisioned.portal);
            println!("  Anchor block: {}", provisioned.anchor_block_number);
            println!("  Dev account:  {}", dev_key.address());
            println!(
                "  HTTP RPC:     http://{}:{}",
                self.http_addr, self.http_port
            );
            println!("  WS RPC:       ws://{}:{ws_port}", self.http_addr);
            println!(
                "  Redacted RPC: http://{}:{}",
                self.http_addr, self.redacted_rpc_port
            );
            println!("  Datadir:      {}", self.datadir.display());

            let mut argv: Vec<String> = [
                "tempo-zone",
                "node",
                "--chain",
                &genesis_path.display().to_string(),
                "--l1.rpc-url",
                &self.l1_rpc_url,
                "--l1.portal-address",
                &provisioned.portal.to_string(),
                "--http",
                "--http.addr",
                &self.http_addr,
                "--http.port",
                &self.http_port.to_string(),
                "--http.api",
                "all",
                "--ws",
                "--ws.addr",
                &self.http_addr,
                "--ws.port",
                &ws_port.to_string(),
                "--ws.api",
                "all",
                "--port",
                &p2p_port.to_string(),
                "--redacted-rpc.port",
                &self.redacted_rpc_port.to_string(),
                "--datadir",
                &self.datadir.join("node").display().to_string(),
                "--log.file.directory",
                &self.datadir.join("logs").display().to_string(),
                "--sequencer",
                "--sequencer-key-file",
                &sequencer_key_path.display().to_string(),
            ]
            .map(str::to_owned)
            .to_vec();
            argv.extend(self.node_args);

            ZoneCli::parse_from(argv).run()
        }
    }

    fn default_datadir() -> PathBuf {
        std::env::temp_dir().join("tempo-zone-dev")
    }

    /// Ensures the L1 RPC URL uses a WebSocket scheme, as `tempo-zone node` requires.
    fn ensure_ws_url(l1_rpc_url: &str) -> eyre::Result<()> {
        let url: url::Url = l1_rpc_url
            .parse()
            .map_err(|err| eyre::eyre!("failed parsing --l1.rpc-url as URL: {err}"))?;
        eyre::ensure!(
            matches!(url.scheme(), "ws" | "wss"),
            "--l1.rpc-url must use ws:// or wss://, got `{}`",
            url.scheme()
        );
        Ok(())
    }

    /// Wipes and recreates the datadir.
    ///
    /// Every run provisions a fresh zone anchored to fresh L1 state, so stale node
    /// data can never be reused. Refuses to wipe a directory that does not look
    /// like a previous dev datadir.
    fn prepare_datadir(datadir: &Path) -> eyre::Result<()> {
        if datadir.exists() {
            let is_dev_datadir =
                datadir.join("zone.json").exists() || std::fs::read_dir(datadir)?.next().is_none();
            eyre::ensure!(
                is_dev_datadir,
                "refusing to wipe {}: not a tempo-zone dev datadir (no zone.json); \
                 pass an empty or fresh --datadir",
                datadir.display()
            );
            std::fs::remove_dir_all(datadir)?;
        }
        std::fs::create_dir_all(datadir)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use clap::Parser as _;

        use super::{DevCommand, ensure_ws_url};

        #[test]
        fn private_rpc_port_alias_is_accepted() {
            let redacted =
                DevCommand::try_parse_from(["dev", "--redacted-rpc.port", "9544"]).unwrap();
            let private =
                DevCommand::try_parse_from(["dev", "--private-rpc.port", "9544"]).unwrap();

            assert_eq!(redacted.redacted_rpc_port, 9544);
            assert_eq!(private.redacted_rpc_port, 9544);
        }

        #[test]
        fn ensure_ws_url_accepts_websocket_schemes() {
            assert!(ensure_ws_url("ws://localhost:8546").is_ok());
            assert!(ensure_ws_url("wss://rpc.moderato.tempo.xyz").is_ok());
        }

        #[test]
        fn ensure_ws_url_rejects_non_websocket_schemes() {
            assert!(ensure_ws_url("http://localhost:8545").is_err());
        }
    }
}

#[cfg(feature = "cli")]
fn write_owner_only(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::{
            fs::{OpenOptions, Permissions},
            io::Write as _,
            os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
        };

        let mut options = OpenOptions::new();
        options.write(true).create(true).mode(0o600);
        let mut file = options.open(path)?;
        file.set_permissions(Permissions::from_mode(0o600))?;
        file.set_len(0)?;
        file.write_all(contents)
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}
