// The `sol!`generated `ZoneFactory` event/contract bindings expand to functions
// with more than 7 parameters, which trips `clippy::too_many_arguments`.
#![allow(clippy::too_many_arguments)]

use alloy::{
    network::primitives::ReceiptResponse,
    primitives::{Address, TxHash},
    providers::{DynProvider, Provider, ProviderBuilder},
    sol_types::{SolCall as _, SolEvent as _},
};
use alloy_rpc_types_eth::BlockId;
use eyre::{WrapErr as _, ensure, eyre};
use std::path::PathBuf;
use tempo_alloy::{TempoNetwork, rpc::TempoTransactionReceipt};
use tempo_chainspec::{cli::TempoHardforkArgs, spec::TEMPO_T0_BASE_FEE};
use tempo_contracts::precompiles::ITIP403Registry;
use tempo_precompiles::{PATH_USD_ADDRESS, TIP403_REGISTRY_ADDRESS};
use tempo_zone_contracts::{
    MAX_SEQUENCERS, ZONE_MESSENGER_ADDRESS, ZONE_VERIFIER_ADDRESS, ZoneFactory, ZonePortal,
};
use zone_primitives::constants::zone_chain_id;

use crate::{
    generate_zone_genesis::wait_for_finalized_pre_creation_anchor,
    genesis_forks::resolve_l1_forks,
    safe::{SafeProposal, verify_safe, write_safe_proposal},
    zone_utils::{MODERATO_ZONE_FACTORY, parse_private_key, write_owner_only},
};

#[derive(Debug, clap::Parser)]
pub(crate) struct CreateZone {
    /// Output directory where genesis.json will be written.
    #[arg(short, long)]
    output: PathBuf,

    /// Tempo L1 HTTP RPC URL used to fetch headers and send or simulate the createZone
    /// transaction.
    #[arg(long, default_value = "https://rpc.moderato.tempo.xyz")]
    l1_rpc_url: String,

    /// ZoneFactory contract address on Tempo L1.
    #[arg(long, env = "ZONE_FACTORY", default_value_t = MODERATO_ZONE_FACTORY)]
    zone_factory: Address,

    /// Initial TIP-20 token address for the zone (additional tokens can be enabled later).
    #[arg(long, default_value_t = PATH_USD_ADDRESS)]
    initial_token: Address,

    /// Enable account allowlist enforcement. Membership is retained while disabled.
    #[arg(long)]
    access_mode: bool,

    /// Enable callback gateway registration enforcement.
    #[arg(long)]
    gateway_mode: bool,

    /// Callback-only ZoneGateway implementation. Repeat to support legacy and replacement gateways.
    #[arg(long = "zone-gateway")]
    zone_gateways: Vec<Address>,

    /// Allowed plain-withdrawal/deposit account. Repeat for each member.
    /// Zone gateways are configured separately and must not be included.
    #[arg(long = "allowed-account")]
    allowed_accounts: Vec<Address>,

    /// Sequencer address that will operate the zone. Repeat for a
    /// multi-sequencer set; the first address is the leader.
    ///
    /// The complete set and threshold are installed atomically by `createZone`;
    /// the first address is also the initial block-production leader.
    #[arg(long = "sequencer", required = true)]
    sequencers: Vec<Address>,

    /// Number of sequencer signatures required for a settlement attestation
    /// quorum. Must be between 1 and the number of sequencers.
    #[arg(long, default_value_t = 1)]
    threshold: u8,

    /// Admin address that controls token enablement and deposit pause/unpause.
    /// Pass the sequencer address explicitly when both roles should use the same key.
    #[arg(long)]
    admin: Address,

    /// Operator RPC endpoint for the zone, published on-chain in the portal.
    /// Can be left empty and set later via `ZonePortal.setRpcUrl`.
    #[arg(long, default_value = "")]
    rpc_url: String,

    /// ZoneFactory owner private key (hex) for signing the createZone transaction on L1.
    /// Required unless --safe-address or --creation-tx is used. Prefer the
    /// ZONE_FACTORY_OWNER_KEY environment variable so the key is not exposed in the process
    /// argument list.
    #[arg(
        long,
        env = "ZONE_FACTORY_OWNER_KEY",
        hide_env_values = true,
        required_unless_present_any = ["safe_address", "creation_tx"],
        conflicts_with_all = ["safe_address", "creation_tx"]
    )]
    private_key: Option<String>,

    /// Safe contract that owns the ZoneFactory. Simulates createZone from the Safe and writes
    /// an unsigned Safe Transaction Builder proposal instead of sending a transaction. After the
    /// Safe executes it, rerun with --creation-tx to write genesis.json and zone.json.
    #[arg(
        long,
        value_name = "ADDRESS",
        requires = "safe_output",
        conflicts_with = "creation_tx"
    )]
    safe_address: Option<Address>,

    /// New Safe Transaction Builder JSON file to create.
    #[arg(long, value_name = "PATH", requires = "safe_address")]
    safe_output: Option<PathBuf>,

    /// Hash of an already executed createZone transaction, such as the Safe execution of a
    /// --safe-address proposal. Verifies its ZoneCreated event against the other arguments and
    /// writes genesis.json and zone.json without sending a transaction.
    #[arg(long, value_name = "TX_HASH")]
    creation_tx: Option<TxHash>,

    /// Base fee per gas for the zone L2.
    #[arg(long, default_value_t = TEMPO_T0_BASE_FEE.into())]
    base_fee_per_gas: u128,

    /// Genesis block gas limit for the zone L2.
    #[arg(long, default_value_t = 30_000_000)]
    gas_limit: u64,

    #[command(flatten)]
    forks: TempoHardforkArgs,
}

impl CreateZone {
    fn factory_params(&self) -> ZoneFactory::CreateZoneParams {
        ZoneFactory::CreateZoneParams {
            initialToken: self.initial_token,
            accessMode: self.access_mode,
            gatewayMode: self.gateway_mode,
            allowedAccounts: self.allowed_accounts.clone(),
            zoneGateways: self.zone_gateways.clone(),
            admin: self.admin,
            sequencers: self.sequencers.clone(),
            threshold: self.threshold,
            rpcUrl: self.rpc_url.clone(),
        }
    }

    fn safe_proposal(&self) -> Option<SafeProposal> {
        self.safe_address.map(|safe| SafeProposal {
            safe,
            output: self
                .safe_output
                .clone()
                .expect("clap requires --safe-output with --safe-address"),
        })
    }

    /// Validates the requested sequencer set and returns its initial leader.
    fn validate_sequencer_set(&self) -> eyre::Result<Address> {
        let leader = *self
            .sequencers
            .first()
            .ok_or_else(|| eyre!("at least one --sequencer is required"))?;
        if self.sequencers.len() > MAX_SEQUENCERS {
            return Err(eyre!(
                "at most {MAX_SEQUENCERS} sequencers are supported, got {}",
                self.sequencers.len()
            ));
        }
        for (i, sequencer) in self.sequencers.iter().enumerate() {
            if sequencer.is_zero() {
                return Err(eyre!("sequencer address must not be zero"));
            }
            if self.sequencers[..i].contains(sequencer) {
                return Err(eyre!("duplicate sequencer address {sequencer}"));
            }
        }
        if self.threshold == 0 || usize::from(self.threshold) > self.sequencers.len() {
            return Err(eyre!(
                "threshold must be between 1 and the number of sequencers ({}), got {}",
                self.sequencers.len(),
                self.threshold
            ));
        }
        if self.sequencers.len() > 1 && self.threshold < 2 {
            // With threshold 1 a leader can settle blocks no follower holds, so an
            // empty-disk leader recovery cannot reconstruct the settled chain from
            // follower replicas. Threshold >= 2 guarantees every settled batch carries
            // at least one follower signature.
            println!(
                "WARNING: multi-sequencer zone with settlement threshold 1: settled blocks \
                 may not be recoverable from followers after leader disk loss; use a \
                 threshold of at least 2"
            );
        }
        Ok(leader)
    }

    fn print_requested_zone(&self) {
        println!("Initial token: {}", self.initial_token);
        println!("Access enforcement: {}", self.access_mode);
        println!("Gateway enforcement: {}", self.gateway_mode);
        println!("Admin: {}", self.admin);
        println!("Sequencers: {:?}", self.sequencers);
        println!("Threshold: {}", self.threshold);
    }

    /// Simulates createZone from the Safe that owns the ZoneFactory and writes an unsigned
    /// Transaction Builder proposal for it.
    async fn propose_to_safe(&self, proposal: &SafeProposal) -> eyre::Result<()> {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.l1_rpc_url)
            .await
            .wrap_err("failed connecting to Tempo L1 RPC")?;
        resolve_l1_forks(&provider, &self.forks).await?;
        let factory = ZoneFactory::new(self.zone_factory, &provider);
        let owner = factory
            .owner()
            .call()
            .await
            .wrap_err("failed reading ZoneFactory owner")?;
        ensure!(
            proposal.safe == owner,
            "Safe {} is not ZoneFactory owner {owner}",
            proposal.safe
        );
        verify_safe(&provider, proposal.safe).await?;

        // createZone requires a TIP-403 binding for the initial token. The migration is
        // permissionless, so it is not bundled into the Safe proposal, where it would prevent
        // simulating createZone before signers review it.
        let policy = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, &provider)
            .tokenTransferPolicyId(self.initial_token)
            .call()
            .await?;
        ensure!(
            policy.isSet,
            "transfer policy is not set for initial token {token}; call the permissionless \
             TIP-403 registry ({TIP403_REGISTRY_ADDRESS}) migrateTransferPolicyIds([{token}]) \
             from any funded account, then rerun",
            token = self.initial_token
        );

        self.print_requested_zone();
        let simulated = factory
            .createZone(self.factory_params())
            .from(proposal.safe)
            .call()
            .await
            .wrap_err("ZoneFactory.createZone Safe simulation failed")?;
        println!(
            "Simulated createZone: zone {} with portal {} (changes if another zone is created first)",
            simulated.zoneId, simulated.portal
        );

        let calldata = ZoneFactory::createZoneCall {
            params: self.factory_params(),
        }
        .abi_encode();
        write_safe_proposal(
            &provider,
            proposal,
            "ZoneFactory.createZone",
            self.zone_factory,
            calldata,
        )
        .await?;
        println!();
        println!(
            "genesis.json and zone.json are not written yet: they depend on the zone ID, portal, \
             and L1 anchor block that only exist once the Safe executes the proposal."
        );
        println!("After execution, finish with the execution transaction hash:");
        println!("  {}", finish_command(std::env::args()));
        Ok(())
    }

    /// Migrates the initial token's transfer policy if needed and sends createZone with the
    /// ZoneFactory owner key.
    async fn send_create_zone(
        &self,
        provider: &DynProvider<TempoNetwork>,
        signer: Address,
    ) -> eyre::Result<TempoTransactionReceipt> {
        let factory = ZoneFactory::new(self.zone_factory, provider);
        let owner = factory
            .owner()
            .call()
            .await
            .wrap_err("failed reading ZoneFactory owner")?;
        if owner != signer {
            let owner_is_contract = !provider
                .get_code_at(owner)
                .await
                .wrap_err("failed reading ZoneFactory owner bytecode")?
                .is_empty();
            let hint = if owner_is_contract {
                format!(
                    "; the owner is a contract, so if it is a Safe use --safe-address {owner} \
                     --safe-output <path> instead of ZONE_FACTORY_OWNER_KEY"
                )
            } else {
                String::new()
            };
            return Err(eyre!(
                "ZONE_FACTORY_OWNER_KEY signer {signer} is not ZoneFactory owner {owner}{hint}"
            ));
        }

        println!("Verifier: {ZONE_VERIFIER_ADDRESS}");
        println!("Messenger: {ZONE_MESSENGER_ADDRESS}");

        let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, provider);
        let mut policy = registry
            .tokenTransferPolicyId(self.initial_token)
            .call()
            .await?;
        if !policy.isSet {
            println!(
                "Migrating legacy transfer policy for initial token {}...",
                self.initial_token
            );
            let receipt = registry
                .migrateTransferPolicyIds(vec![self.initial_token])
                .send_sync()
                .await?;
            if !receipt.status() {
                return Err(eyre!(
                    "transfer policy migration reverted (tx: {:?})",
                    receipt.transaction_hash
                ));
            }

            policy = registry
                .tokenTransferPolicyId(self.initial_token)
                .call()
                .await?;
        }
        if !policy.isSet {
            return Err(eyre!(
                "transfer policy is not set for initial token {} after migration",
                self.initial_token
            ));
        }

        self.print_requested_zone();

        println!(
            "Creating zone on L1 via ZoneFactory at {}...",
            self.zone_factory
        );
        // Install the requested set in the factory transaction. A separate
        // setSequencerSet call would leave the portal live as a temporary
        // 1-of-1 settlement authority before the intended quorum is active.
        // The portal bootstraps the first sequencer as the initial
        // block-production leader (leaderEpoch 1); later transfers go through
        // setLeader. The factory-installed set starts at version 0.
        Ok(factory
            .createZone(self.factory_params())
            .send_sync()
            .await?)
    }

    /// Returns the single ZoneCreated event emitted by the configured ZoneFactory, checked
    /// against the requested parameters so genesis matches the zone that was actually created.
    fn zone_created_event(
        &self,
        receipt: &TempoTransactionReceipt,
    ) -> eyre::Result<ZoneFactory::ZoneCreated> {
        let tx_hash = receipt.transaction_hash;
        let mut events = receipt
            .logs()
            .iter()
            .filter(|log| log.address() == self.zone_factory)
            .filter_map(|log| ZoneFactory::ZoneCreated::decode_log(&log.inner).ok());
        let event = events
            .next()
            .ok_or_else(|| {
                eyre!(
                    "transaction {tx_hash} emitted no ZoneCreated event from ZoneFactory {}",
                    self.zone_factory
                )
            })?
            .data;
        ensure!(
            events.next().is_none(),
            "transaction {tx_hash} emitted more than one ZoneCreated event"
        );
        self.ensure_requested_zone(&event)
            .wrap_err_with(|| format!("transaction {tx_hash} did not create the requested zone"))?;
        Ok(event)
    }

    fn ensure_requested_zone(&self, event: &ZoneFactory::ZoneCreated) -> eyre::Result<()> {
        let mut mismatches = Vec::new();
        if event.initialToken != self.initial_token {
            mismatches.push(format!(
                "initial token {} (expected {})",
                event.initialToken, self.initial_token
            ));
        }
        if event.accessMode != self.access_mode {
            mismatches.push(format!(
                "access mode {} (expected {})",
                event.accessMode, self.access_mode
            ));
        }
        if event.gatewayMode != self.gateway_mode {
            mismatches.push(format!(
                "gateway mode {} (expected {})",
                event.gatewayMode, self.gateway_mode
            ));
        }
        if event.admin != self.admin {
            mismatches.push(format!("admin {} (expected {})", event.admin, self.admin));
        }
        if event.sequencers != self.sequencers {
            mismatches.push(format!(
                "sequencers {:?} (expected {:?})",
                event.sequencers, self.sequencers
            ));
        }
        if event.threshold != self.threshold {
            mismatches.push(format!(
                "threshold {} (expected {})",
                event.threshold, self.threshold
            ));
        }
        ensure!(
            mismatches.is_empty(),
            "ZoneCreated reports {}",
            mismatches.join(", ")
        );
        Ok(())
    }

    pub(crate) async fn run(self) -> eyre::Result<()> {
        let leader = self.validate_sequencer_set()?;

        if let Some(proposal) = self.safe_proposal() {
            return self.propose_to_safe(&proposal).await;
        }

        let (provider, receipt, forks) = if let Some(tx_hash) = self.creation_tx {
            let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect(&self.l1_rpc_url)
                .await
                .wrap_err("failed connecting to Tempo L1 RPC")?
                .erased();
            let forks = resolve_l1_forks(&provider, &self.forks).await?;
            println!("Reading createZone transaction {tx_hash}...");
            let receipt = provider
                .get_transaction_receipt(tx_hash)
                .await
                .wrap_err_with(|| format!("failed fetching receipt for {tx_hash}"))?
                .ok_or_else(|| {
                    eyre!("transaction {tx_hash} has no receipt yet; rerun once it is mined")
                })?;
            (provider, receipt, forks)
        } else {
            let private_key = self
                .private_key
                .as_deref()
                .ok_or_else(|| eyre!("ZONE_FACTORY_OWNER_KEY is required to send createZone"))?;
            let signer = parse_private_key(private_key)?;
            let signer_address = signer.address();
            let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                .wallet(signer)
                .connect(&self.l1_rpc_url)
                .await
                .wrap_err("failed connecting to Tempo L1 RPC")?
                .erased();
            let forks = resolve_l1_forks(&provider, &self.forks).await?;
            let receipt = self.send_create_zone(&provider, signer_address).await?;
            (provider, receipt, forks)
        };
        println!("Transaction confirmed in block {:?}", receipt.block_number);
        println!("Status: {}", receipt.status());
        println!("Gas used: {:?}", receipt.gas_used);

        if !receipt.status() {
            return Err(eyre!(
                "createZone transaction reverted (tx: {:?})",
                receipt.transaction_hash
            ));
        }
        let creation_block = receipt
            .block_number
            .ok_or_else(|| eyre!("createZone receipt is missing its block number"))?;

        let event = self.zone_created_event(&receipt)?;

        let zone_id = event.zoneId;
        let portal = event.portal;
        let parent_chain_id = provider.get_chain_id().await?;
        let chain_id = zone_chain_id(parent_chain_id, zone_id)?;

        let portal_contract = ZonePortal::new(portal, &provider);
        let creation_block_id = BlockId::number(creation_block);
        let sequencer_set_version = portal_contract
            .sequencerSetVersion()
            .block(creation_block_id)
            .call()
            .await?;
        let initial_leader = portal_contract
            .leader()
            .block(creation_block_id)
            .call()
            .await?;
        let leader_epoch = portal_contract
            .leaderEpoch()
            .block(creation_block_id)
            .call()
            .await?;
        let leader_activation_block = portal_contract
            .leaderActivationTempoBlock()
            .block(creation_block_id)
            .call()
            .await?;

        ensure!(
            sequencer_set_version == 0,
            "ZoneFactory initialized sequencer set version {sequencer_set_version}, expected 0"
        );
        ensure!(
            initial_leader == leader
                && leader_epoch == 1
                && leader_activation_block == creation_block,
            "ZoneFactory initialized leader snapshot ({initial_leader}, epoch {leader_epoch}, activation {leader_activation_block}), expected ({leader}, epoch 1, activation {creation_block})"
        );
        println!("Sequencer set version: {sequencer_set_version}");

        println!("Waiting for creation block {creation_block} to finalize...");
        let anchor =
            wait_for_finalized_pre_creation_anchor(&provider, portal, creation_block).await?;
        println!(
            "Using pre-creation block {} (hash: {}) as genesis anchor",
            anchor.block_number, anchor.hash
        );

        let genesis_cmd = crate::generate_zone_genesis::GenerateZoneGenesis {
            output: self.output.clone(),
            chain_id,
            base_fee_per_gas: self.base_fee_per_gas,
            gas_limit: self.gas_limit,
            tempo_portal: None,
            l1_rpc_url: None,
            default_fee_token: self.initial_token,
            tempo_genesis_header_rlp: None,
            admin: self.admin,
            sequencer: Some(leader),
            with_createx: true,
            with_safe_deployer: true,
            with_create2_factory: true,
            forks: self.forks,
        };
        genesis_cmd.generate(forks, anchor.rlp).await?;

        // Write zone.json with deployment metadata for downstream tooling (e.g. `just zone-up`).
        let zone_json = serde_json::json!({
            "zoneId": zone_id,
            "chainId": chain_id,
            "portal": format!("{portal}"),
            "messenger": format!("{ZONE_MESSENGER_ADDRESS}"),
            "initialToken": format!("{}", self.initial_token),
            "accessMode": self.access_mode,
            "gatewayMode": self.gateway_mode,
            "zoneGateways": self.zone_gateways.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "allowedAccounts": self.allowed_accounts.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "admin": format!("{}", self.admin),
            "sequencer": format!("{leader}"),
            "sequencers": self.sequencers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "sequencerThreshold": self.threshold,
            "sequencerSetVersion": sequencer_set_version,
            "tempoAnchorBlock": anchor.block_number,
            "zoneFactory": format!("{}", self.zone_factory),
            "rpcUrl": self.rpc_url,
        });
        let zone_json_path = self.output.join("zone.json");
        write_owner_only(
            &zone_json_path,
            serde_json::to_string_pretty(&zone_json).wrap_err("failed encoding zone.json")?,
        )
        .wrap_err("failed writing zone.json")?;

        println!("Zone created successfully!");
        println!("  Zone ID: {zone_id}");
        println!("  Chain ID: {chain_id}");
        println!("  Portal: {portal}");
        println!("  Messenger: {ZONE_MESSENGER_ADDRESS}");
        println!("  Initial Token: {}", self.initial_token);
        println!("  Access enforcement: {}", self.access_mode);
        println!("  Gateway enforcement: {}", self.gateway_mode);
        println!("  Admin: {}", self.admin);
        println!("  Sequencers: {:?}", self.sequencers);
        println!("  Threshold: {}", self.threshold);
        println!("  Sequencer set version: {sequencer_set_version}");
        println!("  ZoneFactory: {}", self.zone_factory);
        if !self.rpc_url.is_empty() {
            println!("  RPC URL: {}", self.rpc_url);
        }
        println!("  Tempo anchor block: {}", anchor.block_number);
        println!(
            "  Genesis written to: {}",
            self.output.join("genesis.json").display()
        );
        println!("  Zone metadata written to: {}", zone_json_path.display());

        Ok(())
    }
}

/// Rewrites a `--safe-address` invocation into the `--creation-tx` invocation that finishes it.
fn finish_command(args: impl IntoIterator<Item = String>) -> String {
    const SAFE_FLAGS: [&str; 2] = ["--safe-address", "--safe-output"];
    let mut command = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if SAFE_FLAGS.contains(&arg.as_str()) {
            args.next();
            continue;
        }
        if SAFE_FLAGS.iter().any(|flag| {
            arg.strip_prefix(flag)
                .is_some_and(|rest| rest.starts_with('='))
        }) {
            continue;
        }
        command.push(shell_quote(&arg));
    }
    command.push("--creation-tx <EXECUTION_TX_HASH>".to_owned());
    command.join(" ")
}

fn shell_quote(arg: &str) -> String {
    let is_plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+".contains(c));
    if is_plain {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use clap::Parser;

    fn test_command() -> CreateZone {
        CreateZone {
            output: PathBuf::new(),
            l1_rpc_url: String::new(),
            zone_factory: Address::ZERO,
            initial_token: address!("0x4000000000000000000000000000000000000004"),
            access_mode: true,
            gateway_mode: true,
            zone_gateways: Vec::new(),
            allowed_accounts: Vec::new(),
            sequencers: vec![
                address!("0x1000000000000000000000000000000000000001"),
                address!("0x2000000000000000000000000000000000000002"),
                address!("0x3000000000000000000000000000000000000003"),
            ],
            threshold: 2,
            admin: address!("0x5000000000000000000000000000000000000005"),
            rpc_url: String::new(),
            private_key: None,
            safe_address: None,
            safe_output: None,
            creation_tx: None,
            base_fee_per_gas: 1,
            gas_limit: 30_000_000,
            forks: TempoHardforkArgs::default(),
        }
    }

    fn created_event(command: &CreateZone) -> ZoneFactory::ZoneCreated {
        ZoneFactory::ZoneCreated {
            zoneId: 7,
            portal: address!("0x6000000000000000000000000000000000000006"),
            initialToken: command.initial_token,
            accessMode: command.access_mode,
            gatewayMode: command.gateway_mode,
            admin: command.admin,
            sequencers: command.sequencers.clone(),
            threshold: command.threshold,
            verifier: ZONE_VERIFIER_ADDRESS,
        }
    }

    const BASE_ARGS: [&str; 6] = [
        "create-zone",
        "--output",
        "/tmp/zone",
        "--admin",
        "0x1000000000000000000000000000000000000001",
        "--sequencer=0x1000000000000000000000000000000000000001",
    ];

    fn parse(extra: &[&str]) -> Result<CreateZone, clap::Error> {
        CreateZone::try_parse_from(BASE_ARGS.iter().chain(extra))
    }

    #[test]
    fn factory_params_install_the_requested_quorum_atomically() {
        let command = test_command();

        let params = command.factory_params();
        assert_eq!(params.sequencers, command.sequencers);
        assert_eq!(params.threshold, 2);
    }

    #[test]
    fn signing_modes_are_mutually_exclusive() {
        let safe = "0x7000000000000000000000000000000000000007";
        let tx = "0x1111111111111111111111111111111111111111111111111111111111111111";

        assert!(parse(&["--private-key", "unused"]).is_ok());
        let proposal = parse(&["--safe-address", safe, "--safe-output", "/tmp/safe.json"]).unwrap();
        assert!(proposal.private_key.is_none());
        assert!(proposal.safe_proposal().is_some());
        let finish = parse(&["--creation-tx", tx]).unwrap();
        assert!(finish.private_key.is_none());
        assert!(finish.safe_proposal().is_none());

        assert!(parse(&[]).is_err(), "a signing mode is required");
        assert!(
            parse(&["--safe-address", safe]).is_err(),
            "Safe mode needs an output"
        );
        assert!(parse(&["--safe-output", "/tmp/safe.json"]).is_err());
        assert!(
            parse(&[
                "--private-key",
                "unused",
                "--safe-address",
                safe,
                "--safe-output",
                "/tmp/safe.json",
            ])
            .is_err()
        );
        assert!(parse(&["--private-key", "unused", "--creation-tx", tx]).is_err());
        assert!(
            parse(&[
                "--safe-address",
                safe,
                "--safe-output",
                "/tmp/safe.json",
                "--creation-tx",
                tx,
            ])
            .is_err()
        );
    }

    #[test]
    fn finish_command_replaces_safe_flags_with_creation_tx() {
        let args = [
            "./target/debug/tempo-xtask",
            "create-zone",
            "--safe-address",
            "0x7000000000000000000000000000000000000007",
            "--safe-output=proposal.json",
            "--output",
            "generated/zone a",
            "--sequencer",
            "0x1000000000000000000000000000000000000001",
        ]
        .map(String::from);

        assert_eq!(
            finish_command(args),
            "./target/debug/tempo-xtask create-zone --output 'generated/zone a' \
             --sequencer 0x1000000000000000000000000000000000000001 \
             --creation-tx <EXECUTION_TX_HASH>"
        );
    }

    #[test]
    fn created_zone_must_match_the_requested_parameters() {
        let command = test_command();
        command
            .ensure_requested_zone(&created_event(&command))
            .unwrap();

        let mut event = created_event(&command);
        event.admin = Address::repeat_byte(0x99);
        event.threshold = 3;
        let error = command.ensure_requested_zone(&event).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("admin"), "{message}");
        assert!(message.contains("threshold 3 (expected 2)"), "{message}");

        let mut event = created_event(&command);
        event.sequencers.reverse();
        assert!(command.ensure_requested_zone(&event).is_err());
    }

    #[test]
    fn parses_genesis_fork_overrides() {
        let command = CreateZone::try_parse_from([
            "create-zone",
            "--output",
            "/tmp/zone",
            "--admin",
            "0x1000000000000000000000000000000000000001",
            "--sequencer",
            "0x1000000000000000000000000000000000000001",
            "--private-key",
            "unused",
            "--t12-time",
            "0",
            "--t13-time",
            "9223372036854775807",
            "--t14-time",
            "18446744073709551615",
        ])
        .unwrap();
        let mut config = alloy::genesis::ChainConfig::default();
        command.forks.write_to(&mut config);
        assert_eq!(config.extra_fields["t4Time"], serde_json::json!(0));
        assert_eq!(config.extra_fields["t12Time"], serde_json::json!(0));
        assert_eq!(
            config.extra_fields["t13Time"],
            serde_json::json!(9223372036854775807u64)
        );
        assert_eq!(config.extra_fields["t14Time"], serde_json::json!(u64::MAX));
    }
}
