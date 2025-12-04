//! Ceremony orchestration and main execution loop.

use crate::{
    config::CeremonyConfig,
    constants::output,
    display::{self, ParticipantInfo},
    network::{CeremonyNetwork, ConnectivityArgs},
    protocol::{CeremonyOutcome, FinalizedShares, GenesisCeremony, Message},
};
use bytes::Bytes;
use commonware_codec::{Encode, Read as _};
use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::{Receiver as _, authenticated::lookup};
use commonware_runtime::{Runner, tokio::Context};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tempo_commonware_node_config::{SigningKey, SigningShare};
use tokio::{task::JoinHandle, time::interval};
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Arguments for the ceremony command.
pub struct CeremonyArgs {
    /// Path to ceremony configuration file.
    pub config: PathBuf,
    /// Path to signing key file.
    pub signing_key: PathBuf,
    /// Output directory for ceremony results.
    pub output_dir: PathBuf,
    /// Log level.
    pub log_level: String,
}

/// Shared setup for both ceremony and connectivity test.
struct CeremonySetup {
    /// Parsed ceremony configuration.
    config: CeremonyConfig,
    /// Our ED25519 signing key.
    signing_key: PrivateKey,
    /// Output directory for ceremony results.
    output_dir: PathBuf,
}

impl CeremonySetup {
    fn load(
        config_path: &Path,
        signing_key_path: &Path,
        output_dir: PathBuf,
    ) -> eyre::Result<Self> {
        let config = CeremonyConfig::load(config_path)?;
        let signing_key = SigningKey::read_from_file(signing_key_path)?.into_inner();

        Ok(Self {
            config,
            signing_key,
            output_dir,
        })
    }

    fn load_for_connectivity(config_path: &Path, signing_key_path: &Path) -> eyre::Result<Self> {
        Self::load(config_path, signing_key_path, PathBuf::new())
    }

    /// Initialize network and ceremony context.
    async fn init(self, runtime_ctx: Context) -> eyre::Result<CeremonyContext> {
        let (network_participants, names) = self.config.parse_participants()?;

        let mut network = CeremonyNetwork::new(runtime_ctx, self.signing_key.clone(), &self.config);

        network.register_peers(network_participants.clone()).await;
        let (sender, receiver) = network.register_channel(self.config.network.mailbox_size);
        let network_task = tokio::spawn(async move { network.start().await });

        let ceremony = GenesisCeremony::new(
            &mut rand::thread_rng(),
            self.config.namespace.as_bytes().to_vec(),
            self.signing_key,
            network_participants.keys().into_iter().cloned().collect(),
        )?;

        // Merge names and addresses for display
        let participants: display::Participants = network_participants
            .iter_pairs()
            .map(|(pk, addr)| {
                let name = names.get(pk).cloned().unwrap_or_default();
                (
                    pk.clone(),
                    ParticipantInfo {
                        name,
                        address: *addr,
                    },
                )
            })
            .collect();

        Ok(CeremonyContext {
            output_dir: self.output_dir,
            participants,
            sender,
            receiver,
            ceremony,
            network_task,
        })
    }
}

/// Runtime context for an active ceremony.
struct CeremonyContext {
    /// Output directory for ceremony results.
    output_dir: PathBuf,
    /// Participants with display info (name + address).
    participants: display::Participants,
    /// DKG protocol state machine.
    ceremony: GenesisCeremony,
    /// P2P message sender.
    sender: lookup::Sender<PublicKey>,
    /// P2P message receiver.
    receiver: lookup::Receiver<PublicKey>,
    /// Network task.
    network_task: JoinHandle<Result<(), commonware_runtime::Error>>,
}

impl CeremonyContext {
    /// Check if network task has crashed.
    fn check_network(&mut self) -> eyre::Result<()> {
        if self.network_task.is_finished() {
            return Err(eyre::eyre!("Network task terminated unexpectedly"));
        }
        Ok(())
    }

    /// Phase 1: Wait for all participants to connect.
    async fn wait_for_connections(&mut self) -> eyre::Result<()> {
        let mut display_interval = interval(Duration::from_secs(1));
        let mut ping_interval = interval(Duration::from_secs(2));

        self.ceremony.send_pings(&mut self.sender).await?;

        loop {
            display::connection_status(
                &self.participants,
                self.ceremony.connected_peers(),
                self.ceremony.my_public_key(),
            );
            if self.ceremony.all_connected() {
                display::all_connected(self.participants.len());
                return Ok(());
            }

            tokio::select! {
                biased;
                result = self.receiver.recv() => { self.handle_message(result).await?; }
                _ = ping_interval.tick() => { self.ceremony.send_pings(&mut self.sender).await?; }
                _ = display_interval.tick() => { self.check_network()?; }
            }
        }
    }

    /// Phase 2: Distribute shares and collect acks.
    async fn distribute_and_collect_acks(&mut self) -> eyre::Result<()> {
        self.ceremony.send_shares(&mut self.sender).await?;

        let mut display_interval = interval(Duration::from_secs(1));
        let mut resend_interval = interval(Duration::from_secs(5));

        loop {
            display::share_status(&self.participants, &self.ceremony.status());
            if self.ceremony.has_all_acks() {
                return Ok(());
            }

            tokio::select! {
                biased;
                result = self.receiver.recv() => { self.handle_message(result).await?; }
                _ = resend_interval.tick() => { self.ceremony.send_shares(&mut self.sender).await?; }
                _ = display_interval.tick() => { self.check_network()?; }
            }
        }
    }

    /// Phase 3+4: Broadcast our dealing and collect all dealings.
    async fn broadcast_and_collect_dealings(&mut self) -> eyre::Result<()> {
        display::phase3_broadcasting();

        let dealing = self.ceremony.construct_dealing()?.clone();
        self.ceremony.broadcast_dealing(&mut self.sender).await?;

        // Process our own dealing.
        self.ceremony
            .process_message(
                &mut self.sender,
                self.ceremony.my_public_key().clone(),
                Message::Dealing(dealing),
            )
            .await?;

        let mut display_interval = interval(Duration::from_secs(1));
        let mut rebroadcast_interval = interval(Duration::from_secs(5));

        loop {
            display::dealing_status(&self.participants, &self.ceremony.status());
            if self.ceremony.dealings_phase_complete() {
                return Ok(());
            }

            tokio::select! {
                biased;
                result = self.receiver.recv() => { self.handle_message(result).await?; }
                _ = rebroadcast_interval.tick() => { self.ceremony.broadcast_dealing(&mut self.sender).await?; }
                _ = display_interval.tick() => { self.check_network()?; }
            }
        }
    }

    /// Phase 5: Compute shares.
    fn compute_shares(&self) -> eyre::Result<FinalizedShares> {
        display::finalizing();
        self.ceremony.compute_shares()
    }

    /// Phase 6: Collect outcomes.
    async fn collect_outcomes(
        &mut self,
        shares: &FinalizedShares,
    ) -> eyre::Result<tempo_dkg_onchain_artifacts::PublicOutcome> {
        let outcome = self.ceremony.build_public_outcome(shares);
        self.ceremony
            .broadcast_outcome(&mut self.sender, outcome.clone())
            .await?;

        let mut display_interval = interval(Duration::from_secs(1));
        let mut rebroadcast_interval = interval(Duration::from_secs(5));

        loop {
            display::verification_status(&self.participants, &self.ceremony.status());
            if self.ceremony.has_all_outcomes()? {
                display::verification_success();
                return Ok(outcome);
            }

            tokio::select! {
                biased;
                result = self.receiver.recv() => { self.handle_message(result).await?; }
                _ = rebroadcast_interval.tick() => {
                    self.ceremony.broadcast_outcome(&mut self.sender, outcome.clone()).await?;
                }
                _ = display_interval.tick() => { self.check_network()?; }
            }
        }
    }

    /// Phase 7: Write outputs.
    fn write_outputs(
        self,
        shares: FinalizedShares,
        public_outcome: tempo_dkg_onchain_artifacts::PublicOutcome,
    ) -> eyre::Result<()> {
        let outcome = self.ceremony.into_outcome(shares, public_outcome);
        write_ceremony_outputs(&self.output_dir, &outcome)?;
        display::success(&self.output_dir);
        Ok(())
    }

    /// Handle an incoming message.
    async fn handle_message(
        &mut self,
        result: Result<(PublicKey, Bytes), lookup::Error>,
    ) -> eyre::Result<()> {
        let (from, msg_bytes) = result?;
        let msg = Message::read_cfg(&mut &msg_bytes[..], &(self.participants.len() as u32))?;
        self.ceremony
            .process_message(&mut self.sender, from, msg)
            .await
    }
}

/// Run the full DKG ceremony.
pub fn run(args: CeremonyArgs) -> eyre::Result<()> {
    setup_logging(&args.log_level);

    std::fs::create_dir_all(&args.output_dir)?;
    let setup = CeremonySetup::load(&args.config, &args.signing_key, args.output_dir)?;

    let runner = commonware_runtime::tokio::Runner::new(
        commonware_runtime::tokio::Config::default().with_tcp_nodelay(Some(true)),
    );

    runner.start(|runtime_ctx| run_with_context(setup, runtime_ctx))
}

/// Run the ceremony with a pre-existing runtime context.
async fn run_with_context(setup: CeremonySetup, runtime_ctx: Context) -> eyre::Result<()> {
    let mut ctx = setup.init(runtime_ctx).await?;

    ctx.wait_for_connections().await?;
    ctx.distribute_and_collect_acks().await?;
    ctx.broadcast_and_collect_dealings().await?;
    let shares = ctx.compute_shares()?;
    let public_outcome = ctx.collect_outcomes(&shares).await?;
    ctx.write_outputs(shares, public_outcome)
}

/// Test connectivity only - exits after all participants connected.
pub fn run_connectivity_test(args: ConnectivityArgs) -> eyre::Result<()> {
    setup_logging(&args.log_level);

    let setup = CeremonySetup::load_for_connectivity(&args.config, &args.signing_key)?;

    let runner = commonware_runtime::tokio::Runner::new(
        commonware_runtime::tokio::Config::default().with_tcp_nodelay(Some(true)),
    );

    runner.start(async move |runtime_ctx| {
        let mut ctx = setup.init(runtime_ctx).await?;
        ctx.wait_for_connections().await?;
        display::connectivity_success(ctx.participants.len());
        Ok(())
    })
}

fn hex_encode(data: &impl Encode) -> String {
    const_hex::encode_prefixed(data.encode().as_ref())
}

fn write_ceremony_outputs(output_dir: &Path, outcome: &CeremonyOutcome) -> eyre::Result<()> {
    let share_path = output_dir.join(output::SHARE);
    SigningShare::from(outcome.share.clone()).write_to_file(&share_path)?;
    info!("Wrote {}", share_path.display());

    let public_path = output_dir.join(output::PUBLIC_POLYNOMIAL);
    std::fs::write(&public_path, hex_encode(&outcome.public_outcome.public))?;
    info!("Wrote {}", public_path.display());

    let genesis_path = output_dir.join(output::GENESIS_EXTRA_DATA);
    std::fs::write(&genesis_path, hex_encode(&outcome.public_outcome))?;
    info!("Wrote {}", genesis_path.display());

    let genesis_json = serde_json::json!({
        "epoch": outcome.public_outcome.epoch,
        "participants": outcome.participants.iter().map(hex_encode).collect::<Vec<_>>(),
        "public_polynomial_hex": hex_encode(&outcome.public_outcome.public),
    });
    let outcome_path = output_dir.join(output::GENESIS_OUTCOME);
    std::fs::write(&outcome_path, serde_json::to_string_pretty(&genesis_json)?)?;
    info!("Wrote {}", outcome_path.display());

    let dealings_json: serde_json::Map<String, serde_json::Value> = outcome
        .dealings
        .iter()
        .map(|(dealer, dealing)| {
            (
                hex_encode(dealer),
                serde_json::Value::String(hex_encode(dealing)),
            )
        })
        .collect();
    let dealings_path = output_dir.join(output::ALL_DEALINGS);
    std::fs::write(
        &dealings_path,
        serde_json::to_string_pretty(&dealings_json)?,
    )?;
    info!("Wrote {}", dealings_path.display());

    Ok(())
}

fn setup_logging(log_level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}
