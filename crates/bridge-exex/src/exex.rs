//! Main ExEx implementation.

use alloy::{eips::BlockNumHash, primitives::Sealable};
use eyre::Result;
use futures::StreamExt;
use reth_exex::{ExExContext, ExExEvent};
use reth_node_api::FullNodeComponents;
use reth_primitives_traits::AlloyBlockHeader;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    config::BridgeConfig,
    consensus_client::ConsensusClient,
    health::{HealthState, start_health_server},
    metrics::BridgeMetrics,
    origin_client::OriginClient,
    origin_watcher::{DetectedDeposit, OriginWatcher},
    persistence::{ProcessedBurn, SignedDeposit, StateManager},
    proof::AttestationGenerator,
    signer::BridgeSigner,
    tempo_client::TempoClient,
    tempo_watcher::{DetectedBurn, TempoWatcher},
};

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

struct InFlightGuard<'a> {
    set: &'a Mutex<HashSet<alloy::primitives::B256>>,
    id: alloy::primitives::B256,
}

impl<'a> InFlightGuard<'a> {
    fn try_insert(
        set: &'a Mutex<HashSet<alloy::primitives::B256>>,
        id: alloy::primitives::B256,
    ) -> Option<Self> {
        let mut guard = set.lock().unwrap();
        if guard.contains(&id) {
            None
        } else {
            guard.insert(id);
            Some(Self { set, id })
        }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.id);
    }
}

/// Bridge ExEx
pub struct BridgeExEx<Node: FullNodeComponents> {
    ctx: ExExContext<Node>,
    config: BridgeConfig,
    signer: Option<BridgeSigner>,
    tempo_client: Option<Arc<TempoClient>>,
    consensus_client: Option<Arc<ConsensusClient>>,
    origin_clients: HashMap<u64, Arc<OriginClient>>,
    state_manager: Arc<StateManager>,
    in_flight_deposits: Mutex<HashSet<alloy::primitives::B256>>,
    in_flight_burns: Mutex<HashSet<alloy::primitives::B256>>,
    metrics: BridgeMetrics,
}

impl<Node: FullNodeComponents> BridgeExEx<Node> {
    /// Create a new bridge ExEx
    pub fn new(ctx: ExExContext<Node>, config: BridgeConfig) -> Self {
        Self {
            ctx,
            config,
            signer: None,
            tempo_client: None,
            consensus_client: None,
            origin_clients: HashMap::new(),
            state_manager: Arc::new(StateManager::new_in_memory()),
            in_flight_deposits: Mutex::new(HashSet::new()),
            in_flight_burns: Mutex::new(HashSet::new()),
            metrics: BridgeMetrics::default(),
        }
    }

    /// Set a persistent state manager
    pub fn with_state_manager(mut self, manager: StateManager) -> Self {
        self.state_manager = Arc::new(manager);
        self
    }

    /// Set the signer
    pub fn with_signer(mut self, signer: BridgeSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Set the Tempo client
    pub fn with_tempo_client(mut self, client: TempoClient) -> Self {
        self.tempo_client = Some(Arc::new(client));
        self
    }

    /// Set the consensus client for fetching finalization certificates.
    ///
    /// The consensus client is used to fetch BLS threshold signatures from the
    /// consensus layer, which are required for header relay to origin chains.
    pub fn with_consensus_client(mut self, client: ConsensusClient) -> Self {
        self.consensus_client = Some(Arc::new(client));
        self
    }

    /// Add an origin chain client
    pub fn with_origin_client(mut self, chain_id: u64, client: OriginClient) -> Self {
        self.origin_clients.insert(chain_id, Arc::new(client));
        self
    }

    /// Run the ExEx
    pub async fn run(mut self) -> Result<()> {
        info!("Starting Bridge ExEx");

        // Validate that consensus client is configured in production mode.
        // Without a consensus client, the bridge cannot obtain BLS threshold signatures
        // for header relay, which would cause burns to use empty signatures.
        if self.consensus_client.is_none() && !self.config.test_mode {
            return Err(eyre::eyre!(
                "Bridge ExEx requires consensus client in production. \
                 Set consensus_rpc_url in config or enable test_mode for development."
            ));
        }

        // Start health server if configured
        if let Some(port) = self.config.health_port {
            let health_state = HealthState {
                state_manager: Arc::clone(&self.state_manager),
                tempo_client: self.tempo_client.clone(),
                start_time: std::time::Instant::now(),
            };
            tokio::spawn(async move {
                if let Err(e) = start_health_server(port, health_state).await {
                    error!("Health server error: {}", e);
                }
            });
        }

        // Channels for detected events
        let (deposit_tx, mut deposit_rx) = mpsc::channel::<DetectedDeposit>(100);
        let (burn_tx, mut burn_rx) = mpsc::channel::<DetectedBurn>(100);

        // Spawn origin chain watchers
        for (chain_name, chain_config) in self.config.chains.clone() {
            let watcher = OriginWatcher::new(chain_name, chain_config, deposit_tx.clone());
            tokio::spawn(async move {
                if let Err(e) = watcher.run().await {
                    error!("Origin watcher error: {}", e);
                }
            });
        }

        // Create Tempo watcher
        let tempo_watcher = TempoWatcher::new(burn_tx);

        // Main event loop
        loop {
            tokio::select! {
                // Process ExEx notifications
                Some(notification) = self.ctx.notifications.next() => {
                    let notification = notification?;
                    if let Err(e) = tempo_watcher.process_notification(&notification).await {
                        error!("Failed to process notification: {}", e);
                        continue;
                    }

                    if let Some(committed_chain) = notification.committed_chain() {
                        let tip = committed_chain.tip();
                        let tip_number = tip.header().number();
                        let tip_hash = tip.header().hash_slow();
                        self.ctx
                            .events
                            .send(ExExEvent::FinishedHeight(BlockNumHash::new(tip_number, tip_hash)))?;
                    }
                }

                // Process detected deposits
                Some(deposit) = deposit_rx.recv() => {
                    if let Err(e) = self.handle_deposit(deposit).await {
                        error!("Failed to handle deposit: {}", e);
                    }
                }

                // Process detected burns (for header relay)
                Some(burn) = burn_rx.recv() => {
                    if let Err(e) = self.handle_burn(burn).await {
                        error!("Failed to handle burn: {}", e);
                    }
                }
            }
        }
    }

    async fn handle_deposit(&self, deposit: DetectedDeposit) -> Result<()> {
        self.metrics.record_deposit_detected();

        let Some(signer) = &self.signer else {
            info!("No signer configured, skipping deposit signing");
            return Ok(());
        };

        let Some(tempo_client) = &self.tempo_client else {
            warn!("No Tempo client configured, cannot submit signature");
            return Ok(());
        };

        // Use the deposit ID computed by the origin watcher
        let request_id = deposit.deposit_id;

        // Check and insert into in-flight set
        let Some(_guard) = InFlightGuard::try_insert(&self.in_flight_deposits, request_id) else {
            debug!(%request_id, "Deposit already in-flight, skipping");
            return Ok(());
        };

        // Check local state first (faster than RPC)
        if self.state_manager.has_signed_deposit(&request_id).await {
            debug!(%request_id, "Already signed this deposit (from local state)");
            return Ok(());
        }

        // Double-check on-chain state
        match tempo_client.has_signed_deposit(request_id).await {
            Ok(true) => {
                debug!(%request_id, "Already signed this deposit (on-chain)");
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => {
                // Deposit may not be registered yet, continue to register it
                debug!(%request_id, error = %e, "Could not check signature status");
            }
        }

        // First, ensure the deposit is registered on Tempo
        match tempo_client.get_deposit(request_id).await {
            Ok(existing) => {
                if existing.status == tempo_contracts::precompiles::IBridge::DepositStatus::None {
                    // Need to register first
                    info!(%request_id, "Registering deposit on Tempo");
                    if let Err(e) = tempo_client
                        .register_deposit(
                            deposit.origin_chain_id,
                            deposit.origin_escrow,
                            deposit.origin_token,
                            deposit.tx_hash,
                            deposit.log_index,
                            deposit.tempo_recipient,
                            deposit.amount,
                            deposit.block_number,
                        )
                        .await
                    {
                        // Another validator may have registered it, continue
                        debug!(%request_id, error = %e, "Could not register deposit");
                    }
                }
            }
            Err(_) => {
                // Register the deposit
                info!(%request_id, "Registering deposit on Tempo");
                if let Err(e) = tempo_client
                    .register_deposit(
                        deposit.origin_chain_id,
                        deposit.origin_escrow,
                        deposit.origin_token,
                        deposit.tx_hash,
                        deposit.log_index,
                        deposit.tempo_recipient,
                        deposit.amount,
                        deposit.block_number,
                    )
                    .await
                {
                    warn!(%request_id, error = %e, "Failed to register deposit");
                }
            }
        }

        info!(
            request_id = %request_id,
            validator = %signer.address(),
            "Submitting deposit vote to bridge precompile"
        );

        // Submit vote to bridge precompile
        // Security model: The validator's vote is authenticated by the transaction sender address.
        // No separate signature is required because submitting this transaction from a registered
        // validator address already proves the validator's intent to vote for this deposit.
        match tempo_client.submit_deposit_vote(request_id).await
        {
            Ok(tx_hash) => {
                if !tx_hash.is_zero() {
                    self.metrics.record_signature_success();
                    self.metrics.record_deposit_signed();
                    info!(%request_id, %tx_hash, "Deposit signature submitted");

                    // Record in persistent state
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if let Err(e) = self
                        .state_manager
                        .record_signed_deposit(SignedDeposit {
                            request_id,
                            origin_chain_id: deposit.origin_chain_id,
                            origin_tx_hash: deposit.tx_hash,
                            tempo_recipient: deposit.tempo_recipient,
                            amount: deposit.amount,
                            signature_tx_hash: tx_hash,
                            signed_at: now,
                        })
                        .await
                    {
                        warn!(%request_id, error = %e, "Failed to persist signed deposit");
                    }

                    // Try to finalize if threshold reached
                    if let Ok(Some(finalize_tx)) =
                        tempo_client.try_finalize_deposit(request_id).await
                    {
                        self.metrics.record_deposit_finalized();
                        info!(%request_id, tx_hash = %finalize_tx, "Deposit finalized!");

                        // Mark as finalized in state
                        if let Err(e) = self.state_manager.mark_deposit_finalized(request_id).await
                        {
                            warn!(%request_id, error = %e, "Failed to mark deposit finalized");
                        }
                    }
                }
            }
            Err(e) => {
                self.metrics.record_signature_failure();
                error!(%request_id, error = %e, "Failed to submit deposit signature");
            }
        }

        Ok(())
    }

    async fn handle_burn(&self, burn: DetectedBurn) -> Result<()> {
        self.metrics.record_burn_detected();

        // Check and insert into in-flight set
        let Some(_guard) = InFlightGuard::try_insert(&self.in_flight_burns, burn.burn_id) else {
            debug!(burn_id = %burn.burn_id, "Burn already in-flight, skipping");
            return Ok(());
        };

        // Check if already processed
        if self.state_manager.has_processed_burn(&burn.burn_id).await {
            debug!(burn_id = %burn.burn_id, "Burn already processed");
            return Ok(());
        }

        info!(
            burn_id = %burn.burn_id,
            origin_chain = %burn.origin_chain_id,
            tempo_block = %burn.tempo_block_number,
            "Detected burn, initiating header relay and proof generation"
        );

        let Some(origin_client) = self.origin_clients.get(&burn.origin_chain_id) else {
            warn!(
                origin_chain = %burn.origin_chain_id,
                "No origin client configured for this chain"
            );
            return Ok(());
        };

        let Some(tempo_client) = &self.tempo_client else {
            warn!("No Tempo client configured, cannot generate burn proof");
            return Ok(());
        };

        // Fetch block header and receipts from Tempo for proof generation
        let rpc_start = std::time::Instant::now();
        let header = match tempo_client.get_block_header(burn.tempo_block_number).await {
            Ok(h) => {
                self.metrics.record_rpc_latency(rpc_start.elapsed().as_secs_f64());
                h
            }
            Err(e) => {
                warn!(
                    tempo_block = %burn.tempo_block_number,
                    error = %e,
                    "Failed to fetch Tempo block header"
                );
                return Ok(());
            }
        };

        let rpc_start = std::time::Instant::now();
        let receipts = match tempo_client.get_block_receipts(burn.tempo_block_number).await {
            Ok(r) => {
                self.metrics.record_rpc_latency(rpc_start.elapsed().as_secs_f64());
                r
            }
            Err(e) => {
                warn!(
                    tempo_block = %burn.tempo_block_number,
                    error = %e,
                    "Failed to fetch Tempo block receipts"
                );
                return Ok(());
            }
        };

        // Find the burn event in the receipts
        let Some((tx_index, log_index)) =
            TempoClient::find_burn_in_receipts(&receipts, burn.burn_id)
        else {
            warn!(
                burn_id = %burn.burn_id,
                tempo_block = %burn.tempo_block_number,
                "Burn event not found in block receipts"
            );
            return Ok(());
        };

        debug!(
            burn_id = %burn.burn_id,
            tx_index,
            log_index,
            "Found burn event in receipts"
        );

        // Check if header is already finalized on origin
        let header_finalized = match origin_client
            .is_header_finalized(burn.tempo_block_number)
            .await
        {
            Ok(finalized) => finalized,
            Err(e) => {
                warn!(
                    origin_chain = %burn.origin_chain_id,
                    error = %e,
                    "Could not check header finalization status"
                );
                return Ok(());
            }
        };

        if !header_finalized {
            // Need to relay header first
            info!(
                origin_chain = %burn.origin_chain_id,
                tempo_block = %burn.tempo_block_number,
                "Header not yet finalized, submitting to light client"
            );

            // Fetch finalization certificate from consensus layer for validator signatures
            let (epoch, signature) = match &self.consensus_client {
                Some(consensus_client) => {
                    match consensus_client
                        .get_finalization(burn.tempo_block_number)
                        .await
                    {
                        Ok(Some(cert)) => {
                            debug!(
                                tempo_block = %burn.tempo_block_number,
                                epoch = cert.epoch,
                                "Fetched finalization certificate from consensus"
                            );

                            // Extract the BLS signature from the certificate
                            match crate::consensus_client::extract_bls_signature_from_certificate(
                                &cert.certificate,
                            ) {
                                Ok(sig) => (cert.epoch, sig),
                                Err(e) => {
                                    warn!(
                                        tempo_block = %burn.tempo_block_number,
                                        error = %e,
                                        "Failed to extract BLS signature from certificate"
                                    );
                                    return Ok(());
                                }
                            }
                        }
                        Ok(None) => {
                            warn!(
                                tempo_block = %burn.tempo_block_number,
                                "Block not yet finalized by consensus, will retry later"
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            warn!(
                                tempo_block = %burn.tempo_block_number,
                                error = %e,
                                "Failed to fetch finalization certificate from consensus"
                            );
                            return Ok(());
                        }
                    }
                }
                None => {
                    // No consensus client configured - use empty signature.
                    // This path is only reachable in test_mode (validated at startup).
                    debug!(
                        tempo_block = %burn.tempo_block_number,
                        "No consensus client configured, using empty signature (test_mode=true)"
                    );
                    (0u64, alloy::primitives::Bytes::new())
                }
            };

            match origin_client
                .submit_header(
                    burn.tempo_block_number,
                    header.block_hash,
                    header.state_root,
                    header.receipts_root,
                    epoch,
                    signature,
                )
                .await
            {
                Ok(tx_hash) => {
                    if !tx_hash.is_zero() {
                        info!(
                            origin_chain = %burn.origin_chain_id,
                            tempo_block = %burn.tempo_block_number,
                            tx_hash = %tx_hash,
                            epoch,
                            "Header submitted to light client"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        origin_chain = %burn.origin_chain_id,
                        tempo_block = %burn.tempo_block_number,
                        error = %e,
                        "Failed to submit header to light client"
                    );
                    return Ok(());
                }
            }

            // Wait for header finalization (it should be instant after submission in most cases)
            // In production, we might want to wait and retry
            match origin_client
                .is_header_finalized(burn.tempo_block_number)
                .await
            {
                Ok(true) => {
                    info!(
                        origin_chain = %burn.origin_chain_id,
                        tempo_block = %burn.tempo_block_number,
                        "Header now finalized"
                    );
                }
                Ok(false) => {
                    warn!(
                        origin_chain = %burn.origin_chain_id,
                        tempo_block = %burn.tempo_block_number,
                        "Header still not finalized after submission, will retry later"
                    );
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        origin_chain = %burn.origin_chain_id,
                        error = %e,
                        "Could not verify header finalization"
                    );
                    return Ok(());
                }
            }
        } else {
            info!(
                origin_chain = %burn.origin_chain_id,
                tempo_block = %burn.tempo_block_number,
                "Header already finalized, proceeding to unlock"
            );
        }

        // Generate validator-attested burn proof
        // F-03 fix: Use validator attestations instead of binary Merkle proofs
        // Binary Merkle proofs are incompatible with Ethereum's MPT receipt trie
        let proof_start = std::time::Instant::now();
        
        let mut attestation = AttestationGenerator::<()>::create_unsigned_attestation(
            burn.burn_id,
            burn.tempo_block_number,
            burn.origin_chain_id,
            burn.origin_token,
            burn.origin_recipient,
            burn.amount,
        );

        // Sign the attestation with our validator key
        // In production, multiple validators would sign and we'd collect threshold signatures
        let Some(signer) = &self.signer else {
            error!(
                burn_id = %burn.burn_id,
                "No signer configured for burn attestation"
            );
            return Ok(());
        };

        let tempo_chain_id = self.config.tempo_chain_id;
        let attestation_digest = attestation.compute_digest(tempo_chain_id);
        
        match signer.sign_hash(&attestation_digest).await {
            Ok(signature) => {
                let sig_bytes: Vec<u8> = signature.to_vec();
                attestation.signatures.push(alloy::primitives::Bytes::from(sig_bytes));
                self.metrics.record_proof_generation(proof_start.elapsed().as_secs_f64());
            }
            Err(e) => {
                error!(
                    burn_id = %burn.burn_id,
                    error = %e,
                    "Failed to sign burn attestation"
                );
                return Ok(());
            }
        }

        info!(
            burn_id = %burn.burn_id,
            signatures = attestation.signatures.len(),
            "Generated burn attestation"
        );

        // Encode attestation for on-chain verification
        // The escrow's unlockWithProof expects ABI-encoded:
        // (bytes32 burnId, uint64 tempoHeight, address originToken, address recipient, uint64 amount, bytes[] signatures)
        let encoded_proof = attestation.encode_proof();

        match origin_client
            .unlock_with_proof(
                burn.burn_id,
                burn.origin_recipient,
                burn.amount,
                encoded_proof,
                burn.tempo_block_number,
            )
            .await
        {
            Ok(tx_hash) => {
                if !tx_hash.is_zero() {
                    self.metrics.record_burn_unlocked();
                    info!(
                        burn_id = %burn.burn_id,
                        tx_hash = %tx_hash,
                        origin_chain = %burn.origin_chain_id,
                        "Tokens unlocked on origin chain!"
                    );

                    // Record in persistent state
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    if let Err(e) = self
                        .state_manager
                        .record_processed_burn(ProcessedBurn {
                            burn_id: burn.burn_id,
                            origin_chain_id: burn.origin_chain_id,
                            origin_recipient: burn.origin_recipient,
                            amount: burn.amount,
                            tempo_block_number: burn.tempo_block_number,
                            unlock_tx_hash: Some(tx_hash),
                            processed_at: now,
                        })
                        .await
                    {
                        warn!(burn_id = %burn.burn_id, error = %e, "Failed to persist burn");
                    }
                }
            }
            Err(e) => {
                error!(
                    burn_id = %burn.burn_id,
                    error = %e,
                    "Failed to unlock tokens on origin chain"
                );
            }
        }

        Ok(())
    }
}


