//! Bridge service for integration into the validator.
//!
//! Unlike the standalone BridgeSidecar which loads config from files,
//! BridgeService accepts injected dependencies for use within the validator.

use std::{collections::HashMap, sync::Arc};

use commonware_cryptography::bls12381::primitives::{
    group::Share, sharing::Sharing, variant::MinSig,
};
use tokio::sync::{Mutex, mpsc};

use crate::{
    config::ChainConfig,
    error::Result,
    gossip::{BridgeGossip, BridgeGossipMessage, MessageContext, NoOpGossip},
    message::Message,
    sidecar::{aggregator::Aggregator, submitter::Submitter, watcher::ChainWatcher},
    signer::BLSSigner,
};

/// Configuration for the bridge service.
#[derive(Debug, Clone)]
pub struct BridgeServiceConfig {
    /// Chain configurations (which chains to watch/submit to).
    pub chains: Vec<ChainConfig>,
    /// Current epoch.
    pub epoch: u64,
}

/// Bridge service that can be integrated into the validator.
///
/// Accepts injected BLS share and sharing instead of loading from files.
pub struct BridgeService<G: BridgeGossip = NoOpGossip> {
    signer: BLSSigner,
    aggregator: Arc<Mutex<Aggregator>>,
    watchers: Vec<ChainWatcher>,
    submitters: HashMap<u64, Submitter>,
    gossip: G,
}

impl BridgeService<NoOpGossip> {
    /// Create a new bridge service without gossip (single-validator mode).
    ///
    /// # Arguments
    /// * `share` - The validator's BLS signing share (same as used for consensus)
    /// * `sharing` - The DKG sharing/polynomial (from chain or config)
    /// * `config` - Bridge service configuration (chains, epoch)
    pub async fn new(
        share: Share,
        sharing: Sharing<MinSig>,
        config: BridgeServiceConfig,
    ) -> Result<Self> {
        Self::with_gossip(share, sharing, config, NoOpGossip).await
    }
}

impl<G: BridgeGossip + 'static> BridgeService<G> {
    /// Create a new bridge service with gossip support.
    ///
    /// # Arguments
    /// * `share` - The validator's BLS signing share (same as used for consensus)
    /// * `sharing` - The DKG sharing/polynomial (from chain or config)
    /// * `config` - Bridge service configuration (chains, epoch)
    /// * `gossip` - The gossip implementation for P2P partial signature sharing
    pub async fn with_gossip(
        share: Share,
        sharing: Sharing<MinSig>,
        config: BridgeServiceConfig,
        gossip: G,
    ) -> Result<Self> {
        let signer = BLSSigner::new(share);
        let aggregator = Arc::new(Mutex::new(Aggregator::new(sharing, config.epoch)));

        let mut watchers = Vec::new();
        let mut submitters = HashMap::new();

        for chain in &config.chains {
            let watcher = ChainWatcher::new(chain.clone()).await?;
            watchers.push(watcher);

            let submitter = match &chain.submitter_private_key {
                Some(pk) => {
                    tracing::info!(
                        chain = chain.name,
                        chain_id = chain.chain_id,
                        "bridge: submitter configured with signer"
                    );
                    Submitter::with_signer(chain.clone(), pk).await?
                }
                None => {
                    tracing::warn!(
                        chain = chain.name,
                        chain_id = chain.chain_id,
                        "bridge: submitter in simulation-only mode (no private key)"
                    );
                    Submitter::new(chain.clone()).await?
                }
            };
            submitters.insert(chain.chain_id, submitter);
        }

        Ok(Self {
            signer,
            aggregator,
            watchers,
            submitters,
            gossip,
        })
    }

    /// Run the bridge service main loop.
    ///
    /// This spawns chain watchers and processes messages until shutdown.
    pub async fn run(self) -> Result<()> {
        let Self {
            signer,
            aggregator,
            watchers,
            submitters,
            mut gossip,
        } = self;

        let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(1000);

        for watcher in watchers {
            let tx = msg_tx.clone();
            let chain_id = watcher.chain_id();
            tokio::spawn(async move {
                if let Err(e) = watcher.run(tx).await {
                    tracing::error!(chain = chain_id, "bridge watcher error: {e}");
                }
            });
        }

        let signer = Arc::new(signer);
        let submitters = Arc::new(submitters);

        tracing::info!("bridge service started");

        loop {
            tokio::select! {
                Some(msg) = msg_rx.recv() => {
                    handle_chain_message(
                        &gossip,
                        msg,
                        &signer,
                        &aggregator,
                        &submitters,
                    ).await;
                }

                Some(gossip_msg) = gossip.recv() => {
                    handle_gossip_message(
                        gossip_msg,
                        &aggregator,
                        &submitters,
                    ).await;
                }

                else => break,
            }
        }

        Ok(())
    }

    /// Update the sharing (e.g., after epoch change).
    pub async fn update_sharing(&self, epoch: u64, sharing: Sharing<MinSig>) {
        let mut agg = self.aggregator.lock().await;
        agg.set_epoch(epoch);
        agg.set_sharing(sharing);
        tracing::info!(epoch, "bridge: updated sharing for new epoch");
    }
}

/// Handle a message from a chain watcher (MessageSent event).
async fn handle_chain_message<G: BridgeGossip>(
    gossip: &G,
    msg: Message,
    signer: &Arc<BLSSigner>,
    aggregator: &Arc<Mutex<Aggregator>>,
    submitters: &Arc<HashMap<u64, Submitter>>,
) {
    let attestation_hash = msg.attestation_hash();
    tracing::info!(
        origin = msg.origin_chain_id,
        dest = msg.destination_chain_id,
        hash = %attestation_hash,
        "bridge: received message from chain"
    );

    let partial = match signer.sign_partial(attestation_hash) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("bridge signing error: {e}");
            return;
        }
    };

    tracing::debug!(
        index = partial.index,
        hash = %attestation_hash,
        "bridge: signed partial"
    );

    let gossip_msg = BridgeGossipMessage::new(
        attestation_hash,
        partial.clone(),
        MessageContext::from_message(&msg),
    );
    if let Err(e) = gossip.broadcast(gossip_msg).await {
        tracing::warn!("bridge: failed to broadcast partial: {e}");
    }

    let maybe_sig = {
        let mut agg = aggregator.lock().await;
        agg.add_partial(attestation_hash, partial, &msg)
    };

    if let Some((sig, message)) = maybe_sig {
        submit_attestation(&message, &sig, submitters).await;
    }
}

/// Handle a gossip message containing a partial signature from another validator.
async fn handle_gossip_message(
    gossip_msg: BridgeGossipMessage,
    aggregator: &Arc<Mutex<Aggregator>>,
    submitters: &Arc<HashMap<u64, Submitter>>,
) {
    tracing::debug!(
        index = gossip_msg.partial.index,
        hash = %gossip_msg.attestation_hash,
        "bridge: received partial from peer"
    );

    let msg = gossip_msg.context.to_message();

    if msg.attestation_hash() != gossip_msg.attestation_hash {
        tracing::warn!(
            expected = %msg.attestation_hash(),
            actual = %gossip_msg.attestation_hash,
            "bridge: attestation hash mismatch, ignoring"
        );
        return;
    }

    // TODO: Verify the partial signature is valid for the claimed index
    // This requires access to the public polynomial to check e(sig, G2) == e(H(m), pk_i)

    let maybe_sig = {
        let mut agg = aggregator.lock().await;
        agg.add_partial(gossip_msg.attestation_hash, gossip_msg.partial, &msg)
    };

    if let Some((sig, message)) = maybe_sig {
        submit_attestation(&message, &sig, submitters).await;
    }
}

/// Submit an aggregated attestation to the destination chain.
async fn submit_attestation(
    message: &Message,
    sig: &crate::attestation::AggregatedSignature,
    submitters: &Arc<HashMap<u64, Submitter>>,
) {
    if let Some(submitter) = submitters.get(&message.destination_chain_id) {
        match submitter.submit(message, sig).await {
            Ok(tx_hash) => {
                tracing::info!(
                    dest = message.destination_chain_id,
                    %tx_hash,
                    "bridge: submitted attestation"
                );
            }
            Err(e) => {
                tracing::error!("bridge submission error: {e}");
            }
        }
    } else {
        tracing::warn!(
            dest = message.destination_chain_id,
            "bridge: no submitter for destination chain"
        );
    }
}
