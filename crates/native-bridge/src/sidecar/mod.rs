//! Bridge sidecar components.

pub mod aggregator;
pub mod submitter;
pub mod watcher;

use std::{collections::HashMap, sync::Arc};

use commonware_codec::Read as CwRead;
use commonware_cryptography::bls12381::primitives::{sharing::Sharing, variant::MinSig};
use tokio::sync::{Mutex, mpsc};

use crate::{
    config::Config,
    error::{BridgeError, Result},
    message::Message,
    signer::BLSSigner,
};

use self::{aggregator::Aggregator, submitter::Submitter, watcher::ChainWatcher};

/// The bridge sidecar orchestrates watching, signing, aggregating, and submitting.
pub struct BridgeSidecar {
    #[allow(dead_code)]
    config: Config,
    signer: BLSSigner,
    aggregator: Arc<Mutex<Aggregator>>,
    watchers: Vec<ChainWatcher>,
    submitters: HashMap<u64, Submitter>,
}

impl BridgeSidecar {
    /// Create a new bridge sidecar.
    pub async fn new(config: Config) -> Result<Self> {
        // Load key share from file
        let signer_config = config
            .signer
            .as_ref()
            .ok_or_else(|| crate::error::BridgeError::Config("[signer] section required".into()))?;
        let signer = BLSSigner::from_file(&signer_config.bls_key_share_file)?;

        // Load sharing from file
        let sharing_file = config.threshold.sharing_file.as_ref().ok_or_else(|| {
            crate::error::BridgeError::Config(
                "[threshold].sharing_file required in standalone mode".into(),
            )
        })?;
        let sharing = load_sharing(sharing_file)?;

        let aggregator = Arc::new(Mutex::new(Aggregator::new(sharing, config.threshold.epoch)));

        let mut watchers = Vec::new();
        let mut submitters = HashMap::new();

        for chain in &config.chains {
            let watcher = ChainWatcher::new(chain.clone()).await?;
            watchers.push(watcher);

            let submitter = Submitter::new(chain.clone()).await?;
            submitters.insert(chain.chain_id, submitter);
        }

        Ok(Self {
            config,
            signer,
            aggregator,
            watchers,
            submitters,
        })
    }

    /// Run the sidecar main loop.
    pub async fn run(self) -> Result<()> {
        let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(1000);

        // Spawn watchers
        for watcher in self.watchers {
            let tx = msg_tx.clone();
            let chain_id = watcher.chain_id();
            tokio::spawn(async move {
                if let Err(e) = watcher.run(tx).await {
                    tracing::error!(chain = chain_id, "watcher error: {e}");
                }
            });
        }

        let signer = Arc::new(self.signer);
        let aggregator = self.aggregator;
        let submitters = Arc::new(self.submitters);

        // Main processing loop
        while let Some(msg) = msg_rx.recv().await {
            let attestation_hash = msg.attestation_hash();
            tracing::info!(
                origin = msg.origin_chain_id,
                dest = msg.destination_chain_id,
                hash = %attestation_hash,
                "received message"
            );

            // Sign our partial
            let partial = match signer.sign_partial(attestation_hash) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("signing error: {e}");
                    continue;
                }
            };

            // TODO: Broadcast partial via P2P gossip
            // For now, just add to local aggregator

            // Add partial to aggregator
            let maybe_sig = {
                let mut agg = aggregator.lock().await;
                agg.add_partial(attestation_hash, partial, &msg)
            };

            // If threshold reached, submit
            if let Some((sig, message)) = maybe_sig
                && let Some(submitter) = submitters.get(&message.destination_chain_id)
            {
                match submitter.submit(&message, &sig).await {
                    Ok(tx_hash) => {
                        tracing::info!(
                            dest = message.destination_chain_id,
                            %tx_hash,
                            "submitted attestation"
                        );
                    }
                    Err(e) => {
                        tracing::error!("submission error: {e}");
                    }
                }
            }
        }

        Ok(())
    }
}

/// Load a sharing from a hex-encoded file.
///
/// Uses MinSig variant (same as consensus) so we can reuse the same DKG shares.
pub fn load_sharing(path: &str) -> Result<Sharing<MinSig>> {
    use commonware_utils::NZU32;

    let hex_content = std::fs::read_to_string(path)
        .map_err(|e| BridgeError::Config(format!("failed to read sharing file {path}: {e}")))?;

    let hex_trimmed = hex_content.trim().trim_start_matches("0x");
    let bytes = const_hex::decode(hex_trimmed)
        .map_err(|e| BridgeError::Config(format!("invalid hex in sharing file: {e}")))?;

    // Maximum supported validator count for the bridge (reasonable upper bound)
    let max_validators = NZU32!(1000);

    Sharing::<MinSig>::read_cfg(&mut &bytes[..], &max_validators)
        .map_err(|e| BridgeError::Config(format!("failed to parse sharing: {e}")))
}
