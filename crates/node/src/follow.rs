//! Follow mode synchronization via consensus subscription.
//!
//! This module implements block synchronization by subscribing to
//! `consensus_subscribe` from a remote validator node. It receives
//! finalization events with BLS threshold certificates and verifies
//! the signatures before submitting blocks to the execution engine.

use std::{collections::HashMap, ops::Deref, sync::Arc, time::Duration};

use alloy::{network::Ethereum, transports::ws::WsConnect};
use alloy_primitives::{B256, hex};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_engine::ForkchoiceState;
use alloy_rpc_types_eth::Transaction;
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read as CommonwareRead, ReadExt, Write as CommonwareWrite};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::{Scheme, Signature},
        types::{Proposal, Subject},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, certificate::Scheme as _};
use commonware_parallel::Sequential;
use eyre::{Context as _, OptionExt, bail};
use jsonrpsee::ws_client::WsClientBuilder;
use rand_core::CryptoRngCore;
use reth_node_builder::EngineApiMessageVersion;
use reth_primitives_traits::{AlloyBlockHeader, Block as BlockTrait};
use reth_provider::{BlockNumReader, HeaderProvider};
use reth_tracing::tracing::{debug, error, info, warn};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{Block, TempoHeader, TempoTxEnvelope};

use crate::{TempoFullNode, rpc::consensus::TempoConsensusApiClient};

/// Namespace used for BLS signature domain separation.
const NAMESPACE: &[u8] = b"TEMPO";

/// Digest wrapper around B256 for use with commonware consensus types.
/// This is a local copy of the Digest type used by commonware-node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
struct Digest(B256);

impl commonware_utils::Array for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for Digest {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl commonware_math::algebra::Random for Digest {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut array = B256::ZERO;
        rng.fill_bytes(&mut *array);
        Self(array)
    }
}

impl commonware_cryptography::Digest for Digest {
    const EMPTY: Self = Self(B256::ZERO);
}

impl FixedSize for Digest {
    const SIZE: usize = 32;
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl CommonwareRead for Digest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let array = <[u8; 32]>::read(buf)?;
        Ok(Self(B256::new(array)))
    }
}

impl commonware_utils::Span for Digest {}

impl CommonwareWrite for Digest {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf)
    }
}

/// Type alias for the RPC block type compatible with DebugNode.
type RpcBlock = alloy_rpc_types_eth::Block<Transaction<TempoTxEnvelope>, TempoHeader>;

/// Type alias for the BLS threshold scheme used for certificate verification.
type VerifierScheme = Scheme<commonware_cryptography::ed25519::PublicKey, MinSig, Sequential>;

/// Configuration for the follow sync client.
#[derive(Debug, Clone)]
pub struct FollowSyncConfig {
    /// WebSocket URL to connect to (e.g., "wss://rpc.testnet.tempo.xyz").
    pub ws_url: String,
    /// Maximum reconnection attempts before giving up.
    pub max_reconnect_attempts: u32,
    /// Delay between reconnection attempts.
    pub reconnect_delay: Duration,
    /// Whether to skip certificate verification (unsafe, for testing only).
    pub skip_verification: bool,
}

impl FollowSyncConfig {
    /// Create a new config with the given WebSocket URL.
    pub fn new(ws_url: String) -> Self {
        Self {
            ws_url,
            max_reconnect_attempts: u32::MAX,
            reconnect_delay: Duration::from_secs(5),
            skip_verification: false,
        }
    }

    /// Set whether to skip certificate verification (unsafe).
    pub fn with_skip_verification(mut self, skip: bool) -> Self {
        self.skip_verification = skip;
        self
    }
}

/// Manages BLS threshold verification schemes for different epochs.
struct SchemeManager {
    /// Schemes keyed by epoch.
    schemes: HashMap<u64, VerifierScheme>,
}

impl SchemeManager {
    fn new() -> Self {
        Self {
            schemes: HashMap::new(),
        }
    }

    /// Register a scheme for an epoch from the DKG outcome.
    fn register_from_outcome(&mut self, outcome: &OnchainDkgOutcome) {
        let epoch = outcome.epoch.get();
        let scheme = Scheme::verifier(
            NAMESPACE,
            outcome.players().clone(),
            outcome.sharing().clone(),
            Sequential,
        );
        self.schemes.insert(epoch, scheme);
        debug!(epoch, "registered verification scheme for epoch");
    }

    /// Get the scheme for a given epoch.
    fn get(&self, epoch: u64) -> Option<&VerifierScheme> {
        self.schemes.get(&epoch)
    }

    /// Check if we have a scheme for the given epoch.
    fn has(&self, epoch: u64) -> bool {
        self.schemes.contains_key(&epoch)
    }
}

/// Follow sync client that subscribes to consensus events and syncs blocks.
pub struct FollowSync {
    config: FollowSyncConfig,
    node: TempoFullNode,
}

impl FollowSync {
    /// Create a new follow sync client.
    pub fn new(config: FollowSyncConfig, node: TempoFullNode) -> Self {
        Self { config, node }
    }

    /// Run the follow sync loop.
    ///
    /// This will subscribe to consensus events and process finalized blocks.
    /// On disconnection, it will attempt to reconnect.
    pub async fn run(self) -> eyre::Result<()> {
        let mut reconnect_attempts = 0;

        loop {
            match self.run_inner().await {
                Ok(()) => {
                    info!("follow sync completed normally");
                    return Ok(());
                }
                Err(e) => {
                    reconnect_attempts += 1;
                    if reconnect_attempts > self.config.max_reconnect_attempts {
                        return Err(e).wrap_err("follow sync failed after max reconnect attempts");
                    }
                    warn!(
                        error = %e,
                        attempt = reconnect_attempts,
                        "follow sync disconnected, reconnecting..."
                    );
                    tokio::time::sleep(self.config.reconnect_delay).await;
                }
            }
        }
    }

    /// Initialize scheme manager with the genesis DKG outcome.
    fn init_scheme_manager(&self) -> eyre::Result<SchemeManager> {
        let mut manager = SchemeManager::new();

        // Read the genesis block header to get the initial DKG outcome
        let genesis_header = self
            .node
            .provider
            .header_by_number(0)
            .map_err(|e| eyre::eyre!("failed to read genesis header: {e}"))?
            .ok_or_eyre("genesis header not found")?;

        let outcome = OnchainDkgOutcome::read(&mut genesis_header.extra_data().as_ref())
            .wrap_err("failed to decode DKG outcome from genesis extra_data")?;

        manager.register_from_outcome(&outcome);
        info!(
            epoch = outcome.epoch.get(),
            "initialized verification scheme from genesis"
        );

        // Scan local chain for any additional DKG outcomes (in case we're catching up)
        self.scan_local_chain_for_schemes(&mut manager)?;

        Ok(manager)
    }

    /// Scan local chain for DKG outcomes and register schemes.
    ///
    /// This is used during initialization to recover schemes for epochs
    /// that we may have missed if we're catching up.
    fn scan_local_chain_for_schemes(&self, manager: &mut SchemeManager) -> eyre::Result<()> {
        let best_number = self
            .node
            .provider
            .best_block_number()
            .map_err(|e| eyre::eyre!("failed to get best block number: {e}"))?;

        if best_number == 0 {
            return Ok(());
        }

        debug!(best_number, "scanning local chain for DKG outcomes");

        // Scan all local blocks for DKG outcomes
        for block_num in 1..=best_number {
            let header = self
                .node
                .provider
                .header_by_number(block_num)
                .map_err(|e| eyre::eyre!("failed to read header {block_num}: {e}"))?;

            let Some(header) = header else {
                continue;
            };

            if let Ok(outcome) = OnchainDkgOutcome::read(&mut header.extra_data().as_ref())
                && !manager.has(outcome.epoch.get())
            {
                manager.register_from_outcome(&outcome);
                info!(
                    block_num,
                    epoch = outcome.epoch.get(),
                    "recovered verification scheme from local chain"
                );
            }
        }

        Ok(())
    }

    /// Fetch and register a missing scheme by scanning remote blocks.
    ///
    /// Searches backwards from `start_block` to find a boundary block containing
    /// the DKG outcome for the target epoch.
    async fn fetch_missing_scheme<P: Provider<Ethereum>>(
        &self,
        eth_provider: &P,
        manager: &mut SchemeManager,
        target_epoch: u64,
        start_block: u64,
    ) -> eyre::Result<()> {
        info!(
            target_epoch,
            start_block, "searching for missing DKG outcome"
        );

        // Search backwards for the boundary block containing this epoch's DKG outcome
        for block_num in (0..=start_block).rev() {
            let rpc_block: Option<RpcBlock> = eth_provider
                .raw_request(
                    "eth_getBlockByNumber".into(),
                    (format!("0x{block_num:x}"), false),
                )
                .await
                .wrap_err_with(|| format!("failed to fetch block {block_num}"))?;

            let Some(rpc_block) = rpc_block else {
                continue;
            };

            if let Ok(outcome) =
                OnchainDkgOutcome::read(&mut rpc_block.header.extra_data().as_ref())
            {
                let outcome_epoch = outcome.epoch.get();

                if !manager.has(outcome_epoch) {
                    manager.register_from_outcome(&outcome);
                    info!(
                        block_num,
                        epoch = outcome_epoch,
                        "recovered verification scheme from remote"
                    );
                }

                if outcome_epoch == target_epoch {
                    return Ok(());
                }

                // If we found an epoch lower than target, we've gone too far back
                if outcome_epoch < target_epoch {
                    break;
                }
            }
        }

        bail!("could not find DKG outcome for epoch {target_epoch}");
    }

    /// Verify a finalization certificate.
    fn verify_certificate(
        &self,
        scheme: &VerifierScheme,
        epoch: u64,
        view: u64,
        parent_view: u64,
        digest: B256,
        certificate_hex: &str,
    ) -> eyre::Result<bool> {
        // Decode the certificate from hex
        let certificate_bytes =
            hex::decode(certificate_hex).wrap_err("failed to decode certificate hex")?;

        let certificate: Signature<MinSig> = Signature::read(&mut certificate_bytes.as_slice())
            .wrap_err("failed to parse BLS signature from certificate bytes")?;

        // Construct the proposal that was signed
        let round = Round::new(Epoch::new(epoch), View::new(view));
        let parent = View::new(parent_view);
        let proposal = Proposal::new(round, parent, Digest(digest));

        // Construct the subject for finalization
        let subject = Subject::Finalize {
            proposal: &proposal,
        };

        // Verify the certificate
        let mut rng = rand::rngs::OsRng;
        let is_valid = scheme.verify_certificate(&mut rng, subject, &certificate);

        Ok(is_valid)
    }

    async fn run_inner(&self) -> eyre::Result<()> {
        info!(url = %self.config.ws_url, "connecting to consensus subscription");

        // Initialize scheme manager
        let mut scheme_manager = if self.config.skip_verification {
            warn!("certificate verification is DISABLED - this is unsafe!");
            SchemeManager::new()
        } else {
            self.init_scheme_manager()?
        };

        // Connect to consensus subscription using jsonrpsee
        let ws_client = WsClientBuilder::default()
            .max_request_size(128 * 1024 * 1024)
            .max_response_size(128 * 1024 * 1024)
            .connection_timeout(Duration::from_secs(30))
            .build(&self.config.ws_url)
            .await
            .wrap_err("failed to connect to consensus WebSocket")?;

        let mut subscription = ws_client
            .subscribe_events()
            .await
            .wrap_err("failed to subscribe to consensus events")?;

        // Also connect an eth provider for fetching full blocks
        let eth_provider = ProviderBuilder::new()
            .connect_ws(WsConnect::new(&self.config.ws_url))
            .await
            .wrap_err("failed to connect eth provider")?;

        info!("connected to consensus subscription, processing events...");

        // Track last finalized for forkchoice
        let mut last_finalized_hash: Option<B256> = None;
        let mut safe_block_hash: Option<B256> = None;

        while let Some(event_result) = subscription.next().await {
            let event = event_result.wrap_err("failed to receive event")?;

            match event {
                crate::rpc::consensus::Event::Finalized { block, seen } => {
                    let digest = block.digest;
                    let epoch = block.epoch;
                    let view = block.view;
                    let parent_view = block.parent_view;
                    let certificate_hex = &block.certificate;

                    debug!(
                        %digest,
                        epoch,
                        view,
                        parent_view,
                        height = ?block.height,
                        seen,
                        "received finalization event"
                    );

                    // Verify the BLS threshold certificate
                    if !self.config.skip_verification {
                        // Try to get scheme, or fetch it if missing
                        if !scheme_manager.has(epoch) {
                            // We're missing the scheme for this epoch - try to recover it
                            // Use the block height if available, otherwise fetch latest block number
                            let search_start = if let Some(height) = block.height {
                                height.saturating_sub(1)
                            } else {
                                let latest: alloy_rpc_types_eth::Block = eth_provider
                                    .raw_request("eth_getBlockByNumber".into(), ("latest", false))
                                    .await
                                    .wrap_err("failed to fetch latest block")?;
                                latest.header.number.saturating_sub(1)
                            };

                            self.fetch_missing_scheme(
                                &eth_provider,
                                &mut scheme_manager,
                                epoch,
                                search_start,
                            )
                            .await?;
                        }

                        let scheme = scheme_manager.get(epoch).ok_or_else(|| {
                            eyre::eyre!("no verification scheme registered for epoch {epoch}")
                        })?;

                        let is_valid = self.verify_certificate(
                            scheme,
                            epoch,
                            view,
                            parent_view,
                            digest,
                            certificate_hex,
                        )?;

                        if !is_valid {
                            bail!(
                                "certificate verification failed for block {digest} at epoch {epoch} view {view}"
                            );
                        }

                        debug!(%digest, epoch, view, "certificate verified successfully");
                    } else {
                        debug!(%digest, "certificate verification skipped (disabled)");
                    }

                    // Fetch the full block from eth RPC using raw request
                    let rpc_block: Option<RpcBlock> = eth_provider
                        .raw_request("eth_getBlockByHash".into(), (digest, true))
                        .await
                        .wrap_err("failed to fetch block by hash")?;

                    let rpc_block = rpc_block.ok_or_eyre("block not found on remote node")?;

                    // Convert RPC block to primitive block
                    let block: Block = rpc_block
                        .into_consensus_block()
                        .map_transactions(|tx| tx.into_inner());

                    let sealed_block = block.seal_slow();
                    let block_hash = sealed_block.hash();
                    let block_number = sealed_block.header().inner.number;

                    // Check if this is an epoch boundary block and register new scheme if so
                    if !self.config.skip_verification
                        && let Ok(outcome) = OnchainDkgOutcome::read(
                            &mut sealed_block.header().extra_data().as_ref(),
                        )
                    {
                        // This is a boundary block with a new DKG outcome
                        scheme_manager.register_from_outcome(&outcome);
                        info!(
                            block_number,
                            next_epoch = outcome.epoch.get(),
                            "registered new verification scheme from boundary block"
                        );
                    }

                    debug!(
                        %block_hash,
                        block_number,
                        txs = sealed_block.body().transactions.len(),
                        "fetched full block, submitting to engine"
                    );

                    // Submit to execution engine
                    let payload_status = self
                        .node
                        .add_ons_handle
                        .beacon_engine_handle
                        .new_payload(TempoExecutionData {
                            block: Arc::new(sealed_block),
                            validator_set: None,
                        })
                        .await
                        .wrap_err("failed to submit payload to engine")?;

                    if payload_status.is_invalid() {
                        error!(
                            %block_hash,
                            status = ?payload_status,
                            "engine rejected block payload"
                        );
                        continue;
                    }

                    debug!(%block_hash, status = ?payload_status, "payload accepted");

                    // Update forkchoice
                    let new_safe = last_finalized_hash;
                    let new_finalized = safe_block_hash;

                    let forkchoice = ForkchoiceState {
                        head_block_hash: block_hash,
                        safe_block_hash: new_safe.unwrap_or(block_hash),
                        finalized_block_hash: new_finalized.unwrap_or(block_hash),
                    };

                    let fcu_response = self
                        .node
                        .add_ons_handle
                        .beacon_engine_handle
                        .fork_choice_updated(forkchoice, None, EngineApiMessageVersion::V3)
                        .await
                        .wrap_err("failed to send fork choice update")?;

                    if fcu_response.is_invalid() {
                        error!(
                            %block_hash,
                            status = ?fcu_response,
                            "engine rejected fork choice update"
                        );
                        continue;
                    }

                    info!(
                        %block_hash,
                        block_number,
                        "block finalized and submitted to engine"
                    );

                    // Update tracking
                    safe_block_hash = last_finalized_hash;
                    last_finalized_hash = Some(block_hash);
                }
                crate::rpc::consensus::Event::Notarized { block, .. } => {
                    debug!(
                        digest = %block.digest,
                        epoch = block.epoch,
                        view = block.view,
                        "received notarization event (ignoring, waiting for finalization)"
                    );
                }
                crate::rpc::consensus::Event::Nullified { epoch, view, .. } => {
                    debug!(epoch, view, "received nullification event");
                }
            }
        }

        Ok(())
    }
}
