//! Certified block provider for follow mode.
//!
//! Wraps RPC block fetching with finalization certificate verification and storage.
//!
//! # Ordering and Trust Model
//!
//! This provider assumes blocks are processed in order. The identity chain is built
//! by extracting DKG outcomes from epoch boundary blocks as they are processed.
//!
//! - **Bootstrap (pre-sync)**: Current epoch identity is fetched from upstream (trusted).
//! - **Forward sync**: Identities are extracted from epoch boundary blocks (trustless).
//!   Once sync starts, upstream fetching is disabled.
//! - **Historical blocks**: `get_block` is only called for blocks behind the head
//!   (for FCU safe/finalized hashes). These blocks have already been processed in-order,
//!   so their epoch identities are already cached.

use super::FollowFeedState;
use crate::rpc::consensus::{CertifiedBlock, Query, TempoConsensusApiClient};
use alloy::providers::network::AnyNetwork;
use alloy_primitives::B256;
use alloy_rpc_types_eth::{Block as RpcBlock, Transaction as RpcTransaction};
use commonware_codec::ReadExt as _;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519::PublicKey,
};
use const_hex as hex;
use reth_consensus_debug_client::{BlockProvider, RpcBlockProvider};
use reth_primitives_traits::Block as BlockTrait;
use reth_tracing::tracing::{debug, error, info};
use std::sync::{Arc, RwLock};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::{Block, TempoHeader, TempoTxEnvelope};
use tokio::sync::mpsc;

/// The Tempo network namespace for BLS signature verification.
const NAMESPACE: &[u8] = b"TEMPO";

/// Digest wrapper for use with commonware consensus types.
/// This is a local copy of the type from tempo-commonware-node to avoid cyclic dependencies.
pub(super) mod digest {
    use alloy_primitives::B256;
    use bytes::{Buf, BufMut};
    use commonware_codec::{FixedSize, Read, ReadExt as _, Write};
    use commonware_utils::{Array, Span};
    use std::ops::Deref;

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    #[repr(transparent)]
    pub(in crate::follow) struct Digest(pub B256);

    impl Array for Digest {}

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
        fn random(mut rng: impl ::rand_core::CryptoRngCore) -> Self {
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

    impl Read for Digest {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            let array = <[u8; 32]>::read(buf)?;
            Ok(Self(B256::new(array)))
        }
    }

    impl Span for Digest {}

    impl std::fmt::Display for Digest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }

    impl Write for Digest {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf)
        }
    }
}

use digest::Digest;

/// Block provider that fetches finalization certificates alongside blocks.
///
/// This provider wraps an `RpcBlockProvider` and additionally:
/// 1. Fetches the finalization certificate for each block via `consensus_getFinalization`
/// 2. Verifies the certificate signature against the network identity for that epoch
/// 3. Verifies the certificate digest matches the block hash
/// 4. Stores valid certificates for later RPC serving (via `FollowFeedState` and storage)
/// 5. Passes verified blocks through to reth for execution
#[derive(Clone)]
pub struct CertifiedBlockProvider {
    /// The underlying RPC block provider.
    inner: RpcBlockProvider<AnyNetwork, Block>,
    /// Shared state for serving consensus RPCs and storage.
    feed_state: FollowFeedState,
    /// RPC client for fetching finalization certificates from upstream node.
    rpc_client: Arc<jsonrpsee::http_client::HttpClient>,
    /// Cache of epoch -> BLS public key for certificate verification.
    /// Populated on-demand as we encounter new epochs.
    identity_cache: Arc<RwLock<IdentityCache>>,
}

/// Cache for epoch identities, derived from block headers.
///
/// Identities are extracted from epoch boundary blocks' `extra_data` field,
/// which contains the DKG outcome including the BLS public key.
struct IdentityCache {
    /// Map of epoch -> BLS public key.
    identities: std::collections::HashMap<u64, <MinSig as Variant>::Public>,
    /// Whether forward sync has started. Once true, `subscribe_blocks` never
    /// fetches from upstream again (trustless). Historical `get_block` calls
    /// may still fetch from upstream as a fallback.
    sync_started: bool,
}

impl CertifiedBlockProvider {
    /// Create a new certified block provider.
    ///
    /// # Arguments
    /// * `rpc_url` - WebSocket or HTTP URL to fetch blocks from
    /// * `feed_state` - Feed state for serving consensus RPCs and persisting finalizations
    ///
    /// # Errors
    /// Returns an error if the RPC connection fails.
    pub async fn new(rpc_url: &str, feed_state: FollowFeedState) -> eyre::Result<Self> {
        let inner = RpcBlockProvider::<AnyNetwork, _>::new(rpc_url, |block_response| {
            let json =
                serde_json::to_value(block_response).expect("Block serialization cannot fail");
            let rpc_block: RpcBlock<RpcTransaction<TempoTxEnvelope>, TempoHeader> =
                serde_json::from_value(json).expect("Block deserialization cannot fail");
            rpc_block
                .into_consensus_block()
                .map_transactions(|tx: RpcTransaction<TempoTxEnvelope>| tx.into_inner())
        })
        .await?;

        // Create HTTP client for consensus RPC calls
        // Convert ws:// to http:// if needed for RPC calls
        let http_url = rpc_url
            .replace("ws://", "http://")
            .replace("wss://", "https://");

        let rpc_client = Arc::new(
            jsonrpsee::http_client::HttpClientBuilder::default()
                .build(&http_url)
                .map_err(|e| eyre::eyre!("failed to create RPC client: {}", e))?,
        );

        // Identity cache starts empty. Identities are fetched on-demand before
        // sync starts (trusted), then extracted from epoch boundary blocks
        // during forward sync (trustless).
        //
        // TODO: Instead of a trusted bootstrap, we could read state, and find the last
        // epoch boundary block and extract the identity to start from.
        let identity_cache = Arc::new(RwLock::new(IdentityCache {
            identities: std::collections::HashMap::new(),
            sync_started: false,
        }));

        info!(rpc_url = %rpc_url, "created certified block provider");

        Ok(Self {
            inner,
            feed_state,
            rpc_client,
            identity_cache,
        })
    }

    /// Get a reference to the feed state for RPC serving.
    pub fn feed_state(&self) -> &FollowFeedState {
        &self.feed_state
    }

    /// Try to extract and cache the DKG identity from a block's extra_data.
    ///
    /// This should be called for every block to capture epoch boundary blocks
    /// that contain DKG outcomes for new epochs.
    fn try_extract_identity(&self, block: &Block) {
        let header = BlockTrait::header(block);
        let extra_data = header.inner.extra_data.as_ref();

        // Skip empty extra_data (non-boundary blocks)
        if extra_data.is_empty() {
            return;
        }

        // Try to parse DKG outcome
        match OnchainDkgOutcome::read(&mut &extra_data[..]) {
            Ok(outcome) => {
                let epoch = outcome.epoch.get();
                let identity = outcome.sharing().public().clone();

                if let Ok(mut cache) = self.identity_cache.write() {
                    if !cache.identities.contains_key(&epoch) {
                        debug!(
                            epoch,
                            block_number = header.inner.number,
                            "extracted and cached identity from epoch boundary block"
                        );
                        cache.identities.insert(epoch, identity);
                    }
                }
            }
            Err(_) => {
                // Not a DKG outcome - could be dealer logs or other data
                // This is expected for non-boundary blocks with extra_data
            }
        }
    }

    /// Get the BLS public key for a given epoch.
    ///
    /// Identities are cached from:
    /// - Startup (current epoch from upstream, before sync starts)
    /// - Processing epoch boundary blocks (trustless, extracted from block data)
    ///
    /// Before sync starts, falls back to fetching from upstream if not in cache.
    /// Once sync starts, we never fetch from upstream - all identities must come
    /// from processed blocks (trustless verification).
    async fn get_identity_for_epoch(
        &self,
        epoch: u64,
    ) -> eyre::Result<<MinSig as Variant>::Public> {
        // Check cache and sync_started flag
        let (cached_identity, sync_started) = {
            let cache = self
                .identity_cache
                .read()
                .map_err(|_| eyre::eyre!("identity cache lock poisoned"))?;
            (cache.identities.get(&epoch).cloned(), cache.sync_started)
        };

        if let Some(identity) = cached_identity {
            return Ok(identity);
        }

        // If sync has started, we must have the identity from processed blocks
        if sync_started {
            return Err(eyre::eyre!(
                "no identity cached for epoch {} and sync has started. \
                 This indicates a missing epoch boundary block.",
                epoch
            ));
        }

        // Before sync starts, fetch from upstream (trusted bootstrap)
        debug!(
            epoch,
            "identity not in cache, fetching from upstream (pre-sync)"
        );

        let identity_response = self
            .rpc_client
            .get_identity_transition_proof(Some(epoch), Some(false))
            .await
            .map_err(|e| eyre::eyre!("failed to fetch identity for epoch {}: {}", epoch, e))?;

        let identity_bytes = hex::decode(&identity_response.identity)
            .map_err(|e| eyre::eyre!("invalid identity hex for epoch {}: {}", epoch, e))?;
        let identity = <MinSig as Variant>::Public::read(&mut identity_bytes.as_slice())
            .map_err(|e| eyre::eyre!("invalid BLS public key for epoch {}: {}", epoch, e))?;

        // Cache it
        if let Ok(mut cache) = self.identity_cache.write() {
            cache.identities.insert(epoch, identity.clone());
        }

        Ok(identity)
    }

    /// Mark that sync has started. After this, we never fetch identities from upstream.
    fn mark_sync_started(&self) {
        if let Ok(mut cache) = self.identity_cache.write() {
            if !cache.sync_started {
                debug!("sync started - will no longer fetch identities from upstream");
                cache.sync_started = true;
            }
        }
    }

    /// Fetch, validate, and store the finalization certificate for a block.
    ///
    /// Returns `Ok((cert, finalization))` if the certificate was successfully fetched
    /// and validated, or an error if the certificate is missing, invalid, or verification failed.
    async fn fetch_and_validate_certificate(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> eyre::Result<(
        CertifiedBlock,
        Finalization<Scheme<PublicKey, MinSig>, Digest>,
    )> {
        // Fetch the certificate
        let cert = self
            .rpc_client
            .get_finalization(Query::Height(block_number))
            .await
            .map_err(|e| eyre::eyre!("failed to fetch finalization certificate: {}", e))?
            .ok_or_else(|| {
                eyre::eyre!(
                    "no finalization certificate available for block {}",
                    block_number
                )
            })?;

        debug!(
            block_number,
            epoch = cert.epoch,
            view = cert.view,
            digest = %cert.digest,
            "fetched finalization certificate, validating..."
        );

        // Verify the certificate digest matches the block hash
        if cert.digest != block_hash {
            return Err(eyre::eyre!(
                "certificate digest mismatch: expected {}, got {}",
                block_hash,
                cert.digest
            ));
        }

        // Get the identity for this certificate's epoch
        let identity = self.get_identity_for_epoch(cert.epoch).await?;

        // Decode and verify the BLS signature
        let cert_bytes = hex::decode(&cert.certificate)
            .map_err(|e| eyre::eyre!("invalid certificate hex: {}", e))?;

        let finalization =
            Finalization::<Scheme<PublicKey, MinSig>, Digest>::read(&mut cert_bytes.as_slice())
                .map_err(|e| eyre::eyre!("failed to decode finalization: {}", e))?;

        // Create a verifier with the identity for this epoch
        let verifier = Scheme::certificate_verifier(NAMESPACE, identity.clone());

        // Verify the signature using a thread-local RNG
        let mut rng = rand::thread_rng();
        if !finalization.verify(&mut rng, &verifier, &commonware_parallel::Sequential) {
            return Err(eyre::eyre!(
                "finalization certificate signature verification failed for block {} (epoch {})",
                block_number,
                cert.epoch
            ));
        }

        debug!(
            block_number,
            epoch = cert.epoch,
            view = cert.view,
            "finalization certificate validated successfully"
        );

        Ok((cert, finalization))
    }

    /// Store a finalization to persistent storage if storage is configured.
    fn store_finalization(
        &self,
        height: u64,
        digest: Digest,
        finalization: Finalization<Scheme<PublicKey, MinSig>, Digest>,
    ) {
        if let Some(storage) = self.feed_state.storage() {
            storage.put(height, digest, finalization);
        }
    }
}

impl BlockProvider for CertifiedBlockProvider {
    type Block = Block;

    async fn subscribe_blocks(&self, tx: mpsc::Sender<Self::Block>) {
        // Create a channel to intercept blocks
        let (inner_tx, mut inner_rx) = mpsc::channel::<Block>(64);

        // Spawn the inner provider's subscription
        let inner = self.inner.clone();
        tokio::spawn(async move {
            inner.subscribe_blocks(inner_tx).await;
        });

        // Process blocks as they arrive
        while let Some(block) = inner_rx.recv().await {
            let header = BlockTrait::header(&block);
            let block_number = header.inner.number;
            let block_hash = alloy_consensus::Sealable::hash_slow(header);

            // Extract identity from this block if it's an epoch boundary
            // This must happen BEFORE validation so we have the identity for the next epoch
            self.try_extract_identity(&block);

            // Fetch and validate the finalization certificate BEFORE accepting the block
            match self
                .fetch_and_validate_certificate(block_number, block_hash)
                .await
            {
                Ok((cert, finalization)) => {
                    // First successful verification marks sync as started
                    self.mark_sync_started();

                    // Store the finalization to persistent storage
                    self.store_finalization(block_number, Digest(block_hash), finalization);

                    // Update in-memory state and broadcast event
                    self.feed_state.set_finalized(cert);

                    if tx.send(block).await.is_err() {
                        // Channel closed - receiver dropped
                        break;
                    }
                }
                Err(e) => {
                    // Certificate validation failed - reject the block
                    error!(
                        block_number,
                        block_hash = %block_hash,
                        error = %e,
                        "rejecting block: certificate validation failed"
                    );
                    // Continue processing - don't forward this block
                    // Should we halt? How do make sure we get this block again.
                    continue;
                }
            }
        }
    }

    async fn get_block(&self, block_number: u64) -> eyre::Result<Self::Block> {
        // Fetch the block first to get its hash
        let block = self.inner.get_block(block_number).await?;
        let block_hash = alloy_consensus::Sealable::hash_slow(BlockTrait::header(&block));

        // Extract identity from this block if it's an epoch boundary
        self.try_extract_identity(&block);

        // Validate the certificate BEFORE returning the block
        let (cert, finalization) = self
            .fetch_and_validate_certificate(block_number, block_hash)
            .await?;

        // First successful verification marks sync as started
        self.mark_sync_started();

        // Store the finalization to persistent storage
        self.store_finalization(block_number, Digest(block_hash), finalization);

        // Update in-memory state
        self.feed_state.set_finalized(cert);

        Ok(block)
    }
}
