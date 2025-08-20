//! Application state management for Malachite consensus integration.
//!
//! This module implements the core application logic that bridges Malachite consensus
//! with Reth's execution engine. It handles:
//!
//! - Block proposal creation when requested by consensus
//! - Block validation and execution when received from peers
//! - State persistence and management across consensus rounds
//! - Communication with Reth's engine API for block processing
//!
//! The [`State`] struct is the main entry point, implementing the Malachite application
//! interface to respond to consensus events like proposal requests and commit decisions.
//!
//! # Architecture
//!
//! The state maintains connections to:
//! - Reth's beacon engine handle for block execution
//! - Payload builder for creating new blocks
//! - Storage layer for persisting consensus data
//! - Validator configuration and cryptographic keys

use crate::{
    ProposalPart, Value,
    context::{BasePeer, BasePeerAddress, BasePeerSet, MalachiteContext},
    height::Height,
    provider::{Ed25519Provider, PublicKey},
    store::{DecidedValue, Store},
    types::{Address, ValueId},
    utils::seed_from_address,
};
use alloy_primitives::B256;
use alloy_rpc_types_engine::{ExecutionData, ForkchoiceState, PayloadStatusEnum};
use bytes::Bytes;
use eyre::Result;
use malachitebft_app_channel::app::{
    streaming::{Sequence, StreamContent, StreamMessage},
    types::{LocallyProposedValue, PeerId as MalachitePeerId, ProposedValue},
};
use malachitebft_core_types::{
    CommitCertificate, Height as HeightTrait, Round, Validity, VoteExtensions,
};
use rand::{SeedableRng, rngs::StdRng};
use reth_engine_primitives::ConsensusEngineHandle;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_builder::{NodeTypes, PayloadTypes};
use reth_payload_builder::{PayloadBuilderHandle, PayloadStore};
use reth_payload_primitives::{EngineApiMessageVersion, PayloadKind};
use reth_primitives_traits::SealedBlock;
use reth_provider::DatabaseProviderFactory;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};
use tempo_telemetry_util::error_field;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, warn};

/// Thread-safe wrapper for StdRng
#[derive(Debug)]
struct ThreadSafeRng {
    inner: Arc<TokioMutex<StdRng>>,
}

impl ThreadSafeRng {
    fn new(seed: u64) -> Self {
        Self {
            inner: Arc::new(TokioMutex::new(StdRng::seed_from_u64(seed))),
        }
    }

    async fn with_rng<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut StdRng) -> R,
    {
        let mut rng = self.inner.lock().await;
        f(&mut rng)
    }
}

impl Clone for ThreadSafeRng {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// Manual Clone implementation for State since PayloadStore doesn't implement Clone
impl<N: NodeTypes> Clone for State<N>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            config: self.config.clone(),
            genesis: self.genesis.clone(),
            address: self.address,
            store: self.store.clone(),
            signing_provider: self.signing_provider.clone(),
            engine_handle: self.engine_handle.clone(),
            payload_store: Arc::clone(&self.payload_store),
            current_height: Arc::clone(&self.current_height),
            current_round: Arc::clone(&self.current_round),
            current_proposer: Arc::clone(&self.current_proposer),
            current_role: Arc::clone(&self.current_role),
            peers: Arc::clone(&self.peers),
            streams_map: Arc::clone(&self.streams_map),
            rng: self.rng.clone(),
        }
    }
}

/// State represents the application state for the Malachite-Reth integration.
/// It manages consensus state, validator information, and block production.
///
/// # Architecture and API Boundaries
///
/// State serves as the central mediator between the consensus engine and the storage layer:
///
/// ```text
/// Consensus Handler
///       | (calls State methods)
///     State
///       | (internal Store access)
///     Store
///       | (database operations)
///   RethStore
/// ```
///
/// ## API Categories:
///
/// - **Consensus Operations**: `commit()`, `propose_value()`, `get_decided_value()`
/// - **State Management**: `current_height()`, `current_round()`, `get_validator_set()`
/// - **Storage Access**: `store_synced_proposal()`, `get_proposal_for_restreaming()`
/// - **Peer Management**: `add_peer()`, `remove_peer()`, `get_peers()`
pub struct State<N: NodeTypes> {
    // Immutable fields (no synchronization needed)
    pub ctx: MalachiteContext,
    pub config: Config,
    pub genesis: Genesis,
    pub address: Address,
    store: Store, // Already thread-safe
    pub signing_provider: Ed25519Provider,
    pub engine_handle: ConsensusEngineHandle<N::Payload>,
    pub payload_store: Arc<PayloadStore<N::Payload>>,

    // Mutable fields wrapped in RwLock for concurrent read/write access
    current_height: Arc<RwLock<Height>>,
    current_round: Arc<RwLock<Round>>,
    current_proposer: Arc<RwLock<Option<BasePeerAddress>>>,
    current_role: Arc<RwLock<Role>>,
    peers: Arc<RwLock<HashSet<MalachitePeerId>>>,
    streams_map: Arc<RwLock<PartStreamsMap>>,

    // Thread-safe RNG
    rng: ThreadSafeRng,
}

impl<N: NodeTypes> State<N>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: MalachiteContext,
        config: Config,
        genesis: Genesis,
        address: Address,
        store: Store,
        engine_handle: ConsensusEngineHandle<N::Payload>,
        payload_builder_handle: PayloadBuilderHandle<N::Payload>,
        signing_provider: Option<Ed25519Provider>,
    ) -> Self {
        let payload_store = Arc::new(PayloadStore::new(payload_builder_handle));

        Self {
            ctx,
            config,
            genesis,
            address,
            store,
            signing_provider: signing_provider.unwrap_or_else(Ed25519Provider::new_test),
            engine_handle,
            payload_store,
            current_height: Arc::new(RwLock::new(Height::INITIAL)),
            current_round: Arc::new(RwLock::new(Round::Nil)),
            current_proposer: Arc::new(RwLock::new(None)),
            current_role: Arc::new(RwLock::new(Role::None)),
            peers: Arc::new(RwLock::new(HashSet::new())),
            streams_map: Arc::new(RwLock::new(PartStreamsMap::new())),
            rng: ThreadSafeRng::new(seed_from_address(&address, std::process::id() as u64)),
        }
    }

    /// Creates a new State instance from a database provider.
    ///
    /// This factory method encapsulates Store creation and initialization,
    /// ensuring that Store is not directly accessible outside the State module.
    #[allow(clippy::too_many_arguments)]
    pub async fn from_provider<P>(
        ctx: MalachiteContext,
        config: Config,
        genesis: Genesis,
        address: Address,
        provider: Arc<P>,
        engine_handle: ConsensusEngineHandle<N::Payload>,
        payload_builder_handle: PayloadBuilderHandle<N::Payload>,
        signing_provider: Option<Ed25519Provider>,
    ) -> Result<Self>
    where
        P: DatabaseProviderFactory + Clone + Unpin + Send + Sync + 'static,
        <P as DatabaseProviderFactory>::Provider: Send + Sync,
        <P as DatabaseProviderFactory>::ProviderRW: Send,
    {
        // Create and verify the store
        let store = Store::new(provider);
        store.verify_tables().await?;

        Ok(Self::new(
            ctx,
            config,
            genesis,
            address,
            store,
            engine_handle,
            payload_builder_handle,
            signing_provider,
        ))
    }

    // Getter methods for thread-safe access
    pub fn current_height(&self) -> Result<Height> {
        Ok(*self
            .current_height
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?)
    }

    pub fn set_current_height(&self, height: Height) -> Result<()> {
        *self
            .current_height
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))? = height;
        Ok(())
    }

    pub fn current_round(&self) -> Result<Round> {
        Ok(*self
            .current_round
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?)
    }

    pub fn set_current_round(&self, round: Round) -> Result<()> {
        *self
            .current_round
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))? = round;
        Ok(())
    }

    pub fn current_proposer(&self) -> Result<Option<BasePeerAddress>> {
        Ok(self
            .current_proposer
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .clone())
    }

    pub fn set_current_proposer(&self, proposer: Option<BasePeerAddress>) -> Result<()> {
        *self
            .current_proposer
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))? = proposer;
        Ok(())
    }

    pub fn current_role(&self) -> Result<Role> {
        Ok(*self
            .current_role
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?)
    }

    pub fn set_current_role(&self, role: Role) -> Result<()> {
        *self
            .current_role
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))? = role;
        Ok(())
    }

    pub fn add_peer(&self, peer: MalachitePeerId) -> Result<()> {
        self.peers
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .insert(peer);
        Ok(())
    }

    pub fn remove_peer(&self, peer: &MalachitePeerId) -> Result<bool> {
        Ok(self
            .peers
            .write()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .remove(peer))
    }

    pub fn get_peers(&self) -> Result<HashSet<MalachitePeerId>> {
        Ok(self
            .peers
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?
            .clone())
    }

    pub fn signing_provider(&self) -> &Ed25519Provider {
        &self.signing_provider
    }

    // RNG access through async interface
    pub async fn with_rng<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut StdRng) -> R,
    {
        self.rng.with_rng(f).await
    }

    /// Returns the validator set for the given height
    /// For now, returns a fixed validator set from genesis
    pub fn get_validator_set(&self, _height: Height) -> BasePeerSet {
        // Convert genesis validators to BasePeer format
        let peers: Vec<BasePeer> = self
            .genesis
            .validators
            .iter()
            .map(|validator| {
                // Convert the public key bytes to Ed25519 PublicKey
                if validator.public_key.len() != 32 {
                    panic!(
                        "Invalid public key length for validator {}: expected 32 bytes, got {}",
                        validator.address,
                        validator.public_key.len()
                    );
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&validator.public_key);
                let public_key = PublicKey::from_bytes(key_bytes);

                BasePeer {
                    address: BasePeerAddress::new(validator.address),
                    public_key,
                    voting_power: validator.voting_power,
                }
            })
            .collect();

        // Calculate total voting power
        let total_voting_power = peers.iter().map(|p| p.voting_power).sum();

        BasePeerSet {
            peers,
            total_voting_power,
        }
    }

    /// Creates a new proposal value for the given height and round
    pub async fn propose_value(
        &self,
        height: Height,
        round: Round,
    ) -> Result<(
        LocallyProposedValue<MalachiteContext>,
        reth_ethereum_primitives::Block,
    )> {
        // 1. Get parent block timestamp for monotonic increasing timestamps
        let (parent_hash, parent_timestamp) = if height.as_u64() == 1 {
            // For genesis, use current time
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            (self.genesis.genesis_hash, timestamp)
        } else {
            // For other blocks, get parent block and use parent.timestamp + 1
            let parent_height = Height(height.as_u64() - 1);
            let parent = self
                .get_decided_value(parent_height)
                .await
                .ok_or_else(|| eyre::eyre!("Parent block not found at height {}", parent_height))?;

            // Get the parent block hash
            let parent_hash = parent.value.hash();

            // Retrieve the actual parent block to get its timestamp
            let parent_block = self.store.get_block(&parent_hash).await?.ok_or_else(|| {
                eyre::eyre!("Parent block data not found for hash {}", parent_hash)
            })?;

            let parent_timestamp = parent_block.header.timestamp;

            (parent_hash, parent_timestamp)
        };

        // Use parent_timestamp + 1 to ensure monotonic increasing timestamps
        let timestamp = parent_timestamp + 1;

        // 2. Create payload attributes for the block at this height
        let payload_attrs = alloy_rpc_types_engine::PayloadAttributes {
            timestamp,
            prev_randao: B256::ZERO, // For PoS compatibility
            suggested_fee_recipient: self.config.fee_recipient,
            withdrawals: Some(vec![]), // Empty withdrawals for post-Shanghai
            parent_beacon_block_root: Some(B256::ZERO),
        };

        // 3. Send FCU to trigger payload building
        let forkchoice_state = ForkchoiceState {
            head_block_hash: parent_hash,
            safe_block_hash: parent_hash,
            finalized_block_hash: self.get_finalized_hash().await?,
        };

        let fcu_response = self
            .engine_handle
            .fork_choice_updated(
                forkchoice_state,
                Some(payload_attrs),
                EngineApiMessageVersion::V3,
            )
            .await?;

        // 4. Get the payload ID from the response
        let payload_id = fcu_response
            .payload_id
            .ok_or_else(|| eyre::eyre!("No payload ID returned from FCU"))?;

        // 5. Get the built payload - use WaitForPending to wait for at least one built payload
        // This will wait for the payload builder to produce a payload with transactions
        // It won't return an empty payload immediately like Earliest would
        let payload = self
            .payload_store
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .await
            .ok_or_else(|| eyre::eyre!("No payload found for id {:?}", payload_id))??;

        let sealed_block = payload.block();
        let block = sealed_block.clone_block();
        let value = Value::from(&block);

        debug!(
            "Proposed value for height {} round {} with payload {:?}, value_id: {}",
            height,
            round,
            payload_id,
            value.id()
        );

        let locally_proposed = LocallyProposedValue::new(height, round, value);

        // Store the proposal we just built so it can be retrieved later
        let proposer = BasePeerAddress(self.address);
        let proposed_value = ProposedValue {
            height,
            round,
            valid_round: Round::Nil,
            proposer,
            value,
            validity: Validity::Valid,
        };

        self.store_built_proposal(proposed_value, block.clone())
            .await?;

        Ok((locally_proposed, block))
    }

    /// Processes a received proposal part and potentially returns a complete proposal
    pub async fn received_proposal_part(
        &self,
        from: MalachitePeerId,
        part: StreamMessage<ProposalPart>,
    ) -> Result<Option<ProposedValue<MalachiteContext>>> {
        info!(
            "Received proposal part from {} - sequence: {}, is_fin: {}, part_type: {}",
            from,
            part.sequence,
            part.is_fin(),
            match &part.content {
                StreamContent::Data(p) => match p {
                    ProposalPart::Init(_) => "Init",
                    ProposalPart::Data(_) => "Data",
                    ProposalPart::Fin(_) => "Fin",
                },
                StreamContent::Fin => "StreamFin",
            }
        );

        // Check if we have a full proposal
        let parts = {
            let mut streams_map = self
                .streams_map
                .write()
                .map_err(|_| eyre::eyre!("RwLock poisoned"))?;
            streams_map.insert(from, part)
        };

        let Some(parts) = parts else {
            debug!("Proposal not complete yet, waiting for more parts");
            return Ok(None);
        };

        // Check if the proposal is outdated
        let current_height = *self
            .current_height
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?;
        let current_round = *self
            .current_round
            .read()
            .map_err(|_| eyre::eyre!("RwLock poisoned"))?;

        if parts.height < current_height {
            debug!(
                height = %current_height,
                round = %current_round,
                part.height = %parts.height,
                part.round = %parts.round,
                "Received outdated proposal part, ignoring"
            );
            return Ok(None);
        }

        // Re-assemble the proposal from its parts
        let (value, block) = match assemble_value_from_parts(parts) {
            Ok(result) => result,
            Err(e) => {
                error!(error = error_field(&e), "Failed to assemble proposal");
                return Ok(None);
            }
        };

        // Log block info
        info!(
            "Received block: hash={}, number={}, tx_count={}, id={:x}",
            block.header.hash_slow(),
            block.header.number,
            block.body.transactions.len(),
            value.value.id().as_u64()
        );

        // Store the proposal with its block
        self.store
            .store_undecided_proposal(value.clone(), block)
            .await?;

        Ok(Some(value))
    }

    /// Creates stream messages for a proposal
    pub fn stream_proposal(
        &self,
        value: LocallyProposedValue<MalachiteContext>,
        block: reth_ethereum_primitives::Block,
        _pol_round: Round,
    ) -> impl Iterator<Item = StreamMessage<ProposalPart>> {
        info!("Streaming proposal for height {}", value.height);

        // Create a unique stream ID for this proposal
        let stream_id_bytes =
            format!("{}-{}-{}", value.height, value.round, value.value.id()).into_bytes();
        let stream_id =
            malachitebft_app_channel::app::streaming::StreamId::new(Bytes::from(stream_id_bytes));

        // Encode the block to bytes for streaming
        let value_bytes = encode_block(&block);
        info!(
            "Encoding value of {} bytes for streaming",
            value_bytes.len()
        );

        // Create hasher for signing
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();

        // Add height to hash
        hasher.update(value.height.as_u64().to_be_bytes().as_slice());
        // Add round to hash
        hasher.update(value.round.as_i64().to_be_bytes().as_slice());

        // Create parts vector
        let mut parts = Vec::new();
        let mut sequence = 0u64;

        // Part 1: Init
        let init_part = ProposalPart::Init(crate::types::ProposalInit::new(
            value.height,
            value.round,
            self.address,
            value.value.hash(),
        ));
        parts.push(StreamMessage::new(
            stream_id.clone(),
            sequence,
            StreamContent::Data(init_part),
        ));
        sequence += 1;

        // Part 2: Data chunks (split large values into smaller chunks)
        const CHUNK_SIZE: usize = 32 * 1024; // 32KB chunks
        for chunk in value_bytes.chunks(CHUNK_SIZE) {
            // Add chunk to hash
            hasher.update(chunk);

            let data_part =
                ProposalPart::Data(crate::types::ProposalData::new(Bytes::from(chunk.to_vec())));
            parts.push(StreamMessage::new(
                stream_id.clone(),
                sequence,
                StreamContent::Data(data_part),
            ));
            sequence += 1;
        }

        // Part 3: Fin with signature
        let hash = hasher.finalize();
        let signature = self.signing_provider.sign(hash.as_slice());
        let fin_part = ProposalPart::Fin(crate::types::ProposalFin::new(signature));
        parts.push(StreamMessage::new(
            stream_id.clone(),
            sequence,
            StreamContent::Data(fin_part),
        ));

        info!("Created {} stream messages for proposal", parts.len());
        parts.into_iter()
    }

    /// Commits a decided value
    pub async fn commit(
        &self,
        certificate: CommitCertificate<MalachiteContext>,
        _extensions: VoteExtensions<MalachiteContext>,
    ) -> Result<()> {
        let height = certificate.height;
        let round = certificate.round;
        let value_id = certificate.value_id;

        info!(
            "Committing value at height {} round {} with value_id {:?} (as B256: {})",
            height,
            round,
            value_id,
            value_id.as_b256()
        );

        // Try to find the value that matches the value_id
        // First check the round where it was decided, then check all rounds
        let mut value = None;

        // Check the decided round first
        if let Ok(Some(proposal)) = self.get_undecided_proposal(height, round, value_id).await {
            info!(
                "Found proposal in decided round {} with value_id matching",
                round
            );
            value = Some(proposal.value);
        } else {
            info!(
                "No proposal found in decided round {} for value_id {:?}",
                round, value_id
            );
        }

        // If not found, search all rounds (the proposal might have been from an earlier round)
        if value.is_none() {
            info!(
                "Searching all rounds from 0 to {} for value_id {:?}",
                round.as_i64(),
                value_id
            );
            for check_round in 0..=round.as_i64() as u32 {
                if let Ok(Some(proposal)) = self
                    .get_undecided_proposal(height, Round::new(check_round), value_id)
                    .await
                {
                    info!(
                        "Found proposal in round {} with matching value_id",
                        check_round
                    );
                    value = Some(proposal.value);
                    break;
                }
            }
        }

        // If we still don't have the value, this is an error
        let value = match value {
            Some(v) => v,
            None => {
                // List all proposals at this height to debug
                error!(
                    "Failed to find proposal for value_id {:?} at height {}",
                    value_id, height
                );
                for check_round in 0..=round.as_i64() as u32 {
                    if let Ok(proposals) = self
                        .get_undecided_proposals(height, Round::new(check_round))
                        .await
                    {
                        for proposal in proposals {
                            error!(
                                "  Available proposal: round {} value_id {:?} (B256: {})",
                                check_round,
                                proposal.value.id(),
                                proposal.value.id().as_b256()
                            );
                        }
                    }
                }
                return Err(eyre::eyre!(
                    "Could not find proposal for value_id {:?} at height {}",
                    value_id,
                    height
                ));
            }
        };

        // 1. Store the decided value first (for persistence)
        self.store.store_decided_value(certificate, value).await?;

        // 2. Retrieve the block and convert to execution payload
        let block =
            self.store.get_block(&value.hash()).await?.ok_or_else(|| {
                eyre::eyre!("Block not found for decided value: {}", value.hash())
            })?;
        let sealed_block = SealedBlock::seal_slow(block);
        let payload =
            <reth_node_ethereum::EthEngineTypes as PayloadTypes>::block_to_payload(sealed_block);

        debug!(
            "Sending new_payload with block_number: {}, parent_hash: {}",
            payload.block_number(),
            payload.parent_hash()
        );

        let payload_status = self.engine_handle.new_payload(payload).await?;

        if payload_status.status != PayloadStatusEnum::Valid {
            return Err(eyre::eyre!("Invalid payload status: {:?}", payload_status));
        }

        // 3. Update fork choice to make this block canonical
        let block_hash = value.hash();
        let forkchoice_state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash, // In Malachite with instant finality, head = safe = finalized
            finalized_block_hash: block_hash, // Instant finality means committed = finalized
        };

        let fcu_response = self
            .engine_handle
            .fork_choice_updated(forkchoice_state, None, EngineApiMessageVersion::V3)
            .await?;

        if fcu_response.payload_status.status != PayloadStatusEnum::Valid {
            return Err(eyre::eyre!("Invalid FCU response: {:?}", fcu_response));
        }

        info!(
            "Successfully committed block at height {} with hash {}",
            height, block_hash
        );

        Ok(())
    }

    /// Gets a decided value at the given height
    pub async fn get_decided_value(&self, height: Height) -> Option<DecidedValue> {
        match self.store.get_decided_value(height).await {
            Ok(value) => value,
            Err(e) => {
                tracing::error!(
                    error = error_field(&e),
                    "Failed to get decided value at height {}",
                    height
                );
                None
            }
        }
    }

    /// Gets the earliest available height
    pub async fn get_earliest_height(&self) -> Height {
        Height::INITIAL // Start from height 1
    }

    /// Gets a previously built value for reuse
    pub async fn get_previously_built_value(
        &self,
        height: Height,
        round: Round,
    ) -> Option<LocallyProposedValue<MalachiteContext>> {
        info!(
            "Requested previously built value for height {} round {}",
            height, round
        );

        // Try to find any proposal we built for this height
        // Check the requested round and also round 0 (in case we're looking for any proposal)
        for check_round in [round, Round::new(0)] {
            if let Ok(proposals) = self.get_undecided_proposals(height, check_round).await {
                // Find a proposal that was built by us
                for proposal in proposals {
                    if proposal.proposer == BasePeerAddress(self.address) {
                        return Some(LocallyProposedValue::new(height, round, proposal.value));
                    }
                }
            }
        }

        None
    }

    // ===== Store Access API =====
    // The following methods provide controlled access to the Store for Consensus.
    // This design ensures that:
    // 1. Consensus never directly accesses Store
    // 2. State can enforce business rules and maintain invariants
    // 3. Storage implementation details are hidden from Consensus
    //
    // API Design:
    // - All Store access MUST go through State methods
    // - State methods provide domain-specific operations, not raw storage access
    // - State is responsible for data validation and business logic

    /// Stores a proposal that was synced from another node.
    ///
    /// This is called by consensus when it receives a complete proposal
    /// through the sync mechanism.
    pub async fn store_synced_proposal(
        &self,
        proposal: ProposedValue<MalachiteContext>,
        block: reth_ethereum_primitives::Block,
    ) -> Result<()> {
        tracing::debug!(
            height = %proposal.height,
            round = %proposal.round,
            proposer = %proposal.proposer,
            "Storing synced proposal"
        );
        self.store.store_undecided_proposal(proposal, block).await
    }

    /// Retrieves a previously stored proposal for restreaming to peers.
    ///
    /// This is called when consensus needs to rebroadcast a proposal,
    /// typically when a validator missed the original broadcast.
    pub async fn get_proposal_for_restreaming(
        &self,
        height: Height,
        round: Round,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>> {
        tracing::debug!(
            %height,
            %round,
            value_id = ?value_id,
            "Retrieving proposal for restreaming"
        );
        self.store
            .get_undecided_proposal(height, round, value_id)
            .await
    }

    /// Gets the highest height with a decided value.
    ///
    /// This can be used to determine the current chain height or to find
    /// gaps in the decided values.
    pub async fn get_max_decided_height(&self) -> Option<Height> {
        self.store.max_decided_value_height().await
    }

    /// Gets all undecided proposals for a specific height and round.
    ///
    /// This might be useful for debugging or for consensus to check
    /// what proposals it has received.
    pub async fn get_undecided_proposals(
        &self,
        height: Height,
        round: Round,
    ) -> Result<Vec<ProposedValue<MalachiteContext>>> {
        self.store.get_undecided_proposals(height, round).await
    }

    /// Stores a value that this node has built (not synced from others).
    ///
    /// This is called after successfully building a proposal in propose_value().
    /// Storing it allows us to retrieve it later if needed (e.g., for restreaming).
    pub async fn store_built_proposal(
        &self,
        proposal: ProposedValue<MalachiteContext>,
        block: reth_ethereum_primitives::Block,
    ) -> Result<()> {
        tracing::debug!(
            height = %proposal.height,
            round = %proposal.round,
            "Storing locally built proposal"
        );
        self.store.store_undecided_proposal(proposal, block).await
    }

    /// Gets a specific undecided proposal by height, round, and value_id.
    ///
    /// This is used internally by State for looking up proposals during commit.
    async fn get_undecided_proposal(
        &self,
        height: Height,
        round: Round,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>> {
        self.store
            .get_undecided_proposal(height, round, value_id)
            .await
    }

    /// Get a block by its hash from storage
    pub async fn get_block(&self, hash: &B256) -> Result<Option<reth_ethereum_primitives::Block>> {
        self.store.get_block(hash).await
    }

    /// Get the finalized block hash
    /// In Malachite, blocks have instant finality - once committed, they're immediately finalized
    async fn get_finalized_hash(&self) -> Result<B256> {
        // Get the highest decided block height from the store
        if let Some(max_height) = self.get_max_decided_height().await
            && let Some(decided) = self.get_decided_value(max_height).await
        {
            return Ok(decided.value.hash());
        }

        // If no decided blocks yet, use genesis
        Ok(self.genesis.genesis_hash)
    }

    /// Validate a synced block through the engine API
    /// Returns true if the block is valid, false otherwise
    pub async fn validate_synced_block(
        &self,
        block: &reth_ethereum_primitives::Block,
    ) -> Result<bool> {
        // Convert the block to execution payload
        let sealed_block = SealedBlock::seal_slow(block.clone());
        let payload =
            <reth_node_ethereum::EthEngineTypes as PayloadTypes>::block_to_payload(sealed_block);
        // Send new_payload to validate it
        let payload_status = self.engine_handle.new_payload(payload).await?;

        match payload_status.status {
            PayloadStatusEnum::Valid => {
                info!("Synced block validated successfully");
                Ok(true)
            }
            PayloadStatusEnum::Invalid { .. } => {
                warn!("Synced block is invalid: {:?}", payload_status);
                Ok(false)
            }
            PayloadStatusEnum::Syncing => {
                // The node is still syncing, we might want to retry later
                info!("Engine is syncing, cannot validate block yet");
                Ok(false)
            }
            PayloadStatusEnum::Accepted => {
                // Block is accepted but not yet validated
                info!("Block accepted but not yet validated");
                Ok(true) // For now, treat as valid
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: String,
    pub validators: Vec<ValidatorInfo>,
    pub app_state: Vec<u8>,
    pub genesis_hash: B256,
}

impl Genesis {
    pub fn new(chain_id: String) -> Self {
        Self {
            chain_id,
            validators: Vec::new(),
            app_state: Vec::new(),
            genesis_hash: B256::ZERO,
        }
    }

    pub fn with_validators(mut self, validators: Vec<ValidatorInfo>) -> Self {
        self.validators = validators;
        self
    }

    pub fn with_app_state(mut self, app_state: Vec<u8>) -> Self {
        self.app_state = app_state;
        self
    }
}

impl Default for Genesis {
    fn default() -> Self {
        Self::new("malachite-test".to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub voting_power: u64,
    pub public_key: Vec<u8>,
}

impl ValidatorInfo {
    pub fn new(address: Address, voting_power: u64, public_key: Vec<u8>) -> Self {
        Self {
            address,
            voting_power,
            public_key,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub block_time: std::time::Duration,
    pub create_empty_blocks: bool,
    pub fee_recipient: alloy_primitives::Address,
    pub block_build_time_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Self {
        Self {
            block_time: std::time::Duration::from_secs(1),
            create_empty_blocks: true,
            fee_recipient: alloy_primitives::Address::ZERO,
            block_build_time_ms: 500,
        }
    }
}

/// The role that the node is playing in the consensus protocol during a round.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// The node is the proposer for the current round.
    Proposer,
    /// The node is a validator for the current round.
    Validator,
    /// The node is not participating in the consensus protocol for the current round.
    None,
}

// Role conversion implementation removed as Role type is not exported from malachitebft_app_channel

/// Tracks the state of proposal streaming
#[derive(Debug, Clone)]
pub struct StreamState {
    pub height: Height,
    pub round: Round,
    pub proposer: Option<BasePeerAddress>,
    pub block_hash: Option<B256>,
    pub parts: Vec<Option<ProposalPart>>,
    pub total_parts: Option<usize>,
    pub seen_sequences: std::collections::HashSet<Sequence>,
}

impl Default for StreamState {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamState {
    pub fn new() -> Self {
        Self {
            height: Height(0),
            round: Round::new(0),
            proposer: None,
            block_hash: None,
            parts: Vec::new(),
            total_parts: None,
            seen_sequences: std::collections::HashSet::new(),
        }
    }

    /// Insert a proposal part and return complete ProposalParts if done
    pub fn insert(&mut self, msg: StreamMessage<ProposalPart>) -> Option<ProposalParts> {
        // Check for duplicate
        if !self.seen_sequences.insert(msg.sequence) {
            debug!("Duplicate sequence {} ignored", msg.sequence);
            return None;
        }

        match &msg.content {
            StreamContent::Data(part) => {
                match part {
                    ProposalPart::Init(init) => {
                        self.height = init.height;
                        self.round = init.round;
                        self.proposer = Some(BasePeerAddress::from(init.proposer));
                        self.block_hash = Some(init.block_hash);
                        debug!(
                            "Received Init: height={}, round={}, proposer set, block_hash={}",
                            init.height, init.round, init.block_hash
                        );
                    }
                    ProposalPart::Data(data) => {
                        debug!("Received Data part: {} bytes", data.bytes.len());
                    }
                    ProposalPart::Fin(_fin) => {
                        // Final part - we know total count now
                        self.total_parts = Some(msg.sequence as usize + 1);
                        debug!(
                            "Received Fin part, total_parts={}",
                            msg.sequence as usize + 1
                        );
                    }
                }

                // Ensure we have space for this part
                if self.parts.len() <= msg.sequence as usize {
                    self.parts.resize(msg.sequence as usize + 1, None);
                }
                self.parts[msg.sequence as usize] = Some(part.clone());
            }
            StreamContent::Fin => {
                self.total_parts = Some(msg.sequence as usize);
                debug!(
                    "Received StreamContent::Fin, total_parts={}",
                    msg.sequence as usize
                );
            }
        }

        // Check if we're done
        if let Some(total) = self.total_parts {
            debug!(
                "Checking completion: total_parts={}, current_parts={}, has_proposer={}",
                total,
                self.parts.len(),
                self.proposer.is_some()
            );

            if self.parts.len() >= total && self.parts.iter().take(total).all(|p| p.is_some()) {
                let parts: Vec<ProposalPart> = self
                    .parts
                    .iter()
                    .take(total)
                    .filter_map(|p| p.clone())
                    .collect();

                if let (Some(proposer), Some(block_hash)) = (&self.proposer, &self.block_hash) {
                    debug!(
                        "Proposal complete! Returning ProposalParts with {} parts",
                        parts.len()
                    );
                    return Some(ProposalParts {
                        height: self.height,
                        round: self.round,
                        proposer: proposer.clone(),
                        block_hash: *block_hash,
                        parts,
                    });
                } else {
                    debug!(
                        "All parts received but missing proposer or block_hash - cannot complete"
                    );
                }
            } else {
                debug!("Not all parts received yet");
            }
        } else {
            debug!("total_parts not set yet");
        }

        None
    }

    pub fn is_done(&self) -> bool {
        if let Some(total) = self.total_parts {
            self.parts.len() >= total
                && self.parts.iter().take(total).all(|p| p.is_some())
                && self.proposer.is_some()
        } else {
            false
        }
    }
}

/// Complete proposal parts ready for reassembly
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalParts {
    pub height: Height,
    pub round: Round,
    pub proposer: BasePeerAddress,
    pub block_hash: B256,
    pub parts: Vec<ProposalPart>,
}

/// Serialized stream ID representation for use as HashMap key
/// Since StreamId doesn't implement Hash, we use its byte representation
type StreamIdBytes = Vec<u8>;

#[derive(Debug, Clone)]
pub struct PartStreamsMap {
    // Maps from peer ID to their stream states (stream ID bytes -> stream state)
    streams: HashMap<MalachitePeerId, HashMap<StreamIdBytes, StreamState>>,
}

impl PartStreamsMap {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Insert a stream message and return ProposalParts if complete
    pub fn insert(
        &mut self,
        peer_id: MalachitePeerId,
        msg: StreamMessage<ProposalPart>,
    ) -> Option<ProposalParts> {
        let stream_id_bytes = msg.stream_id.to_bytes().to_vec();

        let peer_streams = self.streams.entry(peer_id).or_default();
        let state = peer_streams.entry(stream_id_bytes.clone()).or_default();

        let result = state.insert(msg);

        if state.is_done() {
            peer_streams.remove(&stream_id_bytes);
            // Clean up empty peer entries
            if peer_streams.is_empty() {
                self.streams.remove(&peer_id);
            }
        }

        result
    }
}

impl Default for PartStreamsMap {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct PartialStreamState {
    pub height: Height,
    pub round: Round,
    pub step: ConsensusStep,
    pub last_activity: std::time::Instant,
}

impl PartialStreamState {
    pub fn new(height: Height, round: Round) -> Self {
        Self {
            height,
            round,
            step: ConsensusStep::NewHeight,
            last_activity: std::time::Instant::now(),
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = std::time::Instant::now();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusStep {
    NewHeight,
    NewRound,
    Propose,
    Prevote,
    Precommit,
    Commit,
}

// Additional types needed for the consensus interface

// Standalone functions

/// Reload the tracing subscriber log level based on the current height and round
pub fn reload_log_level(_height: Height, _round: Round) {
    // For now, do nothing - this would adjust log levels
}

/// Encode a block to its byte representation
pub fn encode_block(block: &reth_ethereum_primitives::Block) -> Bytes {
    use reth_primitives_traits::serde_bincode_compat::SerdeBincodeCompat;

    // Convert block to its bincode-compatible representation
    let block_repr = block.as_repr();

    // Serialize the block
    match bincode::serialize(&block_repr) {
        Ok(bytes) => Bytes::from(bytes),
        Err(e) => {
            tracing::error!(error = error_field(&e), "Failed to encode block");
            Bytes::new()
        }
    }
}

/// Encode a value to its byte representation (now just returns the hash)
pub fn encode_value(value: &Value) -> Bytes {
    Bytes::from(value.hash().to_vec())
}

/// Re-assemble a [`ProposedValue`] from its [`ProposalParts`].
/// Returns both the proposed value and the reconstructed block.
fn assemble_value_from_parts(
    parts: ProposalParts,
) -> Result<(
    ProposedValue<MalachiteContext>,
    reth_ethereum_primitives::Block,
)> {
    // Extract the block hash from ProposalInit
    let block_hash = parts.block_hash;

    // Calculate total size and allocate buffer
    let total_size: usize = parts
        .parts
        .iter()
        .filter_map(|part| match part {
            ProposalPart::Data(data) => Some(data.bytes.len()),
            _ => None,
        })
        .sum();

    let mut data = Vec::with_capacity(total_size);

    // Concatenate all data chunks
    for part in &parts.parts {
        if let ProposalPart::Data(data_part) = part {
            data.extend_from_slice(&data_part.bytes);
        }
    }

    // Convert the concatenated data vector into Bytes
    let data = Bytes::from(data);

    // Decode the block from bytes
    let block = decode_block(data).ok_or_else(|| eyre::eyre!("Failed to decode block data"))?;

    // Verify the block hash matches what was announced
    if block.header.hash_slow() != block_hash {
        return Err(eyre::eyre!(
            "Block hash mismatch: expected {}, got {}",
            block_hash,
            block.header.hash_slow()
        ));
    }

    // Create the value from the hash
    let value = Value::new(block_hash);

    let proposed_value = ProposedValue {
        height: parts.height,
        round: parts.round,
        valid_round: Round::Nil,
        proposer: parts.proposer,
        value,
        validity: Validity::Valid,
    };

    Ok((proposed_value, block))
}

/// Decode a block from its byte representation
pub fn decode_block(bytes: Bytes) -> Option<reth_ethereum_primitives::Block> {
    use reth_primitives_traits::serde_bincode_compat::SerdeBincodeCompat;

    // Deserialize the block representation
    match bincode::deserialize::<
        <reth_ethereum_primitives::Block as SerdeBincodeCompat>::BincodeRepr<'_>,
    >(&bytes)
    {
        Ok(block_repr) => {
            // Convert from bincode-compatible representation back to Block
            Some(reth_ethereum_primitives::Block::from_repr(block_repr))
        }
        Err(e) => {
            tracing::error!(error = error_field(&e), "Failed to decode block");
            None
        }
    }
}

/// Decode a value from its byte representation (now expects a hash)
pub fn decode_value(bytes: Bytes) -> Option<Value> {
    if bytes.len() != 32 {
        tracing::error!(
            "Invalid value bytes length: expected 32, got {}",
            bytes.len()
        );
        return None;
    }

    let hash = alloy_primitives::B256::from_slice(&bytes);
    Some(Value::new(hash))
}

/// Encode a value and block together for sync purposes
pub fn encode_value_with_block(value: &Value, block: &reth_ethereum_primitives::Block) -> Bytes {
    let mut data = Vec::new();

    // First 32 bytes: the hash (value)
    data.extend_from_slice(&value.hash().0);

    // Remaining bytes: the serialized block
    let block_bytes = encode_block(block);
    data.extend_from_slice(&block_bytes);

    Bytes::from(data)
}

/// Decode a value and block from sync data
pub fn decode_value_with_block(bytes: Bytes) -> Option<(Value, reth_ethereum_primitives::Block)> {
    if bytes.len() < 32 {
        tracing::error!(
            "Sync data too short: expected at least 32 bytes, got {}",
            bytes.len()
        );
        return None;
    }

    // First 32 bytes are the hash
    let hash = alloy_primitives::B256::from_slice(&bytes[..32]);
    let value = Value::new(hash);

    // Remaining bytes are the block
    let block_bytes = bytes.slice(32..);
    let block = decode_block(block_bytes)?;

    // Verify the block hash matches
    if block.header.hash_slow() != hash {
        tracing::error!("Block hash mismatch in sync data");
        return None;
    }

    Some((value, block))
}

// Type alias for compatibility

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProposalData, ProposalFin, ProposalInit};
    use malachitebft_app_channel::app::streaming::{StreamContent, StreamId, StreamMessage};

    fn create_test_address() -> Address {
        Address::new([1u8; 20])
    }

    fn create_test_proposal_init() -> ProposalPart {
        ProposalPart::Init(ProposalInit::new(
            Height(1),
            Round::new(0),
            create_test_address(),
            B256::from([1u8; 32]), // Test block hash
        ))
    }

    fn create_test_proposal_data(content: &[u8]) -> ProposalPart {
        ProposalPart::Data(ProposalData::new(Bytes::from(content.to_vec())))
    }

    fn create_test_proposal_fin() -> ProposalPart {
        // Create a dummy signature
        let signature_bytes = [0u8; 64];
        let signature = malachitebft_signing_ed25519::Signature::from_bytes(signature_bytes);
        ProposalPart::Fin(ProposalFin::new(signature))
    }

    fn create_test_stream_id() -> StreamId {
        StreamId::new(Bytes::from(vec![1, 2, 3, 4]))
    }

    #[test]
    fn test_stream_state_new() {
        let state = StreamState::new();
        assert_eq!(state.height, Height(0));
        assert_eq!(state.round, Round::new(0));
        assert!(state.proposer.is_none());
        assert!(state.parts.is_empty());
        assert!(state.total_parts.is_none());
        assert!(state.seen_sequences.is_empty());
        assert!(!state.is_done());
    }

    #[test]
    fn test_stream_state_insert_init() {
        let mut state = StreamState::new();
        let init_part = create_test_proposal_init();

        let msg = StreamMessage::new(
            create_test_stream_id(),
            0,
            StreamContent::Data(init_part.clone()),
        );

        let result = state.insert(msg);
        assert!(result.is_none()); // Not complete yet

        assert_eq!(state.height, Height(1));
        assert_eq!(state.round, Round::new(0));
        assert!(state.proposer.is_some());
        assert_eq!(state.parts.len(), 1);
        assert!(state.parts[0].is_some());
    }

    #[test]
    fn test_stream_state_duplicate_sequence() {
        let mut state = StreamState::new();
        let init_part = create_test_proposal_init();

        let msg = StreamMessage::new(
            create_test_stream_id(),
            0,
            StreamContent::Data(init_part.clone()),
        );

        // First insert should work
        let result1 = state.insert(msg.clone());
        assert!(result1.is_none());

        // Duplicate sequence should be rejected
        let result2 = state.insert(msg);
        assert!(result2.is_none());
        assert_eq!(state.seen_sequences.len(), 1);
    }

    #[test]
    fn test_stream_state_complete_proposal() {
        let mut state = StreamState::new();

        // Insert init part
        let init_msg = StreamMessage::new(
            create_test_stream_id(),
            0,
            StreamContent::Data(create_test_proposal_init()),
        );
        assert!(state.insert(init_msg).is_none());

        // Insert data part
        let data_msg = StreamMessage::new(
            create_test_stream_id(),
            1,
            StreamContent::Data(create_test_proposal_data(b"test data")),
        );
        assert!(state.insert(data_msg).is_none());

        // Insert fin part - should complete the proposal
        let fin_msg = StreamMessage::new(
            create_test_stream_id(),
            2,
            StreamContent::Data(create_test_proposal_fin()),
        );

        let result = state.insert(fin_msg);
        assert!(result.is_some());

        let parts = result.unwrap();
        assert_eq!(parts.height, Height(1));
        assert_eq!(parts.round, Round::new(0));
        assert_eq!(parts.parts.len(), 3);
        assert!(state.is_done());
    }

    #[test]
    fn test_stream_state_fin_content() {
        let mut state = StreamState::new();

        // Insert init part
        let init_msg = StreamMessage::new(
            create_test_stream_id(),
            0,
            StreamContent::Data(create_test_proposal_init()),
        );
        state.insert(init_msg);

        // StreamContent::Fin should set total_parts and complete the proposal
        let fin_msg = StreamMessage::new(create_test_stream_id(), 1, StreamContent::Fin);

        let result = state.insert(fin_msg);
        assert!(result.is_some()); // Should complete - we have init (with proposer) and fin says total=1
        assert_eq!(state.total_parts, Some(1));

        let parts = result.unwrap();
        assert_eq!(parts.parts.len(), 1); // Only init part
        assert_eq!(parts.height, Height(1));
        assert_eq!(parts.round, Round::new(0));
    }

    #[test]
    fn test_proposal_parts_fields() {
        let address = create_test_address();
        let parts = ProposalParts {
            height: Height(10),
            round: Round::new(5),
            proposer: BasePeerAddress::from(address),
            block_hash: B256::from([1u8; 32]),
            parts: vec![
                create_test_proposal_init(),
                create_test_proposal_data(b"data"),
                create_test_proposal_fin(),
            ],
        };

        assert_eq!(parts.height, Height(10));
        assert_eq!(parts.round, Round::new(5));
        assert_eq!(parts.proposer, BasePeerAddress::from(address));
        assert_eq!(parts.parts.len(), 3);
    }

    #[test]
    fn test_stream_state_out_of_order_parts() {
        let mut state = StreamState::new();

        // Insert fin part first (out of order)
        let fin_msg = StreamMessage::new(
            create_test_stream_id(),
            2,
            StreamContent::Data(create_test_proposal_fin()),
        );
        assert!(state.insert(fin_msg).is_none());
        assert_eq!(state.parts.len(), 3); // Should resize to accommodate sequence 2
        assert_eq!(state.total_parts, Some(3)); // Fin part sets total

        // Insert data part
        let data_msg = StreamMessage::new(
            create_test_stream_id(),
            1,
            StreamContent::Data(create_test_proposal_data(b"test")),
        );
        assert!(state.insert(data_msg).is_none());

        // Insert init part - should complete
        let init_msg = StreamMessage::new(
            create_test_stream_id(),
            0,
            StreamContent::Data(create_test_proposal_init()),
        );

        let result = state.insert(init_msg);
        assert!(result.is_some());
        assert!(state.is_done());
    }

    #[test]
    fn test_stream_state_fin_without_init() {
        let mut state = StreamState::new();

        // Receive StreamContent::Fin without any init part
        let fin_msg = StreamMessage::new(create_test_stream_id(), 0, StreamContent::Fin);

        let result = state.insert(fin_msg);
        assert!(result.is_none()); // Should not complete without proposer
        assert_eq!(state.total_parts, Some(0)); // Fin at sequence 0 means 0 total parts
        assert!(state.proposer.is_none()); // No proposer set
        assert!(!state.is_done()); // Not done because no proposer
    }

    #[test]
    fn test_encode_decode_value_preserves_hash() {
        use reth_ethereum_primitives::Block;

        // Create a block
        let block: Block = Block::default();
        let original_hash = block.header.hash_slow();

        // Create a Value from the block hash
        let value = Value::from(&block);

        // Encode the value
        let encoded = encode_value(&value);
        assert!(!encoded.is_empty(), "Encoded value should not be empty");

        // Decode the value
        let decoded = decode_value(encoded).expect("Should decode successfully");

        // Check that the hash is preserved
        assert_eq!(decoded.hash(), original_hash, "Hash should be preserved");

        // Check that the hash is correct
        assert_eq!(
            *decoded.id().as_b256(),
            original_hash,
            "Hash should be preserved through encode/decode"
        );
    }

    #[test]
    fn test_stream_state_fin_without_init_but_with_data() {
        let mut state = StreamState::new();

        // Insert data part first
        let data_msg = StreamMessage::new(
            create_test_stream_id(),
            0,
            StreamContent::Data(create_test_proposal_data(b"test")),
        );
        assert!(state.insert(data_msg).is_none());

        // Receive StreamContent::Fin
        let fin_msg = StreamMessage::new(create_test_stream_id(), 1, StreamContent::Fin);

        let result = state.insert(fin_msg);
        assert!(result.is_none()); // Should not complete without proposer from init
        assert_eq!(state.total_parts, Some(1)); // Fin at sequence 1 means 1 total part
        assert!(state.proposer.is_none()); // No proposer set
        assert!(!state.is_done()); // Not done because no proposer
    }
}
