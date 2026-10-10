//! Establish a certified consensus anchor before starting a node after historical sync.

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use commonware_runtime::{Clock as _, buffer::paged::CacheRef};
use commonware_storage::archive::{Archive as _, Identifier};
use eyre::{OptionExt as _, ensure};
use jsonrpsee::ws_client::WsClientBuilder;
use reth_provider::{
    BlockHashReader as _, BlockNumReader as _, BlockReader as _, BlockSource,
    ChainStateBlockWriter as _, DBProvider as _, DatabaseProviderFactory as _, HeaderProvider as _,
};
use std::time::Duration;
use tempo_chainspec::NetworkIdentity;
use tempo_node::{
    TempoExecutionData, TempoFullNode,
    rpc::consensus::{Query, TempoConsensusApiClient},
};

use super::{
    BUFFER_POOL_CAPACITY, BUFFER_POOL_PAGE_SIZE, init_finalizations_archive,
    init_prunable_finalized_blocks_archive,
};
use crate::{
    PARTITION_PREFIX,
    consensus::Block,
    finalization_verifier::{FinalizationVerifier, verify_boundary},
};

/// Seed a recent certified floor, sync execution to it, then durably establish finality.
/// Call before starting consensus actors, with the historical pipeline already complete.
pub async fn bootstrap(
    mut context: commonware_runtime::tokio::Context,
    identity: Option<NetworkIdentity>,
    node: &TempoFullNode,
    upstream_url: &str,
    request_timeout: Duration,
) -> eyre::Result<()> {
    let chain = node.chain_spec();
    let epochs = FixedEpocher::new(
        chain
            .info
            .epoch_length()
            .ok_or_eyre("missing epoch length")?,
    );
    let identity = identity
        .or_else(|| chain.network_identity.clone())
        .ok_or_eyre("missing trusted network identity")?;
    let verifier = FinalizationVerifier::new(identity, epochs.clone());
    let cache = CacheRef::from_pooler(&context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
    let mut certificates =
        init_finalizations_archive(&context, PARTITION_PREFIX, cache.clone(), &epochs).await?;
    let mut blocks =
        init_prunable_finalized_blocks_archive(&context, PARTITION_PREFIX, cache).await?;
    let historical_tip = node.provider.database_provider_ro()?.best_block_number()?;

    let (floor, certificate) = if let Some(height) = certificates.last_index().filter(|height| {
        *height >= historical_tip
            && epochs
                .containing(Height::new(*height))
                .unwrap()
                .epoch()
                .get()
                >= verifier.network_identity().from_epoch
    }) {
        let certificate = certificates
            .get(Identifier::Index(height))
            .await?
            .ok_or_eyre("bootstrap floor certificate is missing")?;
        verifier.verify_certificate(&mut context, &certificate)?;
        let floor = blocks
            .get(Identifier::Index(height))
            .await?
            .ok_or_eyre("bootstrap floor block is missing")?;
        ensure!(
            floor.number() == height && floor.digest() == certificate.proposal.payload,
            "bootstrap floor digest mismatch"
        );
        (floor, certificate)
    } else {
        let client = WsClientBuilder::default()
            .request_timeout(request_timeout)
            .build(upstream_url)
            .await?;
        let floor = client.get_finalization(Query::Latest).await?;
        let certificate = verifier.decode_and_verify(&mut context, &floor)?;
        let floor = Block::try_from_execution_block(floor.block)?;
        // A durable certificate is the commit marker: its block must survive a restart first.
        blocks = blocks
            .put(floor.number(), floor.digest(), floor.clone())
            .await?;
        blocks = blocks.sync().await?;
        certificates = certificates
            .put(
                floor.number(),
                certificate.proposal.payload,
                certificate.clone(),
            )
            .await?;
        certificates = certificates.sync().await?;
        (floor, certificate)
    };
    drop(certificates);

    ensure!(
        floor.number() >= historical_tip,
        "bootstrap floor is behind execution storage"
    );

    let engine = &node.add_ons_handle.beacon_engine_handle;
    // Replay a complete cached tail after a restart; fresh anchors use Reth's bulk sync.
    let mut start = historical_tip.saturating_add(1).min(floor.number());
    if blocks
        .next_gap(start)
        .0
        .is_none_or(|end| end < floor.number())
    {
        start = floor.number();
    }
    for height in start..=floor.number() {
        let block = blocks
            .get(Identifier::Index(height))
            .await?
            .ok_or_eyre("bootstrap cached payload is missing")?;
        let status = engine
            .new_payload(TempoExecutionData {
                block: block.into_execution_block(),
            })
            .await?;
        ensure!(
            status.is_valid() || status.is_syncing(),
            "bootstrap payload rejected: {status}"
        );
    }
    // Publish finality only after the restart path has reached disk.
    let state = ForkchoiceState {
        head_block_hash: floor.hash(),
        ..Default::default()
    };
    let durable_height = loop {
        let update = engine.fork_choice_updated(state, None).await?;
        ensure!(
            update.is_valid() || update.is_syncing(),
            "bootstrap forkchoice rejected: {}",
            update.payload_status
        );
        if update.is_valid() {
            ensure!(
                node.provider.block_hash(floor.number())? == Some(floor.hash()),
                "bootstrap floor is not on the certified chain"
            );
            // RPC certificate archives may skip boundaries. Execution has now authenticated
            // every ancestor of the certified floor, including the boundary's DKG outcome.
            let boundary = node
                .provider
                .header_by_number(verifier.boundary_height(floor.number()))?
                .ok_or_eyre("bootstrap boundary header is missing")?;
            verify_boundary(&mut context, &certificate, &boundary)?;
            let provider = node.provider.database_provider_ro()?;
            let height = provider.best_block_number()?.min(floor.number());
            ensure!(
                height >= historical_tip,
                "bootstrap execution storage regressed"
            );
            let hash = provider
                .block_hash(height)?
                .ok_or_eyre("bootstrap durable head is missing")?;
            ensure!(
                node.provider.block_hash(height)? == Some(hash),
                "bootstrap durable head is not on the certified chain"
            );
            break height;
        }
        context.sleep(Duration::from_secs(1)).await;
    };

    // Cache the executed tail before finalizing its durable prefix, so restart backfill
    // does not depend on Reth's in-memory buffer.
    for height in (durable_height..floor.number()).map(|height| height + 1) {
        let hash = node
            .provider
            .block_hash(height)?
            .ok_or_eyre("bootstrap tail hash is missing")?;
        let block = node
            .provider
            .find_sealed_or_recovered_block(hash, BlockSource::Canonical)?
            .ok_or_eyre("bootstrap executed tail block is missing")?;
        let block = Block::try_from_execution_block(block)?;
        blocks = blocks.put(height, block.digest(), block).await?;
    }
    blocks.sync().await?;
    ensure!(
        engine
            .fork_choice_updated(ForkchoiceState::same_hash(floor.hash()), None)
            .await?
            .is_valid(),
        "bootstrap finality rejected"
    );
    let provider = node.provider.database_provider_rw()?;
    provider.save_finalized_block_number(durable_height)?;
    provider.save_safe_block_number(durable_height)?;
    provider.commit()?;
    Ok(())
}
