//! Certified consensus bootstrap after frozen era writers synced execution without consensus.

use std::{future::Future, num::NonZeroU64, time::Duration};

use alloy_consensus::BlockHeader as _;
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{
    Epochable as _,
    types::{FixedEpocher, Height},
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::{Archive as _, Identifier};
use eyre::{OptionExt as _, WrapErr as _, ensure, eyre};
use jsonrpsee::ws_client::WsClientBuilder;
use rand_core::CryptoRng;
use reth_provider::{
    BlockHashReader as _, BlockNumReader as _, BlockReader as _, ChainStateBlockWriter as _,
    DBProvider as _, DatabaseProviderFactory as _, HeaderProvider as _,
};
use tempo_chainspec::NetworkIdentity;
use tempo_node::{
    TempoExecutionData, TempoFullNode,
    rpc::consensus::{CertifiedBlock, Query, TempoConsensusApiClient as _},
};
use tracing::{info, instrument};

use crate::{
    consensus::block::Block,
    finalization_verifier::{FinalizationVerifier, verify_boundary},
    gossip::Certificate,
    storage::{
        BUFFER_POOL_CAPACITY, BUFFER_POOL_PAGE_SIZE, init_finalizations_archive,
        init_prunable_finalized_blocks_archive,
    },
};

/// Delay between forkchoice updates while execution syncs to the floor.
const SYNC_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Anchors consensus storage at a certified floor at or above the execution head.
///
/// `latest_finalization` is awaited only when no reusable certificate is archived, so restarts
/// recover offline. Finality is persisted only through the durable execution prefix.
#[instrument(skip_all, err)]
pub async fn bootstrap<TContext>(
    mut context: TContext,
    partition_prefix: &str,
    identity: Option<NetworkIdentity>,
    node: &TempoFullNode,
    latest_finalization: impl Future<Output = eyre::Result<CertifiedBlock>>,
) -> eyre::Result<()>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + CryptoRng + Send + 'static,
{
    let chain_spec = node.chain_spec();
    let identity = identity
        .or_else(|| chain_spec.network_identity.clone())
        .ok_or_eyre("missing trusted network identity")?;
    let epoch_length: NonZeroU64 = chain_spec
        .info
        .epoch_length()
        .ok_or_eyre("chainspec did not contain epochLength")?;
    let epoch_strategy = FixedEpocher::new(epoch_length);
    let verifier = FinalizationVerifier::new(identity, epoch_strategy.clone());

    let page_cache = CacheRef::from_pooler(&context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
    let mut certificates = init_finalizations_archive(
        &context,
        partition_prefix,
        page_cache.clone(),
        &epoch_strategy,
    )
    .await
    .wrap_err("failed to open finalizations archive")?;
    let mut blocks = init_prunable_finalized_blocks_archive(&context, partition_prefix, page_cache)
        .await
        .wrap_err("failed to open finalized blocks archive")?;
    let historical_tip = node.provider.best_block_number()?;

    // A durable certificate is the commit marker of a previous bootstrap.
    let reusable = match certificates.last_index() {
        Some(last) if last >= historical_tip => {
            let certificate: Certificate = certificates
                .get(Identifier::Index(last))
                .await?
                .ok_or_eyre("archive did not contain its last certificate")?;
            (certificate.epoch().get() >= verifier.network_identity().from_epoch)
                .then_some((last, certificate))
        }
        _ => None,
    };
    let (floor, certificate, floor_block) = match reusable {
        Some((height, certificate)) => {
            verifier.verify_certificate(&mut context, &certificate)?;
            let block = blocks
                .get(Identifier::Index(height))
                .await?
                .ok_or_eyre("archive did not contain the finalized floor block")?;
            ensure!(
                block.number() == height && block.digest() == certificate.proposal.payload,
                "archived floor block does not match its certificate"
            );
            (height, certificate, block)
        }
        None => {
            let certified = latest_finalization
                .await
                .wrap_err("failed to fetch the latest finalization")?;
            let certificate = verifier
                .decode_and_verify(&mut context, &certified)
                .wrap_err("upstream finalization failed verification")?;
            let block = Block::try_from_execution_block(certified.block)?;
            let height = block.number();
            // The block is written first so the durable certificate implies its block.
            blocks = blocks
                .put_sync(height, block.digest(), block.clone())
                .await?;
            certificates = certificates
                .put_sync(height, certificate.proposal.payload, certificate.clone())
                .await?;
            (height, certificate, block)
        }
    };
    ensure!(
        floor >= historical_tip,
        "finalized floor `{floor}` is below the historical tip `{historical_tip}`"
    );
    let floor_hash = floor_block.digest().0;
    info!(floor, historical_tip, "selected certified consensus floor");

    // Replay cached blocks offline; with a gap, execution bulk syncs to the floor instead.
    let mut start = historical_tip.saturating_add(1).min(floor);
    if blocks.next_gap(start).0.is_none_or(|end| end < floor) {
        start = floor;
    }
    let engine = &node.add_ons_handle.beacon_engine_handle;
    for height in start..=floor {
        let block = if height == floor {
            floor_block.clone()
        } else {
            blocks
                .get(Identifier::Index(height))
                .await?
                .ok_or_else(|| eyre!("archive lost cached block `{height}`"))?
        };
        let status = engine
            .new_payload(TempoExecutionData {
                block: block.into_execution_block(),
            })
            .await
            .wrap_err_with(|| format!("failed to submit block `{height}`"))?;
        ensure!(
            status.is_valid() || status.is_syncing(),
            "block `{height}` was neither valid nor syncing: `{status}`"
        );
    }

    let head = ForkchoiceState {
        head_block_hash: floor_hash,
        ..Default::default()
    };
    loop {
        let updated = engine
            .fork_choice_updated(head, None)
            .await
            .wrap_err("failed to update forkchoice to the floor")?;
        let status = updated.payload_status.status;
        if status.is_valid() {
            break;
        }
        ensure!(
            status.is_syncing(),
            "forkchoice to the floor was neither valid nor syncing: `{status}`"
        );
        context.sleep(SYNC_POLL_INTERVAL).await;
    }
    ensure!(
        node.provider.block_hash(floor)? == Some(floor_hash),
        "execution did not canonicalize the finalized floor"
    );

    let boundary_height = verifier.boundary_height(Height::new(floor))?.get();
    let boundary = node
        .provider
        .header_by_number(boundary_height)?
        .ok_or_else(|| eyre!("missing boundary header at height `{boundary_height}`"))?;
    verify_boundary(&mut context, &certificate, &boundary)
        .wrap_err("finalized floor failed boundary verification")?;

    let database = node.provider.database_provider_ro()?;
    let durable = database.best_block_number()?.min(floor);
    ensure!(
        durable >= historical_tip,
        "durable execution `{durable}` is below the historical tip `{historical_tip}`"
    );
    ensure!(
        database.block_hash(durable)? == node.provider.block_hash(durable)?,
        "durable execution block `{durable}` is not canonical"
    );
    drop(database);

    // A restart can replay the executed tail without an upstream or Reth's in-memory buffer.
    for height in durable + 1..floor {
        let block = node
            .provider
            .sealed_block_with_senders(height.into(), Default::default())?
            .ok_or_else(|| eyre!("execution is missing block `{height}`"))?;
        let block = Block::from_execution_block_unchecked(block);
        blocks = blocks.put(height, block.digest(), block).await?;
    }
    // Both archives close here, before the engines reopen them.
    drop((blocks.sync().await?, certificates));

    let finalized = engine
        .fork_choice_updated(
            ForkchoiceState {
                head_block_hash: floor_hash,
                safe_block_hash: floor_hash,
                finalized_block_hash: floor_hash,
            },
            None,
        )
        .await
        .wrap_err("failed to finalize the floor")?;
    ensure!(
        finalized.payload_status.status.is_valid(),
        "finalizing the floor was not valid: `{}`",
        finalized.payload_status.status
    );

    // Finality is persisted only through the durable execution prefix.
    let writer = node.provider.database_provider_rw()?;
    writer.save_finalized_block_number(durable)?;
    writer.save_safe_block_number(durable)?;
    writer.commit()?;
    info!(
        floor,
        durable, "bootstrapped consensus at the certified floor"
    );
    Ok(())
}

/// Fetches the latest finalization from a consensus RPC upstream over WebSocket.
#[instrument(skip_all, fields(%upstream_url), err)]
pub async fn latest_finalization(
    upstream_url: &str,
    request_timeout: Duration,
) -> eyre::Result<CertifiedBlock> {
    let client = WsClientBuilder::default()
        .request_timeout(request_timeout)
        .build(upstream_url)
        .await
        .wrap_err("failed to connect to the consensus upstream")?;
    Ok(client.get_finalization(Query::Latest).await?)
}
