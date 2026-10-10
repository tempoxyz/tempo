//! Establish a certified consensus anchor before starting a node after historical sync.

use std::time::Duration;

use alloy_consensus::BlockHeader as _;
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    Epochable as _,
    simplex::scheme::bls12381_threshold::vrf::Scheme,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock as _, buffer::paged::CacheRef};
use commonware_storage::archive::{Archive as _, Identifier};
use eyre::{OptionExt as _, ensure};
use jsonrpsee::ws_client::WsClientBuilder;
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_provider::{
    BlockHashReader as _, BlockNumReader as _, BlockReader as _, BlockSource,
    ChainStateBlockWriter as _, DBProvider as _, DatabaseProviderFactory as _,
};
use tempo_chainspec::NetworkIdentity;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{
    TempoExecutionData, TempoFullNode,
    rpc::consensus::{CertifiedBlock, Query, TempoConsensusApiClient},
};
use tempo_primitives::TempoHeader;

use super::{
    BUFFER_POOL_CAPACITY, BUFFER_POOL_PAGE_SIZE, init_finalizations_archive,
    init_prunable_finalized_blocks_archive,
};
use crate::{
    PARTITION_PREFIX, config::NAMESPACE, consensus::Block,
    finalization_verifier::FinalizationVerifier, gossip::Certificate,
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
    let cache = CacheRef::from_pooler(&context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
    let mut certificates =
        init_finalizations_archive(&context, PARTITION_PREFIX, cache.clone(), &epochs).await?;
    let mut blocks =
        init_prunable_finalized_blocks_archive(&context, PARTITION_PREFIX, cache).await?;
    let historical_tip = node.provider.database_provider_ro()?.best_block_number()?;

    let (floor, boundary) = if let Some(height) = certificates.last_index().filter(|height| {
        *height >= historical_tip
            && epochs
                .containing(Height::new(*height))
                .unwrap()
                .epoch()
                .get()
                >= identity.from_epoch
    }) {
        let certificate: Certificate = certificates
            .get(Identifier::Index(height))
            .await?
            .ok_or_eyre("bootstrap floor certificate is missing")?;
        FinalizationVerifier::new(identity.clone(), epochs.clone())
            .verify_certificate(&mut context, &certificate)?;
        let floor = blocks
            .get(Identifier::Index(height))
            .await?
            .ok_or_eyre("bootstrap floor block is missing")?;
        ensure!(
            floor.number() == height && floor.digest() == certificate.proposal.payload,
            "bootstrap floor digest mismatch"
        );
        let boundary = blocks
            .get(Identifier::Index(boundary_height(&epochs, height)))
            .await?
            .ok_or_eyre("bootstrap boundary block is missing")?;
        verify_boundary(&mut context, &certificate, boundary.header())?;
        (floor, boundary)
    } else {
        let client = WsClientBuilder::default()
            .request_timeout(request_timeout)
            .build(upstream_url)
            .await?;
        let floor = client.get_finalization(Query::Latest).await?;
        let height = boundary_height(&epochs, floor.block.number());
        let boundary = if height == 0 {
            CertifiedBlock {
                epoch: 0,
                view: 0,
                digest: chain.genesis_hash(),
                certificate: String::new(),
                block: node
                    .provider
                    .find_sealed_or_recovered_block(chain.genesis_hash(), BlockSource::Canonical)?
                    .ok_or_eyre("genesis block is missing")?,
            }
        } else {
            client.get_finalization(Query::Height(height)).await?
        };
        let (certificate, boundary_certificate) = verify_anchor(
            &mut context,
            identity.clone(),
            epochs.clone(),
            &floor,
            &boundary,
        )?;
        let floor = Block::try_from_execution_block(floor.block)?;
        let boundary = Block::try_from_execution_block(boundary.block)?;
        // A durable certificate is the commit marker: its blocks must survive a restart first.
        for block in [&boundary, &floor] {
            blocks = blocks
                .put(block.number(), block.digest(), block.clone())
                .await?;
        }
        blocks = blocks.sync().await?;
        // Retain the boundary certificate for downstream bootstrap.
        for (height, certificate) in [(floor.number(), certificate)]
            .into_iter()
            .chain(boundary_certificate.map(|certificate| (boundary.number(), certificate)))
        {
            certificates = certificates
                .put(height, certificate.proposal.payload, certificate)
                .await?;
        }
        certificates = certificates.sync().await?;
        (floor, boundary)
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
            for block in [&floor, &boundary] {
                ensure!(
                    node.provider.block_hash(block.number())? == Some(block.hash()),
                    "bootstrap block {} is not on the certified chain",
                    block.number()
                );
            }
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

fn boundary_height(epochs: &FixedEpocher, height: u64) -> u64 {
    epochs
        .containing(Height::new(height))
        .unwrap()
        .epoch()
        .previous()
        .map_or(0, |epoch| epochs.last(epoch).unwrap().get())
}

fn verify_anchor(
    context: &mut impl rand_core::CryptoRng,
    identity: NetworkIdentity,
    epochs: FixedEpocher,
    floor: &CertifiedBlock,
    boundary: &CertifiedBlock,
) -> eyre::Result<(Certificate, Option<Certificate>)> {
    let verifier = FinalizationVerifier::new(identity, epochs.clone());
    let certificate = verifier.decode_and_verify(context, floor)?;
    ensure!(
        boundary.block.number() == boundary_height(&epochs, floor.block.number()),
        "bootstrap boundary height mismatch"
    );
    let boundary_certificate = (boundary.block.number() != 0)
        .then(|| verifier.decode_and_verify(context, boundary))
        .transpose()?;
    verify_boundary(context, &certificate, boundary.block.header())?;
    Ok((certificate, boundary_certificate))
}

fn verify_boundary(
    context: &mut impl rand_core::CryptoRng,
    certificate: &Certificate,
    boundary: &TempoHeader,
) -> eyre::Result<()> {
    let outcome = OnchainDkgOutcome::read(&mut boundary.extra_data().as_ref())?;
    ensure!(
        outcome.epoch() == certificate.epoch(),
        "bootstrap DKG epoch mismatch"
    );
    ensure!(
        certificate.verify(
            context,
            &Scheme::verifier(
                NAMESPACE,
                outcome.players().clone(),
                outcome.sharing().clone()
            ),
            &Sequential
        ),
        "bootstrap floor does not verify against its boundary"
    );
    Ok(())
}

#[cfg(test)]
#[path = "bootstrap_test.rs"]
mod test;
