//! Authenticates Zone genesis and its Portal creation on Tempo.

use std::collections::BTreeSet;

use alloy_consensus::BlockHeader as _;
use alloy_eips::{BlockId, BlockNumHash};
use alloy_network::{BlockResponse as _, ReceiptResponse as _};
use alloy_primitives::{Address, B256, U256};
use alloy_provider::{DynProvider, Provider as _};
use alloy_rpc_types_eth::Filter;
use alloy_sol_types::SolEvent as _;
use futures::{StreamExt as _, stream};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_storage_api::{BlockNumReader, StateProviderFactory};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::TempoHardforks;
use tempo_contracts::zones::{ZONE_FACTORY_ADDRESS, ZoneFactory};

use crate::{
    AttemptError, CheckerConfig,
    accounting::State,
    decode_event,
    l1::{classify_rpc_error, validate_rpc_header},
    l2::read_zone_genesis,
    persistence::{self, Checkpoint},
};

const GENESIS_BLOCK: u64 = 0;
const LOG_QUERY_BLOCKS: u64 = 10_000;
const LOG_QUERY_CONCURRENCY: usize = 8;

/// Authenticated Zone genesis and Portal identity, without replayed accounting state.
pub(crate) struct Bootstrap {
    identity: persistence::Identity,
    zone: persistence::BlockRef,
    tempo: persistence::BlockRef,
}

impl Bootstrap {
    pub(crate) const fn identity(&self) -> persistence::Identity {
        self.identity
    }

    pub(crate) const fn zone(&self) -> persistence::BlockRef {
        self.zone
    }

    /// Build the empty checkpoint preceding Portal creation.
    pub(crate) fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            identity: self.identity,
            zone: self.zone,
            tempo: self.tempo,
            state: State::default(),
        }
    }
}

/// Discover and authenticate the identity encoded by local Zone genesis.
pub(crate) async fn discover<P>(
    provider: &P,
    l1: &DynProvider<TempoNetwork>,
    config: &CheckerConfig,
) -> Result<Bootstrap, AttemptError>
where
    P: BlockNumReader + ChainSpecProvider + StateProviderFactory + ?Sized,
    P::ChainSpec: TempoHardforks,
{
    let context = read_context(provider, l1, config).await?;
    let creation = discover_creation(l1, config, context.tempo.number).await?;
    finish_bootstrap(context, l1, config, creation, CreationSource::Discovery).await
}

/// Authenticate the creation coordinate retained by an existing database.
pub(crate) async fn authenticate<P>(
    provider: &P,
    l1: &DynProvider<TempoNetwork>,
    config: &CheckerConfig,
    identity: persistence::Identity,
) -> Result<Bootstrap, AttemptError>
where
    P: BlockNumReader + ChainSpecProvider + StateProviderFactory + ?Sized,
    P::ChainSpec: TempoHardforks,
{
    let context = read_context(provider, l1, config).await?;
    if context.identity(config, identity.creation) != identity {
        return Err(AttemptError::disable(eyre::eyre!(
            "checker database identity does not match the configured Zone"
        )));
    }
    finish_bootstrap(
        context,
        l1,
        config,
        identity.creation,
        CreationSource::Persistence,
    )
    .await
}

/// Local genesis fields authenticated independently from Portal creation.
struct BootstrapContext {
    l1_chain_id: u64,
    zone: persistence::BlockRef,
    tempo: BlockNumHash,
    initial_token: Address,
}

impl BootstrapContext {
    const fn identity(
        &self,
        config: &CheckerConfig,
        creation: persistence::BlockRef,
    ) -> persistence::Identity {
        persistence::Identity {
            l1_chain_id: self.l1_chain_id,
            zone_chain_id: config.zone_chain_id,
            zone_id: config.zone_id,
            portal: config.portal_address,
            creation,
        }
    }
}

/// Authenticate configured chain identity and read local Zone genesis.
async fn read_context<P>(
    provider: &P,
    l1: &DynProvider<TempoNetwork>,
    config: &CheckerConfig,
) -> Result<BootstrapContext, AttemptError>
where
    P: BlockNumReader + ChainSpecProvider + StateProviderFactory + ?Sized,
    P::ChainSpec: TempoHardforks,
{
    let zone_id = config.zone_id;
    let zone_chain_id = config.zone_chain_id;
    if zone_id == 0 {
        return Err(AttemptError::disable(eyre::eyre!(
            "Zone ID must not be zero"
        )));
    }
    let l1_chain_id = l1.get_chain_id().await.map_err(classify_rpc_error)?;
    let expected_chain_id = zone_primitives::constants::zone_chain_id(l1_chain_id, zone_id)
        .map_err(AttemptError::disable)?;
    if zone_chain_id != expected_chain_id {
        return Err(AttemptError::disable(eyre::eyre!(
            "Zone chain ID {zone_chain_id} does not match Zone {zone_id} on Tempo {l1_chain_id}"
        )));
    }

    let zone_hash = provider
        .block_hash(GENESIS_BLOCK)
        .map_err(AttemptError::disable)?
        .ok_or_else(|| AttemptError::disable(eyre::eyre!("local Zone genesis is unavailable")))?;
    let (tempo, initial_token) =
        read_genesis(provider, zone_hash).map_err(AttemptError::disable)?;

    Ok(BootstrapContext {
        l1_chain_id,
        zone: persistence::BlockRef::new(GENESIS_BLOCK, zone_hash),
        tempo,
        initial_token,
    })
}

/// Source determining whether a changed creation coordinate can be rediscovered.
#[derive(Clone, Copy)]
enum CreationSource {
    Discovery,
    Persistence,
}

/// Authenticate creation and the genesis anchor, then assemble bootstrap state.
async fn finish_bootstrap(
    context: BootstrapContext,
    l1: &DynProvider<TempoNetwork>,
    config: &CheckerConfig,
    creation: persistence::BlockRef,
    source: CreationSource,
) -> Result<Bootstrap, AttemptError> {
    authenticate_creation(l1, creation, config, context.initial_token, source).await?;
    if context.tempo.number >= creation.number {
        return Err(AttemptError::disable(eyre::eyre!(
            "Zone genesis Tempo anchor {} must precede Portal creation block {}",
            context.tempo.number,
            creation.number,
        )));
    }
    if !is_canonical(l1, context.tempo, "Zone genesis anchor").await? {
        return Err(AttemptError::disable(eyre::eyre!(
            "Zone genesis Tempo anchor is not canonical"
        )));
    }

    Ok(Bootstrap {
        identity: context.identity(config, creation),
        zone: context.zone,
        tempo: persistence::BlockRef::from(context.tempo),
    })
}

/// Read and validate Zone genesis, returning its Tempo anchor and initial token.
fn read_genesis<P>(provider: &P, hash: B256) -> eyre::Result<(BlockNumHash, Address)>
where
    P: ChainSpecProvider + StateProviderFactory + ?Sized,
    P::ChainSpec: TempoHardforks,
{
    let chain_spec = provider.chain_spec();
    let spec = chain_spec.tempo_hardfork_at(chain_spec.genesis_header().timestamp());
    let snapshot = read_zone_genesis(provider, hash, spec)?;
    eyre::ensure!(
        !snapshot.tempo_block_hash.is_zero(),
        "Zone genesis has no Tempo anchor"
    );
    eyre::ensure!(
        snapshot.processed_deposit_queue_hash.is_zero()
            && snapshot.processed_deposit_number == 0
            && snapshot.withdrawal_queue_hash.is_zero()
            && snapshot.withdrawal_batch_index == 0,
        "Zone genesis contains prior bridge progress"
    );
    eyre::ensure!(
        !snapshot.default_fee_token.is_zero(),
        "Zone genesis has no initial token"
    );
    eyre::ensure!(
        snapshot.initial_token_supply.is_zero(),
        "Zone genesis initial token has nonzero supply"
    );
    Ok((
        BlockNumHash::new(snapshot.tempo_block_number, snapshot.tempo_block_hash),
        snapshot.default_fee_token,
    ))
}

/// Discover the unique creation coordinate from the RPC log index.
async fn discover_creation(
    provider: &DynProvider<TempoNetwork>,
    config: &CheckerConfig,
    anchor_number: u64,
) -> Result<persistence::BlockRef, AttemptError> {
    let head = provider
        .get_block_number()
        .await
        .map_err(classify_rpc_error)?;
    let filters = (0..=head).step_by(LOG_QUERY_BLOCKS as usize).map(|start| {
        Filter::new()
            .address(ZONE_FACTORY_ADDRESS)
            .event_signature(ZoneFactory::ZoneCreated::SIGNATURE_HASH)
            .topic1(U256::from(config.zone_id))
            .topic2(config.portal_address)
            .from_block(start)
            .to_block(start.saturating_add(LOG_QUERY_BLOCKS - 1).min(head))
    });
    let mut pages = stream::iter(filters)
        .map(|filter| async move { provider.get_logs(&filter).await.map_err(classify_rpc_error) })
        .buffer_unordered(LOG_QUERY_CONCURRENCY);
    let mut candidates = BTreeSet::new();
    while let Some(page) = pages.next().await {
        let page = page?;
        for log in page {
            if !log.removed {
                let number = log.block_number.ok_or_else(|| {
                    AttemptError::disable(eyre::eyre!(
                        "ZoneCreated discovery result has no block number"
                    ))
                })?;
                let hash = log.block_hash.ok_or_else(|| {
                    AttemptError::disable(eyre::eyre!(
                        "ZoneCreated discovery result has no block hash"
                    ))
                })?;
                candidates.insert(persistence::BlockRef::new(number, hash));
            }
        }
    }
    if candidates.is_empty() {
        return Err(AttemptError::retry(eyre::eyre!(
            "creation block is not yet available for Zone {} and Portal {} after genesis anchor {}",
            config.zone_id,
            config.portal_address,
            anchor_number,
        )));
    }
    if candidates.len() != 1 {
        return Err(AttemptError::disable(eyre::eyre!(
            "expected one creation block for Zone {} and Portal {}, found {}",
            config.zone_id,
            config.portal_address,
            candidates.len()
        )));
    }
    Ok(candidates
        .into_iter()
        .next()
        .expect("one creation coordinate was found"))
}

/// Require one matching `ZoneCreated` event with authenticated receipt provenance.
async fn authenticate_creation(
    provider: &DynProvider<TempoNetwork>,
    creation: persistence::BlockRef,
    config: &CheckerConfig,
    initial_token: Address,
    source: CreationSource,
) -> Result<(), AttemptError> {
    let block = provider
        .get_block_by_number(creation.number.into())
        .hashes()
        .await
        .map_err(classify_rpc_error)?
        .ok_or_else(|| {
            AttemptError::retry(eyre::eyre!(
                "Portal creation block {} is unavailable",
                creation.number
            ))
        })?;
    let header = validate_rpc_header(block.header())?;
    let coordinate = persistence::BlockRef::from(header.block);
    if coordinate != creation {
        let error = eyre::eyre!(
            "Portal creation coordinate changed from block {} ({}) to block {} ({})",
            creation.number,
            creation.hash,
            coordinate.number,
            coordinate.hash
        );
        return Err(match source {
            CreationSource::Discovery => AttemptError::retry(error),
            CreationSource::Persistence => AttemptError::disable(error),
        });
    }
    let receipts = provider
        .get_block_receipts(BlockId::hash(creation.hash))
        .await
        .map_err(classify_rpc_error)?
        .ok_or_else(|| {
            AttemptError::retry(eyre::eyre!("Portal creation receipts are unavailable"))
        })?;
    zone_l1::verify_receipts_against_header(
        coordinate.into(),
        header.receipts_root,
        header.logs_bloom,
        &receipts,
    )
    .map_err(AttemptError::disable)?;

    let mut creations = receipts
        .iter()
        .filter(|receipt| receipt.status())
        .flat_map(|receipt| receipt.logs())
        .filter(|log| log.address() == ZONE_FACTORY_ADDRESS)
        .filter(|log| log.topic0() == Some(&ZoneFactory::ZoneCreated::SIGNATURE_HASH))
        .map(|log| {
            decode_event::<ZoneFactory::ZoneCreated>(&log.inner, "ZoneCreated", creation.number)
        })
        .collect::<eyre::Result<Vec<_>>>()
        .map_err(AttemptError::disable)?
        .into_iter()
        .filter(|event| event.zoneId == config.zone_id && event.portal == config.portal_address);
    let event = creations.next().ok_or_else(|| {
        AttemptError::disable(eyre::eyre!(
            "authenticated block has no matching ZoneCreated event"
        ))
    })?;
    if creations.next().is_some() {
        return Err(AttemptError::disable(eyre::eyre!(
            "authenticated block has multiple matching ZoneCreated events"
        )));
    }
    if event.initialToken != initial_token {
        return Err(AttemptError::disable(eyre::eyre!(
            "Portal initial token does not match Zone genesis"
        )));
    }
    Ok(())
}

async fn is_canonical(
    provider: &DynProvider<TempoNetwork>,
    coordinate: BlockNumHash,
    name: &str,
) -> Result<bool, AttemptError> {
    let block = provider
        .get_block_by_number(coordinate.number.into())
        .hashes()
        .await
        .map_err(classify_rpc_error)?
        .ok_or_else(|| AttemptError::retry(eyre::eyre!("canonical {name} block is unavailable")))?;
    Ok(validate_rpc_header(block.header())?.block == coordinate)
}
