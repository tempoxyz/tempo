//! Zone transaction pool maintenance for Tempo state the zone reads but never stores.

use futures::StreamExt;
use reth_chainspec::EthChainSpec;
use reth_provider::{CanonStateSubscriptions, Chain, ChainSpecProvider};
use reth_storage_api::StateProviderFactory;
use tempo_chainspec::hardfork::TempoHardforks;
use tempo_primitives::{TempoHeader, TempoPrimitives};
use tempo_transaction_pool::TempoTransactionPool;
use tracing::debug;
use zone_evm::ZoneEvmConfig;
use zone_l1::state::L1StateCache;
use zone_precompiles::tempo_state::TEMPO_BLOCK_NUMBER_SLOT;
use zone_primitives::constants::TEMPO_STATE_ADDRESS;

/// Revalidates pooled transactions as canonical zone blocks move the Tempo anchor, so that
/// owner updates, migrations and registrations on Tempo reach pending transactions (TIP-1154).
///
/// Zone state never stores commitments, so zone blocks do not show these changes. The
/// transactions revalidated are those with an authority whose Tempo account changed between the
/// anchors, as recorded in `l1_state_cache`, or every transaction when the cache has not recorded
/// all of those Tempo blocks. Runs until the canonical state stream ends.
pub(crate) async fn maintain_mirrored_commitments<Client>(
    pool: TempoTransactionPool<Client, ZoneEvmConfig>,
    l1_state_cache: L1StateCache,
) where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let mut chain_events = pool.client().canonical_state_stream();
    while let Some(event) = chain_events.next().await {
        // A reorg also moves the anchor back from the blocks it drops.
        let Some((from, to)) = event
            .reverted()
            .into_iter()
            .chain([event.committed()])
            .filter_map(|chain| tempo_anchor_change(&chain))
            .reduce(|(from, to), (next_from, next_to)| (from.min(next_from), to.max(next_to)))
        else {
            continue;
        };
        let changed = l1_state_cache.lock().mutated_addresses(from + 1..=to);
        debug!(
            target: "txpool",
            from,
            to,
            changed = changed.as_ref().map(|changed| changed.len()),
            "Revalidating transactions after a Tempo anchor change"
        );
        pool.revalidate_authorities(changed.as_ref()).await;
    }
}

/// Returns the lower and higher of the Tempo anchors before and after `chain`, or `None` when its
/// blocks leave the anchor unchanged.
fn tempo_anchor_change(chain: &Chain<TempoPrimitives>) -> Option<(u64, u64)> {
    let slot = chain
        .execution_outcome()
        .state()
        .account(&TEMPO_STATE_ADDRESS)?
        .storage
        .get(&TEMPO_BLOCK_NUMBER_SLOT)?;
    let before = u64::try_from(slot.original_value()).ok()?;
    let after = u64::try_from(slot.present_value).ok()?;
    (before != after).then(|| (before.min(after), before.max(after)))
}
