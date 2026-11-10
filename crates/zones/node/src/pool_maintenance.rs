//! Zone transaction pool maintenance for Tempo state the zone reads but never stores.

use futures::StreamExt;
use reth_chainspec::EthChainSpec;
use reth_provider::{CanonStateSubscriptions, ChainSpecProvider};
use reth_storage_api::StateProviderFactory;
use tempo_chainspec::hardfork::TempoHardforks;
use tempo_primitives::{TempoHeader, TempoPrimitives};
use tempo_transaction_pool::TempoTransactionPool;
use tracing::{debug, warn};
use zone_evm::ZoneEvmConfig;
use zone_l1::{TempoStateExt as _, state::L1StateCache};

/// Revalidates pooled transactions as canonical zone blocks move the Tempo anchor, so that
/// owner updates, migrations and registrations on Tempo reach pending transactions (TIP-1154).
///
/// Zone state never stores commitments, so zone blocks do not show these changes. Each canonical
/// state event compares the anchor at the latest zone block with the last one processed, so a reorg
/// that moves it back and the events the stream drops during a revalidation are both covered. The
/// transactions revalidated are those with an authority whose Tempo account changed between the two
/// anchors, as recorded in `l1_state_cache`, or every transaction when the cache has not recorded
/// all of those Tempo blocks or no anchor was processed yet. An anchor counts as processed only
/// once every selected transaction was validated, so a failed validation is retried on the next
/// event. Runs until the canonical state stream ends.
pub(crate) async fn maintain_mirrored_commitments<Client>(
    pool: TempoTransactionPool<Client, ZoneEvmConfig>,
    l1_state_cache: L1StateCache,
) where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let latest_anchor = || {
        pool.client()
            .latest()
            .and_then(|state| state.tempo_block_number())
    };
    let mut chain_events = pool.client().canonical_state_stream();
    let mut anchor = latest_anchor().ok();
    while chain_events.next().await.is_some() {
        let current = match latest_anchor() {
            Ok(current) => current,
            Err(error) => {
                warn!(target: "txpool", %error, "Failed to read the zone's Tempo anchor");
                continue;
            }
        };
        let changed = match anchor {
            Some(previous) if previous == current => continue,
            Some(previous) => l1_state_cache
                .lock()
                .mutated_addresses(previous.min(current) + 1..=previous.max(current)),
            None => None,
        };
        debug!(
            target: "txpool",
            anchor = current,
            changed = changed.as_ref().map(|changed| changed.len()),
            "Revalidating transactions after a Tempo anchor change"
        );
        // Keep the previous anchor when a validation failed, so the next event retries the range.
        if pool.revalidate_authorities(changed.as_ref()).await {
            anchor = Some(current);
        } else {
            warn!(target: "txpool", anchor = current, "Failed to revalidate transactions, retrying on the next event");
        }
    }
}
