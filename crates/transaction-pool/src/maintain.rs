//! Maintainence loops for the tempo pool

use crate::TempoTransactionPool;
use futures::{Stream, StreamExt};
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_provider::CanonStateNotification;
use reth_storage_api::StateProviderFactory;
use tempo_precompiles::NONCE_PRECOMPILE_ADDRESS;
use tempo_primitives::TempoPrimitives;

/// An endless future that maintains the [`TempoTransactionPool`] 2d nonce pool based on the storage changes of the `NonceManager` precompile.
///
/// The `NonceManager` contains
///
/// ```solidity
///  mapping(address => mapping(uint256 => uint64)) public nonces
/// ```
///
/// where each slot tracks the current nonce for a nonce key assigned to the transaction.
/// The next executable nonce is the current value of in the contract's state.
pub async fn maintain_2d_nonce_pool<Client, St>(pool: TempoTransactionPool<Client>, mut events: St)
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
    St: Stream<Item = CanonStateNotification<TempoPrimitives>> + Send + Unpin + 'static,
{
    let nonce_keys = pool.aa_2d_nonce_keys();
    while let Some(notification) = events.next().await {
        let tip = notification.committed();
        let Some(nonce_manager_changes) = tip
            .execution_outcome()
            .bundle
            .account(&NONCE_PRECOMPILE_ADDRESS)
        else {
            continue;
        };
        // this contains all the nonce manager precompile changes. if any
        let changed_slots = nonce_manager_changes
            .storage
            .iter()
            .map(|(slot, change)| (*slot, change.present_value))
            .collect::<Vec<_>>();
        if changed_slots.is_empty() {
            continue;
        }

        // we can now map the slots back to addresses and nonce keys and then update the pool
        let updates = nonce_keys.update_tracked(changed_slots);

        pool.on_aa_2d_nonce_changes(updates);
    }
}
