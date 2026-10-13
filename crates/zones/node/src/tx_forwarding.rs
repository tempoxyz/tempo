//! Raw transaction propagation and replica pool admission.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use alloy_eips::eip2718::Encodable2718 as _;
use alloy_primitives::B256;
use reth_transaction_pool::{
    NewTransactionEvent, PoolTransaction, TransactionOrigin, TransactionPool, error::PoolErrorKind,
};
use tempo_transaction_pool::transaction::TempoPooledTransaction;
use tokio::{
    sync::mpsc,
    time::{Instant, MissedTickBehavior},
};
use tracing::{debug, warn};
use zone_p2p::{P2pCommand, P2pEvent};

#[cfg(not(test))]
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(test)]
const RECONCILIATION_INTERVAL: Duration = Duration::from_millis(10);

const MAX_RECONCILIATION_BATCH: usize = 256;

enum QueueOutcome {
    Queued,
    Full,
    Closed,
}

/// Immediately queue locally originated follower transactions for the quorum, then periodically
/// reconcile local-origin pool entries to recover from intermittent connection issues / restarts.
pub(crate) async fn forward_new_transactions<P>(
    pool: P,
    mut transactions: mpsc::Receiver<NewTransactionEvent<TempoPooledTransaction>>,
    commands: mpsc::Sender<P2pCommand>,
) where
    P: TransactionPool<Transaction = TempoPooledTransaction>,
{
    // Retry state is bounded by live txpool membership and pruned on each reconciliation tick.
    let mut retry_at = HashMap::new();
    let mut reconciliation = tokio::time::interval(RECONCILIATION_INTERVAL);
    reconciliation.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = transactions.recv() => {
                let Some(event) = event else {
                    tracing::error!(target: "zone::p2p", "Follower transaction pool listener closed");
                    return;
                };
                // Transactions admitted from P2P use `External` origin. Retain them for a future
                // promotion, but do not relay them and create quorum-wide re-flooding.
                if !event.transaction.origin.is_local() {
                    continue;
                }
                let transaction = &event.transaction.transaction;
                let hash = *transaction.hash();

                // Reth emits an event before reporting transactions discarded under pool pressure.
                if !pool.contains(&hash) || retry_at.contains_key(&hash) {
                    continue;
                }
                match try_queue_transaction(transaction, &commands) {
                    QueueOutcome::Queued => {
                        retry_at.insert(hash, Instant::now() + RECONCILIATION_INTERVAL);
                    }
                    // If the command queue is full, wait until the next tick to retry.
                    QueueOutcome::Full => {}
                    QueueOutcome::Closed => return,
                }
            }
            _ = reconciliation.tick() => {
                if !reconcile_txpool(&pool, &commands, &mut retry_at) {
                    return;
                }
            }
        }
    }
}

fn try_queue_transaction(
    transaction: &TempoPooledTransaction,
    commands: &mpsc::Sender<P2pCommand>,
) -> QueueOutcome {
    let hash = *transaction.hash();
    let encoded = transaction.encoded_2718();
    let encoded_len = encoded.len();
    match commands.try_send(P2pCommand::ForwardTransaction {
        transaction_hash: hash,
        transaction: encoded,
    }) {
        Ok(()) => {
            metrics::counter!("zone_node_transactions_queued_for_forwarding_total").increment(1);
            debug!(target: "zone::p2p", ?hash, transaction_size_bytes = encoded_len, "Queued local follower transaction for quorum peers");
            QueueOutcome::Queued
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            debug!(target: "zone::p2p", ?hash, "P2P command queue full; deferring follower transaction");
            QueueOutcome::Full
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::error!(target: "zone::p2p", ?hash, "P2P command channel closed while forwarding transaction");
            QueueOutcome::Closed
        }
    }
}

/// Scan locally originated txpool entries to recover missed listener events and retry transactions
/// whose retry interval has elapsed. Prune retry state for transactions no longer in that set,
/// stop when the command channel applies backpressure, and return `false` if that channel closes.
fn reconcile_txpool<P>(
    pool: &P,
    commands: &mpsc::Sender<P2pCommand>,
    retry_at: &mut HashMap<B256, Instant>,
) -> bool
where
    P: TransactionPool<Transaction = TempoPooledTransaction>,
{
    let mut transactions = pool.get_transactions_by_origin(TransactionOrigin::Local);
    let live_hashes: HashSet<_> = transactions.iter().map(|tx| *tx.hash()).collect();
    retry_at.retain(|hash, _| live_hashes.contains(hash));

    // Always give transactions discovered by the pool scan their first forwarding attempt before
    // retrying older transactions. Otherwise, due retries can repeatedly consume the entire batch
    // and starve later transactions indefinitely.
    transactions.sort_unstable_by_key(|transaction| retry_at.contains_key(transaction.hash()));

    let now = Instant::now();
    let mut queued = 0;
    for transaction in transactions {
        if queued == MAX_RECONCILIATION_BATCH {
            break;
        }
        let hash = *transaction.hash();
        let due = retry_at
            .get(&hash)
            .is_none_or(|next_attempt| now >= *next_attempt);
        if !due {
            continue;
        }
        match try_queue_transaction(&transaction.transaction, commands) {
            QueueOutcome::Queued => {
                retry_at.insert(hash, now + RECONCILIATION_INTERVAL);
                queued += 1;
            }
            QueueOutcome::Full => break,
            QueueOutcome::Closed => return false,
        }
    }
    true
}

/// Recover forwarded bytes and admit valid transactions to this replica's pool as external traffic.
///
/// The P2P layer emits these events only on quorum members, so promotable followers retain pending
/// transactions while RPC-only standbys never receive their bodies.
pub(crate) async fn insert_forwarded_transactions<P>(pool: P, mut events: mpsc::Receiver<P2pEvent>)
where
    P: TransactionPool<Transaction = TempoPooledTransaction>,
{
    while let Some(event) = events.recv().await {
        let P2pEvent::TransactionReceived {
            follower_ed25519_public_key: peer,
            transaction,
        } = event
        else {
            continue;
        };

        let transaction = match <TempoPooledTransaction as PoolTransaction>::recover_raw_transaction(
            &transaction,
        ) {
            Ok(transaction) => transaction,
            Err(err) => {
                metrics::counter!("zone_node_forwarded_transaction_rejections_total").increment(1);
                warn!(target: "zone::p2p", %peer, %err, "Rejected malformed forwarded transaction");
                continue;
            }
        };
        let hash = *transaction.hash();

        match pool.add_external_transaction(transaction).await {
            Ok(outcome) => {
                metrics::counter!("zone_node_forwarded_transaction_admissions_total").increment(1);
                debug!(target: "zone::p2p", %peer, ?hash, ?outcome, "Admitted forwarded transaction to local pool");
            }
            Err(err) if matches!(err.kind, PoolErrorKind::AlreadyImported) => {
                metrics::counter!("zone_node_forwarded_transaction_duplicates_total").increment(1);
                debug!(target: "zone::p2p", %peer, ?hash, "Ignored duplicate forwarded transaction");
            }
            Err(err) => {
                metrics::counter!("zone_node_forwarded_transaction_rejections_total").increment(1);
                warn!(target: "zone::p2p", %peer, ?hash, %err, "Local pool rejected forwarded transaction");
            }
        }
    }
    debug!(target: "zone::p2p", "Transaction P2P event channel closed");
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use alloy_eips::eip2718::Encodable2718 as _;
    use alloy_primitives::{Address, B256, TxKind};
    use alloy_signer::SignerSync as _;
    use alloy_signer_local::PrivateKeySigner;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use reth_transaction_pool::{
        Pool, PoolConfig, PoolTransaction, SubPoolLimit, TransactionOrigin, TransactionPool as _,
        blobstore::InMemoryBlobStore,
        error::{PoolErrorKind, RawPoolTransactionError},
        noop::MockTransactionValidator,
    };
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{Call, TempoTransaction},
    };
    use tempo_transaction_pool::{ordering::TempoTipOrdering, transaction::TempoPooledTransaction};

    use super::{forward_new_transactions, insert_forwarded_transactions, reconcile_txpool};
    use zone_p2p::{P2pCommand, P2pEvent};

    type TestPool = Pool<
        MockTransactionValidator<TempoPooledTransaction>,
        TempoTipOrdering<TempoPooledTransaction>,
        InMemoryBlobStore,
    >;

    fn test_pool() -> TestPool {
        Pool::new(
            MockTransactionValidator::default(),
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        )
    }

    fn signed_transaction(nonce: u64) -> (TempoPooledTransaction, Vec<u8>) {
        let signer = PrivateKeySigner::from_bytes(&B256::with_last_byte(1)).unwrap();
        let transaction = TempoTransaction {
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 2_000_000_000,
            calls: vec![Call {
                to: TxKind::Call(Address::ZERO),
                value: Default::default(),
                input: Default::default(),
            }],
            ..Default::default()
        };
        let signature = signer
            .sign_hash_sync(&transaction.signature_hash())
            .unwrap();
        let envelope: TempoTxEnvelope = transaction.into_signed(signature.into()).into();
        let raw = envelope.encoded_2718();
        let pooled = <TempoPooledTransaction as PoolTransaction>::recover_raw_transaction(&raw)
            .expect("test transaction must recover");
        (pooled, raw)
    }

    #[tokio::test]
    async fn propagatable_pool_event_forwards_exact_canonical_bytes() {
        let pool = test_pool();
        let listener = pool.new_transactions_listener();
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(forward_new_transactions(pool.clone(), listener, commands));
        let (transaction, expected) = signed_transaction(0);
        let transaction_hash = *transaction.hash();

        pool.add_transaction(TransactionOrigin::Local, transaction)
            .await
            .unwrap();

        let command = tokio::time::timeout(Duration::from_secs(1), command_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            command,
            P2pCommand::ForwardTransaction {
                transaction_hash,
                transaction: expected,
            }
        );
        task.abort();
    }

    #[tokio::test]
    async fn transaction_discarded_on_insert_is_not_forwarded() {
        let pool = Pool::new(
            MockTransactionValidator::default(),
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig {
                pending_limit: SubPoolLimit::new(0, usize::MAX),
                ..Default::default()
            },
        );
        let listener = pool.new_transactions_listener();
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(forward_new_transactions(pool.clone(), listener, commands));
        let (transaction, _) = signed_transaction(0);
        let transaction_hash = *transaction.hash();

        let err = pool
            .add_transaction(TransactionOrigin::External, transaction)
            .await
            .unwrap_err();
        assert!(matches!(err.kind, PoolErrorKind::DiscardedOnInsert));
        assert!(!pool.contains(&transaction_hash));

        assert!(
            tokio::time::timeout(Duration::from_millis(100), command_rx.recv())
                .await
                .is_err(),
            "discarded transaction was forwarded"
        );
        task.abort();
    }

    #[tokio::test]
    async fn externally_admitted_transaction_is_retained_without_reforwarding() {
        let pool = test_pool();
        let listener = pool.new_transactions_listener();
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(forward_new_transactions(pool.clone(), listener, commands));
        let (transaction, _) = signed_transaction(0);
        let transaction_hash = *transaction.hash();

        pool.add_transaction(TransactionOrigin::External, transaction)
            .await
            .unwrap();

        assert!(pool.contains(&transaction_hash));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), command_rx.recv())
                .await
                .is_err(),
            "externally admitted transaction was re-forwarded"
        );
        task.abort();
    }

    #[tokio::test]
    async fn forwarder_excludes_private_transactions() {
        let pool = test_pool();
        let listener = pool.new_transactions_listener();
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(forward_new_transactions(pool.clone(), listener, commands));
        let (transaction, _) = signed_transaction(0);

        pool.add_transaction(TransactionOrigin::Private, transaction)
            .await
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(100), command_rx.recv())
                .await
                .is_err()
        );
        task.abort();
    }

    #[tokio::test]
    async fn retries_propagatable_transaction_while_it_remains_in_pool() {
        let pool = test_pool();
        let listener = pool.new_transactions_listener();
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(forward_new_transactions(pool.clone(), listener, commands));
        let (transaction, _) = signed_transaction(0);
        let transaction_hash = *transaction.hash();

        pool.add_transaction(TransactionOrigin::Local, transaction)
            .await
            .unwrap();

        for _ in 0..2 {
            let command = tokio::time::timeout(Duration::from_secs(1), command_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                command,
                P2pCommand::ForwardTransaction { transaction_hash: hash, .. }
                    if hash == transaction_hash
            ));
        }
        task.abort();
    }

    #[tokio::test]
    async fn reconciliation_prioritizes_unseen_transactions_over_due_retries() {
        let pool = test_pool();
        for nonce in 0..257 {
            let (transaction, _) = signed_transaction(nonce);
            pool.add_transaction(TransactionOrigin::Local, transaction)
                .await
                .unwrap();
        }

        let transactions = pool.pooled_transactions();
        let victim_hash = *transactions.last().unwrap().hash();
        let mut retry_at = transactions
            .iter()
            .take(transactions.len() - 1)
            .map(|transaction| (*transaction.hash(), tokio::time::Instant::now()))
            .collect::<HashMap<_, _>>();
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(1);

        assert!(reconcile_txpool(&pool, &commands, &mut retry_at));
        assert!(matches!(
            command_rx.recv().await,
            Some(P2pCommand::ForwardTransaction { transaction_hash, .. })
                if transaction_hash == victim_hash
        ));
    }

    #[tokio::test]
    async fn replica_consumer_survives_malformed_and_duplicate_transactions() {
        let pool = test_pool();
        let (events, event_rx) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(insert_forwarded_transactions(pool.clone(), event_rx));
        let peer = PrivateKey::from_seed(9).public_key();
        let (first, first_raw) = signed_transaction(0);
        let first_hash = *first.hash();
        let (second, second_raw) = signed_transaction(1);
        let second_hash = *second.hash();
        let mut invalid_signature = signed_transaction(2).1;
        let signature_start = invalid_signature.len() - 65;
        invalid_signature[signature_start..].fill(0);
        assert!(matches!(
            <TempoPooledTransaction as PoolTransaction>::recover_raw_transaction(
                &invalid_signature
            ),
            Err(RawPoolTransactionError::InvalidTransactionSignature)
        ));

        for transaction in [
            vec![0x76, 0xff],
            invalid_signature,
            first_raw.clone(),
            first_raw,
            second_raw,
        ] {
            events
                .send(P2pEvent::TransactionReceived {
                    follower_ed25519_public_key: peer.clone(),
                    transaction,
                })
                .await
                .unwrap();
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while !pool.contains(&first_hash) || !pool.contains(&second_hash) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("valid transactions were not admitted after malformed/duplicate events");
        let external = pool.get_transactions_by_origin(TransactionOrigin::External);
        assert_eq!(external.len(), 2);
        drop(events);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn listener_overflow_is_recovered_by_mempool_reconciliation() {
        let pool = test_pool();
        let mut listener = pool.new_transactions_listener();

        for nonce in 0..1024 {
            let (transaction, _) = signed_transaction(nonce);
            pool.add_transaction(TransactionOrigin::Local, transaction)
                .await
                .unwrap();
        }

        let (victim, _) = signed_transaction(1024);
        let victim_hash = *victim.hash();
        pool.add_transaction(TransactionOrigin::Local, victim.clone())
            .await
            .unwrap();
        assert!(
            pool.contains(&victim_hash),
            "victim transaction was admitted locally"
        );

        let mut seen_victim = false;
        let mut received = 0usize;
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(10), listener.recv()).await
        {
            received += 1;
            if event.transaction.hash() == &victim_hash {
                seen_victim = true;
            }
        }

        assert_eq!(received, 1024, "listener buffer size changed");
        assert!(
            !seen_victim,
            "overflowed transaction unexpectedly reached the forwarding listener"
        );
        assert!(
            pool.add_transaction(TransactionOrigin::Local, victim)
                .await
                .is_err(),
            "duplicate resubmission should be rejected as already imported"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.recv())
                .await
                .is_err(),
            "duplicate resubmission unexpectedly re-emitted a forwarding event"
        );

        let (commands, mut command_rx) = tokio::sync::mpsc::channel(256);
        let task = tokio::spawn(forward_new_transactions(pool, listener, commands));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(
                    command_rx.recv().await,
                    Some(P2pCommand::ForwardTransaction { transaction_hash, .. })
                        if transaction_hash == victim_hash
                ) {
                    return;
                }
            }
        })
        .await
        .expect("reconciliation did not recover the overflowed transaction");
        task.abort();
    }
}
