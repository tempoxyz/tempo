//! Wait directly on pool arrivals without a forwarding task or a second channel.

use alloy_primitives::B256;
use tokio::sync::mpsc;

/// Coalesce buffered arrivals into one retry of the best-transaction iterator.
/// A missing or closed subscription must not make an idle consumer spin.
pub(crate) async fn pending_transactions_changed(pending: &mut Option<mpsc::Receiver<B256>>) {
    let Some(receiver) = pending else {
        return std::future::pending().await;
    };
    if receiver.recv().await.is_none() {
        *pending = None;
        return std::future::pending().await;
    }
    // Bound the drain so a continuous stream cannot delay cancellation or other work.
    for _ in 0..receiver.len() {
        let _ = receiver.try_recv();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn buffered_arrivals_are_coalesced() {
        let (sender, receiver) = mpsc::channel(8);
        let mut pending = Some(receiver);
        for _ in 0..8 {
            sender.try_send(B256::ZERO).unwrap();
        }
        pending_transactions_changed(&mut pending).await;
        assert!(pending.as_ref().unwrap().is_empty());
        sender.try_send(B256::ZERO).unwrap();
        pending_transactions_changed(&mut pending).await;
        assert!(pending.as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn arrivals_wake_an_idle_consumer() {
        let (sender, receiver) = mpsc::channel(1);
        let mut pending = Some(receiver);
        let waiter = tokio::spawn(async move {
            pending_transactions_changed(&mut pending).await;
        });
        tokio::task::yield_now().await;
        sender.send(B256::ZERO).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn closed_subscription_does_not_spin() {
        let (sender, receiver) = mpsc::channel(1);
        let mut pending = Some(receiver);
        drop(sender);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                pending_transactions_changed(&mut pending)
            )
            .await
            .is_err()
        );
        assert!(pending.is_none());
    }
}
