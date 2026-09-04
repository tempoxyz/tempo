//! Inline verification with Commonware's certification durability gates.

use commonware_consensus::{
    marshal::{core::DigestFallback, standard::Gates},
    types::Round,
};
use commonware_macros::select;
use commonware_utils::channel::{fallible::OneshotExt, oneshot};

use crate::{
    alias::marshal,
    consensus::{Digest, block::Block},
};

#[derive(Clone)]
pub(super) struct Durability {
    pub(super) gates: Gates<Digest, Block>,
    pub(super) marshal: marshal::Mailbox,
}

impl Durability {
    pub(super) fn new(marshal: marshal::Mailbox) -> Self {
        Self {
            gates: Gates::new(),
            marshal,
        }
    }

    /// Follow standard::Inline's recovery path, preserving a live local rejection.
    pub(super) async fn certify(
        &self,
        round: Round,
        digest: Digest,
        mut tx: oneshot::Sender<bool>,
    ) {
        self.gates.flush_unrelayed(&self.marshal, round, digest);
        if let Some(task) = self.gates.take(round, digest) {
            self.marshal.hint_notarized(round, digest);
            let result = select! {
                _ = tx.closed() => return,
                result = task => result,
            };
            if let Ok(verdict) = result {
                tx.send_lossy(verdict);
                return;
            }
        }

        // A notarization implies prior inline verification by an honest quorum.
        // Missing or cancelled local work must fetch its exact round and persist it.
        let block = select! {
            _ = tx.closed() => return,
            result = self.marshal.subscribe_by_digest(digest, DigestFallback::FetchByRound { round }) => {
                let Ok(block) = result else { return; };
                block
            },
        };
        if self.marshal.certified(round, block).await {
            tx.send_lossy(true);
        }
    }
}

/// Publish a completed application verdict, then hold certification on its durable store.
/// The caller must finish every header and execution check before calling this function.
pub(super) async fn publish_verification(
    valid: bool,
    response: oneshot::Sender<bool>,
    durable: oneshot::Sender<bool>,
    store: impl std::future::Future<Output = bool> + Send,
) {
    response.send_lossy(valid);
    let is_durable = valid && store.await;
    if let Some(verdict) =
        commonware_consensus::marshal::standard::resolve_verification(Some(valid), is_durable)
    {
        durable.send_lossy(verdict);
    }
}

/// A persisted proposal may carry a different parent from Simplex's recovered view.
/// Inline mode skips that round, matching Commonware's standard::Inline recovery guard.
pub(super) fn recovered_proposal(block: Block, inline: bool) -> eyre::Result<Block> {
    eyre::ensure!(!inline, "skipping recovered proposal round");
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::publish_verification;
    use commonware_runtime::{Runner as _, Spawner as _, deterministic};
    use commonware_utils::channel::{fallible::OneshotExt as _, oneshot};

    #[test]
    fn valid_verdict_precedes_store_but_certify_waits_for_durability() {
        deterministic::Runner::default().start(|context| async move {
            let (response, verify) = oneshot::channel();
            let (durable, mut certify) = oneshot::channel();
            let (release, store) = oneshot::channel();
            let task = context.spawn(move |_| {
                publish_verification(true, response, durable, async move { store.await.unwrap() })
            });
            assert!(verify.await.unwrap());
            assert!(matches!(
                certify.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            release.send_lossy(true);
            assert!(certify.await.unwrap());
            task.await.unwrap();
        });
    }

    #[test]
    fn rejection_is_preserved_without_storing_invalid_block() {
        deterministic::Runner::default().start(|_| async move {
            let (response, verify) = oneshot::channel();
            let (durable, certify) = oneshot::channel();
            publish_verification(false, response, durable, async {
                panic!("invalid block must not be stored")
            })
            .await;
            assert!(!verify.await.unwrap());
            assert!(!certify.await.unwrap());
        });
    }

    #[test]
    fn cancelled_verify_response_does_not_cancel_durable_store() {
        deterministic::Runner::default().start(|_| async move {
            let (response, verify) = oneshot::channel();
            let (durable, certify) = oneshot::channel();
            drop(verify);
            publish_verification(true, response, durable, async { true }).await;
            assert!(certify.await.unwrap());
        });
    }

    #[test]
    fn interrupted_store_abandons_gate_instead_of_certifying() {
        deterministic::Runner::default().start(|_| async move {
            let (response, verify) = oneshot::channel();
            let (durable, certify) = oneshot::channel();
            publish_verification(true, response, durable, async { false }).await;
            assert!(verify.await.unwrap());
            assert!(certify.await.is_err());
        });
    }
}
