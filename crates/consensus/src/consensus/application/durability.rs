//! Keep application validity and candidate durability as separate vote gates.

use std::future::Future;

use eyre::ensure;
use futures::future::{Either, select};

/// A recovered candidate may be invalid or have been broadcast in a different
/// parent context. Its presence must prevent releasing either that candidate or
/// a freshly built replacement for the same round.
pub(super) async fn build_fresh_proposal<T>(
    has_candidate: impl Future<Output = bool>,
    build: impl Future<Output = eyre::Result<T>>,
) -> eyre::Result<T> {
    let guard = async {
        ensure!(
            !has_candidate.await,
            "skipping proposal: candidate already exists for round on restart"
        );
        Ok(())
    };
    let ((), proposal) = futures::try_join!(guard, build)?;
    Ok(proposal)
}

/// Poll both operations concurrently. A rejected block need not wait for its
/// candidate write; a successful verdict must wait for the durability barrier.
/// Dropping the observer does not cancel a sync already started by marshal.
pub(super) async fn verify_and_persist(
    verify: impl Future<Output = eyre::Result<bool>>,
    persist: impl Future<Output = bool>,
) -> eyre::Result<bool> {
    futures::pin_mut!(verify, persist);
    match select(verify, persist).await {
        Either::Left((verdict, persist)) => {
            if !verdict? {
                return Ok(false);
            }
            ensure!(persist.await, "marshal refused to persist candidate");
            Ok(true)
        }
        Either::Right((durable, verify)) => {
            ensure!(durable, "marshal refused to persist candidate");
            verify.await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt, channel::oneshot, executor::block_on, future};

    #[test]
    fn recovered_candidate_prevents_pending_build_release() {
        assert!(
            block_on(build_fresh_proposal::<()>(
                future::ready(true),
                future::pending(),
            ))
            .is_err()
        );
    }

    #[test]
    fn finished_build_waits_for_recovery_read_and_cannot_replace_candidate() {
        for has_candidate in [false, true] {
            let (cached_tx, cached_rx) = oneshot::channel();
            let gate =
                build_fresh_proposal(async { cached_rx.await.unwrap() }, future::ready(Ok(42)));
            futures::pin_mut!(gate);
            assert!(gate.as_mut().now_or_never().is_none());
            cached_tx.send(has_candidate).unwrap();
            let result = block_on(gate);
            if has_candidate {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), 42);
            }
        }
    }

    #[test]
    fn fresh_round_still_waits_for_build() {
        let (built_tx, built_rx) = oneshot::channel();
        let gate =
            build_fresh_proposal(future::ready(false), async { Ok(built_rx.await.unwrap()) });
        futures::pin_mut!(gate);
        assert!(gate.as_mut().now_or_never().is_none());
        built_tx.send(42).unwrap();
        assert_eq!(block_on(gate).unwrap(), 42);
    }

    #[test]
    fn cancelled_verification_drops_both_observers_after_store_start() {
        let (verdict_tx, verdict_rx) = oneshot::channel::<bool>();
        let (started_tx, started_rx) = oneshot::channel();
        let (durable_tx, durable_rx) = oneshot::channel();
        let mut gate = Box::pin(verify_and_persist(
            async { Ok(verdict_rx.await.unwrap()) },
            async {
                started_tx.send(()).unwrap();
                durable_rx.await.unwrap()
            },
        ));
        assert!(gate.as_mut().now_or_never().is_none());
        assert_eq!(block_on(started_rx), Ok(()));
        drop(gate);
        assert!(verdict_tx.is_canceled());
        assert!(durable_tx.is_canceled());
    }

    #[test]
    fn persistence_starts_while_verification_is_pending() {
        let (verdict_tx, verdict_rx) = oneshot::channel();
        let (started_tx, started_rx) = oneshot::channel();
        let (durable_tx, durable_rx) = oneshot::channel();
        let gate = verify_and_persist(async { Ok(verdict_rx.await.unwrap()) }, async {
            started_tx.send(()).unwrap();
            durable_rx.await.unwrap()
        });
        futures::pin_mut!(gate);
        assert!(gate.as_mut().now_or_never().is_none());
        assert_eq!(block_on(started_rx), Ok(()));
        verdict_tx.send(true).unwrap();
        assert!(gate.as_mut().now_or_never().is_none());
        durable_tx.send(true).unwrap();
        assert!(block_on(gate).unwrap());
    }

    #[test]
    fn early_durability_does_not_release_an_unverified_block() {
        let (verdict_tx, verdict_rx) = oneshot::channel();
        let gate = verify_and_persist(async { Ok(verdict_rx.await.unwrap()) }, future::ready(true));
        futures::pin_mut!(gate);
        assert!(gate.as_mut().now_or_never().is_none());
        verdict_tx.send(false).unwrap();
        assert!(!block_on(gate).unwrap());
    }

    #[test]
    fn invalid_block_does_not_wait_for_durability() {
        assert!(
            !block_on(verify_and_persist(
                future::ready(Ok(false)),
                future::pending()
            ))
            .unwrap()
        );
    }

    #[test]
    fn shutdown_cannot_release_a_valid_block() {
        assert!(
            block_on(verify_and_persist(
                future::ready(Ok(true)),
                future::ready(false)
            ))
            .is_err()
        );
        assert!(block_on(verify_and_persist(future::pending(), future::ready(false))).is_err());
    }

    #[test]
    fn verification_error_does_not_become_a_valid_verdict() {
        assert!(
            block_on(verify_and_persist(
                future::ready(Err(eyre::eyre!("execution unavailable"))),
                future::ready(true),
            ))
            .is_err()
        );
    }

    #[test]
    #[should_panic(expected = "fatal storage failure")]
    fn fatal_storage_errors_are_not_converted_to_rejection() {
        block_on(verify_and_persist(future::pending(), async {
            panic!("fatal storage failure");
        }))
        .unwrap();
    }
}
