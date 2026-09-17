//! Keep application validity and candidate durability as separate vote gates.

use std::future::Future;

use eyre::ensure;

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
}
