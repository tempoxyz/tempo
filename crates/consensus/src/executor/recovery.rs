//! Bootstrap replay below marshal's processed floor without rewinding consensus state.
//!
//! The persisted finalized tip authenticates its ancestors. Walk headers backwards
//! to the local finalized block before replaying any downloaded payload. Keep only
//! hashes on disk, not a potentially unbounded collection of block bodies in RAM.

use std::{future::Future, time::Duration};

use alloy_consensus::{BlockHeader as _, Sealable as _};
use alloy_primitives::B256;
use bytes::Buf as _;
use commonware_consensus::{Heightable as _, types::Height};
use commonware_runtime::{Blob, Clock, ReadOptions, Storage, WriteOptions};
use eyre::{WrapErr as _, ensure, eyre};
use tempo_primitives::TempoHeader;
use tracing::{info, warn};

use super::ExecutionLayer;
use crate::consensus::{Digest, block::Block};

const HEADER_BATCH: u64 = 128;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_ATTEMPTS: usize = 3;

pub(super) struct Recovery<B> {
    hashes: B,
    start: u64,
    end: u64,
}

impl<B: Blob> Recovery<B> {
    pub(super) async fn init<C: Clock + Storage<Blob = B>, E: ExecutionLayer>(
        context: &C,
        execution: &E,
        partition: &str,
        local: (Height, Digest),
        target: Height,
        anchor: (Height, Digest),
    ) -> eyre::Result<Self> {
        ensure!(
            local.0 < target && target <= anchor.0,
            "invalid recovery range"
        );
        let start = local.0.get() + 1;
        let end = target.get();
        let (hashes, _) = context.open(partition, b"hashes").await?;
        // Never trust a partial index from a previous process. Execution's
        // finalized marker is the resumable cursor; signing state is untouched.
        hashes.resize(0).await?;
        let recovery = Self { hashes, start, end };
        let mut cursor = anchor;
        info!(%target, anchor = %anchor.0, local = %local.0, "authenticating bootstrap history");
        while cursor.0 > local.0 {
            let count = HEADER_BATCH.min(cursor.0.get() - local.0.get());
            let headers = headers(context, execution, cursor, count).await?;
            for header in headers {
                if cursor.0 <= target {
                    recovery
                        .hashes
                        .write_at(
                            recovery.offset(cursor.0)?,
                            cursor.1.0.to_vec(),
                            WriteOptions::default(),
                        )
                        .await?;
                }
                cursor = (
                    Height::new(cursor.0.get() - 1),
                    Digest(header.parent_hash()),
                );
            }
        }
        ensure!(
            cursor == local,
            "finalized recovery history conflicts with local finality"
        );
        Ok(recovery)
    }

    fn offset(&self, height: Height) -> eyre::Result<u64> {
        ensure!(
            (self.start..=self.end).contains(&height.get()),
            "height outside recovery range"
        );
        (height.get() - self.start)
            .checked_mul(32)
            .ok_or_else(|| eyre!("recovery index too large"))
    }

    pub(super) async fn block<C: Clock, E: ExecutionLayer>(
        &self,
        context: &C,
        execution: &E,
        height: Height,
    ) -> eyre::Result<Block> {
        let mut data = self
            .hashes
            .read_at(self.offset(height)?, 32, ReadOptions::default())
            .await?;
        let mut hash = [0; 32];
        data.copy_to_slice(&mut hash);
        let digest = Digest(B256::from(hash));
        let block = match execution.block_by_digest(digest)? {
            Some(block) => block,
            None => request(context, || execution.fetch_block(digest)).await?,
        };
        ensure!(
            block.digest() == digest && block.height() == height,
            "recovery block does not match authenticated history"
        );
        Ok(block)
    }

    pub(super) async fn clear(self) -> eyre::Result<()> {
        self.hashes.resize(0).await?;
        Ok(())
    }
}

/// Retrieve a startup/DKG header authenticated by a persisted finalized anchor.
/// This also works before marshal and its peer manager have started.
pub(crate) async fn header_at<C: Clock, E: ExecutionLayer>(
    context: &C,
    execution: &E,
    mut anchor: (Height, Digest),
    target: Height,
) -> eyre::Result<TempoHeader> {
    ensure!(target <= anchor.0, "header above finalized recovery anchor");
    loop {
        let count = (anchor.0.get() - target.get()).min(HEADER_BATCH - 1) + 1;
        for header in headers(context, execution, anchor, count).await? {
            if anchor.0 == target {
                return Ok(header);
            }
            anchor = (
                Height::new(anchor.0.get() - 1),
                Digest(header.parent_hash()),
            );
        }
    }
}

async fn headers<C: Clock, E: ExecutionLayer>(
    context: &C,
    execution: &E,
    anchor: (Height, Digest),
    count: u64,
) -> eyre::Result<Vec<TempoHeader>> {
    request(context, || async {
        let headers = execution.fetch_headers(anchor.1, count).await?;
        ensure!(
            !headers.is_empty() && headers.len() as u64 <= count,
            "invalid recovery header count"
        );
        let mut expected = anchor.1;
        for (index, header) in headers.iter().enumerate() {
            ensure!(
                header.hash_slow() == expected.0,
                "recovery header does not match finalized ancestry"
            );
            ensure!(
                header.number() == anchor.0.get() - index as u64,
                "non-contiguous recovery header heights"
            );
            expected = Digest(header.parent_hash());
        }
        Ok(headers)
    })
    .await
}

async fn request<C, T, F, Fut>(context: &C, mut fetch: F) -> eyre::Result<T>
where
    C: Clock,
    F: FnMut() -> Fut,
    Fut: Future<Output = eyre::Result<T>>,
{
    for attempt in 1..=REQUEST_ATTEMPTS {
        let result = tokio::select! {
            result = fetch() => result,
            _ = context.sleep(REQUEST_TIMEOUT) => Err(eyre!("bootstrap peer request timed out")),
        };
        match result {
            Ok(value) => return Ok(value),
            Err(error) if attempt == REQUEST_ATTEMPTS => {
                return Err(error).wrap_err("authenticated bootstrap recovery failed");
            }
            Err(error) => warn!(attempt, %error, "retrying bootstrap peer request"),
        }
        context.sleep(Duration::from_secs(1)).await;
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    // All fetches in this test remain pending, so each sleep can advance
    // directly to its deadline without the runtime's external-process delay.
    #[derive(Clone, Default)]
    struct ClockForTimeout(Arc<Mutex<Duration>>);

    impl governor::clock::Clock for ClockForTimeout {
        type Instant = SystemTime;
        fn now(&self) -> SystemTime {
            self.current()
        }
    }
    impl governor::clock::ReasonablyRealtime for ClockForTimeout {}
    impl Clock for ClockForTimeout {
        fn current(&self) -> SystemTime {
            UNIX_EPOCH + *self.0.lock()
        }
        fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
            self.sleep_until(self.current() + duration)
        }
        fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
            let elapsed = self.0.clone();
            async move {
                *elapsed.lock() = deadline.duration_since(UNIX_EPOCH).unwrap();
            }
        }
    }

    #[test]
    fn stalled_peer_requests_have_a_bounded_retry_budget() {
        futures::executor::block_on(async {
            let context = ClockForTimeout::default();
            let start = context.current();
            let mut attempts = 0;
            let error = request(&context, || {
                attempts += 1;
                std::future::pending::<eyre::Result<()>>()
            })
            .await
            .unwrap_err();
            assert_eq!(attempts, REQUEST_ATTEMPTS);
            assert_eq!(
                context.current().duration_since(start).unwrap(),
                Duration::from_secs(92)
            );
            assert!(format!("{error:?}").contains("bootstrap peer request timed out"));
        });
    }
}
