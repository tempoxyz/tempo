use super::*;
use std::time::Duration;

/// How often finalized Portal pause state is polled.
pub const PORTAL_PAUSE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Refresh the tracker's pause gate from `ZonePortal.paused()` at the latest finalized L1 block.
///
/// The L1 subscriber applies `PortalPaused` and `PortalResumed` events at their exact block, but a
/// pause also expires without an event, and a paused Zone stops consuming L1 so the subscriber
/// stalls at its lookahead bound. This read observes both independently of ingestion. It is pinned
/// to the finalized block hash, and failures leave the previous state in place so the gate fails
/// closed.
///
/// The finalized header timestamp is recorded as well. A pause or outage that spans a hardfork
/// activation fills the lookahead with pre-fork headers, and the engine needs to see the activation
/// on L1 before it can checkpoint that prefix and let ingestion resume.
pub async fn refresh_portal_pause(
    l1_provider: &impl Provider<TempoNetwork>,
    portal_address: Address,
    tracker: &L1BlockTracker,
) -> eyre::Result<()> {
    let header = l1_provider
        .get_header_by_number(BlockNumberOrTag::Finalized)
        .await?
        .ok_or_else(|| eyre::eyre!("L1 finalized block is not available"))?;
    let block = header.num_hash();
    tracker.observe_finalized_l1_timestamp(header.timestamp());
    if tracker.portal_pause_block() == Some(block) {
        return Ok(());
    }
    let paused = abi::ZonePortal::new(portal_address, l1_provider)
        .paused()
        .block(BlockId::hash_canonical(block.hash))
        .call()
        .await?;
    if tracker.observe_portal_pause(block, paused)? {
        info!(
            target: "zone::l1",
            block_number = block.number,
            paused,
            "Finalized Portal pause state changed"
        );
    }
    Ok(())
}

/// Read the finalized Portal pause state, retrying until it is available.
///
/// Call this before starting block production, so a node restarted during a pause does not
/// produce blocks while the subscriber catches up to the pause event.
pub async fn initialize_portal_pause(
    l1_provider: &impl Provider<TempoNetwork>,
    portal_address: Address,
    tracker: &L1BlockTracker,
) {
    while let Err(err) = refresh_portal_pause(l1_provider, portal_address, tracker).await {
        warn!(
            target: "zone::l1",
            %portal_address,
            %err,
            "Waiting for finalized Portal pause state"
        );
        tokio::time::sleep(PORTAL_PAUSE_POLL_INTERVAL).await;
    }
}

/// Poll finalized Portal pause state forever.
pub async fn watch_portal_pause(
    l1_provider: DynProvider<TempoNetwork>,
    portal_address: Address,
    tracker: L1BlockTracker,
) {
    let mut interval = tokio::time::interval(PORTAL_PAUSE_POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(err) = refresh_portal_pause(&l1_provider, portal_address, &tracker).await {
            warn!(target: "zone::l1", %err, "Failed to refresh finalized Portal pause state");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use alloy_sol_types::SolCall as _;
    use alloy_transport::mock::Asserter;
    use tempo_alloy::rpc::TempoHeaderResponse;

    const PORTAL: Address = Address::repeat_byte(0x11);

    fn provider() -> (Asserter, DynProvider<TempoNetwork>) {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        (asserter, provider)
    }

    fn block(number: u64) -> NumHash {
        NumHash::new(number, B256::with_last_byte(number as u8))
    }

    fn push_finalized_header(asserter: &Asserter, number: u64) {
        asserter.push_success(&Some(TempoHeaderResponse {
            inner: alloy_rpc_types_eth::Header {
                hash: block(number).hash,
                inner: TempoHeader {
                    inner: alloy_consensus::Header {
                        number,
                        timestamp: number,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                total_difficulty: None,
                size: None,
            },
            timestamp_millis: 0,
        }));
    }

    fn push_paused(asserter: &Asserter, paused: bool) {
        asserter.push_success(&Bytes::from(
            abi::ZonePortal::pausedCall::abi_encode_returns(&paused),
        ));
    }

    #[tokio::test]
    async fn refresh_applies_finalized_state_and_skips_an_applied_block() {
        let (asserter, provider) = provider();
        let tracker = L1BlockTracker::default();

        push_finalized_header(&asserter, 10);
        push_paused(&asserter, true);
        refresh_portal_pause(&provider, PORTAL, &tracker)
            .await
            .unwrap();
        assert!(tracker.portal_paused());
        assert_eq!(tracker.portal_pause_block(), Some(block(10)));
        assert_eq!(tracker.finalized_l1_timestamp(), Some(10));

        // An unchanged finalized block does not repeat the state read.
        push_finalized_header(&asserter, 10);
        refresh_portal_pause(&provider, PORTAL, &tracker)
            .await
            .unwrap();
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn refresh_failures_preserve_the_previous_state() {
        let (asserter, provider) = provider();
        let tracker = L1BlockTracker::default();
        tracker.observe_portal_pause(block(10), true).unwrap();

        push_finalized_header(&asserter, 11);
        asserter.push_failure_msg("paused call unavailable");
        assert!(
            refresh_portal_pause(&provider, PORTAL, &tracker)
                .await
                .is_err()
        );
        asserter.push_success(&None::<TempoHeaderResponse>);
        assert!(
            refresh_portal_pause(&provider, PORTAL, &tracker)
                .await
                .is_err()
        );
        assert!(tracker.portal_paused());
        assert_eq!(tracker.portal_pause_block(), Some(block(10)));
        // Finalized hardfork readiness does not depend on the Portal state read succeeding.
        assert_eq!(tracker.finalized_l1_timestamp(), Some(11));
    }

    #[tokio::test]
    async fn initialization_retries_until_state_is_available() {
        let (asserter, provider) = provider();
        let tracker = L1BlockTracker::default();
        asserter.push_failure_msg("L1 unavailable");
        push_finalized_header(&asserter, 11);
        push_paused(&asserter, true);

        tokio::time::timeout(
            PORTAL_PAUSE_POLL_INTERVAL * 5,
            initialize_portal_pause(&provider, PORTAL, &tracker),
        )
        .await
        .expect("initialization must retry transient failures");
        assert!(tracker.portal_paused());
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn watcher_observes_expiry_without_an_event() {
        let (asserter, provider) = provider();
        let tracker = L1BlockTracker::default();
        tracker.observe_portal_pause(block(10), true).unwrap();
        push_finalized_header(&asserter, 11);
        push_paused(&asserter, false);

        let watcher = tokio::spawn(watch_portal_pause(provider, PORTAL, tracker.clone()));
        tokio::time::timeout(Duration::from_secs(1), async {
            while tracker.portal_paused() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("polling must observe expiry");
        watcher.abort();
    }
}
