//! Follower sync driver.
//!
//! Subscribes to upstream finalization events and processes epoch boundary
//! blocks for DKG scheme extraction. Non-boundary blocks are synced by Reth
//! via P2P and fetched by marshal's gap-repair resolver on demand.

use std::{sync::Arc, time::Duration};

use commonware_codec::ReadExt as _;
use commonware_consensus::{
    Reporter as _,
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme,
        types::{Activity, Finalization},
    },
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::Clock;

use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tracing::{debug, debug_span, info, info_span, warn, warn_span};

use super::resolver::RpcResolver;
use crate::{
    alias::marshal, config::NAMESPACE, consensus::block::Block, epoch::SchemeProvider, feed,
};

const RECONNECT_DELAY: Duration = Duration::from_secs(2);

pub(super) struct FollowDriver<C> {
    context: C,
    resolver: Arc<RpcResolver>,
    scheme_provider: SchemeProvider,
    marshal_mailbox: marshal::Mailbox,
    feed_mailbox: feed::Mailbox,
    epocher: FixedEpocher,
    last_seen: Height,
}

impl<C: Clock> FollowDriver<C> {
    pub(super) fn new(
        context: C,
        resolver: Arc<RpcResolver>,
        scheme_provider: SchemeProvider,
        marshal_mailbox: marshal::Mailbox,
        feed_mailbox: feed::Mailbox,
        epocher: FixedEpocher,
        last_finalized_height: Height,
    ) -> Self {
        Self {
            context,
            resolver,
            scheme_provider,
            marshal_mailbox,
            feed_mailbox,
            epocher,
            last_seen: last_finalized_height,
        }
    }

    pub(super) async fn run(mut self) -> eyre::Result<()> {
        loop {
            match self.run_subscription().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn_span!("follow")
                        .in_scope(|| warn!(error = %e, "subscription loop failed, reconnecting"));
                    self.context.sleep(RECONNECT_DELAY).await;
                }
            }
        }
    }

    async fn run_subscription(&mut self) -> eyre::Result<()> {
        let mut sub = self
            .resolver
            .subscribe_events()
            .await
            .map_err(|e| eyre::eyre!("{e}"))?;

        info_span!("follow").in_scope(|| info!("subscribed to upstream events"));

        while let Some(event) = sub.next().await {
            let event = event.map_err(|e| eyre::eyre!("subscription error: {e}"))?;

            let Event::Finalized {
                block: certified, ..
            } = event
            else {
                continue;
            };

            let height = certified
                .height
                .map(Height::new)
                .ok_or_else(|| eyre::eyre!("finalized event missing height"))?;

            if height <= self.last_seen {
                continue;
            }

            self.process_boundaries(height).await?;
            self.process_finalization(&certified, height).await?;
            self.last_seen = height;
        }

        Err(eyre::eyre!("subscription stream ended"))
    }

    async fn process_boundaries(&mut self, up_to: Height) -> eyre::Result<()> {
        for boundary_height in boundary_heights_between(&self.epocher, self.last_seen, up_to) {
            self.process_boundary_block(boundary_height).await?;
        }
        Ok(())
    }

    async fn process_boundary_block(&mut self, height: Height) -> eyre::Result<()> {
        debug_span!("follow").in_scope(|| {
            debug!(%height, "processing epoch boundary block");
        });

        let block = self
            .resolver
            .fetch_block(height.get())
            .await
            .map_err(|e| eyre::eyre!("{e}"))?
            .ok_or_else(|| eyre::eyre!("block not found for boundary height {height}"))?;

        self.extract_scheme(&block, height)?;

        Ok(())
    }

    async fn process_finalization(
        &mut self,
        certified: &CertifiedBlock,
        height: Height,
    ) -> eyre::Result<()> {
        debug_span!("follow").in_scope(|| {
            debug!(
                %height,
                epoch = certified.epoch,
                "forwarding finalization to marshal"
            );
        });

        let block = self
            .resolver
            .fetch_block(height.get())
            .await
            .map_err(|e| eyre::eyre!("{e}"))?
            .ok_or_else(|| eyre::eyre!("block not found for height {height}"))?;

        let epoch = Epoch::new(certified.epoch);
        let round = Round::new(epoch, View::new(certified.view));

        self.marshal_mailbox.verified(round, block).await;

        let finalization = self.decode_finalization(certified)?;
        let activity = Activity::Finalization(finalization);
        self.marshal_mailbox.report(activity.clone()).await;
        self.feed_mailbox.report(activity).await;
        Ok(())
    }

    fn decode_finalization(
        &self,
        certified: &CertifiedBlock,
    ) -> eyre::Result<Finalization<Scheme<PublicKey, MinSig>, crate::consensus::Digest>> {
        let cert_bytes = alloy_primitives::hex::decode(&certified.certificate)
            .map_err(|e| eyre::eyre!("failed to decode certificate hex: {e}"))?;
        Finalization::read(&mut &cert_bytes[..])
            .map_err(|e| eyre::eyre!("failed to decode finalization: {e:?}"))
    }

    fn extract_scheme(&self, block: &Block, height: Height) -> eyre::Result<()> {
        let extra_data = block.header().inner.extra_data.as_ref();
        if extra_data.is_empty() {
            return Err(eyre::eyre!(
                "boundary block at height {height} has empty extra_data"
            ));
        }

        let outcome = OnchainDkgOutcome::read(&mut &extra_data[..])
            .map_err(|e| eyre::eyre!("failed to decode DKG outcome at height {height}: {e:?}"))?;

        let epoch = outcome.epoch;
        let scheme: Scheme<PublicKey, MinSig> = Scheme::verifier(
            NAMESPACE,
            outcome.players().clone(),
            outcome.sharing().clone(),
        );

        if self.scheme_provider.register(epoch, scheme) {
            info_span!("follow").in_scope(|| {
                info!(
                    %height,
                    epoch = epoch.get(),
                    "registered DKG scheme from boundary block"
                );
            });
        }

        Ok(())
    }
}

fn boundary_heights_between(epocher: &FixedEpocher, after: Height, up_to: Height) -> Vec<Height> {
    let mut boundaries = Vec::new();

    let start = after.next();
    if start > up_to {
        return boundaries;
    }

    let Some(start_epoch_info) = epocher.containing(start) else {
        return boundaries;
    };

    let mut epoch = start_epoch_info.epoch();
    while let Some(boundary) = epocher.last(epoch) {
        if boundary > up_to {
            break;
        } else if boundary > after {
            boundaries.push(boundary);
        }

        epoch = epoch.next();
    }

    boundaries
}

#[cfg(test)]
mod tests {
    use super::boundary_heights_between;
    use commonware_consensus::types::{FixedEpocher, Height};
    use commonware_utils::NZU64;

    fn h(v: u64) -> Height {
        Height::new(v)
    }

    #[test]
    fn no_boundaries_when_same_height() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert_eq!(boundary_heights_between(&epocher, h(5), h(5)), vec![]);
    }

    #[test]
    fn no_boundaries_when_after_exceeds_up_to() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert_eq!(boundary_heights_between(&epocher, h(15), h(5)), vec![]);
    }

    #[test]
    fn no_boundaries_within_same_epoch() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert_eq!(boundary_heights_between(&epocher, h(1), h(8)), vec![]);
    }

    #[test]
    fn single_boundary_at_epoch_end() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert_eq!(boundary_heights_between(&epocher, h(1), h(9)), vec![h(9)]);
    }

    #[test]
    fn multiple_boundaries_across_epochs() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert_eq!(
            boundary_heights_between(&epocher, h(1), h(29)),
            vec![h(9), h(19), h(29)]
        );
    }

    #[test]
    fn boundary_excluded_when_equal_to_after() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert_eq!(boundary_heights_between(&epocher, h(9), h(19)), vec![h(19)]);
    }

    #[test]
    fn starts_from_zero() {
        let epocher = FixedEpocher::new(NZU64!(10));
        assert_eq!(boundary_heights_between(&epocher, h(0), h(9)), vec![h(9)]);
    }

    #[test]
    fn large_epoch_no_boundary_in_range() {
        let epocher = FixedEpocher::new(NZU64!(100));
        assert_eq!(boundary_heights_between(&epocher, h(10), h(50)), vec![]);
    }

    #[test]
    fn large_epoch_boundary_in_range() {
        let epocher = FixedEpocher::new(NZU64!(100));
        assert_eq!(
            boundary_heights_between(&epocher, h(10), h(99)),
            vec![h(99)]
        );
    }
}
