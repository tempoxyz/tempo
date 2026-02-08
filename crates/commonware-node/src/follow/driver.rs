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
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider, ed25519::PublicKey,
};
use commonware_parallel::Sequential;
use commonware_runtime::Clock;
use futures::StreamExt as _;
use rand_08::{CryptoRng, Rng};

use eyre::OptionExt;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tracing::{debug, debug_span, info, info_span, warn, warn_span};

use super::upstream::UpstreamNode;
use crate::{alias::marshal, config::NAMESPACE, consensus::Digest, epoch::SchemeProvider, feed};

const RECONNECT_DELAY: Duration = Duration::from_secs(2);

pub(super) struct FollowDriver<C, U: UpstreamNode> {
    context: C,
    upstream: Arc<U>,
    scheme_provider: SchemeProvider,
    marshal_mailbox: marshal::Mailbox,
    feed_mailbox: feed::Mailbox,
    epocher: FixedEpocher,
    last_seen: Height,
}

impl<C: Clock + Rng + CryptoRng, U: UpstreamNode> FollowDriver<C, U> {
    pub(super) fn new(
        context: C,
        upstream: Arc<U>,
        scheme_provider: SchemeProvider,
        marshal_mailbox: marshal::Mailbox,
        feed_mailbox: feed::Mailbox,
        epocher: FixedEpocher,
        last_finalized_height: Height,
    ) -> Self {
        Self {
            context,
            upstream,
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
                Ok(()) => {
                    info_span!("follow_driver").in_scope(|| info!("subscription loop ended"));
                }
                Err(e) => {
                    warn_span!("follow_driver")
                        .in_scope(|| warn!(error = %e, "subscription loop failed, retrying"));
                }
            }

            self.context.sleep(RECONNECT_DELAY).await;
        }
    }

    async fn run_subscription(&mut self) -> eyre::Result<()> {
        let mut sub = self
            .upstream
            .subscribe_events()
            .await
            .map_err(|e| eyre::eyre!("{e}"))?;

        info_span!("follow_driver").in_scope(|| info!("subscribed to consensus events"));
        while let Some(event) = sub.next().await {
            let Event::Finalized {
                block: certified, ..
            } = event?
            else {
                continue;
            };

            let height = certified
                .height
                .map(Height::new)
                .ok_or_eyre("finalized event missing height")?;

            if height <= self.last_seen {
                continue;
            }

            debug_span!("follow_driver").in_scope(|| {
                debug!(%height, %certified.epoch, "new finalized event");
            });

            self.process_boundaries(height).await?;
            self.process_finalization(&certified, height).await?;
            self.last_seen = height;
        }

        info_span!("follow_driver").in_scope(|| info!("subscription stream ended"));
        Ok(())
    }

    async fn process_boundaries(&mut self, up_to: Height) -> eyre::Result<()> {
        let boundaries = boundary_heights_between(&self.epocher, self.last_seen, up_to);
        if boundaries.is_empty() {
            return Ok(());
        }

        info_span!("follow_driver").in_scope(|| {
            info!(boundaries = boundaries.len(), "processing epoch boundaries");
        });

        for height in boundaries {
            let (block, certified) = self
                .upstream
                .get_block_and_finalization_by_number(height.get())
                .await
                .map_err(|e| eyre::eyre!("{e}"))?
                .ok_or_eyre(format!(
                    "block and finalization at height {} not found on upstream",
                    height.get()
                ))?;

            let cert_bytes = alloy_primitives::hex::decode(&certified.certificate)
                .map_err(|e| eyre::eyre!("failed to decode certificate hex: {e}"))?;
            let finalization: Finalization<Scheme<PublicKey, MinSig>, Digest> =
                Finalization::read(&mut &cert_bytes[..])
                    .map_err(|e| eyre::eyre!("failed to decode finalization: {e:?}"))?;

            let scheme = self
                .scheme_provider
                .scoped(finalization.proposal.round.epoch())
                .ok_or_eyre("no scheme registered for epoch")?;

            // Validate the finalization certificate
            eyre::ensure!(finalization.verify(&mut self.context, scheme.as_ref(), &Sequential));

            let extra_data = block.header().inner.extra_data.as_ref();
            let outcome = OnchainDkgOutcome::read(&mut &extra_data[..]).map_err(|e| {
                eyre::eyre!("failed to decode DKG outcome at height {height}: {e:?}")
            })?;

            let outcome_scheme: Scheme<PublicKey, MinSig> = Scheme::verifier(
                NAMESPACE,
                outcome.players().clone(),
                outcome.sharing().clone(),
            );

            // Register the scheme for the next epoch.
            self.scheme_provider.register(outcome.epoch, outcome_scheme);

            // Store the Boundary Block
            let round = Round::new(Epoch::new(certified.epoch), View::new(certified.view));
            let activity = Activity::Finalization(finalization);
            self.marshal_mailbox.verified(round, block).await;
            self.marshal_mailbox.report(activity.clone()).await;
            self.feed_mailbox.report(activity).await;
        }

        Ok(())
    }

    async fn process_finalization(
        &mut self,
        certified: &CertifiedBlock,
        height: Height,
    ) -> eyre::Result<()> {
        let block = self
            .upstream
            .get_block_by_number(height.get())
            .await
            .map_err(|e| eyre::eyre!("{e}"))?
            .ok_or_eyre("block not found on upstream")?;

        eyre::ensure!(certified.digest == block.block_hash());

        let cert_bytes = alloy_primitives::hex::decode(&certified.certificate)
            .map_err(|e| eyre::eyre!("failed to decode certificate hex: {e}"))?;
        let finalization: Finalization<Scheme<PublicKey, MinSig>, Digest> =
            Finalization::read(&mut &cert_bytes[..])
                .map_err(|e| eyre::eyre!("failed to decode finalization: {e:?}"))?;

        let epoch = finalization.proposal.round.epoch();
        let scheme = self
            .scheme_provider
            .scoped(epoch)
            .ok_or_eyre("no scheme registered for epoch")?;

        // Validate the finalization certificate
        eyre::ensure!(
            finalization.verify(&mut self.context, scheme.as_ref(), &Sequential),
            "finalization certificate verification failed for epoch {epoch}"
        );

        // Store the Finalized Block
        let round = Round::new(Epoch::new(certified.epoch), View::new(certified.view));
        let activity = Activity::Finalization(finalization);
        self.marshal_mailbox.verified(round, block).await;
        self.marshal_mailbox.report(activity.clone()).await;
        self.feed_mailbox.report(activity).await;
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
