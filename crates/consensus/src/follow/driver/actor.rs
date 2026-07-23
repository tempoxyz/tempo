use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use commonware_codec::{DecodeExt as _, ReadExt as _};
use commonware_consensus::{
    Epochable, Heightable as _, marshal,
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme,
        types::{Activity, Finalization},
    },
    types::{Epoch, Epocher as _, Height},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider, ed25519::PublicKey,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, ContextCell, Spawner, spawn_cell};
use commonware_utils::Acknowledgement as _;
use eyre::{OptionExt as _, Report, WrapErr as _, bail, ensure};
use rand_08::{CryptoRng, Rng};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tokio::{select, sync::mpsc};
use tracing::{debug, instrument, warn};

use super::{Config, ExecutionProvider, Feed, Mailbox, Marshal, ingress::Message};
use crate::consensus::{Block, Digest};

pub(super) fn try_init<TContext, P, M, F>(
    context: TContext,
    config: Config<P, M, F>,
) -> eyre::Result<(Driver<TContext, P, M, F>, Mailbox)>
where
    TContext: Clock + Spawner,
    P: ExecutionProvider + 'static,
    M: Marshal + 'static,
    F: Feed + 'static,
{
    let (tx, rx) = mpsc::unbounded_channel();
    let mailbox = Mailbox(tx);

    // Use the last boundary block available in the execution layer as the
    // trusted starting point.
    //
    // TODO: Provide a certificate with the latest boundary to not just trust
    // but also verify.
    let last_finalized_number = config.execution_provider.finalized_block_number()?;

    let epoch_info = config
        .epoch_strategy
        .containing(Height::new(last_finalized_number))
        .expect("strategy valid for all heights and epochs");

    let startup_execution_boundary = if epoch_info.last().get() == last_finalized_number {
        epoch_info.last()
    } else if let Some(previous) = epoch_info.epoch().previous() {
        config
            .epoch_strategy
            .last(previous)
            .expect("strategy valid for all heights and epochs")
    } else {
        Height::zero()
    };

    let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
        &mut config
            .execution_provider
            .finalized_header_by_number(startup_execution_boundary.get())
            .and_then(|header| header.ok_or_eyre("execution layer did not have header"))
            .wrap_err_with(|| {
                format!(
                    "cannot establish baseline - unable to read the header \
                    from the last boundary block at height `{startup_execution_boundary}` \
                    from the execution layer"
                )
            })?
            .extra_data()
            .as_ref(),
    )
    .wrap_err_with(|| {
        format!(
            "the last boundary (`{startup_execution_boundary}`) block header did not contain a DKG outcome"
        )
    })?;

    config.scheme_provider.register(
        onchain_outcome.epoch,
        Scheme::certificate_verifier(
            crate::config::NAMESPACE,
            *onchain_outcome.sharing().public(),
        ),
    );

    let current_epoch = onchain_outcome.epoch;
    let network_scheme = Arc::new(Scheme::certificate_verifier(
        crate::config::NAMESPACE,
        config.network_identity.identity,
    ));

    let actor = Driver {
        context: ContextCell::new(context),
        config,
        mailbox: rx,
        startup_execution_boundary,
        current_epoch,
        network_scheme,
    };
    Ok((actor, mailbox))
}

pub(crate) struct Driver<TContext, P, M, F> {
    context: ContextCell<TContext>,
    config: Config<P, M, F>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    startup_execution_boundary: Height,
    current_epoch: Epoch,
    network_scheme: Arc<Scheme<PublicKey, MinSig>>,
}

impl<C, P, M, F> Driver<C, P, M, F>
where
    C: Clock + Rng + CryptoRng + Spawner,
    P: ExecutionProvider + 'static,
    M: Marshal + 'static,
    F: Feed + 'static,
{
    pub(crate) fn start(mut self) -> commonware_runtime::Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        if self.install_scheme_for_latest_epoch().await.is_err() {
            return;
        }

        loop {
            select!(
                biased;

                Some(message) = self.mailbox.recv() => {
                    match message {
                        Message::Event(event) => {
                            let Event::Finalized {
                                block: certified, ..
                            } = *event
                            else {
                                continue;
                            };

                            // Emits an event on error.
                            let _: Result<_, _> = self.process_event(certified).await;
                        }
                        Message::Finalized(update) => {
                            self.process_update(update).await;
                        }
                    }
                }
            );
        }
    }

    /// Fills in the missing scheme if the execution layer did not persist.
    #[instrument(skip_all, err(Display))]
    async fn install_scheme_for_latest_epoch(&mut self) -> eyre::Result<()> {
        let current_consensus_epoch = self
            .config
            .epoch_strategy
            .containing(self.config.last_finalized_height)
            .expect("strategy is valid for all heights and epochs");

        let current_execution_epoch = self
            .config
            .epoch_strategy
            .containing(self.startup_execution_boundary)
            .expect("strategy is valid for all heights and epochs");

        if let Some(previous) = current_consensus_epoch.epoch().previous()
            && previous > current_execution_epoch.epoch()
        {
            let last_consensus_boundary = self
                .config
                .epoch_strategy
                .last(previous)
                .expect("strategy is valid for all heights and epochs");

            let Some(boundary_block) = self.config.marshal.get_block(last_consensus_boundary).await
            else {
                let consensus_epoch = current_consensus_epoch.epoch();
                let execution_epoch = current_execution_epoch.epoch();
                warn!(
                    "cannot install scheme; consensus layer epoch {consensus_epoch} is ahead \
                    of execution layer epoch {execution_epoch}, but the consensus layer does not have \
                    the boundary block at height `{last_consensus_boundary}`. The node likely previously skipped \
                    epoch boundaries via the network identity and will continue to try use it to verify finalizations"
                );

                return Ok(());
            };

            let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
                &mut &mut boundary_block.header().extra_data().as_ref(),
            )
            .wrap_err_with(|| {
                format!(
                    "the boundary block at height `{last_consensus_boundary}` \
                    contained no or a malformed DKG outcome"
                )
            })?;

            self.config.scheme_provider.register(
                onchain_outcome.epoch,
                Scheme::certificate_verifier(
                    crate::config::NAMESPACE,
                    *onchain_outcome.sharing().public(),
                ),
            );

            self.current_epoch = self.current_epoch.max(onchain_outcome.epoch);
        } else {
            debug!("no gap detected");
        }

        Ok(())
    }

    #[instrument(
        skip_all,
        fields(
            height = certified.block.number(),
            digest = %certified.digest,
        ),
        err(Display)
    )]
    async fn process_event(&mut self, certified: CertifiedBlock) -> eyre::Result<()> {
        // TODO: ensure well-formedness at the type level so we don't need extra decoding here.
        let finalization = alloy_primitives::hex::decode(&certified.certificate)
            .map_err(Report::new)
            .and_then(|bytes| {
                Finalization::<Scheme<PublicKey, MinSig>, Digest>::decode(&*bytes)
                    .map_err(Report::new)
            })
            .wrap_err("event contained a malformed finalization certificate")?;

        let finalization_epoch = finalization.epoch();
        let consensus_block = Block::from_execution_block_unchecked(certified.block, None);

        ensure!(
            finalization.proposal.payload == consensus_block.digest(),
            "mismatch in finalization and block digest"
        );

        let can_use_network_identity_fallback =
            finalization_epoch.get() >= self.config.network_identity.from_epoch;

        let scheme = match self.config.scheme_provider.scoped(finalization_epoch) {
            Some(scheme) => scheme,
            None if can_use_network_identity_fallback => self.network_scheme.clone(),
            None => {
                bail!(
                    "finalization epoch `{finalization_epoch}` behind network identity starting epoch `{}`",
                    self.config.network_identity.from_epoch,
                );
            }
        };

        let identity = scheme.identity();
        if !finalization.verify(&mut self.context, &scheme, &Sequential) {
            debug!(
                "failed to verify finalization {} against scheme: {identity}",
                finalization.proposal.payload
            );

            // This network may have rotated identity, so hint the boundary of
            // the node's current epoch to unblock syncing through the next
            // onchain scheme.
            let boundary_height = self
                .config
                .epoch_strategy
                .last(self.current_epoch)
                .expect("strategy is valid for all heights and epochs");

            debug!(
                current_epoch = %self.current_epoch,
                %boundary_height,
                "hinting current epoch boundary after finalization verification failed",
            );

            self.config.marshal.hint_finalized(boundary_height).await;

            return Ok(());
        }

        let round = finalization.round();
        let activity = Activity::Finalization(finalization);

        let _ = self.config.marshal.certified(round, consensus_block).await;
        self.config.marshal.report(activity.clone()).await;
        self.config.feed.report(activity).await;
        Ok(())
    }

    #[instrument(skip_all)]
    async fn process_update(&mut self, update: marshal::Update<Block>) {
        let marshal::Update::Block(block, ack) = update else {
            return;
        };

        let epoch_info = self
            .config
            .epoch_strategy
            .containing(block.height())
            .expect("strategy valid for all heights");

        if epoch_info.last() == block.height() {
            let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
                &mut &mut block.header().extra_data().as_ref(),
            )
            .expect("boundary blocks must contain DKG outcomes");

            let network_identity = &self.config.network_identity;
            if onchain_outcome.epoch.get() >= network_identity.from_epoch
                && network_identity.identity != *onchain_outcome.network_identity()
            {
                warn!(
                    compiled_from_epoch = network_identity.from_epoch,
                    onchain_epoch = %onchain_outcome.epoch,
                    compiled_network_identity = %network_identity.identity,
                    onchain_network_identity = %onchain_outcome.network_identity(),
                    "Network identity differs from the onchain DKG outcome!!! Update the binary with the latest network identity"
                );
            }

            self.config.scheme_provider.register(
                onchain_outcome.epoch,
                Scheme::certificate_verifier(
                    crate::config::NAMESPACE,
                    *onchain_outcome.network_identity(),
                ),
            );

            self.current_epoch = self.current_epoch.max(onchain_outcome.epoch);
        }

        ack.acknowledge();
    }
}
