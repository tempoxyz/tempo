use alloy_consensus::BlockHeader as _;
use commonware_consensus::{
    Epochable as _, Heightable as _, marshal,
    simplex::types::Activity,
    types::{Epoch, Epocher as _, Height, Round},
};
use commonware_runtime::{Clock, ContextCell, Spawner, spawn_cell};
use commonware_utils::Acknowledgement as _;
use eyre::{OptionExt as _, Report, WrapErr as _};
use rand_core::{CryptoRng, Rng};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tokio::{select, sync::mpsc};
use tracing::{debug, instrument, warn};

use super::{Config, ExecutionProvider, Executor, Mailbox, Marshal, ingress::Message};
use crate::{
    consensus::Block,
    finalization_verifier::{
        CertificateVerificationError, Error as VerificationError, FinalizationVerifier,
    },
    gossip::{Certificate, CertificateError},
};

pub(super) fn try_init<TContext, P, M, E>(
    context: TContext,
    config: Config<P, M, E>,
) -> eyre::Result<super::Initialized<TContext, P, M, E>>
where
    TContext: Clock + Spawner,
    P: ExecutionProvider + 'static,
    M: Marshal + 'static,
    E: Executor + 'static,
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

    let verifier = FinalizationVerifier::new(
        config.network_identity.clone(),
        config.epoch_strategy.clone(),
    )
    .with_scheme_provider(config.scheme_provider.clone());
    let boundary_header = config
        .execution_provider
        .finalized_header_by_number(startup_execution_boundary.get())
        .and_then(|header| header.ok_or_eyre("execution layer did not have header"))
        .wrap_err_with(|| {
            format!(
                "cannot establish baseline - unable to read the header \
                from the last boundary block at height `{startup_execution_boundary}` \
                from the execution layer"
            )
        })?;
    let onchain_outcome = verifier
        .decode_dkg_outcome_and_register_boundary(boundary_header.extra_data().as_ref())
        .wrap_err_with(|| {
            format!(
                "the last boundary (`{startup_execution_boundary}`) block header did not contain a DKG outcome"
            )
        })?;

    let current_epoch = onchain_outcome.epoch;

    let actor = Driver {
        context: ContextCell::new(context),
        config,
        mailbox: rx,
        startup_execution_boundary,
        current_epoch,
        verifier,
        latest_verified_round: Round::zero(),
    };
    Ok((actor, mailbox))
}

pub(crate) struct Driver<TContext, P, M, E = crate::follow::executor::Mailbox> {
    context: ContextCell<TContext>,
    config: Config<P, M, E>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    startup_execution_boundary: Height,
    current_epoch: Epoch,
    verifier: FinalizationVerifier,
    latest_verified_round: Round,
}

impl<C, P, M, E> Driver<C, P, M, E>
where
    C: Clock + Rng + CryptoRng + Spawner,
    P: ExecutionProvider + 'static,
    M: Marshal + 'static,
    E: Executor + 'static,
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
                        Message::Certificate { certificate, response } => {
                            let result = self.process_certificate(*certificate).await;
                            let _ = response.send(result);
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

            let onchain_outcome = self
                .verifier
                .decode_dkg_outcome_and_register_boundary(
                    boundary_block.header().extra_data().as_ref(),
                )
                .wrap_err_with(|| {
                    format!(
                        "the boundary block at height `{last_consensus_boundary}` \
                        contained no or a malformed DKG outcome"
                    )
                })?;

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
        let finalization = match self
            .verifier
            .decode_and_verify(&mut self.context, &certified)
        {
            Ok(finalization) => finalization,
            Err(
                error @ VerificationError::CertificateVerification(
                    CertificateVerificationError::FallbackVerificationFailed,
                ),
            ) => {
                debug!(%error, "failed to verify finalization certificate");
                self.hint_current_epoch_boundary().await;
                return Ok(());
            }
            Err(VerificationError::CertificateVerification(
                CertificateVerificationError::Invalid,
            )) => return Ok(()),
            Err(error) => return Err(Report::new(error)),
        };

        let consensus_block = Block::from_execution_block_unchecked(certified.block, None);

        let round = finalization.round();
        self.latest_verified_round = self.latest_verified_round.max(round);

        let _ = self.config.marshal.certified(round, consensus_block).await;
        self.config
            .marshal
            .report(Activity::Finalization(finalization))
            .await;

        Ok(())
    }

    /// Verifies a gossiped certificate and applies it if valid.
    #[instrument(skip_all, fields(round = %certificate.round(), digest = %certificate.proposal.payload))]
    async fn process_certificate(
        &mut self,
        certificate: Certificate,
    ) -> eyre::Result<(), CertificateError> {
        if certificate.round() <= self.latest_verified_round {
            return Ok(());
        }

        match self
            .verifier
            .verify_certificate(&mut self.context, &certificate)
        {
            Ok(()) => {}
            Err(CertificateVerificationError::Invalid) => {
                debug!(
                    epoch = %certificate.epoch(),
                    digest = %certificate.proposal.payload,
                    "certificate failed verification against a registered scheme",
                );
                return Err(CertificateError::Invalid);
            }
            Err(CertificateVerificationError::IdentityUnavailable { .. }) => {
                return Err(CertificateError::NeedsScheme {
                    epoch: certificate.epoch(),
                });
            }
            Err(CertificateVerificationError::FallbackVerificationFailed) => {
                debug!(
                    epoch = %certificate.epoch(),
                    digest = %certificate.proposal.payload,
                    "certificate failed verification against the network identity fallback",
                );
                self.hint_current_epoch_boundary().await;
                return Err(CertificateError::NeedsScheme {
                    epoch: certificate.epoch(),
                });
            }
        }

        let round = certificate.round();
        let digest = certificate.proposal.payload;

        self.latest_verified_round = self.latest_verified_round.max(round);
        self.config
            .marshal
            .report(Activity::Finalization(certificate))
            .await;

        self.config.executor.finalization(round, digest);
        Ok(())
    }

    async fn hint_current_epoch_boundary(&self) {
        // A failed built-in identity may mean it has rotated. Ask marshal for
        // the local epoch boundary, which contains the next scheme. Do not take
        // the height from the certificate because an unauthenticated peer could
        // make the node fetch any height.
        let boundary_height = self
            .config
            .epoch_strategy
            .last(self.current_epoch)
            .expect("strategy is valid for all heights and epochs");

        debug!(
            current_epoch = %self.current_epoch,
            %boundary_height,
            "hinting current epoch boundary after the network identity fallback failed",
        );
        // NOTE: Repeated hints are intentional. The follow resolver coalesces
        // active requests for the same boundary height.
        self.config.marshal.hint_finalized(boundary_height).await;
    }

    #[instrument(skip_all)]
    async fn process_update(&mut self, update: marshal::Update<Block>) {
        // Marshal sends its startup tip and each finalization it stores. These
        // durable tips recover the latest verified round and provide later progress.
        let (block, ack) = match update {
            marshal::Update::Tip(round, _, _) => {
                self.latest_verified_round = self.latest_verified_round.max(round);
                return;
            }
            marshal::Update::Block(block, ack) => (block, ack),
        };

        let epoch_info = self
            .config
            .epoch_strategy
            .containing(block.height())
            .expect("strategy valid for all heights");

        if epoch_info.last() == block.height() {
            let onchain_outcome = self
                .verifier
                .decode_dkg_outcome_and_register_boundary(block.header().extra_data().as_ref())
                .expect("boundary blocks must contain DKG outcomes");

            let network_identity = self.verifier.network_identity();
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

            self.current_epoch = self.current_epoch.max(onchain_outcome.epoch);

            if let Some(gossip) = &self.config.gossip {
                gossip.boundary_scheme_installed(onchain_outcome.epoch);
            }
        }

        // Always acknowledge last. Marshal waits for every consumer before it
        // sends the next update. Dropping the acknowledgement means shutdown,
        // so an early return would stop block delivery.
        ack.acknowledge();
    }
}
