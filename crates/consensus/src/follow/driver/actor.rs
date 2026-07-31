use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use commonware_codec::{DecodeExt as _, ReadExt as _};
use commonware_consensus::{
    Epochable, Heightable as _, marshal,
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme,
        types::{Activity, Finalization},
    },
    types::{Epoch, Epocher as _, Height, Round},
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Provider, ed25519::PublicKey,
};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, ContextCell, Spawner, spawn_cell};
use commonware_utils::Acknowledgement as _;
use eyre::{OptionExt as _, Report, WrapErr as _, bail, ensure};
use rand_core::{CryptoRng, Rng};
use tempo_node::rpc::consensus::{CertifiedBlock, Event};
use tokio::{select, sync::mpsc};
use tracing::{debug, instrument, warn};

use super::{
    Config, ExecutionProvider, Executor, FollowerProgress, Mailbox, Marshal, ingress::Message,
};
use crate::{
    consensus::{Block, Digest},
    gossip::{Certificate, Outcome},
};

/// Outcome of checking a certificate's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Verified,
    /// Failed with an available scheme, so the sender is responsible.
    Invalid,
    /// No available scheme can verify it.
    NeedsScheme,
}

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

    let progress = FollowerProgress::new();
    let actor = Driver {
        context: ContextCell::new(context),
        config,
        mailbox: rx,
        startup_execution_boundary,
        current_epoch,
        network_scheme,
        progress: progress.clone(),
    };
    Ok((actor, mailbox, progress))
}

pub(crate) struct Driver<TContext, P, M, E = crate::follow::executor::Mailbox> {
    context: ContextCell<TContext>,
    config: Config<P, M, E>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    startup_execution_boundary: Height,
    current_epoch: Epoch,
    network_scheme: Arc<Scheme<PublicKey, MinSig>>,
    progress: FollowerProgress,
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
                            let result = self.verify_and_apply(*certificate).await;
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

        match self.verify(&finalization).await {
            Verdict::Verified => {}
            Verdict::Invalid => bail!("finalization failed verification"),
            Verdict::NeedsScheme => bail!(
                "no usable scheme for finalization epoch `{finalization_epoch}`; \
                 network identity starts at epoch `{}`",
                self.config.network_identity.from_epoch,
            ),
        }

        let round = finalization.round();
        let digest = consensus_block.digest();

        // Always give the block to marshal, even if the round is stale. An RPC
        // event includes the block, and storing it may close a gap.
        let _ = self.config.marshal.certified(round, consensus_block).await;
        self.report_verified(round, digest, finalization).await;

        Ok(())
    }

    /// Verifies a gossiped certificate and applies it if valid.
    ///
    /// A certificate contains a block hash but no block. Applying it sends the
    /// finalization to marshal so the resolver can fetch the block. It also
    /// points the execution layer at the same hash.
    #[instrument(skip_all, fields(round = %certificate.round(), digest = %certificate.proposal.payload))]
    async fn verify_and_apply(&mut self, certificate: Certificate) -> Outcome {
        self.judge(certificate).await
    }

    async fn judge(&mut self, certificate: Certificate) -> Outcome {
        if certificate.round() <= self.progress.watermark() {
            return Outcome::Stale;
        }

        match self.verify(&certificate).await {
            Verdict::Verified => {}
            Verdict::Invalid => return Outcome::Invalid,
            Verdict::NeedsScheme => {
                return Outcome::NeedsScheme {
                    epoch: certificate.epoch(),
                };
            }
        }

        let round = certificate.round();
        let digest = certificate.proposal.payload;
        self.report_verified(round, digest, certificate).await;

        Outcome::Admitted
    }

    /// Hands a verified finalization to the rest of the follower.
    ///
    /// # Invariant
    ///
    /// The caller must verify the signature first. Marshal creates an archive
    /// for the certificate's epoch and stops the node if that fails. Reporting
    /// an unchecked certificate would let an unauthenticated peer create
    /// unlimited state or stop the node by naming any epoch. Verification and
    /// reporting stay in one call chain so this rule is easy to check.
    async fn report_verified(&mut self, round: Round, digest: Digest, finalization: Certificate) {
        self.progress.advance(round);
        self.config
            .marshal
            .report(Activity::Finalization(finalization))
            .await;
        self.config.executor.certified_tip(round, digest);
    }

    /// Selects the verifier for a certificate's epoch and checks the signature.
    ///
    /// A failure with a registered scheme is invalid and can be blamed on the
    /// peer. A failure with the built-in network identity may mean the identity
    /// has rotated. Do not blame the peer in that case. Doing so could disconnect
    /// honest relayers while gossip is needed for recovery.
    async fn verify(&mut self, finalization: &Certificate) -> Verdict {
        let epoch = finalization.epoch();
        let can_use_network_identity_fallback =
            epoch.get() >= self.config.network_identity.from_epoch;

        let (scheme, used_fallback) = match self.config.scheme_provider.scheme(epoch) {
            Some(scheme) => (scheme, false),
            None if can_use_network_identity_fallback => (self.network_scheme.clone(), true),
            None => return Verdict::NeedsScheme,
        };

        if finalization.verify(&mut self.context, scheme.as_ref(), &Sequential) {
            if used_fallback {
                // Marshal verifies again after fetching the block, so keep the
                // successful fallback scheme for that step.
                self.config
                    .scheme_provider
                    .register(epoch, scheme.as_ref().clone());
            }
            return Verdict::Verified;
        }

        if !used_fallback {
            debug!(
                %epoch,
                identity = %scheme.identity(),
                digest = %finalization.proposal.payload,
                "certificate failed verification against a registered scheme",
            );
            return Verdict::Invalid;
        }

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
        self.config.marshal.hint_finalized(boundary_height).await;

        Verdict::NeedsScheme
    }

    #[instrument(skip_all)]
    async fn process_update(&mut self, update: marshal::Update<Block>) {
        // Marshal sends its startup tip and each finalization it stores. These
        // durable tips provide the initial watermark and later progress.
        let (block, ack) = match update {
            marshal::Update::Tip(round, _, _) => {
                self.progress.advance(round);
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

            self.progress.scheme_installed(onchain_outcome.epoch);
        }

        // Always acknowledge last. Marshal waits for every consumer before it
        // sends the next update. Dropping the acknowledgement means shutdown,
        // so an early return would stop block delivery.
        ack.acknowledge();
    }
}
