//! Standalone follower driver actor tests.

use std::time::Duration;

use commonware_consensus::{
    Reporter as _,
    marshal::Update,
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round},
};
use commonware_cryptography::certificate::Provider as _;
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use tempo_chainspec::NetworkIdentity;
use tempo_node::rpc::consensus::Event;

use super::{Config, FollowerProgress, try_init};
use crate::{
    epoch::SchemeProvider,
    follow::test_utils::{
        DkgFixture, EPOCH_LENGTH, StubExecutionProvider, StubExecutor, StubMarshal, dkg_fixture,
        make_block, make_certified_block, make_finalization,
    },
    gossip::{CertSink as _, Outcome},
};

const WAIT_ATTEMPTS: usize = 100;

async fn wait_until<T: commonware_runtime::Clock>(context: &T, mut cond: impl FnMut() -> bool) {
    for _ in 0..WAIT_ATTEMPTS {
        if cond() {
            return;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    assert!(cond(), "condition was not met before the test deadline");
}

#[test_traced]
fn startup_uses_previous_execution_boundary() {
    deterministic::Runner::default().start(|mut context| async move {
        let strategy = FixedEpocher::new(EPOCH_LENGTH);
        let finalized_height = Height::new(EPOCH_LENGTH.get() + EPOCH_LENGTH.get() / 2);
        let expected_boundary = strategy
            .last(Epoch::zero())
            .expect("epoch zero has a boundary");

        let fixture = dkg_fixture(&mut context, Epoch::new(1));
        let boundary_block = make_block(expected_boundary.get(), Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.set_finalized(finalized_height.get());
        provider.add_header(&boundary_block);

        let schemes = SchemeProvider::new();
        let result = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider.clone(),
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: finalized_height,
                marshal: StubMarshal::default(),
                executor: StubExecutor::default(),
                epoch_strategy: strategy,
            },
        );

        assert!(result.is_ok());
        assert_eq!(provider.header_reads(), vec![expected_boundary.get()]);
        assert!(schemes.scoped(Epoch::new(1)).is_some());
    });
}

#[test_traced]
fn startup_propagates_finalized_block_read_failure() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let provider = StubExecutionProvider::default();
        provider.fail_finalized_read();

        let result = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider.clone(),
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: StubMarshal::default(),
                executor: StubExecutor::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        );

        assert!(result.is_err());
        assert!(provider.header_reads().is_empty());
    });
}

#[test_traced]
fn startup_requires_execution_boundary_header() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let provider = StubExecutionProvider::default();

        let result = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider.clone(),
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: StubMarshal::default(),
                executor: StubExecutor::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        );

        assert!(result.is_err());
        assert_eq!(provider.header_reads(), vec![0]);
    });
}

#[test_traced]
fn valid_finalization_is_certified_and_reported() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);

        let marshal = StubMarshal::default();

        let executor = StubExecutor::default();

        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        actor.start();

        let block = make_block(1, None);
        let finalization = make_finalization(&block, Epoch::zero(), &fixture.schemes);
        let certified = make_certified_block(block.clone(), &finalization);
        let event = Event::Finalized {
            block: certified,
            seen: 0,
        };

        let mut reporter = mailbox.to_event_reporter();
        assert!(reporter.report(event).accepted());

        let (ack, processed) = Exact::handle();
        let _ = mailbox
            .to_marshal_reporter()
            .report(Update::Block(make_block(2, None).into(), ack));
        processed
            .await
            .expect("the marker update should be acknowledged");

        let certified = marshal.certified();
        assert_eq!(certified[0].0, finalization.proposal.round);
        assert_eq!(certified[0].1, block);
        assert_eq!(marshal.report_count(), 1);
        assert!(marshal.hints().is_empty());
        assert!(
            executor.finalizations().is_empty(),
            "marshal's durable tip drives execution for upstream finalizations",
        );
    });
}

#[test_traced]
fn network_identity_verifies_finalization_when_epoch_scheme_is_missing() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let network_fixture = dkg_fixture(&mut context, Epoch::new(2));
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);
        let marshal = StubMarshal::default();
        let executor = StubExecutor::default();
        let schemes = SchemeProvider::new();
        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: network_fixture.outcome.epoch.get(),
                    identity: *network_fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        assert!(
            schemes.scoped(network_fixture.outcome.epoch).is_none(),
            "network identity fallback requires the epoch scheme to be missing",
        );
        actor.start();

        let block = make_block(EPOCH_LENGTH.get() * 2 + 1, None);
        let finalization = make_finalization(
            &block,
            network_fixture.outcome.epoch,
            &network_fixture.schemes,
        );
        let certified = make_certified_block(block, &finalization);
        let event = Event::Finalized {
            block: certified,
            seen: 0,
        };
        let mut reporter = mailbox.to_event_reporter();
        assert!(reporter.report(event).accepted());
        wait_until(&context, || marshal.certified().len() == 1).await;

        assert_eq!(marshal.report_count(), 1);
        assert!(marshal.hints().is_empty());
    });
}

/// A gossiped certificate has no block. The driver sends the certificate to
/// marshal and its round and digest to execution so both can pursue the same
/// block.
#[test_traced]
fn gossiped_certificate_is_admitted_and_nudges_the_execution_layer() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let network_fixture = dkg_fixture(&mut context, Epoch::new(2));
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);
        let marshal = StubMarshal::default();
        let executor = StubExecutor::default();
        let schemes = SchemeProvider::new();

        let (actor, mailbox, progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: network_fixture.outcome.epoch.get(),
                    identity: *network_fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        let mut boundary_schemes = progress.boundary_schemes();
        actor.start();

        let block = make_block(EPOCH_LENGTH.get() * 2 + 1, None);
        let finalization = make_finalization(
            &block,
            network_fixture.outcome.epoch,
            &network_fixture.schemes,
        );
        let round = finalization.round();
        let digest = block.digest();

        assert!(
            schemes.scoped(network_fixture.outcome.epoch).is_none(),
            "the certificate must require the network identity fallback",
        );

        let result = mailbox
            .verify_and_apply(finalization)
            .await
            .expect("driver should answer");
        assert_eq!(result, Outcome::Admitted);
        assert!(
            schemes.scoped(network_fixture.outcome.epoch).is_some(),
            "marshal needs the successful fallback to re-verify the resolved block",
        );
        assert!(
            matches!(
                boundary_schemes.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "caching a successful fallback is not authenticated boundary progress",
        );
        assert_eq!(
            progress.watermark(),
            round,
            "applying the certificate advanced the shared progress",
        );

        // The driver reports only the certificate to marshal.
        assert_eq!(marshal.report_count(), 1);
        assert!(marshal.certified().is_empty());
        assert_eq!(executor.finalizations(), vec![(round, digest)]);

        // The first offer advanced the watermark, so the same round is now stale.
        let repeat = make_finalization(
            &make_block(EPOCH_LENGTH.get() * 2 + 1, None),
            network_fixture.outcome.epoch,
            &network_fixture.schemes,
        );
        let result = mailbox
            .verify_and_apply(repeat)
            .await
            .expect("driver should answer");
        assert_eq!(result, Outcome::Stale);
        assert_eq!(marshal.report_count(), 1);
    });
}

/// A running driver and the state inspected by certificate tests.
///
/// This is a utility for a group of tests found below.
struct Rig {
    mailbox: super::Mailbox,
    marshal: StubMarshal,
    progress: FollowerProgress,
    fixture: DkgFixture,
}

fn start_rig(context: &mut deterministic::Context) -> Rig {
    let fixture = dkg_fixture(context, Epoch::zero());
    let startup_block = make_block(0, Some(&fixture.outcome));
    let provider = StubExecutionProvider::default();
    provider.add_header(&startup_block);

    let marshal = StubMarshal::default();

    let (actor, mailbox, progress) = try_init(
        context.child("driver"),
        Config {
            execution_provider: provider,
            scheme_provider: SchemeProvider::new(),
            network_identity: NetworkIdentity {
                from_epoch: 0,
                identity: *fixture.outcome.network_identity(),
            },
            last_finalized_height: Height::zero(),
            marshal: marshal.clone(),
            executor: StubExecutor::default(),
            epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
        },
    )
    .expect("driver should initialize");
    actor.start();

    Rig {
        mailbox,
        marshal,
        progress,
        fixture,
    }
}

/// An admitted certificate raises the watermark. The gossip actor uses it to
/// discard offers that the driver would reject as stale.
#[test_traced]
fn newer_certificate_advances_watermark() {
    deterministic::Runner::default().start(|mut context| async move {
        let rig = start_rig(&mut context);

        let first = make_block(1, None);
        let first_certificate = make_finalization(&first, Epoch::zero(), &rig.fixture.schemes);
        let result = rig
            .mailbox
            .verify_and_apply(first_certificate)
            .await
            .expect("driver should answer");
        assert_eq!(result, Outcome::Admitted);
        let first_watermark = rig.progress.watermark();

        let second = make_block(2, None);
        let second_certificate = make_finalization(&second, Epoch::zero(), &rig.fixture.schemes);
        let result = rig
            .mailbox
            .verify_and_apply(second_certificate)
            .await
            .expect("driver should answer");

        assert_eq!(result, Outcome::Admitted);
        assert!(
            rig.progress.watermark() > first_watermark,
            "a strictly newer certificate moves the watermark",
        );
    });
}

/// An upstream finalization can advance the driver without gossip. Its round
/// must update the shared watermark so gossip can discard stale offers.
#[test_traced]
fn upstream_event_advances_watermark() {
    deterministic::Runner::default().start(|mut context| async move {
        let rig = start_rig(&mut context);

        let block = make_block(1, None);
        let certificate = make_finalization(&block, Epoch::zero(), &rig.fixture.schemes);
        let round = certificate.round();

        let _ = rig.mailbox.to_event_reporter().report(Event::Finalized {
            block: make_certified_block(block, &certificate),
            seen: 0,
        });
        wait_until(&context, || rig.progress.watermark() == round).await;

        assert_eq!(rig.marshal.certified().len(), 1);
        assert_eq!(rig.progress.watermark(), round);
    });
}

/// Marshal reports a tip only after it stores the block. This report must also
/// advance the shared watermark.
#[test_traced]
fn marshal_tip_advances_watermark() {
    deterministic::Runner::default().start(|mut context| async move {
        let rig = start_rig(&mut context);

        let block = make_block(1, None);
        let digest = block.digest();
        let certificate = make_finalization(&block, Epoch::zero(), &rig.fixture.schemes);
        let round = certificate.proposal.round;

        let _ =
            rig.mailbox
                .to_marshal_reporter()
                .report(Update::Tip(round, Height::new(1), digest));
        wait_until(&context, || rig.progress.watermark() == round).await;
        assert_eq!(rig.progress.watermark(), round);
    });
}

/// A gossiped certificate that fails an installed scheme is invalid. It must
/// not advance progress or make marshal resolve its block.
#[test_traced]
fn gossiped_certificate_failing_registered_scheme_is_invalid() {
    deterministic::Runner::default().start(|mut context| async move {
        let rig = start_rig(&mut context);
        let wrong_fixture = dkg_fixture(&mut context, Epoch::zero());
        let block = make_block(1, None);
        let certificate = make_finalization(&block, Epoch::zero(), &wrong_fixture.schemes);

        let result = rig
            .mailbox
            .verify_and_apply(certificate)
            .await
            .expect("driver should answer");

        assert_eq!(result, Outcome::Invalid);
        assert_eq!(rig.progress.watermark(), Round::zero());
        assert_eq!(rig.marshal.report_count(), 0);
    });
}

/// A boundary block provides the scheme for the next epoch. Certificates that
/// need this scheme cannot be retried until the driver announces it. Polling
/// cannot discover the new scheme.
#[test_traced]
fn installing_a_boundary_scheme_is_announced() {
    deterministic::Runner::default().start(|mut context| async move {
        let rig = start_rig(&mut context);
        let mut schemes = rig.progress.boundary_schemes();
        let next = dkg_fixture(&mut context, Epoch::new(1));
        let boundary = FixedEpocher::new(EPOCH_LENGTH)
            .last(Epoch::zero())
            .expect("epoch zero has a boundary");

        let block = make_block(boundary.get(), Some(&next.outcome));
        let (ack, waiter) = Exact::handle();
        let _ = rig
            .mailbox
            .to_marshal_reporter()
            .report(Update::Block(block.into(), ack));
        waiter.await.expect("the update should be acknowledged");

        assert_eq!(
            schemes.try_recv().expect("a scheme was announced"),
            Epoch::new(1),
        );
    });
}

/// A missing scheme may mean the network identity changed. Honest peers can send
/// such certificates. Penalizing them could disconnect the node while gossip is
/// its only way to catch up.
#[test_traced]
fn unverifiable_gossiped_certificate_is_not_blamed_on_the_sender() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let rotated = dkg_fixture(&mut context, Epoch::new(1));
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);
        let marshal = StubMarshal::default();
        let executor = StubExecutor::default();
        let strategy = FixedEpocher::new(EPOCH_LENGTH);
        let expected_boundary = strategy
            .last(Epoch::zero())
            .expect("epoch zero has a boundary");

        let (actor, mailbox, progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: strategy,
            },
        )
        .expect("driver should initialize");

        actor.start();

        // This certificate uses a key we do not have for an epoch with no scheme.
        let block = make_block(EPOCH_LENGTH.get() + 1, None);
        let finalization = make_finalization(&block, Epoch::new(1), &rotated.schemes);

        let result = mailbox
            .verify_and_apply(finalization)
            .await
            .expect("driver should answer");
        assert_eq!(
            result,
            Outcome::NeedsScheme {
                epoch: Epoch::new(1)
            }
        );
        assert_eq!(
            progress.watermark(),
            Round::zero(),
            "nothing was applied, so nothing advanced",
        );
        assert_eq!(marshal.report_count(), 0);
        assert_eq!(marshal.hints(), vec![expected_boundary]);
        assert!(executor.finalizations().is_empty());
    });
}

/// An upstream finalization that fails an installed scheme is dropped. It must
/// not hint for another scheme or update marshal or execution.
#[test_traced]
fn upstream_finalization_failing_registered_scheme_is_dropped_without_hint() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let wrong_fixture = dkg_fixture(&mut context, Epoch::zero());
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);

        let marshal = StubMarshal::default();
        let executor = StubExecutor::default();
        let strategy = FixedEpocher::new(EPOCH_LENGTH);

        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: strategy,
            },
        )
        .expect("driver should initialize");

        actor.start();

        // Startup installed the epoch-zero scheme, so the driver does not use
        // the network identity fallback.
        let block = make_block(1, None);
        let finalization = make_finalization(&block, Epoch::zero(), &wrong_fixture.schemes);
        let certified = make_certified_block(block, &finalization);
        let _ = mailbox.to_event_reporter().report(Event::Finalized {
            block: certified,
            seen: 0,
        });

        // This update is queued after the invalid event, so its acknowledgement
        // proves that the event was handled.
        let (ack, processed) = Exact::handle();
        let _ = mailbox
            .to_marshal_reporter()
            .report(Update::Block(make_block(2, None).into(), ack));
        processed
            .await
            .expect("the marker update should be acknowledged");

        assert!(marshal.hints().is_empty());
        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert!(executor.finalizations().is_empty());
    });
}

/// Failure against the built-in network identity may mean the identity changed.
/// The driver requests the local epoch boundary so gap repair can fetch the
/// block that contains the next scheme.
#[test_traced]
fn finalization_failing_the_identity_fallback_hints_current_epoch_boundary() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let wrong_fixture = dkg_fixture(&mut context, Epoch::new(1));
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);

        let marshal = StubMarshal::default();

        let executor = StubExecutor::default();

        let strategy = FixedEpocher::new(EPOCH_LENGTH);
        let expected_boundary = strategy
            .last(Epoch::zero())
            .expect("epoch zero has a boundary");

        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: strategy,
            },
        )
        .expect("driver should initialize");

        actor.start();

        // Epoch one has no installed scheme, so verification uses the network
        // identity. A different key models an identity change.
        let block = make_block(EPOCH_LENGTH.get(), None);
        let finalization = make_finalization(&block, Epoch::new(1), &wrong_fixture.schemes);
        let certified = make_certified_block(block, &finalization);
        let event = Event::Finalized {
            block: certified,
            seen: 0,
        };

        let mut reporter = mailbox.to_event_reporter();
        assert!(reporter.report(event).accepted());
        wait_until(&context, || !marshal.hints().is_empty()).await;

        assert_eq!(marshal.hints(), vec![expected_boundary]);
        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert!(executor.finalizations().is_empty());
    });
}

#[test_traced]
fn mismatched_finalization_digest_is_dropped_without_stopping_driver() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();

        provider.add_header(&startup_block);
        let marshal = StubMarshal::default();
        let executor = StubExecutor::default();
        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        actor.start();

        let signed_block = make_block(1, None);
        let delivered_block = make_block(2, None);
        let finalization = make_finalization(&signed_block, Epoch::zero(), &fixture.schemes);
        let certified = make_certified_block(delivered_block, &finalization);
        let event = Event::Finalized {
            block: certified,
            seen: 0,
        };

        let mut reporter = mailbox.to_event_reporter();
        assert!(reporter.report(event).accepted());
        context.sleep(Duration::from_millis(1)).await;

        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert!(marshal.hints().is_empty());

        let block = make_block(3, None);
        let finalization = make_finalization(&block, Epoch::zero(), &fixture.schemes);
        let certified = make_certified_block(block.clone(), &finalization);
        let event = Event::Finalized {
            block: certified,
            seen: 0,
        };

        assert!(reporter.report(event).accepted());
        wait_until(&context, || marshal.certified().len() == 1).await;

        assert_eq!(marshal.certified()[0].1, block);
        assert_eq!(marshal.report_count(), 1);
    });
}

#[test_traced]
fn scheme_before_network_identity_epoch_is_required() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let missing_fixture = dkg_fixture(&mut context, Epoch::new(1));
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);

        let marshal = StubMarshal::default();

        let executor = StubExecutor::default();

        let schemes = SchemeProvider::new();
        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: missing_fixture.outcome.epoch.get() + 1,
                    identity: *missing_fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        assert!(schemes.scoped(missing_fixture.outcome.epoch).is_none());
        actor.start();

        let block = make_block(EPOCH_LENGTH.get() + 1, None);
        let finalization = make_finalization(
            &block,
            missing_fixture.outcome.epoch,
            &missing_fixture.schemes,
        );

        let certified = make_certified_block(block, &finalization);
        let event = Event::Finalized {
            block: certified,
            seen: 0,
        };

        let mut reporter = mailbox.to_event_reporter();
        assert!(reporter.report(event).accepted());
        context.sleep(Duration::from_millis(1)).await;

        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert!(marshal.hints().is_empty());
    });
}

#[test_traced]
fn gossiped_certificate_without_a_usable_identity_needs_scheme() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let missing_fixture = dkg_fixture(&mut context, Epoch::new(1));
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);

        let marshal = StubMarshal::default();
        let executor = StubExecutor::default();
        let (actor, mailbox, progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: missing_fixture.outcome.epoch.get() + 1,
                    identity: *missing_fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        actor.start();

        let block = make_block(EPOCH_LENGTH.get() + 1, None);
        let certificate = make_finalization(
            &block,
            missing_fixture.outcome.epoch,
            &missing_fixture.schemes,
        );
        let result = mailbox
            .verify_and_apply(certificate)
            .await
            .expect("driver should answer");

        assert_eq!(
            result,
            Outcome::NeedsScheme {
                epoch: missing_fixture.outcome.epoch,
            }
        );
        assert_eq!(progress.watermark(), Round::zero());
        assert_eq!(marshal.report_count(), 0);
        assert!(marshal.hints().is_empty());
        assert!(executor.finalizations().is_empty());
    });
}

#[test_traced]
fn boundary_update_registers_scheme_before_acknowledging() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let next_fixture = dkg_fixture(&mut context, Epoch::new(1));
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);

        let schemes = SchemeProvider::new();
        let strategy = FixedEpocher::new(EPOCH_LENGTH);
        let boundary = strategy
            .last(Epoch::zero())
            .expect("epoch zero has a boundary");

        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: StubMarshal::default(),
                executor: StubExecutor::default(),
                epoch_strategy: strategy,
            },
        )
        .expect("driver should initialize");

        actor.start();

        let block = make_block(boundary.get(), Some(&next_fixture.outcome));
        let (ack, waiter) = Exact::handle();
        let mut reporter = mailbox.to_marshal_reporter();

        assert!(reporter.report(Update::Block(block.into(), ack)).accepted());
        waiter
            .await
            .expect("boundary update should be acknowledged");

        assert!(schemes.scoped(Epoch::new(1)).is_some());
    });
}

#[test_traced]
fn non_boundary_update_is_acknowledged_without_registering_a_scheme() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);
        let schemes = SchemeProvider::new();
        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: StubMarshal::default(),
                executor: StubExecutor::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        actor.start();

        let block = make_block(1, None);
        let (ack, waiter) = Exact::handle();
        let mut reporter = mailbox.to_marshal_reporter();
        assert!(reporter.report(Update::Block(block.into(), ack)).accepted());
        waiter.await.expect("block should be acknowledged");

        assert!(schemes.scoped(Epoch::new(1)).is_none());
    });
}

#[test_traced]
fn startup_installs_missing_consensus_epoch_scheme_from_marshal() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let recovered_fixture = dkg_fixture(&mut context, Epoch::new(2));
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);

        let marshal = StubMarshal::default();

        let executor = StubExecutor::default();

        let strategy = FixedEpocher::new(EPOCH_LENGTH);
        let last_finalized_height = Height::new(EPOCH_LENGTH.get() * 3);
        let current_epoch = strategy
            .containing(last_finalized_height)
            .expect("height belongs to an epoch")
            .epoch();

        let previous_epoch = current_epoch.previous().expect("epoch has a predecessor");
        let boundary = strategy
            .last(previous_epoch)
            .expect("previous epoch has a boundary");

        marshal.add_block(make_block(boundary.get(), Some(&recovered_fixture.outcome)));

        let schemes = SchemeProvider::new();
        let (actor, _mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height,
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: strategy,
            },
        )
        .expect("driver should initialize");

        actor.start();
        wait_until(&context, || {
            schemes.scoped(recovered_fixture.outcome.epoch).is_some()
        })
        .await;

        assert_eq!(marshal.block_reads(), vec![boundary]);
    });
}

#[test_traced]
fn non_finalized_events_are_ignored() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);
        let marshal = StubMarshal::default();
        let executor = StubExecutor::default();
        let (actor, mailbox, _progress) = try_init(
            context.child("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                executor: executor.clone(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        actor.start();

        let event = Event::Nullified {
            epoch: 0,
            view: 1,
            seen: 0,
        };
        let mut reporter = mailbox.to_event_reporter();
        assert!(reporter.report(event).accepted());

        context.sleep(Duration::from_millis(1)).await;

        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert!(marshal.hints().is_empty());
    });
}
