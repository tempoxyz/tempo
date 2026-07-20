//! Standalone follower driver actor tests.

mod utils;

use std::time::Duration;

use commonware_consensus::{
    Reporter as _,
    marshal::Update,
    types::{Epoch, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::certificate::Provider as _;
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, deterministic};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use tempo_chainspec::NetworkIdentity;
use tempo_node::rpc::consensus::Event;

use super::{Config, try_init};
use crate::epoch::SchemeProvider;
use utils::{
    EPOCH_LENGTH, StubExecutionProvider, StubFeed, StubMarshal, dkg_fixture, make_block,
    make_certified_block, make_finalization,
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
            context.with_label("driver"),
            Config {
                execution_provider: provider.clone(),
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: finalized_height,
                marshal: StubMarshal::default(),
                feed: StubFeed::default(),
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
            context.with_label("driver"),
            Config {
                execution_provider: provider.clone(),
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: StubMarshal::default(),
                feed: StubFeed::default(),
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
            context.with_label("driver"),
            Config {
                execution_provider: provider.clone(),
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: StubMarshal::default(),
                feed: StubFeed::default(),
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
        let feed = StubFeed::default();
        let (actor, mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                feed: feed.clone(),
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
        reporter.report(event).await;
        wait_until(&context, || marshal.certified().len() == 1).await;

        let certified = marshal.certified();
        assert_eq!(certified[0].0, finalization.proposal.round);
        assert_eq!(certified[0].1, block);
        assert_eq!(marshal.report_count(), 1);
        assert_eq!(feed.report_count(), 1);
        assert!(marshal.hints().is_empty());
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
        let feed = StubFeed::default();
        let schemes = SchemeProvider::new();
        let (actor, mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: network_fixture.outcome.epoch.get(),
                    identity: *network_fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                feed: feed.clone(),
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
        reporter.report(event).await;
        wait_until(&context, || marshal.certified().len() == 1).await;

        assert_eq!(marshal.report_count(), 1);
        assert_eq!(feed.report_count(), 1);
        assert!(marshal.hints().is_empty());
    });
}

#[test_traced]
fn invalid_finalization_hints_current_epoch_boundary() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let wrong_fixture = dkg_fixture(&mut context, Epoch::zero());
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);

        let marshal = StubMarshal::default();
        let feed = StubFeed::default();
        let strategy = FixedEpocher::new(EPOCH_LENGTH);
        let expected_boundary = strategy
            .last(Epoch::zero())
            .expect("epoch zero has a boundary");

        let (actor, mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                feed: feed.clone(),
                epoch_strategy: strategy,
            },
        )
        .expect("driver should initialize");

        actor.start();

        let block = make_block(1, None);
        let finalization = make_finalization(&block, Epoch::zero(), &wrong_fixture.schemes);
        let certified = make_certified_block(block, &finalization);
        let event = Event::Finalized {
            block: certified,
            seen: 0,
        };

        let mut reporter = mailbox.to_event_reporter();
        reporter.report(event).await;
        wait_until(&context, || !marshal.hints().is_empty()).await;

        assert_eq!(marshal.hints(), vec![expected_boundary]);
        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert_eq!(feed.report_count(), 0);
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
        let feed = StubFeed::default();
        let (actor, mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                feed: feed.clone(),
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
        reporter.report(event).await;
        context.sleep(Duration::from_millis(1)).await;

        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert_eq!(feed.report_count(), 0);
        assert!(marshal.hints().is_empty());

        let block = make_block(3, None);
        let finalization = make_finalization(&block, Epoch::zero(), &fixture.schemes);
        let certified = make_certified_block(block.clone(), &finalization);
        let event = Event::Finalized {
            block: certified,
            seen: 0,
        };

        reporter.report(event).await;
        wait_until(&context, || marshal.certified().len() == 1).await;

        assert_eq!(marshal.certified()[0].1, block);
        assert_eq!(marshal.report_count(), 1);
        assert_eq!(feed.report_count(), 1);
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
        let feed = StubFeed::default();
        let schemes = SchemeProvider::new();
        let (actor, mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: missing_fixture.outcome.epoch.get() + 1,
                    identity: *missing_fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                feed: feed.clone(),
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
        reporter.report(event).await;
        context.sleep(Duration::from_millis(1)).await;

        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert_eq!(feed.report_count(), 0);
        assert!(marshal.hints().is_empty());
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

        let (actor, mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: StubMarshal::default(),
                feed: StubFeed::default(),
                epoch_strategy: strategy,
            },
        )
        .expect("driver should initialize");

        actor.start();

        let block = make_block(boundary.get(), Some(&next_fixture.outcome));
        let (ack, waiter) = Exact::handle();
        let mut reporter = mailbox.to_marshal_reporter();

        reporter.report(Update::Block(block, ack)).await;
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
        let (actor, mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: StubMarshal::default(),
                feed: StubFeed::default(),
                epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            },
        )
        .expect("driver should initialize");

        actor.start();

        let block = make_block(1, None);
        let (ack, waiter) = Exact::handle();
        let mut reporter = mailbox.to_marshal_reporter();
        reporter.report(Update::Block(block, ack)).await;
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
        let (actor, _mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: schemes.clone(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height,
                marshal: marshal.clone(),
                feed: StubFeed::default(),
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
fn non_finalized_event_is_ignored() {
    deterministic::Runner::default().start(|mut context| async move {
        let fixture = dkg_fixture(&mut context, Epoch::zero());
        let startup_block = make_block(0, Some(&fixture.outcome));
        let provider = StubExecutionProvider::default();
        provider.add_header(&startup_block);
        let marshal = StubMarshal::default();
        let feed = StubFeed::default();
        let (actor, mailbox) = try_init(
            context.with_label("driver"),
            Config {
                execution_provider: provider,
                scheme_provider: SchemeProvider::new(),
                network_identity: NetworkIdentity {
                    from_epoch: 0,
                    identity: *fixture.outcome.network_identity(),
                },
                last_finalized_height: Height::zero(),
                marshal: marshal.clone(),
                feed: feed.clone(),
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
        reporter.report(event).await;
        context.sleep(Duration::from_millis(1)).await;

        assert!(marshal.certified().is_empty());
        assert_eq!(marshal.report_count(), 0);
        assert_eq!(feed.report_count(), 0);
        assert!(marshal.hints().is_empty());
    });
}
