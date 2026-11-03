//! Mixed-version tests: stock commonware upgraders, as nodes on one version run them, against
//! [MultiVersion] in each phase of the rolling upgrade.

use super::*;

use commonware_cryptography::{
    ChaCha20Poly1305,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic, mocks};
use commonware_stream::{Receiver as _, Sender as _};

const NAMESPACE: &[u8] = b"tempo_p2p_upgrader_test";
const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

type Multi = MultiVersion<PrivateKey, ChaCha20Poly1305>;
type Stock = Cups<Sake<PrivateKey>, ChaCha20Poly1305>;

/// A node's software during the rollout.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Node {
    /// Today's binary: SAKE and CUPS V0 only.
    Old,
    /// Phase 1: accepts V0 and V1, dials V0.
    AcceptBoth,
    /// Phase 2: accepts V0 and V1, dials V1.
    DialV1,
    /// Phase 3: V1 only.
    V1Only,
}

impl Node {
    const ALL: [Self; 4] = [Self::Old, Self::AcceptBoth, Self::DialV1, Self::V1Only];

    const fn dials(self) -> Version {
        match self {
            Self::Old | Self::AcceptBoth => Version::V0,
            Self::DialV1 | Self::V1Only => Version::V1,
        }
    }

    const fn accepts(self) -> &'static [Version] {
        match self {
            Self::Old => &[Version::V0],
            Self::AcceptBoth | Self::DialV1 => &[Version::V1, Version::V0],
            Self::V1Only => &[Version::V1],
        }
    }
}

/// Every pair of nodes connects exactly when the listener accepts the dialer's version.
#[test]
fn connects_exactly_when_listener_accepts_dial_version() {
    for dialer in Node::ALL {
        for listener in Node::ALL {
            let result = connect_nodes(dialer, listener);
            let expected = listener.accepts().contains(&dialer.dials());
            assert_eq!(
                result.is_ok(),
                expected,
                "{dialer:?} -> {listener:?}: {result:?}"
            );
        }
    }
}

/// Each rollout step mixes only two adjacent binaries, and every pair of nodes in such a mixed
/// network connects both ways, so every step is a rolling restart.
#[test]
fn every_rollout_step_is_a_rolling_restart() {
    let steps = [
        (Node::Old, Node::AcceptBoth),
        (Node::AcceptBoth, Node::DialV1),
        (Node::DialV1, Node::V1Only),
    ];
    for (before, after) in steps {
        for (a, b) in [
            (before, before),
            (before, after),
            (after, before),
            (after, after),
        ] {
            connect_nodes(a, b).unwrap_or_else(|err| {
                panic!("{before:?} -> {after:?} rollout: {a:?} -> {b:?} failed: {err}")
            });
        }
    }
}

/// Skipping phase 1 partitions old nodes, and the listener reports that no version verified.
#[test]
fn skipping_a_step_partitions_old_nodes() {
    let err = connect_nodes(Node::Old, Node::V1Only).unwrap_err();
    assert_eq!(err, Error::NoAcceptedVersion.to_string());
    assert!(connect_nodes(Node::DialV1, Node::Old).is_err());
}

/// The order of accepted versions does not decide which one a dialer gets.
#[test]
fn accept_order_does_not_matter() {
    for accept in [[Version::V0, Version::V1], [Version::V1, Version::V0]] {
        for dial in [Version::V0, Version::V1] {
            let dialer_key = PrivateKey::from_seed(1);
            let listener_key = PrivateKey::from_seed(2);
            connect(
                stock(dialer_key.clone(), dial),
                dialer_key,
                multi(listener_key.clone(), Version::V0, &accept),
                listener_key,
            )
            .unwrap_or_else(|err| panic!("{dial:?} into {accept:?}: {err}"));
        }
    }
}

/// A handshake valid under no accepted version is rejected, so accepting several versions does
/// not weaken authentication.
#[test]
fn rejects_handshake_valid_under_no_accepted_version() {
    let result = listen_against_stock_dialer(b"another_namespace", true);
    assert!(
        matches!(result, Err(Error::NoAcceptedVersion)),
        "{result:?}"
    );
}

/// The bouncer still runs before any handshake work.
#[test]
fn bouncer_rejection_is_reported() {
    let result = listen_against_stock_dialer(NAMESPACE, false);
    assert!(matches!(result, Err(Error::PeerRejected)), "{result:?}");
}

#[test]
fn accept_rejects_empty_versions() {
    assert!(Accept::new(Vec::new()).is_none());
}

/// The upgrader a node on a single version runs. V0 is commonware v2026.9.0's protocol.
fn stock(signer: PrivateKey, version: Version) -> Stock {
    Cups::new(
        Sake {
            signer,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(1),
            version: version.sake(),
        },
        version.cups(),
    )
}

fn multi(signer: PrivateKey, dial: Version, accept: &[Version]) -> Multi {
    MultiVersion::new(
        signer,
        Duration::from_secs(1),
        Duration::from_secs(1),
        dial,
        Accept::new(accept.to_vec()).expect("tests accept at least one version"),
    )
}

/// Connects two nodes, using the stock upgrader for single-version nodes so the old binary's
/// behavior comes from commonware itself rather than from [MultiVersion].
fn connect_nodes(dialer: Node, listener: Node) -> Result<(), String> {
    let dialer_key = PrivateKey::from_seed(1);
    let listener_key = PrivateKey::from_seed(2);
    match (dialer, listener) {
        (Node::Old, Node::Old) => connect(
            stock(dialer_key.clone(), Version::V0),
            dialer_key,
            stock(listener_key.clone(), Version::V0),
            listener_key,
        ),
        (Node::Old, l) => connect(
            stock(dialer_key.clone(), Version::V0),
            dialer_key,
            multi(listener_key.clone(), l.dials(), l.accepts()),
            listener_key,
        ),
        (d, Node::Old) => connect(
            multi(dialer_key.clone(), d.dials(), d.accepts()),
            dialer_key,
            stock(listener_key.clone(), Version::V0),
            listener_key,
        ),
        (d, l) => connect(
            multi(dialer_key.clone(), d.dials(), d.accepts()),
            dialer_key,
            multi(listener_key.clone(), l.dials(), l.accepts()),
            listener_key,
        ),
    }
}

/// Connects a dialer to a listener over an in-memory stream and exchanges a message each way.
///
/// Returns the listener's error on failure, since the listener verifies the dialer first.
fn connect<D, L>(
    dialer: D,
    dialer_key: PrivateKey,
    listener: L,
    listener_key: PrivateKey,
) -> Result<(), String>
where
    D: Upgrader<PublicKey = PublicKey>,
    L: Upgrader<PublicKey = PublicKey>,
{
    deterministic::Runner::timed(Duration::from_secs(5)).start(move |context| async move {
        let (dialer_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, dialer_stream) = mocks::Channel::init();

        let listener_handle = context.child("listener").spawn(move |context| async move {
            listener
                .listen(
                    context,
                    NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    |_| async { true },
                    listener_stream,
                    listener_sink,
                )
                .await
                .map_err(|err| err.to_string())
        });
        let listener_public_key = listener_key.public_key();
        let dialer_handle = context.child("dialer").spawn(move |context| async move {
            dialer
                .dial(
                    context,
                    NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    listener_public_key,
                    dialer_stream,
                    dialer_sink,
                )
                .await
                .map_err(|err| err.to_string())
        });

        let (peer, mut listener_sender, mut listener_receiver) = listener_handle.await.unwrap()?;
        assert_eq!(peer, dialer_key.public_key());
        let (mut dialer_sender, mut dialer_receiver) = dialer_handle.await.unwrap()?;

        dialer_sender.send(&b"ping"[..]).await.unwrap();
        assert_eq!(listener_receiver.recv().await.unwrap().coalesce(), b"ping");
        listener_sender.send(&b"pong"[..]).await.unwrap();
        assert_eq!(dialer_receiver.recv().await.unwrap().coalesce(), b"pong");
        Ok(())
    })
}

/// Runs a listener accepting both versions against a stock V1 dialer in dial_namespace, with a
/// bouncer that admits the dialer when admit is set, and returns the listener's result.
fn listen_against_stock_dialer(
    dial_namespace: &'static [u8],
    admit: bool,
) -> Result<PublicKey, Error> {
    let dialer_key = PrivateKey::from_seed(1);
    let listener_key = PrivateKey::from_seed(2);
    deterministic::Runner::timed(Duration::from_secs(5)).start(move |context| async move {
        let (dialer_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, dialer_stream) = mocks::Channel::init();
        let listener = multi(
            listener_key.clone(),
            Version::V0,
            &[Version::V1, Version::V0],
        );
        let listener_handle = context.child("listener").spawn(move |context| async move {
            listener
                .listen(
                    context,
                    NAMESPACE,
                    MAX_MESSAGE_SIZE,
                    move |_| async move { admit },
                    listener_stream,
                    listener_sink,
                )
                .await
                .map(|(peer, _, _)| peer)
        });
        let dialer = stock(dialer_key, Version::V1);
        let listener_public_key = listener_key.public_key();
        // The dialer fails once the listener gives up; only the listener's verdict matters.
        context.child("dialer").spawn(move |context| async move {
            dialer
                .dial(
                    context,
                    dial_namespace,
                    MAX_MESSAGE_SIZE,
                    listener_public_key,
                    dialer_stream,
                    dialer_sink,
                )
                .await
                .is_ok()
        });
        listener_handle.await.unwrap()
    })
}
