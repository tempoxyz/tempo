//! The resolver is responsible for ensuring that the voter has all the certificates it needs to
//! make progress. The voter is voting in a view and has a "floor" view which is the latest
//! certified (or finalized) view that it knows about. Thus, it either requires covering
//! nullification evidence for intermediate views, or a higher floor. It will request the required
//! nullifications from the resolver, and proposal verification can also request the exact parent
//! notarization a proposal names. Other nodes serve matching certificates, or higher floors.
//!
//! # Fetch Strategy
//!
//! A nullification covers the view it was created for and the rest of that view's term, and a
//! request only accepts nullifications from its own term (see [`crate::types::View::covers`]).
//! One request per term, at its lowest uncovered view (the term's "anchor"), is therefore
//! sufficient: whatever answers it covers the rest of the term, and a higher floor moots it. The
//! fetch scan requests each term's anchor and advances a cursor past everything it scanned:
//!
//! ```text
//! term:      [1  2  3  4  5] [6 . . . 10] [11 . . . 15]    current = 14
//! request:   [1]             [6]          [11]             cursor -> 16
//!
//! nullification@4 covers 4..=5:  only a request keyed in [4, 5] retrieves it
//! nullification@4 for request 6: rejected (wrong term)
//! ```
//!
//! Requests stay pending in the resolver until answered or retained out, so the cursor never
//! revisits scanned views on its own (a rescan re-issues fetches for requests that are still
//! pending, which the resolver engine deduplicates).
//!
//! # Proposal Ancestry
//!
//! Background repair cannot detect a split where one participant certifies a notarization while
//! another holds a covering nullification. Proposal verification exposes the missing ancestry and
//! targets the first gap at the proposal's leader. A blocked certification exposes the same gap
//! and asks any peer, since the leader that withheld the certificate may never answer. Matching
//! evidence, finalization, or a failed certification verdict retires that request, whereas a
//! certified-floor raise retires only background work.
//!
//! The wire key names only the view. A retained finalization settles every ask at or below it.
//! Otherwise serving prefers an exact certified notarization to a covering nullification, matching
//! proposal construction. If neither is retained, the responder serves its current floor. The
//! highest finalization remains servable even when a newer certified notarization advances the
//! construction floor. The requester treats a valid response that does not settle its ask as
//! ambiguous and retries without faulting the peer.
//!
//! A notarization is served only after local certification succeeds. Possession still settles the
//! holder's own ask, because certification judges evidence already in hand. A failed verdict also
//! settles it, since no copy of that notarization can certify anywhere.
//!
//! # Mid-Term Floor Raises
//!
//! A floor raise landing inside a term (a certified notarization or a finalization at a mid-term
//! view) strands the term's tail: the anchor request is retained out with the floor, requests in
//! later terms reject this term's nullifications, and the cursor is already past it. Nothing
//! would ever re-request the tail, so a validator whose parent chain rests at the floor could
//! never validate proposals that skip it:
//!
//! ```text
//! floor raises to 3, mid-term of [1, 5]:
//!
//! term:      [1  2  3 |  4  5] [6 . . . 10] [11 . . . 15]
//!                     ^floor
//! request:    x          ??    [6]          [11]
//!            (retained out)    (reject term-1 evidence)
//! ```
//!
//! Pruning repairs this by pulling the cursor back to just above the floor, so a later scan
//! re-requests the tail. Anchors whose requests are still pending are re-issued along the way
//! and deduplicated by the engine, while anchors with a stored covering nullification are
//! skipped:
//!
//! ```text
//! pull-back: cursor = min(cursor, floor + 1) = 4
//!
//! next scan: fetch(4), then the later anchors: fetch(6), fetch(11)
//!                                              (still pending: deduplicated)
//!
//! term:      [1  2  3 |  4  5] [6 . . . 10] [11 . . . 15]
//! request:              [4]    [6]          [11]
//! ```
//!
//! With single-view terms every view is its own anchor, a floor raise can never land mid-term,
//! and the pull-back never fires.

mod actor;
mod ingress;
mod state;

use crate::types::{Epoch, TermLength};
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::MailboxMessage;
use std::{num::NonZeroUsize, time::Duration};

pub struct Config<S: Scheme, B: Blocker, T: Strategy> {
    pub scheme: S,

    pub blocker: B,

    /// Strategy for parallel operations.
    pub strategy: T,

    pub epoch: Epoch,
    pub mailbox_size: NonZeroUsize,
    pub fetch_timeout: Duration,
    pub term_length: TermLength,
}

/// Certificate builders shared by the resolver test modules.
#[cfg(test)]
mod test_helpers {
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{
                Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal,
            },
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_parallel::Sequential;
    use commonware_utils::non_empty;

    type TestScheme = ed25519::Scheme;

    pub(super) fn build_nullification(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Nullification<TestScheme> {
        let round = Round::new(epoch, view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        Nullification::from_nullifies(verifier, non_empty![@&votes], &Sequential)
            .expect("nullification quorum")
    }

    pub(super) fn build_notarization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Notarization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(verifier, non_empty![@&votes], &Sequential)
            .expect("notarization quorum")
    }

    pub(super) fn build_finalization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        epoch: Epoch,
        view: View,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(verifier, non_empty![@&votes], &Sequential)
            .expect("finalization quorum")
    }
}
