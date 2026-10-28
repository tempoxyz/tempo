//! Shared consensus-relay plumbing for the standard variant wrappers.

use crate::{
    Block,
    marshal::{application::gates::Gates, core::Mailbox, standard::Standard},
    simplex::Plan,
};
use commonware_actor::Feedback;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Recipients;
use tracing::debug;

/// Relays a consensus broadcast [`Plan`] through marshal for the standard
/// variants ([`super::Deferred`] and [`super::Inline`]).
///
/// A propose plan sends the staged proposal to all peers, delivering the
/// durable-sync handle through the staged ack. A forward plan re-sends a
/// stored block to the requested recipients. A propose plan whose staged
/// proposal was already consumed falls back to a best-effort forward of the
/// persisted block.
pub(super) fn broadcast<S, B>(
    gates: &Gates<B::Digest, B>,
    marshal: &Mailbox<S, Standard<B>>,
    commitment: B::Digest,
    plan: Plan<S::PublicKey>,
) -> Feedback
where
    S: Scheme,
    B: Block,
{
    match plan {
        Plan::Propose { round } => {
            let Some((block, ack)) = gates.take_staged(round, commitment) else {
                debug!(%round, %commitment, "no staged proposal to relay, attempting forwarding");
                return marshal.forward(round, commitment, Recipients::All);
            };
            marshal.proposed(round, block, Recipients::All, ack)
        }
        Plan::Forward { round, recipients } => marshal.forward(round, commitment, recipients),
    }
}
