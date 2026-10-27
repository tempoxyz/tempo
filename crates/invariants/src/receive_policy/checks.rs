//! The receive policy invariants.

use std::fmt;

use invariants_core::check;

use super::{AuthoritySet, ReceiptClaimed, Signer};
use crate::{Check, Checked, Verdict};

pub const CLAIM_AUTHORITY: &str = "TEMPO-RECEIVE-POLICY-CLAIM-AUTHORITY";

pub const CHECKS: &[Check<Claim>] = &[check! {
    id: CLAIM_AUTHORITY,
    judge: |c: &Claim| {
        let claim = &c.claim;
        let (receiver, authority) = (claim.receiver, claim.recoveryAuthority);
        if [receiver, claim.recipient, claim.originator].contains(&claim.to) || authority == receiver {
            return None;
        }
        let set = c.set.filter(|s| s.authority == authority)?;
        Some(match set.signer {
            Signer::Access(key) => Verdict::Broken(format!(
                "addressed to {receiver}, claimed by {authority}, an authority set by \
                 {receiver}'s access key {key}, not its root or an admin key"
            )),
            Signer::Root | Signer::Admin => Verdict::Holds,
        })
    },
}];

/// A claim, judged against
/// `set`, the receiver's latest observed policy update (`None`: none
/// observed, not judged). A claim back to the receiver, the addressed
/// recipient or the originator returns value to a party of the transfer, and
/// an authority that is the receiver itself is the receiver's choice; neither
/// is judged.
pub struct Claim {
    pub claim: ReceiptClaimed,
    pub set: Option<AuthoritySet>,
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "claim of {} {} to {}",
            self.claim.amount, self.claim.token, self.claim.to
        )
    }
}

impl Checked for Claim {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}
