//! The receive policy invariants.

use invariants_core::check;

use super::{Claim, Signer};
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

impl Checked for Claim {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}
