//! The receive policy invariants.

use invariants_core::check;

use super::{Claim, Signer};
use crate::{Check, Checked, Severity, Verdict};

pub const CLAIM_AUTHORITY: &str = "TEMPO-RECEIVE-POLICY-CLAIM-AUTHORITY";

pub const CHECKS: &[Check<Claim>] = &[check! {
    id: CLAIM_AUTHORITY,
    doc: "When `ReceivePolicyGuard` pays a receipt to an address other than its receiver, addressed recipient or originator under a recovery authority other than the receiver, the receiver's latest observed `setReceivePolicy` naming that authority was signed by its root key or an admin access key, not a non-admin access key.",
    tip: "TIP-1028",
    severity: Severity::High,
    since: "T6",
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
