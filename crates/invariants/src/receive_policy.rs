//! Receive policies: blocked inbound value claimed to a third party must be
//! claimed under a recovery authority the receiver chose itself.

use std::fmt;

use alloy_primitives::Address;
use alloy_sol_types::sol;

use invariants_core::check;

use crate::{Check, Verdict, Violation, judge};

pub const CLAIM_AUTHORITY: &str = "TEMPO-RECEIVE-POLICY-CLAIM-AUTHORITY";

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

pub static CHECKS: &[Check<Claim>] = &[check! {
    id: CLAIM_AUTHORITY,
    over: |claim: &Claim| [claim],
    judge: |_, c| {
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

/// The violation of [`CHECKS`] by `claim` against `set`, if any.
pub fn check_claim(claim: &ReceiptClaimed, set: Option<&AuthoritySet>) -> Option<Violation> {
    judge(
        CHECKS,
        &Claim {
            claim: claim.clone(),
            set: set.copied(),
        },
    )
    .into_iter()
    .next()
}

sol! {
    // `ReceiptClaimed`'s generated constructor takes its 11 fields.
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug, PartialEq, Eq)]
    interface IReceivePolicyGuard {
        event ReceiptClaimed(
            address indexed token,
            address indexed receiver,
            uint64 indexed blockedNonce,
            uint64 blockedAt,
            uint8 receiptVersion,
            address originator,
            address recipient,
            address recoveryAuthority,
            address caller,
            address to,
            uint256 amount
        );
    }
}

pub use IReceivePolicyGuard::ReceiptClaimed;

/// Who signed a policy update for its account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    Root,
    /// An access key that was an admin key at the block.
    Admin,
    /// Any other access key.
    Access(Address),
}

/// The recovery authority an account last named, and who signed that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthoritySet {
    pub authority: Address,
    pub signer: Signer,
}
