//! Receive policies: blocked inbound value claimed to a third party must be
//! claimed under a recovery authority the receiver chose itself.

use std::fmt;

use alloy_primitives::Address;

pub use tempo_contracts::precompiles::IReceivePolicyGuard::{self, ReceiptClaimed};

mod checks;

pub use checks::{CHECKS, CLAIM_AUTHORITY};

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

/// A claim, judged against `set`, the receiver's latest observed policy update (`None`: none
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
