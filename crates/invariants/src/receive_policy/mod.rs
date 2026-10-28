//! Receive policies: blocked inbound value claimed to a third party must be
//! claimed under a recovery authority the receiver chose itself.

use alloy_primitives::Address;

pub use tempo_contracts::precompiles::IReceivePolicyGuard::{self, ReceiptClaimed};

mod checks;

pub use checks::{CHECKS, CLAIM_AUTHORITY, Claim};

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
