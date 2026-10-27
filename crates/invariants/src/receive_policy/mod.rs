//! Receive policies: blocked inbound value claimed to a third party must be
//! claimed under a recovery authority the receiver chose itself.

use alloy_primitives::Address;
use alloy_sol_types::sol;

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
