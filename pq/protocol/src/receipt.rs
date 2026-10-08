//! Verifies native composite ZK-STARK receipts, rejecting fake and curve-wrapped proofs.

use crate::{MAX_PROOF_LEN, Statement};
use risc0_zkvm::{InnerReceipt, Receipt};

/// Verify a receipt against the chain-pinned guest image and exact public statement.
pub fn verify(proof: &[u8], image: [u32; 8], statement: &Statement) -> bool {
    if proof.len() > MAX_PROOF_LEN {
        return false;
    }
    let Ok(receipt) = serde_json::from_slice::<Receipt>(proof) else {
        return false;
    };
    if !matches!(&receipt.inner, InnerReceipt::Composite(composite) if composite.assumption_receipts.is_empty())
    {
        return false;
    }
    receipt.journal.bytes == statement.journal() && receipt.verify(image).is_ok()
}
