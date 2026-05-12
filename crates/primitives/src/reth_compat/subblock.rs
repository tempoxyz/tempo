use crate::subblock::{RecoveredSubBlock, SignedSubBlock};
use alloy_primitives::B256;

impl SignedSubBlock {
    /// Attempts to recover the senders and convert the subblock into a [`RecoveredSubBlock`].
    ///
    /// Note that the validator is assumed to be pre-validated to match the submitted signature.
    pub fn try_into_recovered(
        self,
        validator: B256,
    ) -> Result<RecoveredSubBlock, alloy_consensus::crypto::RecoveryError> {
        let senders =
            reth_primitives_traits::transaction::recover::recover_signers(&self.transactions)?;

        Ok(RecoveredSubBlock::new_unchecked(self, senders, validator))
    }
}
