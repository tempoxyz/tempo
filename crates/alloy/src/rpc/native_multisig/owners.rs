//! Owner-quorum validation for simulation specs.

use super::{MultisigSimulationError, MultisigSimulationSpec};
use alloy_primitives::Address;
use tempo_primitives::{
    SignatureType,
    transaction::{MAX_MULTISIG_SIGNATURES, MultisigQuorumError, MultisigWeightAccumulator},
};

impl MultisigSimulationSpec {
    /// Checks the claimed primitive quorum before constructing simulation signatures.
    pub fn validate_owners(&self, account: Address) -> Result<(), MultisigSimulationError> {
        if self.signer.is_some_and(|signer| signer != account) {
            return Err(MultisigSimulationError::SignerMismatch);
        }
        if self.approvals.len() > MAX_MULTISIG_SIGNATURES {
            return Err(MultisigSimulationError::Quorum(
                MultisigQuorumError::TooManySignatures,
            ));
        }
        self.config
            .validate_for_account(account)
            .map_err(MultisigSimulationError::Config)?;
        let mut weight = MultisigWeightAccumulator::new(self.config.threshold)
            .map_err(MultisigSimulationError::Quorum)?;
        for approval in &self.approvals {
            if approval
                .key_data
                .as_ref()
                .is_some_and(|hint| !matches!(hint.len(), 1 | 2 | 4))
            {
                return Err(MultisigSimulationError::InvalidKeyData);
            }
            if approval.key_type == Some(SignatureType::Multisig) {
                return Err(MultisigSimulationError::NestedMultisigOwner);
            }
            let owner_weight =
                self.config
                    .owner_weight(approval.owner)
                    .ok_or(MultisigSimulationError::Quorum(
                        MultisigQuorumError::SignerNotOwner,
                    ))?;
            weight
                .record_owner(approval.owner, owner_weight)
                .map_err(MultisigSimulationError::Quorum)?;
        }
        weight.finish().map_err(MultisigSimulationError::Quorum)
    }
}
