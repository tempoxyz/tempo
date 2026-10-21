//! Owner-quorum validation for simulation specs.

use super::{ConfigurableAccountSimulationError, ConfigurableAccountSimulationSpec};
use alloy_primitives::Address;
use tempo_primitives::{
    SignatureType,
    transaction::{
        ConfigurableAccountQuorumError, ConfigurableAccountWeightAccumulator,
        MAX_CONFIGURABLE_ACCOUNT_SIGNATURES,
    },
};

impl ConfigurableAccountSimulationSpec {
    /// Checks the claimed primitive quorum before constructing simulation signatures.
    pub fn validate_owners(
        &self,
        account: Address,
    ) -> Result<(), ConfigurableAccountSimulationError> {
        if self.signer.is_some_and(|signer| signer != account) {
            return Err(ConfigurableAccountSimulationError::SignerMismatch);
        }
        if self.approvals.len() > MAX_CONFIGURABLE_ACCOUNT_SIGNATURES {
            return Err(ConfigurableAccountSimulationError::Quorum(
                ConfigurableAccountQuorumError::TooManySignatures,
            ));
        }
        self.config
            .validate_for_account(account)
            .map_err(ConfigurableAccountSimulationError::Config)?;
        let mut weight = ConfigurableAccountWeightAccumulator::new(self.config.threshold)
            .map_err(ConfigurableAccountSimulationError::Quorum)?;
        for approval in &self.approvals {
            if approval
                .key_data
                .as_ref()
                .is_some_and(|hint| !matches!(hint.len(), 1 | 2 | 4))
            {
                return Err(ConfigurableAccountSimulationError::InvalidKeyData);
            }
            if approval.key_type == Some(SignatureType::ConfigurableAccount) {
                return Err(ConfigurableAccountSimulationError::NestedConfigurableAccountOwner);
            }
            let owner_weight = self.config.owner_weight(approval.owner).ok_or(
                ConfigurableAccountSimulationError::Quorum(
                    ConfigurableAccountQuorumError::SignerNotOwner,
                ),
            )?;
            weight
                .record_owner(approval.owner, owner_weight)
                .map_err(ConfigurableAccountSimulationError::Quorum)?;
        }
        weight
            .finish()
            .map_err(ConfigurableAccountSimulationError::Quorum)
    }
}
