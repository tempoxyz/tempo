//! Configurable account transaction authority (TIP-1112, TIP-1113).

use crate::{TempoTx as _, TempoTxEnv};
use alloy_consensus::Transaction as _;
use alloy_primitives::{Address, TxKind};
use tempo_precompiles::{
    CONFIGURABLE_ACCOUNT_ADDRESS,
    configurable_account::{ConfigurableAccount, UpgradeEligibility},
    error::TempoPrecompileError,
};
use tempo_primitives::transaction::TempoSignature;

impl TempoTxEnv {
    /// Seeds the transaction authority read by the configurable-account precompile.
    ///
    /// `upgradeAccount` must be the whole transaction: no other call and no authorization or key
    /// authorization that could change the account beside it. No signature type authorizes a
    /// configurable account directly, so no account is directly authorized.
    pub(crate) fn seed_upgrade_authority(&self) -> Result<(), TempoPrecompileError> {
        let aa = self.as_aa();
        let sole_call = match aa {
            None => {
                self.kind() == TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS)
                    && self
                        .as_eip7702()
                        .is_none_or(|tx| tx.authorization_list.is_empty())
            }
            Some(aa) => {
                let tx = aa.tx();
                matches!(
                    tx.calls.as_slice(),
                    [call] if call.to == TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS)
                ) && tx.tempo_authorization_list.is_empty()
                    && tx.key_authorization.is_none()
            }
        };
        let eligibility = if !sole_call {
            UpgradeEligibility::NotSoleCall
        } else if !self.signed_by_primitive_root() {
            UpgradeEligibility::NotPrimitiveRoot
        } else {
            UpgradeEligibility::PrimitiveRoot
        };
        ConfigurableAccount::new().set_authority(self.caller(), Address::ZERO, eligibility)
    }

    /// Whether the sender signs with a bare primitive key, as every non-AA transaction does.
    fn signed_by_primitive_root(&self) -> bool {
        self.as_aa().is_none_or(|aa| match aa.signature() {
            TempoSignature::Primitive(_) => true,
            TempoSignature::Keychain(_) => false,
        })
    }
}
