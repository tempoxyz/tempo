use alloy_primitives::{Address, B256, B512};
use serde::{Deserialize, Serialize};
use tempo_primitives::transaction::{AttestedSignature, attested_address};

/// Validity, in seconds after the block timestamp, of a simulated attested signature that names
/// no `validUntil`. Attested signers sign for at most this long, within the 600-second window.
pub const ATTESTED_SIMULATION_VALIDITY: u64 = 300;

/// An attested signature (type `0x06`) to model in a simulation, before the program key signs.
///
/// Simulation reads the Attested Key Registry for `slot` and `programKey` as block validation does,
/// and charges the same gas, but does not verify the P256 signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestedSimulationSpec {
    /// Attested Key Registry policy of the program key.
    pub policy_id: B256,
    /// User tag of the attested address.
    pub user_tag: B256,
    /// Key slot that holds the program key.
    #[serde(with = "alloy_serde::quantity")]
    pub slot: u8,
    /// Uncompressed P256 program key, `x || y`.
    pub program_key: B512,
    /// The signature's `validUntil`. Defaults to [`ATTESTED_SIMULATION_VALIDITY`] seconds after the
    /// block timestamp.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "alloy_serde::quantity::opt"
    )]
    pub valid_until: Option<u64>,
}

impl AttestedSimulationSpec {
    /// Returns the attested address this signature signs for.
    pub fn address(&self) -> Address {
        attested_address(self.policy_id, self.user_tag)
    }

    /// Returns a placeholder signature with these fields, valid until `validUntil` or
    /// [`ATTESTED_SIMULATION_VALIDITY`] seconds after `now`. Its `r` and `s` are 1, which decodes but
    /// does not verify.
    pub fn mock_signature(&self, now: u64) -> AttestedSignature {
        let mut signature = B512::ZERO;
        signature[31] = 1;
        signature[63] = 1;
        AttestedSignature {
            policy_id: self.policy_id,
            user_tag: self.user_tag,
            slot: self.slot,
            program_key: self.program_key,
            valid_until: self
                .valid_until
                .unwrap_or_else(|| now.saturating_add(ATTESTED_SIMULATION_VALIDITY)),
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_and_placeholder() {
        let spec: AttestedSimulationSpec = serde_json::from_value(serde_json::json!({
            "policyId": B256::repeat_byte(0xAA),
            "userTag": B256::repeat_byte(0xBB),
            "slot": "0x1",
            "programKey": B512::repeat_byte(0x03),
        }))
        .unwrap();
        assert_eq!(spec.slot, 1);
        assert_eq!(spec.valid_until, None);

        let placeholder = spec.mock_signature(1_800_000_000);
        assert_eq!(
            placeholder.valid_until,
            1_800_000_000 + ATTESTED_SIMULATION_VALIDITY
        );
        assert_eq!(placeholder.address(), spec.address());
        assert_eq!(
            AttestedSimulationSpec {
                valid_until: Some(7),
                ..spec
            }
            .mock_signature(1_800_000_000)
            .valid_until,
            7
        );
        assert!(
            serde_json::from_value::<AttestedSimulationSpec>(serde_json::json!({
                "policyId": B256::ZERO, "userTag": B256::ZERO, "slot": "0x0",
                "programKey": B512::ZERO, "keyType": "p256",
            }))
            .is_err(),
            "unknown fields are rejected"
        );
    }
}
