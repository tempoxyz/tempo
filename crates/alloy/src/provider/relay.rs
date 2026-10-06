//! Typed clients for Tempo relay RPCs, including viem-compatible multisig mailboxes.
//!
//! Multisig execution requires a protocol-capable downstream node; the relay itself
//! coordinates approvals and durable submissions independently of consensus types.

use crate::{TempoNetwork, rpc::TempoTransactionRequest};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::Provider;
use alloy_transport::TransportResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Relay fill request, retaining all Tempo estimation metadata.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayFillRequest {
    /// Transaction fields, including access-key gas-estimation metadata.
    #[serde(flatten)]
    pub transaction: TempoTransactionRequest,
    /// Explicitly request or decline fee-payer sponsorship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<RelayFeePayer>,
    /// Requested relay capabilities.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities: BTreeMap<String, bool>,
    /// Native multisig simulation metadata, passed through unchanged to the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multisig_simulation: Option<Value>,
}

/// Explicit sponsorship choice or an operator-allowlisted remote endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RelayFeePayer {
    /// Request or decline local sponsorship.
    Enabled(bool),
    /// Use an explicitly allowlisted remote fee payer.
    Url(String),
}

/// Sponsor identity attached to a filled transaction.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelaySponsor {
    /// Fee-payer account.
    pub address: Address,
    /// Optional human-readable sponsor name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional sponsor URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Relay capabilities with extensible plugin fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayCapabilities {
    /// Whether a fee payer approved the transaction.
    #[serde(default)]
    pub sponsored: bool,
    /// Sponsor metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsor: Option<RelaySponsor>,
    /// Net token movements and final approval exposure by sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance_diffs: Option<BTreeMap<Address, Vec<RelayBalanceDiff>>>,
    /// Estimated maximum transaction fee in token units.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<RelayFee>,
    /// Resolved virtual recipient addresses; null means an unregistered master.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_addresses: Option<BTreeMap<Address, Option<Address>>>,
    /// Opt-in decoded execution revert; such a fill is not signed or executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    /// Additional capabilities from simulation and other relay plugins.
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

/// Exact fee amount and display metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayFee {
    /// Integer amount in the token's smallest unit.
    pub amount: U256,
    /// Token precision.
    pub decimals: u8,
    /// Exact decimal representation.
    pub formatted: String,
    /// Ticker symbol.
    pub symbol: String,
}

/// Balance preview for one token, including final allowance exposure.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayBalanceDiff {
    /// Token address.
    pub address: Address,
    /// Token precision.
    pub decimals: u8,
    /// Token name.
    pub name: String,
    /// Ticker symbol.
    pub symbol: String,
    /// Movement direction.
    pub direction: RelayMovement,
    /// Exact decimal representation.
    pub formatted: String,
    /// Outgoing transfer recipients and approved spenders.
    pub recipients: Vec<Address>,
    /// Amount in the token's smallest unit.
    pub value: U256,
}

/// Net movement direction.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayMovement {
    /// Net incoming tokens.
    Incoming,
    /// Net outgoing tokens plus final approval exposure.
    Outgoing,
}

/// Filled transaction returned by a relay.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayFillResult {
    /// Filled transaction ready for sender signing.
    pub tx: TempoTransactionRequest,
    /// Capability results.
    #[serde(default)]
    pub capabilities: RelayCapabilities,
    /// Optional sponsor metadata used by viem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsor: Option<RelaySponsor>,
    /// Other node fields, retained for forward compatibility.
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

/// Weighted multisig owner.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelayMultisigOwner {
    /// Owner account.
    pub owner: Address,
    /// Owner's voting weight.
    pub weight: u8,
}

/// Native multisig configuration in the viem RPC representation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelayMultisigConfig {
    /// Canonical ascending owner list.
    pub owners: Vec<RelayMultisigOwner>,
    /// Account derivation salt.
    pub salt: B256,
    /// Required owner weight.
    pub threshold: u8,
    /// Configuration version, encoded as a hexadecimal RPC quantity.
    #[serde(with = "alloy_serde::quantity")]
    pub version: u64,
}

/// Common operation fields. Timestamps are Unix milliseconds, not RPC quantities.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayOperationDetails {
    /// Root multisig account.
    pub account: Address,
    /// Retained serialized owner signatures.
    pub approvals: Vec<Bytes>,
    /// Configuration used for approval verification.
    pub config: RelayMultisigConfig,
    /// Creation timestamp.
    pub created_at: u64,
    /// Deterministic operation hash.
    pub hash: B256,
    /// Number of approvals selected for quorum.
    pub signature_count: u8,
    /// Required owner weight.
    pub threshold: u8,
    /// Last update timestamp.
    pub updated_at: u64,
    /// Selected approval weight.
    pub weight: u8,
}

/// Transaction submission lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RelayTransactionStatus {
    /// Awaiting quorum.
    Pending,
    /// A submitter holds the durable submission lease.
    Submitting,
    /// Downstream accepted the transaction (not necessarily executed successfully).
    Success,
}

/// Key authorization approval lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RelayAuthorizationStatus {
    /// Awaiting quorum.
    Pending,
    /// Approval quorum reached.
    Success,
}

/// Transaction or key-authorization operation returned by a multisig relay.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RelayOperation {
    /// Transaction approval and submission.
    Transaction {
        /// Common approval state.
        #[serde(flatten)]
        details: RelayOperationDetails,
        /// Submission lifecycle.
        status: RelayTransactionStatus,
        /// Serialized unsigned transaction.
        transaction: Bytes,
        /// Submission lease expiration timestamp.
        #[serde(default, rename = "expiresAt", skip_serializing_if = "Option::is_none")]
        expires_at: Option<u64>,
        /// Fencing token for the current submitter.
        #[serde(
            default,
            rename = "submissionId",
            skip_serializing_if = "Option::is_none"
        )]
        submission_id: Option<B256>,
        /// Actual downstream transaction hash.
        #[serde(
            default,
            rename = "transactionHash",
            skip_serializing_if = "Option::is_none"
        )]
        transaction_hash: Option<B256>,
    },
    /// Key authorization approval.
    KeyAuthorization {
        /// Common approval state.
        #[serde(flatten)]
        details: RelayOperationDetails,
        /// Approval lifecycle.
        status: RelayAuthorizationStatus,
        /// Serialized unsigned key authorization.
        #[serde(rename = "keyAuthorization")]
        key_authorization: Bytes,
    },
}

/// Typed relay RPC extensions for Alloy providers.
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait TempoRelayProviderExt: Provider<TempoNetwork> {
    /// Fills a transaction through relay middleware.
    async fn relay_fill_transaction(
        &self,
        request: RelayFillRequest,
    ) -> TransportResult<RelayFillResult>
    where
        Self: Sized,
    {
        self.raw_request("eth_fillTransaction".into(), (request,))
            .await
    }

    /// Obtains a fee-payer signature without broadcasting a sender-signed transaction.
    async fn relay_sign_raw_transaction(&self, transaction: Bytes) -> TransportResult<Bytes>
    where
        Self: Sized,
    {
        self.raw_request("eth_signRawTransaction".into(), (transaction,))
            .await
    }

    /// Reads the current configuration from a multisig-capable relay.
    async fn relay_multisig_config(
        &self,
        address: Address,
    ) -> TransportResult<Option<RelayMultisigConfig>>
    where
        Self: Sized,
    {
        self.raw_request(
            "multisig_getConfig".into(),
            (serde_json::json!({"address": address}),),
        )
        .await
    }

    /// Reads approval and submission state for an operation hash.
    async fn relay_multisig_operation(&self, hash: B256) -> TransportResult<Option<RelayOperation>>
    where
        Self: Sized,
    {
        self.raw_request("multisig_getOperation".into(), (hash,))
            .await
    }

    /// Submits an owner-signed transaction approval to a multisig-capable relay.
    async fn relay_multisig_approve_raw_transaction(
        &self,
        transaction: Bytes,
    ) -> TransportResult<B256>
    where
        Self: Sized,
    {
        self.raw_request("multisig_approveRawTransaction".into(), (transaction,))
            .await
    }

    /// Collects an approval and returns the operation after synchronous coordination.
    async fn relay_multisig_approve_raw_transaction_sync(
        &self,
        transaction: Bytes,
        timeout_ms: u64,
    ) -> TransportResult<RelayOperation>
    where
        Self: Sized,
    {
        self.raw_request(
            "multisig_approveRawTransactionSync".into(),
            (transaction, timeout_ms),
        )
        .await
    }

    /// Starts a key-authorization operation from a signed serialized authorization.
    async fn relay_multisig_approve_serialized_key_authorization(
        &self,
        authorization: Bytes,
    ) -> TransportResult<RelayOperation>
    where
        Self: Sized,
    {
        self.raw_request(
            "multisig_approveKeyAuthorization".into(),
            (serde_json::json!({"keyAuthorization": authorization}),),
        )
        .await
    }

    /// Starts an operation from viem's RPC key-authorization representation.
    async fn relay_multisig_approve_rpc_key_authorization(
        &self,
        authorization: Value,
    ) -> TransportResult<RelayOperation> {
        self.client()
            .request(
                "multisig_approveKeyAuthorization",
                (serde_json::json!({"keyAuthorization": authorization}),),
            )
            .await
    }

    /// Adds a signature to an existing key-authorization approval operation.
    async fn relay_multisig_approve_key_authorization(
        &self,
        hash: B256,
        signature: Bytes,
    ) -> TransportResult<RelayOperation>
    where
        Self: Sized,
    {
        self.raw_request(
            "multisig_approveKeyAuthorization".into(),
            (serde_json::json!({"hash": hash, "signature": signature}),),
        )
        .await
    }
}

impl<T: Provider<TempoNetwork>> TempoRelayProviderExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_matches_viem_rpc_quantities() {
        let value = serde_json::json!({
            "owners": [{"owner": Address::repeat_byte(1), "weight": 2}],
            "salt": B256::ZERO, "threshold": 2, "version": "0x3"
        });
        let config: RelayMultisigConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(config.version, 3);
        assert_eq!(serde_json::to_value(config).unwrap(), value);
    }

    #[test]
    fn key_authorizations_cannot_be_submitting() {
        let value = serde_json::json!({
            "type": "keyAuthorization", "account": Address::repeat_byte(1), "approvals": [],
            "config": {"owners": [], "salt": B256::ZERO, "threshold": 1, "version": "0x0"},
            "createdAt": 1, "hash": B256::ZERO, "signatureCount": 0,
            "threshold": 1, "updatedAt": 1, "weight": 0,
            "status": "submitting", "keyAuthorization": "0x"
        });
        assert!(serde_json::from_value::<RelayOperation>(value).is_err());
    }
}
