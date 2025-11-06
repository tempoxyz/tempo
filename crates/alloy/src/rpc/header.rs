use alloy_rpc_types_eth::Header;
use serde::{Deserialize, Serialize};
use tempo_primitives::TempoHeader;

/// Tempo RPC header response type.
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::Deref, derive_more::DerefMut)]
#[serde(rename_all = "camelCase")]
pub struct TempoHeaderResponse {
    /// Inner [`Header`].
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    pub inner: Header<TempoHeader>,

    /// Block timestamp in milliseconds.
    #[serde(with = "alloy_serde::quantity")]
    pub timestamp_millis: u64,
}
