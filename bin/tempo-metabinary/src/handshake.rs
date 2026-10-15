//! Identity validation and readiness polling for supervised RPC workers.

use alloy_primitives::{B256, U64};
use eyre::{Result, bail, ensure};
use jsonrpsee::{
    core::client::{ClientT, Error as ClientError},
    http_client::HttpClient,
    types::error::METHOD_NOT_FOUND_CODE,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;

/// Private discovery method and wire protocol shared by workers and their launchers.
pub const EXECUTION_INFO_METHOD: &str = "tempo_executionInfo";
pub const EXECUTION_INFO_PROTOCOL_VERSION: u32 = 1;

/// A private read-only worker's identity. Unsupported methods surface as JSON-RPC
/// method-not-found errors when forwarded.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionInfo {
    pub protocol_version: u32,
    pub chain_id: U64,
    pub genesis_hash: B256,
    pub read_only: bool,
    /// Detects another process on the worker's port.
    pub process_id: u32,
}

impl ExecutionInfo {
    /// Verify chain, access mode, and the owned child's PID before accepting its endpoint.
    pub fn validate(&self, identity: WorkerIdentity, process_id: u32) -> Result<()> {
        ensure!(
            self.protocol_version == EXECUTION_INFO_PROTOCOL_VERSION,
            "unsupported worker protocol"
        );
        ensure!(
            self.chain_id == identity.chain_id,
            "worker chain ID mismatch"
        );
        ensure!(
            self.genesis_hash == identity.genesis_hash,
            "worker genesis mismatch"
        );
        ensure!(self.read_only, "worker is not read-only");
        ensure!(
            self.process_id == process_id,
            "private endpoint belongs to another process"
        );
        Ok(())
    }
}

/// Expected chain for a supervised worker.
#[derive(Clone, Copy)]
pub struct WorkerIdentity {
    pub chain_id: U64,
    pub genesis_hash: B256,
}

/// Retry transport failures until the original startup deadline, checking child ownership each time.
/// A valid response with the wrong identity or a missing protocol fails immediately.
pub async fn wait_for_worker(
    client: &HttpClient,
    identity: WorkerIdentity,
    process_id: u32,
    deadline: Instant,
    mut check_alive: impl FnMut() -> Result<()>,
) -> Result<()> {
    loop {
        check_alive()?;
        ensure!(Instant::now() < deadline, "worker startup timed out");
        let response = tokio::time::timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(1)),
            client.request::<ExecutionInfo, _>(EXECUTION_INFO_METHOD, jsonrpsee::rpc_params![]),
        )
        .await;
        match response {
            Ok(Ok(info)) => return info.validate(identity, process_id),
            Ok(Err(ClientError::Call(error))) if error.code() == METHOD_NOT_FOUND_CODE => {
                bail!(
                    "executable lacks {EXECUTION_INFO_METHOD}; it needs the private RPC worker protocol"
                );
            }
            _ => {}
        }
        tokio::time::sleep_until(deadline.min(Instant::now() + Duration::from_millis(50))).await;
    }
}
