//! Identity validation and readiness polling shared by eager and lazy workers.

use alloy_primitives::B256;
use eyre::{Result, bail, ensure};
use jsonrpsee::{
    core::client::{ClientT, Error as ClientError},
    http_client::HttpClient,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;

/// Private discovery method and wire protocol shared by workers and their launchers.
pub const EXECUTION_INFO_METHOD: &str = "tempo_executionInfo";
pub const EXECUTION_INFO_PROTOCOL_VERSION: u32 = 1;

/// The actual private transport's registered methods, not a global RPC catalogue.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionInfo {
    pub protocol_version: u32,
    pub chain_id: String,
    pub genesis_hash: B256,
    pub read_only: bool,
    pub process_id: u32,
    pub methods: Vec<String>,
}

/// Expected chain and access mode, independent of either launcher's configuration.
#[derive(Clone, Copy)]
pub struct WorkerIdentity<'a> {
    pub chain_id: &'a str,
    pub genesis_hash: &'a str,
    pub read_only: bool,
}

impl ExecutionInfo {
    /// Startup checks the owned child's PID; router construction can recheck metadata without it.
    pub fn validate(&self, identity: WorkerIdentity<'_>, process_id: Option<u32>) -> Result<()> {
        ensure!(
            self.protocol_version == EXECUTION_INFO_PROTOCOL_VERSION,
            "unsupported worker protocol"
        );
        ensure!(
            self.chain_id.eq_ignore_ascii_case(identity.chain_id),
            "worker chain ID mismatch"
        );
        ensure!(
            self.genesis_hash == identity.genesis_hash.parse::<B256>()?,
            "worker genesis mismatch"
        );
        ensure!(
            self.read_only == identity.read_only,
            "worker read-only mode mismatch"
        );
        ensure!(
            process_id.is_none_or(|pid| self.process_id == pid),
            "private endpoint belongs to another process"
        );
        ensure!(
            self.methods.len() <= 1024,
            "worker reports too many RPC methods"
        );
        ensure!(
            self.methods.iter().all(|method| method.len() <= 256),
            "worker method name too long"
        );
        Ok(())
    }
}

/// Retry transport failures until the original startup deadline, checking child ownership each time.
/// A valid response with the wrong identity or a missing protocol fails immediately.
pub async fn wait_for_worker(
    client: &HttpClient,
    identity: WorkerIdentity<'_>,
    process_id: u32,
    deadline: Instant,
    mut check_alive: impl FnMut() -> Result<()>,
) -> Result<ExecutionInfo> {
    loop {
        check_alive()?;
        ensure!(Instant::now() < deadline, "worker startup timed out");
        let response = tokio::time::timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(1)),
            client.request::<ExecutionInfo, _>(EXECUTION_INFO_METHOD, jsonrpsee::rpc_params![]),
        )
        .await;
        match response {
            Ok(Ok(info)) => {
                info.validate(identity, Some(process_id))?;
                return Ok(info);
            }
            Ok(Err(ClientError::Call(error))) if error.code() == -32601 => {
                bail!(
                    "executable lacks {EXECUTION_INFO_METHOD}; it needs the private RPC worker protocol"
                );
            }
            _ => {}
        }
        tokio::time::sleep_until(deadline.min(Instant::now() + Duration::from_millis(50))).await;
    }
}
