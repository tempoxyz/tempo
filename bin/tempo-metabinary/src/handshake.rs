//! Discovery protocol for private era workers. It detects port collisions, it is not auth.

use alloy_primitives::{B256, U64};
use eyre::{bail, ensure};
use jsonrpsee::{
    core::{ClientError, client::ClientT},
    http_client::HttpClient,
    rpc_params,
    types::error::METHOD_NOT_FOUND_CODE,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::Instant;

/// Worker discovery method served by `tempo rpc-only`.
pub const EXECUTION_INFO_METHOD: &str = "tempo_executionInfo";

/// Worker protocol version. v1 serves HTTP and WS (incl. `traceChain`) on one port.
pub const EXECUTION_INFO_PROTOCOL_VERSION: u32 = 1;

/// Upper bound on a single discovery request.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

/// Delay between discovery attempts.
const RETRY_DELAY: Duration = Duration::from_millis(50);

/// Response of [`EXECUTION_INFO_METHOD`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionInfo {
    /// The worker's [`EXECUTION_INFO_PROTOCOL_VERSION`].
    pub protocol_version: u32,
    /// Chain the worker serves.
    pub chain_id: U64,
    /// Genesis hash of the worker's database.
    pub genesis_hash: B256,
    /// Whether the worker opened storage read-only.
    pub read_only: bool,
    /// The worker's OS process ID.
    pub process_id: u32,
}

impl ExecutionInfo {
    /// Checks the protocol, that `identity` is served read-only, and that the worker is `pid`.
    pub fn validate(&self, identity: &WorkerIdentity, pid: u32) -> eyre::Result<()> {
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
            self.process_id == pid,
            "private endpoint belongs to another process"
        );
        Ok(())
    }
}

/// The chain a worker must serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerIdentity {
    /// Expected chain ID.
    pub chain_id: U64,
    /// Expected genesis hash.
    pub genesis_hash: B256,
}

/// Polls `client` until the worker answers [`EXECUTION_INFO_METHOD`] or `deadline` passes.
///
/// `check_alive` runs before each attempt. The first response is validated, never retried.
pub async fn wait_for_worker(
    client: &HttpClient,
    identity: &WorkerIdentity,
    pid: u32,
    deadline: Instant,
    mut check_alive: impl FnMut() -> eyre::Result<()>,
) -> eyre::Result<ExecutionInfo> {
    loop {
        check_alive()?;
        let now = Instant::now();
        if now >= deadline {
            bail!("worker startup timed out");
        }
        let attempt = tokio::time::timeout_at(
            deadline.min(now + ATTEMPT_TIMEOUT),
            client.request::<ExecutionInfo, _>(EXECUTION_INFO_METHOD, rpc_params![]),
        )
        .await;
        match attempt {
            Ok(Ok(info)) => {
                info.validate(identity, pid)?;
                return Ok(info);
            }
            Ok(Err(ClientError::Call(err))) if err.code() == METHOD_NOT_FOUND_CODE => {
                bail!(
                    "executable lacks {EXECUTION_INFO_METHOD}; it needs the private RPC worker protocol"
                );
            }
            // Not listening yet, or a transient failure.
            Ok(Err(_)) | Err(_) => {}
        }
        tokio::time::sleep_until(deadline.min(Instant::now() + RETRY_DELAY)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_every_field_of_the_camel_case_response() {
        let identity = WorkerIdentity {
            chain_id: U64::from(4217),
            genesis_hash: B256::repeat_byte(1),
        };
        let valid: ExecutionInfo = serde_json::from_value(serde_json::json!({
            "protocolVersion": 1,
            "chainId": "0x1079",
            "genesisHash": B256::repeat_byte(1),
            "readOnly": true,
            "processId": 7,
        }))
        .unwrap();
        valid.validate(&identity, 7).unwrap();

        type Case = (fn(&mut ExecutionInfo), &'static str);
        let cases: [Case; 5] = [
            (|i| i.protocol_version += 1, "unsupported worker protocol"),
            (|i| i.chain_id = U64::from(1), "worker chain ID mismatch"),
            (|i| i.genesis_hash = B256::ZERO, "worker genesis mismatch"),
            (|i| i.read_only = false, "worker is not read-only"),
            (
                |i| i.process_id = 8,
                "private endpoint belongs to another process",
            ),
        ];
        for (mutate, expected) in cases {
            let mut info = valid.clone();
            mutate(&mut info);
            assert_eq!(
                info.validate(&identity, 7).unwrap_err().to_string(),
                expected
            );
        }
    }
}
