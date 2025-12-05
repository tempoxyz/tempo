use alloy_primitives::B256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(server, namespace = "admin")]
pub trait TempoAdminApi {
    /// Returns the validator public key if configured.
    ///
    /// This method exposes the ed25519 public key used by this node
    /// for validator operations in the consensus layer.
    ///
    /// Returns `null` if the node is not configured as a validator.
    #[method(name = "validatorKey")]
    async fn validator_key(&self) -> RpcResult<Option<B256>>;
}

/// Tempo-specific `admin_` namespace extensions.
#[derive(Debug, Clone)]
pub struct TempoAdminApi {
    validator_key: Option<B256>,
}

impl TempoAdminApi {
    /// Create a new admin API handler.
    pub fn new(validator_key: Option<B256>) -> Self {
        Self { validator_key }
    }
}

#[async_trait::async_trait]
impl TempoAdminApiServer for TempoAdminApi {
    async fn validator_key(&self) -> RpcResult<Option<B256>> {
        Ok(self.validator_key)
    }
}
