use alloy_rpc_types_admin::PeerInfo;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_network_api::{NetworkInfo, Peers};
use reth_rpc_server_types::ToRpcResult;
use revm_primitives::keccak256;

/// `operator_` namespace RPC trait.
///
/// Exposes a subset of admin-like methods under the `operator` namespace,
/// allowing node operators to query peer information without enabling the
/// full `admin` API.
#[rpc(server, namespace = "operator")]
pub trait OperatorApi {
    /// Returns information about all connected peers.
    ///
    /// Equivalent to `admin_peers` but exposed under the `operator` namespace.
    #[method(name = "peers")]
    async fn peers(&self) -> RpcResult<Vec<PeerInfo>>;
}

/// Implementation of the `operator_` namespace.
#[derive(Debug, Clone)]
pub struct OperatorApi<N> {
    network: N,
}

impl<N> OperatorApi<N> {
    /// Creates a new `OperatorApi` with the given network handle.
    pub fn new(network: N) -> Self {
        Self { network }
    }
}

#[async_trait::async_trait]
impl<N> OperatorApiServer for OperatorApi<N>
where
    N: NetworkInfo + Peers + 'static,
{
    async fn peers(&self) -> RpcResult<Vec<PeerInfo>> {
        let peers = self.network.get_all_peers().await.to_rpc_result()?;
        let mut infos = Vec::with_capacity(peers.len());

        for peer in peers {
            infos.push(PeerInfo {
                id: alloy_primitives::hex::encode(keccak256(peer.remote_id.as_slice())),
                name: peer.client_version.to_string(),
                enode: peer.enode,
                enr: peer.enr,
                caps: peer
                    .capabilities
                    .capabilities()
                    .iter()
                    .map(|cap| cap.to_string())
                    .collect(),
                network: alloy_rpc_types_admin::PeerNetworkInfo {
                    remote_address: peer.remote_addr,
                    local_address: peer
                        .local_addr
                        .unwrap_or_else(|| self.network.local_addr()),
                    inbound: peer.direction.is_incoming(),
                    trusted: peer.kind.is_trusted(),
                    static_node: peer.kind.is_static(),
                },
                protocols: alloy_rpc_types_admin::PeerProtocolInfo {
                    eth: Some(alloy_rpc_types_admin::EthPeerInfo::Info(
                        alloy_rpc_types_admin::EthInfo {
                            version: peer.status.version as u64,
                        },
                    )),
                    snap: None,
                    other: Default::default(),
                },
            })
        }

        Ok(infos)
    }
}
