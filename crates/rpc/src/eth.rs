use reth_rpc::eth::{RpcNodeCore, core::EthApiInner};
use reth_rpc_convert::RpcConvert;
use std::sync::Arc;

/// Tempo `Eth` API implementation.
///
/// This type provides the functionality for handling `eth_` related requests.
///
/// This wraps a default `Eth` implementation, and provides additional functionality where the
/// Tempo spec deviates from the default ethereum spec, e.g. gas estimation denominated in
/// `feeToken`
///
/// This type implements the [`FullEthApi`](reth_rpc_eth_api::helpers::FullEthApi) by implemented
/// all the `Eth` helper traits and prerequisite traits.
#[derive(Clone)]
pub struct TempoEthApi<N: RpcNodeCore, Rpc: RpcConvert> {
    /// Gateway to node's core components.
    inner: Arc<EthApiInner<N, Rpc>>,
}

impl<N: RpcNodeCore, Rpc: RpcConvert> TempoEthApi<N, Rpc> {
    /// Creates a new `OpEthApi`.
    pub fn new(eth_api: EthApiInner<N, Rpc>) -> Self {
        Self {
            inner: Arc::new(eth_api),
        }
    }
}
