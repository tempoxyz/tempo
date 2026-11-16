//! Helpers for tests that drive a node through contract bindings.

use alloy_contract::{CallBuilder, CallDecoder};
use alloy_network::Network;
use alloy_provider::Provider;

/// Extends [`CallBuilder`] for tests.
pub trait CallBuilderExt<N: Network> {
    /// Sends the call and waits for its receipt.
    ///
    /// The receipt's status is not checked, so tests can assert reverts on it.
    fn mined(&self) -> impl Future<Output = alloy_contract::Result<N::ReceiptResponse>> + Send;
}

impl<P: Provider<N>, D: CallDecoder + Sync, N: Network> CallBuilderExt<N> for CallBuilder<P, D, N> {
    async fn mined(&self) -> alloy_contract::Result<N::ReceiptResponse> {
        Ok(self.send().await?.get_receipt().await?)
    }
}
