use crate::rpc::TempoTransactionRequest;
use alloy_network::{Network, TransactionBuilder};
use alloy_primitives::U256;
use alloy_provider::{
    SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_transport::TransportResult;

/// A [`TxFiller`] that populates the `nonce_key` field with a random value for 2D nonce support.
///
/// The `nonce` field is set to 0 since the `nonce_key` determines the nonce sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct Random2DNonceFiller;

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for Random2DNonceFiller {
    type Fillable = U256;

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if tx.nonce().is_some() || tx.nonce_key.is_some() {
            return FillerControlFlow::Finished;
        }
        FillerControlFlow::Ready
    }

    fn fill_sync(&self, _tx: &mut SendableTx<N>) {}

    async fn prepare<P>(
        &self,
        _provider: &P,
        _tx: &N::TransactionRequest,
    ) -> TransportResult<Self::Fillable>
    where
        P: alloy_provider::Provider<N>,
    {
        Ok(U256::random())
    }

    async fn fill(
        &self,
        fillable: Self::Fillable,
        mut tx: SendableTx<N>,
    ) -> TransportResult<SendableTx<N>> {
        if let Some(builder) = tx.as_mut_builder() {
            builder.set_nonce_key(fillable);
            builder.set_nonce(0);
        }
        Ok(tx)
    }
}
