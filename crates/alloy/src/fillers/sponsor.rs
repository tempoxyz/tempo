use crate::rpc::TempoTransactionRequest;
use alloy_network::Network;
use alloy_provider::{
    Provider, SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_transport::TransportResult;
use tempo_primitives::transaction::FEE_PAYER_SIGNATURE_MARKER;

/// A [`TxFiller`] that marks Tempo AA transactions for fee-payer sponsorship.
///
/// The sponsor service expects user-signed transactions to include the Tempo fee-payer signature
/// placeholder. The sponsor replaces that placeholder with its real fee-payer signature before
/// relaying the transaction.
#[derive(Clone, Copy, Debug, Default)]
pub struct SponsorFiller;

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for SponsorFiller {
    type Fillable = ();

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        // Only fill absent signatures; never overwrite an existing marker or real signature.
        if tx.fee_payer_signature.is_none() {
            FillerControlFlow::Ready
        } else {
            FillerControlFlow::Finished
        }
    }

    fn fill_sync(&self, _tx: &mut SendableTx<N>) {}

    async fn prepare<P>(&self, _provider: &P, _tx: &N::TransactionRequest) -> TransportResult<()>
    where
        P: Provider<N>,
    {
        Ok(())
    }

    async fn fill(&self, _fillable: (), mut tx: SendableTx<N>) -> TransportResult<SendableTx<N>> {
        if let Some(builder) = tx.as_mut_builder()
            && builder.fee_payer_signature.is_none()
        {
            builder.set_fee_payer_signature(FEE_PAYER_SIGNATURE_MARKER);
        }
        Ok(tx)
    }
}
