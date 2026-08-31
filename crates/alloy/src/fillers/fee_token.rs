use crate::rpc::TempoTransactionRequest;
use alloy_network::Network;
use alloy_primitives::Address;
use alloy_provider::{
    Provider, SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_transport::TransportResult;

/// A [`TxFiller`] that sets a default fee token on Tempo transactions.
///
/// Transactions that already specify a fee token are left unchanged.
#[derive(Clone, Copy, Debug)]
pub struct FeeTokenFiller {
    fee_token: Address,
}

impl FeeTokenFiller {
    /// Creates a filler that uses `fee_token` when a transaction does not specify one.
    pub const fn new(fee_token: Address) -> Self {
        Self { fee_token }
    }

    /// Returns the default fee token.
    pub const fn fee_token(&self) -> Address {
        self.fee_token
    }
}

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for FeeTokenFiller {
    type Fillable = ();

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if tx.fee_token.is_some() {
            FillerControlFlow::Finished
        } else {
            FillerControlFlow::Ready
        }
    }

    fn fill_sync(&self, tx: &mut SendableTx<N>) {
        if let Some(builder) = tx.as_mut_builder()
            && builder.fee_token.is_none()
        {
            builder.set_fee_token(self.fee_token);
        }
    }

    async fn prepare<P>(&self, _provider: &P, _tx: &N::TransactionRequest) -> TransportResult<()>
    where
        P: Provider<N>,
    {
        Ok(())
    }

    async fn fill(&self, _fillable: (), tx: SendableTx<N>) -> TransportResult<SendableTx<N>> {
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use alloy_provider::{SendableTx, fillers::TxFiller};

    use super::*;
    use crate::TempoNetwork;

    #[test]
    fn sets_the_default_fee_token() {
        let fee_token = Address::repeat_byte(0x11);
        let filler = FeeTokenFiller::new(fee_token);
        let mut tx = SendableTx::Builder(TempoTransactionRequest::default());

        <FeeTokenFiller as TxFiller<TempoNetwork>>::fill_sync(&filler, &mut tx);

        assert_eq!(tx.as_builder().unwrap().fee_token, Some(fee_token));
    }

    #[test]
    fn preserves_an_explicit_fee_token() {
        let default_fee_token = Address::repeat_byte(0x11);
        let explicit_fee_token = Address::repeat_byte(0x22);
        let filler = FeeTokenFiller::new(default_fee_token);
        let mut tx = SendableTx::Builder(
            TempoTransactionRequest::default().with_fee_token(explicit_fee_token),
        );

        <FeeTokenFiller as TxFiller<TempoNetwork>>::fill_sync(&filler, &mut tx);

        assert_eq!(tx.as_builder().unwrap().fee_token, Some(explicit_fee_token));
    }
}
