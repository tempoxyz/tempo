use crate::rpc::TempoTransactionRequest;
use alloy_network::{Network, TransactionBuilder};
use alloy_primitives::U256;
use alloy_provider::{
    SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_transport::TransportResult;
use tempo_primitives::subblock::has_sub_block_nonce_key_prefix;

/// A [`TxFiller`] that populates the [`TxAA`](`tempo_primitives::TxAA`) transaction with a random `nonce_key`, and `nonce` set to `0`.
///
/// This filler can be used to avoid nonce gaps by having a random 2D nonce key that doesn't conflict with any other transactions.
#[derive(Clone, Copy, Debug, Default)]
pub struct Random2DNonceFiller;

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for Random2DNonceFiller {
    type Fillable = ();

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if tx.nonce().is_some() || tx.nonce_key.is_some() {
            return FillerControlFlow::Finished;
        }
        FillerControlFlow::Ready
    }

    fn fill_sync(&self, tx: &mut SendableTx<N>) {
        if let Some(builder) = tx.as_mut_builder() {
            let nonce_key = loop {
                let key = U256::random();
                // We need to ensure that it doesn't use the subblock nonce key prefix
                if !has_sub_block_nonce_key_prefix(&key) {
                    break key;
                }
            };
            builder.set_nonce_key(nonce_key);
            builder.set_nonce(0);
        }
    }

    async fn prepare<P>(
        &self,
        _provider: &P,
        _tx: &N::TransactionRequest,
    ) -> TransportResult<Self::Fillable>
    where
        P: alloy_provider::Provider<N>,
    {
        Ok(())
    }

    async fn fill(
        &self,
        _fillable: Self::Fillable,
        tx: SendableTx<N>,
    ) -> TransportResult<SendableTx<N>> {
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        TempoFillers, TempoNetwork, fillers::Random2DNonceFiller,
        provider::ext::TempoProviderBuilderExt, rpc::TempoTransactionRequest,
    };
    use alloy_network::TransactionBuilder;
    use alloy_primitives::ruint::aliases::U256;
    use alloy_provider::{Identity, ProviderBuilder, fillers::JoinFill, mock::Asserter};
    use eyre;

    #[tokio::test]
    async fn test_random_2d_nonce_filler() -> eyre::Result<()> {
        let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
            .filler(Random2DNonceFiller)
            .connect_mocked_client(Asserter::default());

        // No nonce key, no nonce => nonce key and nonce are filled
        let filled_request = provider
            .fill(TempoTransactionRequest::default())
            .await?
            .try_into_request()?;
        assert!(filled_request.nonce_key.is_some());
        assert_eq!(filled_request.nonce(), Some(0));

        // Has nonce => nothing is filled
        let filled_request = provider
            .fill(TempoTransactionRequest::default().with_nonce(1))
            .await?
            .try_into_request()?;
        assert!(filled_request.nonce_key.is_none());
        assert_eq!(filled_request.nonce(), Some(1));

        // Has nonce key => nothing is filled
        let filled_request = provider
            .fill(TempoTransactionRequest::default().with_nonce_key(U256::ONE))
            .await?
            .try_into_request()?;
        assert_eq!(filled_request.nonce_key, Some(U256::ONE));
        assert!(filled_request.nonce().is_none());

        Ok(())
    }

    #[test]
    fn test_with_random_nonces() {
        let _: ProviderBuilder<_, JoinFill<Identity, TempoFillers<Random2DNonceFiller>>, _> =
            ProviderBuilder::new_with_network::<TempoNetwork>().with_random_2d_nonces();
    }
}
