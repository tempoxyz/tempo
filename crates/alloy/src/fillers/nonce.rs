use crate::{TempoNetwork, rpc::TempoTransactionRequest};
use alloy_network::{Network, TransactionBuilder};
use alloy_primitives::U256;
use alloy_provider::{
    Identity, ProviderBuilder, SendableTx,
    fillers::{FillerControlFlow, NonceFiller, RecommendedFillers, TxFiller},
};
use alloy_transport::TransportResult;
use tempo_primitives::subblock::has_sub_block_nonce_key_prefix;

#[derive(Clone, Debug, Default)]
pub struct TempoNonceFiller {
    inner: TempoNonceFillerVariant,
}

impl TempoNonceFiller {
    fn enable_random_2d_nonce(&mut self) {
        self.inner = TempoNonceFillerVariant::Random2D(Random2DNonceFiller::default());
    }
}

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for TempoNonceFiller {
    type Fillable = u64;

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        match &self.inner {
            TempoNonceFillerVariant::Default(inner) => TxFiller::<N>::status(inner, tx),
            TempoNonceFillerVariant::Random2D(inner) => TxFiller::<N>::status(inner, tx),
        }
    }

    fn fill_sync(&self, tx: &mut SendableTx<N>) {
        match &self.inner {
            TempoNonceFillerVariant::Default(inner) => inner.fill_sync(tx),
            TempoNonceFillerVariant::Random2D(inner) => inner.fill_sync(tx),
        }
    }

    async fn prepare<P>(
        &self,
        provider: &P,
        tx: &N::TransactionRequest,
    ) -> TransportResult<Self::Fillable>
    where
        P: alloy_provider::Provider<N>,
    {
        match &self.inner {
            TempoNonceFillerVariant::Default(inner) => inner.prepare(provider, tx).await,
            TempoNonceFillerVariant::Random2D(inner) => inner.prepare(provider, tx).await,
        }
    }

    async fn fill(
        &self,
        fillable: Self::Fillable,
        tx: SendableTx<N>,
    ) -> TransportResult<SendableTx<N>> {
        match &self.inner {
            TempoNonceFillerVariant::Default(inner) => inner.fill(fillable, tx).await,
            TempoNonceFillerVariant::Random2D(inner) => inner.fill(fillable, tx).await,
        }
    }
}

#[derive(Debug, Clone)]
enum TempoNonceFillerVariant {
    Default(NonceFiller),
    Random2D(Random2DNonceFiller),
}

impl Default for TempoNonceFillerVariant {
    fn default() -> Self {
        Self::Default(NonceFiller::default())
    }
}

/// A [`TxFiller`] that populates the [`TxAA`](`tempo_primitives::TxAA`) transaction with a random `nonce_key`, and `nonce` set to `0`.
///
/// This filler can be used to avoid nonce gaps by having a random 2D nonce key that doesn't conflict with any other transactions.
#[derive(Clone, Copy, Debug, Default)]
pub struct Random2DNonceFiller;

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for Random2DNonceFiller {
    type Fillable = u64;

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
        Ok(0)
    }

    async fn fill(
        &self,
        _fillable: Self::Fillable,
        tx: SendableTx<N>,
    ) -> TransportResult<SendableTx<N>> {
        Ok(tx)
    }
}

pub trait Random2DNoncesProviderExt {
    fn with_random_nonces(self) -> Self;
}

impl Random2DNoncesProviderExt
    for ProviderBuilder<
        Identity,
        <TempoNetwork as RecommendedFillers>::RecommendedFillers,
        TempoNetwork,
    >
{
    fn with_random_nonces(self) -> Self {
        self.filler_mut().right().left().enable_random_2d_nonce();
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{TempoNetwork, fillers::Random2DNonceFiller, rpc::TempoTransactionRequest};
    use alloy_network::TransactionBuilder;
    use alloy_primitives::ruint::aliases::U256;
    use alloy_provider::{ProviderBuilder, mock::Asserter};
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
}
