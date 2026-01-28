use crate::rpc::TempoTransactionRequest;
use alloy_network::{Network, TransactionBuilder};
use alloy_primitives::U256;
use alloy_provider::{
    SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_transport::TransportResult;
use std::time::{SystemTime, UNIX_EPOCH};
use tempo_primitives::{
    subblock::has_sub_block_nonce_key_prefix, transaction::TEMPO_EXPIRING_NONCE_KEY,
};

/// A [`TxFiller`] that populates the [`TempoTransaction`](`tempo_primitives::TempoTransaction`) transaction with a random `nonce_key`, and `nonce` set to `0`.
///
/// This filler can be used to avoid nonce gaps by having a random 2D nonce key that doesn't conflict with any other transactions.
#[derive(Clone, Copy, Debug, Default)]
pub struct Random2DNonceFiller;

impl Random2DNonceFiller {
    /// Returns `true` if either the nonce or nonce key is already filled.
    fn is_filled(tx: &TempoTransactionRequest) -> bool {
        tx.nonce().is_some() || tx.nonce_key.is_some()
    }
}

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for Random2DNonceFiller {
    type Fillable = ();

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if Self::is_filled(tx) {
            return FillerControlFlow::Finished;
        }
        FillerControlFlow::Ready
    }

    fn fill_sync(&self, tx: &mut SendableTx<N>) {
        if let Some(builder) = tx.as_mut_builder()
            && !Self::is_filled(builder)
        {
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

/// A [`TxFiller`] that populates transactions with expiring nonce fields (TIP-1009).
///
/// Sets `nonce_key` to `U256::MAX`, `nonce` to `0`, and `valid_before` to current time + expiry window.
/// This enables transactions to use the circular buffer replay protection instead of 2D nonce storage.
#[derive(Clone, Copy, Debug)]
pub struct ExpiringNonceFiller {
    /// Expiry window in seconds from current time.
    expiry_secs: u64,
}

impl Default for ExpiringNonceFiller {
    fn default() -> Self {
        Self {
            expiry_secs: Self::DEFAULT_EXPIRY_SECS,
        }
    }
}

impl ExpiringNonceFiller {
    /// Default expiry window in seconds (25s, within the 30s max allowed by TIP-1009).
    pub const DEFAULT_EXPIRY_SECS: u64 = 25;

    /// Create a new filler with a custom expiry window.
    ///
    /// For benchmarking purposes, use a large value (e.g., 3600 for 1 hour) to avoid
    /// transactions expiring before they're sent.
    pub fn with_expiry_secs(expiry_secs: u64) -> Self {
        Self { expiry_secs }
    }

    /// Returns `true` if all expiring nonce fields are properly set:
    /// - `nonce_key` is `TEMPO_EXPIRING_NONCE_KEY`
    /// - `nonce` is `0`
    /// - `valid_before` is set
    fn is_filled(tx: &TempoTransactionRequest) -> bool {
        tx.nonce_key == Some(TEMPO_EXPIRING_NONCE_KEY)
            && tx.nonce() == Some(0)
            && tx.valid_before.is_some()
    }

    /// Returns the current unix timestamp, saturating to 0 if system time is before UNIX_EPOCH
    /// (which can occur due to NTP adjustments or VM clock drift).
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|_| {
                tracing::warn!("system clock before UNIX_EPOCH, using 0");
                0
            })
    }
}

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for ExpiringNonceFiller {
    type Fillable = ();

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if Self::is_filled(tx) {
            return FillerControlFlow::Finished;
        }
        FillerControlFlow::Ready
    }

    fn fill_sync(&self, tx: &mut SendableTx<N>) {
        if let Some(builder) = tx.as_mut_builder()
            && !Self::is_filled(builder)
        {
            // Set expiring nonce key (U256::MAX)
            builder.set_nonce_key(TEMPO_EXPIRING_NONCE_KEY);
            // Nonce must be 0 for expiring nonce transactions
            builder.set_nonce(0);
            // Set valid_before to current time + expiry window
            builder.set_valid_before(Self::current_timestamp() + self.expiry_secs);
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
