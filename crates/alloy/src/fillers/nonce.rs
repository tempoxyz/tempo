use crate::rpc::TempoTransactionRequest;
use alloy_network::{Network, TransactionBuilder};
use alloy_primitives::{Address, U256};
use alloy_provider::{
    Provider, SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_transport::{TransportErrorKind, TransportResult};
use dashmap::DashMap;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tempo_contracts::precompiles::{INonce, NONCE_PRECOMPILE_ADDRESS};
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

/// A [`TxFiller`] that populates transactions with expiring nonce fields ([TIP-1009]).
///
/// Sets `nonce_key` to `U256::MAX`, `nonce` to `0`, and `valid_before` to current time + expiry window.
/// This enables transactions to use the circular buffer replay protection instead of 2D nonce storage.
///
/// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
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
    /// Default expiry window in seconds (25s, within the 30s max allowed by [TIP-1009]).
    ///
    /// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
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

/// A [`TxFiller`] that fills the nonce for transactions with a pre-set `nonce_key`.
///
/// This filler requires `nonce_key` to already be set on the transaction request and fills
/// the correct next nonce by querying the chain. Nonces are cached per `(address, nonce_key)`
/// pair so that batched sends get sequential nonces without extra RPC calls.
///
/// Nonce resolution depends on the key:
/// - `U256::ZERO` (protocol nonce): uses `get_transaction_count`
/// - `TEMPO_EXPIRING_NONCE_KEY` (U256::MAX): always 0, no caching (use [`ExpiringNonceFiller`]
///   instead for full expiring nonce support including `valid_before`)
/// - Any other key: queries the `NonceManager` precompile via `eth_call`
#[derive(Clone, Debug, Default)]
pub struct NonceKeyFiller {
    #[allow(clippy::type_complexity)]
    nonces: Arc<DashMap<(Address, U256), Arc<futures::lock::Mutex<u64>>>>,
}

/// Sentinel value indicating the nonce has not been fetched yet.
const NONCE_NOT_FETCHED: u64 = u64::MAX;

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for NonceKeyFiller {
    type Fillable = u64;

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if tx.nonce().is_some() {
            return FillerControlFlow::Finished;
        }
        if tx.nonce_key.is_none() {
            return FillerControlFlow::missing("NonceKeyFiller", vec!["nonce_key"]);
        }
        if TransactionBuilder::from(tx).is_none() {
            return FillerControlFlow::missing("NonceKeyFiller", vec!["from"]);
        }
        FillerControlFlow::Ready
    }

    fn fill_sync(&self, _tx: &mut SendableTx<N>) {}

    async fn prepare<P>(
        &self,
        provider: &P,
        tx: &N::TransactionRequest,
    ) -> TransportResult<Self::Fillable>
    where
        P: Provider<N>,
    {
        let from = TransactionBuilder::from(tx)
            .ok_or_else(|| TransportErrorKind::custom_str("missing `from` address"))?;
        let nonce_key = tx
            .nonce_key
            .ok_or_else(|| TransportErrorKind::custom_str("missing `nonce_key`"))?;

        // Expiring nonces always use nonce 0
        if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
            return Ok(0);
        }

        let key = (from, nonce_key);
        let mutex = self
            .nonces
            .entry(key)
            .or_insert_with(|| Arc::new(futures::lock::Mutex::new(NONCE_NOT_FETCHED)))
            .clone();

        let mut nonce = mutex.lock().await;

        if *nonce == NONCE_NOT_FETCHED {
            *nonce = if nonce_key.is_zero() {
                provider.get_transaction_count(from).await?
            } else {
                let contract = INonce::new(NONCE_PRECOMPILE_ADDRESS, provider);
                contract
                    .getNonce(from, nonce_key)
                    .call()
                    .await
                    .map_err(|e| TransportErrorKind::custom_str(&e.to_string()))?
            };
        } else {
            *nonce += 1;
        }

        Ok(*nonce)
    }

    async fn fill(
        &self,
        fillable: Self::Fillable,
        mut tx: SendableTx<N>,
    ) -> TransportResult<SendableTx<N>> {
        if let Some(builder) = tx.as_mut_builder() {
            builder.set_nonce(fillable);
        }
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
