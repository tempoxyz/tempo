//! Gas configuration filler for Tempo network.

use crate::rpc::TempoTransactionRequest;
use alloy_network::{Network, TransactionBuilder};
use alloy_provider::{
    SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_transport::TransportResult;

/// Default max fee per gas in wei (20 gwei).
pub const DEFAULT_MAX_FEE_PER_GAS: u128 = 20_000_000_000;

/// Default max priority fee per gas in wei (1 gwei).
pub const DEFAULT_MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;

/// A [`TxFiller`] that populates transactions with default gas configuration for Tempo networks.
///
/// Sets `max_fee_per_gas` to 20 gwei and `max_priority_fee_per_gas` to 1 gwei if not already set.
#[derive(Clone, Copy, Debug, Default)]
pub struct TempoGasFiller;

impl TempoGasFiller {
    /// Returns `true` if gas fees are already filled.
    fn is_filled(tx: &TempoTransactionRequest) -> bool {
        tx.max_fee_per_gas().is_some() && tx.max_priority_fee_per_gas().is_some()
    }
}

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for TempoGasFiller {
    type Fillable = ();

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if Self::is_filled(tx) {
            return FillerControlFlow::Finished;
        }
        FillerControlFlow::Ready
    }

    fn fill_sync(&self, tx: &mut SendableTx<N>) {
        if let Some(builder) = tx.as_mut_builder() {
            if builder.max_fee_per_gas().is_none() {
                builder.set_max_fee_per_gas(DEFAULT_MAX_FEE_PER_GAS);
            }
            if builder.max_priority_fee_per_gas().is_none() {
                builder.set_max_priority_fee_per_gas(DEFAULT_MAX_PRIORITY_FEE_PER_GAS);
            }
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
    use super::*;
    use crate::TempoNetwork;
    use alloy_provider::fillers::TxFiller;

    #[test]
    fn test_tempo_gas_filler_defaults() {
        let filler = TempoGasFiller;
        let tx = TempoTransactionRequest::default();

        assert!(tx.max_fee_per_gas().is_none());
        assert!(tx.max_priority_fee_per_gas().is_none());

        let status = <TempoGasFiller as TxFiller<TempoNetwork>>::status(&filler, &tx);
        assert!(matches!(status, FillerControlFlow::Ready));
    }

    #[test]
    fn test_tempo_gas_filler_already_set() {
        let filler = TempoGasFiller;
        let mut tx = TempoTransactionRequest::default();
        tx.set_max_fee_per_gas(10_000_000_000);
        tx.set_max_priority_fee_per_gas(500_000_000);

        let status = <TempoGasFiller as TxFiller<TempoNetwork>>::status(&filler, &tx);
        assert!(matches!(status, FillerControlFlow::Finished));
    }
}
