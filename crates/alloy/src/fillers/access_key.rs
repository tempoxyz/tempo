use crate::{account::AccessKeyAccount, rpc::TempoTransactionRequest};
use alloy_network::{Network, TransactionBuilder};
use alloy_provider::{
    SendableTx,
    fillers::{FillerControlFlow, TxFiller},
};
use alloy_transport::TransportResult;

/// A [`TxFiller`] that injects access key metadata into transaction requests.
///
/// When an [`AccessKeyAccount`] is configured, this filler sets:
/// - `from` to the root account address (the sender)
/// - `key_id` for accurate gas estimation and AA type detection
/// - `key_authorization` on the first transaction only (consumed after use)
///
/// All fields are injected synchronously via [`fill_sync`](TxFiller::fill_sync)
/// because alloy's filler loop re-checks [`status`](TxFiller::status) on the
/// filled request — if `status` returns [`Finished`](FillerControlFlow::Finished)
/// after `fill_sync`, the async `prepare`/`fill` methods are never called.
#[derive(Clone, Debug)]
pub struct AccessKeyFiller {
    account: AccessKeyAccount,
}

impl AccessKeyFiller {
    /// Create a new filler from an access key account.
    ///
    /// If the account has a [`SignedKeyAuthorization`](tempo_primitives::transaction::SignedKeyAuthorization),
    /// it will be attached to the first transaction and then consumed automatically.
    pub fn new(account: AccessKeyAccount) -> Self {
        Self { account }
    }
}

impl<N: Network<TransactionRequest = TempoTransactionRequest>> TxFiller<N> for AccessKeyFiller {
    type Fillable = ();

    fn status(&self, tx: &N::TransactionRequest) -> FillerControlFlow {
        if tx.key_id.is_some() && TransactionBuilder::from(tx).is_some() {
            return FillerControlFlow::Finished;
        }
        FillerControlFlow::Ready
    }

    fn fill_sync(&self, tx: &mut SendableTx<N>) {
        if let Some(builder) = tx.as_mut_builder() {
            // Set `from` to the root address if not already set
            if TransactionBuilder::from(builder).is_none() {
                builder.set_from(self.account.sender_address());
            }

            // Inject key_id for AA type detection and gas estimation
            if builder.key_id.is_none() {
                builder.key_id = Some(self.account.key_id());
            }

            // Inject key_authorization once (consumed after first use)
            if builder.key_authorization.is_none() {
                builder.key_authorization = self.account.take_key_authorization();
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
