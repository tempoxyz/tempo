use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::{B256, Bytes, hex};
use alloy_provider::{
    PendingTransactionBuilder, Provider, ProviderLayer, RootProvider, SendableTx,
};
use alloy_transport::{TransportErrorKind, TransportResult};
use tempo_primitives::TempoTxEnvelope;

use crate::{TempoNetwork, rpc::SPONSOR_SIGNATURE_PLACEHOLDER};

/// Controls how a sponsor service handles sponsored raw transactions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SponsorPolicy {
    /// Ask the sponsor service to co-sign with `eth_signRawTransaction`, then broadcast through
    /// the default provider.
    #[default]
    SignOnly,
    /// Send the raw transaction to the sponsor service and let it co-sign and broadcast.
    SignAndBroadcast,
}

/// Provider layer that routes sponsor-marked Tempo transactions through a remote sponsor service.
#[derive(Clone, Debug)]
pub struct SponsorLayer<R> {
    sponsor: R,
    policy: SponsorPolicy,
}

impl<R> SponsorLayer<R> {
    /// Create a sponsor layer using the default `sign-only` policy.
    pub const fn new(sponsor: R) -> Self {
        Self {
            sponsor,
            policy: SponsorPolicy::SignOnly,
        }
    }

    /// Set the sponsor policy.
    pub const fn with_policy(mut self, policy: SponsorPolicy) -> Self {
        self.policy = policy;
        self
    }
}

impl<P, R> ProviderLayer<P, TempoNetwork> for SponsorLayer<R>
where
    P: Provider<TempoNetwork>,
    R: Provider<TempoNetwork> + Clone,
{
    type Provider = SponsorProvider<P, R>;

    fn layer(&self, inner: P) -> Self::Provider {
        SponsorProvider::new(inner, self.sponsor.clone()).with_policy(self.policy)
    }
}

/// Provider wrapper that implements remote sponsor routing for Tempo raw transactions.
#[derive(Clone, Debug)]
pub struct SponsorProvider<P, R> {
    inner: P,
    sponsor: R,
    policy: SponsorPolicy,
}

impl<P, R> SponsorProvider<P, R> {
    /// Create a sponsor provider wrapper using the default `sign-only` policy.
    pub const fn new(inner: P, sponsor: R) -> Self {
        Self {
            inner,
            sponsor,
            policy: SponsorPolicy::SignOnly,
        }
    }

    /// Set the sponsor policy.
    pub const fn with_policy(mut self, policy: SponsorPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Returns the wrapped default provider.
    pub const fn inner(&self) -> &P {
        &self.inner
    }

    /// Returns the sponsor provider.
    pub const fn sponsor(&self) -> &R {
        &self.sponsor
    }
}

/// Extension trait for wrapping an existing Tempo provider with sponsor support.
pub trait TempoSponsorProviderExt: Provider<TempoNetwork> + Sized {
    /// Route sponsor-marked transactions through `sponsor`.
    fn with_sponsor_provider<R>(self, sponsor: R) -> SponsorProvider<Self, R>
    where
        R: Provider<TempoNetwork>,
    {
        SponsorProvider::new(self, sponsor)
    }
}

impl<P> TempoSponsorProviderExt for P where P: Provider<TempoNetwork> {}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<P, R> Provider<TempoNetwork> for SponsorProvider<P, R>
where
    P: Provider<TempoNetwork>,
    R: Provider<TempoNetwork>,
{
    fn root(&self) -> &RootProvider<TempoNetwork> {
        self.inner.root()
    }

    async fn send_raw_transaction(
        &self,
        encoded_tx: &[u8],
    ) -> TransportResult<PendingTransactionBuilder<TempoNetwork>> {
        if !is_sponsor_marked(encoded_tx) {
            return self.inner.send_raw_transaction(encoded_tx).await;
        }

        match self.policy {
            SponsorPolicy::SignOnly => {
                let signed = self.sponsor_sign_raw_transaction(encoded_tx).await?;
                self.inner.send_raw_transaction(&signed).await
            }
            SponsorPolicy::SignAndBroadcast => {
                let tx_hash = self.sponsor_send_raw_transaction(encoded_tx).await?;
                Ok(PendingTransactionBuilder::new(
                    self.inner.root().clone(),
                    tx_hash,
                ))
            }
        }
    }

    async fn send_raw_transaction_sync(
        &self,
        encoded_tx: &[u8],
    ) -> TransportResult<<TempoNetwork as alloy_network::Network>::ReceiptResponse> {
        if !is_sponsor_marked(encoded_tx) {
            return self.inner.send_raw_transaction_sync(encoded_tx).await;
        }

        match self.policy {
            SponsorPolicy::SignOnly => {
                let signed = self.sponsor_sign_raw_transaction(encoded_tx).await?;
                self.inner.send_raw_transaction_sync(&signed).await
            }
            SponsorPolicy::SignAndBroadcast => {
                self.sponsor_send_raw_transaction_sync(encoded_tx).await
            }
        }
    }

    async fn send_transaction_internal(
        &self,
        tx: SendableTx<TempoNetwork>,
    ) -> TransportResult<PendingTransactionBuilder<TempoNetwork>> {
        if let SendableTx::Envelope(envelope) = &tx
            && is_sponsor_marked_envelope(envelope)
        {
            return self.send_raw_transaction(&envelope.encoded_2718()).await;
        }

        self.inner.send_transaction_internal(tx).await
    }

    async fn send_transaction_sync_internal(
        &self,
        tx: SendableTx<TempoNetwork>,
    ) -> TransportResult<<TempoNetwork as alloy_network::Network>::ReceiptResponse> {
        if let SendableTx::Envelope(envelope) = &tx
            && is_sponsor_marked_envelope(envelope)
        {
            return self
                .send_raw_transaction_sync(&envelope.encoded_2718())
                .await;
        }

        self.inner.send_transaction_sync_internal(tx).await
    }
}

impl<P, R> SponsorProvider<P, R>
where
    P: Provider<TempoNetwork>,
    R: Provider<TempoNetwork>,
{
    async fn sponsor_sign_raw_transaction(&self, encoded_tx: &[u8]) -> TransportResult<Bytes> {
        let rlp_hex = hex::encode_prefixed(encoded_tx);
        self.sponsor
            .raw_request("eth_signRawTransaction".into(), (rlp_hex,))
            .await
    }

    async fn sponsor_send_raw_transaction(&self, encoded_tx: &[u8]) -> TransportResult<B256> {
        let rlp_hex = hex::encode_prefixed(encoded_tx);
        self.sponsor
            .raw_request("eth_sendRawTransaction".into(), (rlp_hex,))
            .await
    }

    async fn sponsor_send_raw_transaction_sync(
        &self,
        encoded_tx: &[u8],
    ) -> TransportResult<<TempoNetwork as alloy_network::Network>::ReceiptResponse> {
        let rlp_hex = hex::encode_prefixed(encoded_tx);
        self.sponsor
            .raw_request("eth_sendRawTransactionSync".into(), (rlp_hex,))
            .await
    }
}

fn is_sponsor_marked(encoded_tx: &[u8]) -> bool {
    decode_envelope(encoded_tx)
        .as_ref()
        .is_ok_and(|envelope| is_sponsor_marked_envelope(envelope))
}

fn decode_envelope(encoded_tx: &[u8]) -> TransportResult<TempoTxEnvelope> {
    TempoTxEnvelope::decode_2718(&mut encoded_tx.as_ref())
        .map_err(|err| TransportErrorKind::custom_str(&err.to_string()))
}

fn is_sponsor_marked_envelope(envelope: &TempoTxEnvelope) -> bool {
    matches!(
        envelope,
        TempoTxEnvelope::AA(tx)
            if tx.tx().fee_payer_signature == Some(SPONSOR_SIGNATURE_PLACEHOLDER)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::transaction::TxHashRef;
    use alloy_primitives::{Address, Signature, U256};
    use alloy_provider::{ProviderBuilder, mock::Asserter};
    use tempo_primitives::{
        TempoTransaction,
        transaction::{Call, TempoSignature},
    };

    fn aa_envelope(fee_payer_signature: Option<Signature>) -> TempoTxEnvelope {
        let tx = TempoTransaction {
            chain_id: 1,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 21_000,
            calls: vec![Call {
                to: Address::ZERO.into(),
                value: U256::ZERO,
                input: Default::default(),
            }],
            fee_payer_signature,
            ..Default::default()
        };

        TempoTxEnvelope::AA(tx.into_signed(TempoSignature::default()))
    }

    #[test]
    fn detects_sponsor_placeholder_only() {
        let sponsored = aa_envelope(Some(SPONSOR_SIGNATURE_PLACEHOLDER));
        let unsponsored = aa_envelope(None);

        assert!(is_sponsor_marked_envelope(&sponsored));
        assert!(is_sponsor_marked(&sponsored.encoded_2718()));
        assert!(!is_sponsor_marked_envelope(&unsponsored));
        assert!(!is_sponsor_marked(&unsponsored.encoded_2718()));
    }

    #[tokio::test]
    async fn sign_only_policy_cosigns_with_sponsor_then_broadcasts_default() {
        let default_asserter = Asserter::new();
        let sponsor_asserter = Asserter::new();
        let default = ProviderBuilder::<_, _, TempoNetwork>::default()
            .connect_mocked_client(default_asserter.clone());
        let sponsor = ProviderBuilder::<_, _, TempoNetwork>::default()
            .connect_mocked_client(sponsor_asserter.clone());
        let provider = default.with_sponsor_provider(sponsor);

        let sponsor_marked = aa_envelope(Some(SPONSOR_SIGNATURE_PLACEHOLDER));
        let cosigned = aa_envelope(Some(Signature::test_signature()));
        let cosigned_bytes = Bytes::from(cosigned.encoded_2718());
        let tx_hash = *cosigned.tx_hash();

        sponsor_asserter.push_success(&cosigned_bytes);
        default_asserter.push_success(&tx_hash);

        let pending = provider
            .send_raw_transaction(&sponsor_marked.encoded_2718())
            .await
            .expect("sponsored transaction should route");

        assert_eq!(*pending.tx_hash(), tx_hash);
        assert!(sponsor_asserter.read_q().is_empty());
        assert!(default_asserter.read_q().is_empty());
    }
}
