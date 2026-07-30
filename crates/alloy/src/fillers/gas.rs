//! Tempo gas estimation with access-key authorization resolution.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy_json_rpc::RpcError;
use alloy_network::TransactionBuilder;
use alloy_primitives::Address;
use alloy_provider::{
    Provider, SendableTx,
    fillers::{FillerControlFlow, GasFillable, GasFiller, TxFiller},
};
use alloy_transport::TransportResult;
use tempo_primitives::transaction::{FEE_PAYER_SIGNATURE_MARKER, SignedKeyAuthorization};

use crate::{TempoNetwork, provider::TempoProviderExt, rpc::TempoTransactionRequest};

/// Gas estimation for Tempo transactions.
///
/// When an access-key request carries a persisted one-time authorization, this
/// filler checks the Account Keychain before estimating gas. Published keys
/// omit the authorization; missing keys retain it for authorize-and-use.
#[derive(Clone, Debug, Default)]
pub struct TempoGasFiller {
    inner: GasFiller,
}

/// Values prepared by [`TempoGasFiller`].
#[doc(hidden)]
#[derive(Debug)]
pub struct TempoGasFillable {
    gas: GasFillable,
    key_authorization: Option<Option<SignedKeyAuthorization>>,
}

impl TxFiller<TempoNetwork> for TempoGasFiller {
    type Fillable = TempoGasFillable;

    fn status(&self, request: &TempoTransactionRequest) -> FillerControlFlow {
        if !request.has_aa_fields() {
            return <GasFiller as TxFiller<TempoNetwork>>::status(&self.inner, request);
        }
        if request.gas_price().is_some() {
            return FillerControlFlow::Ready;
        }
        if request.chain_id().is_none() {
            return FillerControlFlow::missing("TempoGasFiller", vec!["chain_id"]);
        }
        if request.from().is_none() {
            return FillerControlFlow::missing("TempoGasFiller", vec!["from"]);
        }
        <GasFiller as TxFiller<TempoNetwork>>::status(&self.inner, request)
    }

    fn fill_sync(&self, tx: &mut SendableTx<TempoNetwork>) {
        <GasFiller as TxFiller<TempoNetwork>>::fill_sync(&self.inner, tx);
    }

    async fn prepare<P>(
        &self,
        provider: &P,
        request: &TempoTransactionRequest,
    ) -> TransportResult<Self::Fillable>
    where
        P: Provider<TempoNetwork>,
    {
        if request.has_aa_fields() && request.gas_price().is_some() {
            return Err(RpcError::local_usage(
                KeyAuthorizationError::LegacyGasPriceUnsupported,
            ));
        }
        let mut estimate_request = request_for_gas_estimation(request);
        let key_authorization = resolve_key_authorization(provider, request).await?;
        if let Some(resolved) = &key_authorization {
            estimate_request.key_authorization = resolved.clone();
        }
        let gas = <GasFiller as TxFiller<TempoNetwork>>::prepare(
            &self.inner,
            provider,
            &estimate_request,
        )
        .await?;
        Ok(TempoGasFillable {
            gas,
            key_authorization,
        })
    }

    async fn fill(
        &self,
        fillable: Self::Fillable,
        tx: SendableTx<TempoNetwork>,
    ) -> TransportResult<SendableTx<TempoNetwork>> {
        let mut tx =
            <GasFiller as TxFiller<TempoNetwork>>::fill(&self.inner, fillable.gas, tx).await?;
        if let Some(request) = tx.as_mut_builder()
            && let Some(key_authorization) = fillable.key_authorization
        {
            request.key_authorization = key_authorization;
        }
        Ok(tx)
    }
}

fn request_for_gas_estimation(request: &TempoTransactionRequest) -> TempoTransactionRequest {
    let mut estimate_request = request.clone();
    if estimate_request.fee_payer_signature == Some(FEE_PAYER_SIGNATURE_MARKER) {
        estimate_request.fee_payer_signature = None;
    }
    estimate_request
}

/// Resolve a persisted one-time authorization against the Account Keychain.
///
/// The outer `Option` is `None` when the request did not contain an
/// authorization and therefore needs no mutation. `Some(None)` removes an
/// authorization for an already-published key.
pub(crate) async fn resolve_key_authorization<P>(
    provider: &P,
    request: &TempoTransactionRequest,
) -> TransportResult<Option<Option<SignedKeyAuthorization>>>
where
    P: Provider<TempoNetwork>,
{
    let Some(authorization) = request.key_authorization.as_ref() else {
        return Ok(None);
    };
    let account = request
        .from()
        .ok_or_else(|| RpcError::local_usage(KeyAuthorizationError::MissingAccount))?;
    validate_authorization(request, account, authorization).map_err(RpcError::local_usage)?;
    let Some(key_id) = request
        .key_id
        .filter(|key_id| *key_id == authorization.key_id)
    else {
        return Ok(Some(Some(authorization.clone())));
    };
    if let Some(key_type) = request.key_type
        && authorization.key_type != key_type
    {
        return Err(RpcError::local_usage(
            KeyAuthorizationError::AuthorizationTypeMismatch,
        ));
    }

    let key = provider
        .get_keychain_key(account, key_id)
        .await
        .map_err(|error| match error {
            alloy_contract::Error::TransportError(error) => error,
            error => RpcError::local_usage(error),
        })?;
    if key.isRevoked {
        return Err(RpcError::local_usage(KeyAuthorizationError::Revoked {
            account,
            key_id,
        }));
    }
    if key.keyId == Address::ZERO {
        return Ok(Some(Some(authorization.clone())));
    }
    if key.keyId != key_id {
        return Err(RpcError::local_usage(
            KeyAuthorizationError::UnexpectedOnchainKey {
                expected: key_id,
                actual: key.keyId,
            },
        ));
    }
    if key.expiry <= unix_now() {
        return Err(RpcError::local_usage(KeyAuthorizationError::Expired {
            account,
            key_id,
        }));
    }

    Ok(Some(None))
}

fn validate_authorization(
    request: &TempoTransactionRequest,
    account: Address,
    signed: &SignedKeyAuthorization,
) -> Result<(), KeyAuthorizationError> {
    let authorization = &signed.authorization;
    if let Some(chain_id) = request.chain_id()
        && authorization.chain_id != chain_id
    {
        return Err(KeyAuthorizationError::AuthorizationChainMismatch {
            expected: chain_id,
            actual: authorization.chain_id,
        });
    }
    if let Some(authorized_account) = authorization.account
        && authorized_account != account
    {
        return Err(KeyAuthorizationError::AuthorizationAccountMismatch {
            expected: account,
            actual: authorized_account,
        });
    }
    if authorization
        .expiry
        .is_some_and(|expiry| expiry.get() <= unix_now())
    {
        return Err(KeyAuthorizationError::AuthorizationExpired);
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, thiserror::Error)]
enum KeyAuthorizationError {
    #[error("Tempo access-key authorization requires a transaction sender")]
    MissingAccount,
    #[error("Tempo AA transactions require EIP-1559 fees; gas_price is unsupported")]
    LegacyGasPriceUnsupported,
    #[error("Tempo key authorization is expired")]
    AuthorizationExpired,
    #[error("Tempo key authorization chain is {actual}, expected {expected}")]
    AuthorizationChainMismatch { expected: u64, actual: u64 },
    #[error("Tempo key authorization signature type does not match the selected signer")]
    AuthorizationTypeMismatch,
    #[error("Tempo key authorization account is {actual}, expected {expected}")]
    AuthorizationAccountMismatch { expected: Address, actual: Address },
    #[error("Account Keychain returned key {actual}, expected {expected}")]
    UnexpectedOnchainKey { expected: Address, actual: Address },
    #[error("Tempo access key {key_id} for {account} has been revoked")]
    Revoked { account: Address, key_id: Address },
    #[error("Tempo access key {key_id} for {account} has expired")]
    Expired { account: Address, key_id: Address },
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Bytes, Signature};
    use alloy_provider::{ProviderBuilder, fillers::TxFiller, mock::Asserter};
    use alloy_rpc_types_eth::TransactionRequest;
    use tempo_primitives::{
        SignatureType, TempoTxType,
        transaction::{KeyAuthorization, PrimitiveSignature},
    };

    use super::*;

    #[test]
    fn delegates_non_aa_status_to_the_inner_filler() {
        let filler = TempoGasFiller::default();
        for transaction_type in [TempoTxType::Legacy, TempoTxType::Eip2930] {
            let request = TempoTransactionRequest {
                inner: TransactionRequest {
                    transaction_type: Some(transaction_type as u8),
                    gas_price: Some(1),
                    gas: Some(21_000),
                    ..Default::default()
                },
                ..Default::default()
            };

            assert!(matches!(
                filler.status(&request),
                FillerControlFlow::Finished
            ));
        }
    }

    #[test]
    fn waits_for_the_endpoint_chain_and_sender_before_aa_estimation() {
        let filler = TempoGasFiller::default();
        let mut request = TempoTransactionRequest {
            key_type: Some(SignatureType::Secp256k1),
            ..Default::default()
        };

        assert!(matches!(
            filler.status(&request),
            FillerControlFlow::Missing(_)
        ));

        request.set_chain_id(4217);
        assert!(matches!(
            filler.status(&request),
            FillerControlFlow::Missing(_)
        ));

        request.set_from(Address::repeat_byte(0x11));
        assert!(matches!(filler.status(&request), FillerControlFlow::Ready));
    }

    #[test]
    fn strips_only_the_sponsor_marker_before_estimation() {
        let mut request = TempoTransactionRequest {
            fee_payer_signature: Some(FEE_PAYER_SIGNATURE_MARKER),
            ..Default::default()
        };

        let estimate_request = request_for_gas_estimation(&request);
        assert!(estimate_request.fee_payer_signature.is_none());
        assert_eq!(
            request.fee_payer_signature,
            Some(FEE_PAYER_SIGNATURE_MARKER)
        );

        let signature = Signature::test_signature();
        request.fee_payer_signature = Some(signature);
        assert_eq!(
            request_for_gas_estimation(&request).fee_payer_signature,
            Some(signature)
        );
    }

    #[tokio::test]
    async fn accepts_legacy_gas_price_without_an_rpc() {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Default::default());
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                gas_price: Some(1),
                gas: Some(21_000),
                ..Default::default()
            },
            ..Default::default()
        };

        TempoGasFiller::default()
            .prepare(&provider, &request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_aa_gas_price_without_an_rpc() {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Default::default());
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                gas_price: Some(1),
                ..Default::default()
            },
            key_type: Some(SignatureType::Secp256k1),
            ..Default::default()
        };

        let error = TempoGasFiller::default()
            .prepare(&provider, &request)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("require EIP-1559 fees"));
    }

    #[tokio::test]
    async fn preserves_root_provisioning_authorization_without_an_rpc() {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Default::default());
        let account = Address::repeat_byte(0x11);
        let authorization = KeyAuthorization::unrestricted(
            4217,
            SignatureType::Secp256k1,
            Address::repeat_byte(0x22),
        )
        .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                chain_id: Some(4217),
                ..Default::default()
            },
            key_authorization: Some(authorization.clone()),
            ..Default::default()
        };

        let resolved = resolve_key_authorization(&provider, &request)
            .await
            .unwrap();

        assert_eq!(resolved, Some(Some(authorization)));
    }

    #[tokio::test]
    async fn preserves_cross_key_provisioning_authorization_without_an_rpc() {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Default::default());
        let account = Address::repeat_byte(0x11);
        let authorization = KeyAuthorization::unrestricted(
            4217,
            SignatureType::Secp256k1,
            Address::repeat_byte(0x22),
        )
        .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                chain_id: Some(4217),
                ..Default::default()
            },
            key_id: Some(Address::repeat_byte(0x33)),
            key_authorization: Some(authorization.clone()),
            ..Default::default()
        };

        let resolved = resolve_key_authorization(&provider, &request)
            .await
            .unwrap();

        assert_eq!(resolved, Some(Some(authorization)));
    }

    #[tokio::test]
    async fn preserves_keychain_transport_errors_and_localizes_decode_errors() {
        let account = Address::repeat_byte(0x11);
        let key_id = Address::repeat_byte(0x22);
        let authorization = KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, key_id)
            .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                chain_id: Some(4217),
                ..Default::default()
            },
            key_type: Some(SignatureType::Secp256k1),
            key_id: Some(key_id),
            key_authorization: Some(authorization),
            ..Default::default()
        };

        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Asserter::new());
        let error = resolve_key_authorization(&provider, &request)
            .await
            .unwrap_err();
        assert!(error.is_transport_error());

        let asserter = Asserter::new();
        asserter.push_failure_msg("keychain unavailable");
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter);
        let error = resolve_key_authorization(&provider, &request)
            .await
            .unwrap_err();
        assert!(error.is_error_resp());
        assert!(error.to_string().contains("keychain unavailable"));

        let asserter = Asserter::new();
        asserter.push_success(&Bytes::new());
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter);
        let error = resolve_key_authorization(&provider, &request)
            .await
            .unwrap_err();
        assert!(error.is_local_usage_error());
    }
}
