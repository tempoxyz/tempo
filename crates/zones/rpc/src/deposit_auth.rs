//! TIP-1151 deposit authorizer behind `zone_authorizeDeposit`.
//!
//! The authorizer applies the operator's deposit policy and, if it approves, signs the portal's
//! EIP-712 `DepositAuthorization` digest for the exact deposit arguments. Whether to sign is not
//! consensus: the portal only checks that the signer holds `DepositAuthorizer`.

use std::time::Duration;

use alloy_primitives::{Address, U64};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde::{Deserialize, Serialize};
use tempo_contracts::zones::eip712::DepositAuthorization;
use tracing::warn;
use url::Url;

use crate::{
    auth::now_unix_seconds,
    types::{AuthorizeDepositRequest, DepositAuthorizationResponse, JsonRpcError, internal},
};

/// Longest authorization lifetime the portal accepts (`MAX_DEPOSIT_AUTHORIZATION_TTL`).
pub const MAX_DEPOSIT_AUTHORIZATION_TTL: Duration = Duration::from_secs(3600);

/// Default lifetime of issued authorizations.
pub const DEFAULT_DEPOSIT_AUTHORIZATION_TTL: Duration = Duration::from_secs(120);

/// How long the authorizer waits for the operator policy webhook.
const POLICY_TIMEOUT: Duration = Duration::from_secs(5);

/// Deposit authorizer settings.
#[derive(Debug, Clone)]
pub struct DepositAuthorizerConfig {
    /// Key registered as `DepositAuthorizer` on the portal.
    pub signer: PrivateKeySigner,
    /// Lifetime of issued authorizations. Must be in `1..=MAX_DEPOSIT_AUTHORIZATION_TTL`.
    pub ttl: Duration,
    /// Operator policy webhook. Every authenticated depositor is approved when unset.
    ///
    /// The authorizer POSTs a [`PolicyRequest`] and signs only after a 2xx response with body
    /// `{"approved": true}`. Any other response refuses the deposit.
    pub policy_url: Option<Url>,
}

/// Body POSTed to the operator policy webhook.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRequest<'a> {
    /// Zone the deposit targets.
    pub zone_id: u32,
    /// Authenticated account that will call `depositAuthorized`.
    pub depositor: Address,
    /// Deposit arguments and operator-defined credentials from the caller.
    #[serde(flatten)]
    pub request: &'a AuthorizeDepositRequest,
}

#[derive(Debug, Deserialize)]
struct PolicyResponse {
    approved: bool,
}

/// Signs TIP-1151 deposit authorizations for one portal.
#[derive(Debug)]
pub struct DepositAuthorizer {
    config: DepositAuthorizerConfig,
    client: reqwest::Client,
    zone_id: u32,
    tempo_chain_id: u64,
    portal: Address,
}

impl DepositAuthorizer {
    /// Creates an authorizer for the portal at `portal` on Tempo chain `tempo_chain_id`.
    pub fn new(
        config: DepositAuthorizerConfig,
        zone_id: u32,
        tempo_chain_id: u64,
        portal: Address,
    ) -> eyre::Result<Self> {
        eyre::ensure!(
            !config.ttl.is_zero() && config.ttl <= MAX_DEPOSIT_AUTHORIZATION_TTL,
            "deposit authorization TTL must be between 1 and {} seconds",
            MAX_DEPOSIT_AUTHORIZATION_TTL.as_secs()
        );
        let client = reqwest::Client::builder().timeout(POLICY_TIMEOUT).build()?;
        Ok(Self {
            config,
            client,
            zone_id,
            tempo_chain_id,
            portal,
        })
    }

    /// Address that must hold `DepositAuthorizer` on the portal.
    pub fn address(&self) -> Address {
        self.config.signer.address()
    }

    /// Applies the operator policy and signs an authorization for `depositor`.
    ///
    /// `nonce` is the depositor's current `depositAuthorizationNonce` on the portal.
    pub async fn authorize(
        &self,
        depositor: Address,
        request: &AuthorizeDepositRequest,
        nonce: u64,
    ) -> Result<DepositAuthorizationResponse, JsonRpcError> {
        self.check_policy(depositor, request).await?;

        let valid_before = now_unix_seconds() + self.config.ttl.as_secs();
        let digest = DepositAuthorization {
            depositor,
            token: request.token,
            amount: request.amount.to(),
            keyIndex: request.key_index,
            payloadHash: request.encrypted.authorization_hash(),
            tempoRefundRecipient: request.tempo_refund_recipient,
            nonce,
            validBefore: valid_before,
        }
        .signing_hash(self.tempo_chain_id, self.portal);
        let signature = self
            .config
            .signer
            .sign_hash_sync(&digest)
            .map_err(internal)?;

        Ok(DepositAuthorizationResponse {
            authorizer: self.address(),
            nonce: U64::from(nonce),
            valid_before: U64::from(valid_before),
            signature: signature.as_bytes().into(),
        })
    }

    async fn check_policy(
        &self,
        depositor: Address,
        request: &AuthorizeDepositRequest,
    ) -> Result<(), JsonRpcError> {
        let Some(url) = &self.config.policy_url else {
            return Ok(());
        };
        let response = self
            .client
            .post(url.clone())
            .json(&PolicyRequest {
                zone_id: self.zone_id,
                depositor,
                request,
            })
            .send()
            .await
            .map_err(|err| {
                warn!(target: "zone::rpc", %err, "deposit policy webhook unavailable");
                JsonRpcError::internal("deposit policy unavailable")
            })?;
        if !response.status().is_success() {
            return Err(JsonRpcError::deposit_not_authorized());
        }
        match response.json::<PolicyResponse>().await {
            Ok(PolicyResponse { approved: true }) => Ok(()),
            _ => Err(JsonRpcError::deposit_not_authorized()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{B256, Bytes, Signature, U128, U256};
    use axum::{Json, Router, http::StatusCode, routing::post};
    use parking_lot::Mutex;
    use serde_json::{Value, json};
    use tempo_contracts::zones::DepositPayload;

    use super::*;

    const TEMPO_CHAIN_ID: u64 = 42431;

    fn request() -> AuthorizeDepositRequest {
        AuthorizeDepositRequest {
            token: Address::repeat_byte(0x33),
            amount: U128::from(1_000_000),
            key_index: U256::from(2),
            encrypted: DepositPayload {
                ephemeralPubkeyX: B256::repeat_byte(0x44),
                ephemeralPubkeyYParity: 3,
                ciphertext: Bytes::from(vec![0xaa; 64]),
                nonce: [0x55; 12].into(),
                tag: [0x66; 16].into(),
            },
            tempo_refund_recipient: Address::repeat_byte(0x77),
            credentials: Some(json!({ "idToken": "header.payload.signature" })),
        }
    }

    fn authorizer(policy_url: Option<Url>) -> DepositAuthorizer {
        DepositAuthorizer::new(
            DepositAuthorizerConfig {
                signer: PrivateKeySigner::random(),
                ttl: Duration::from_secs(90),
                policy_url,
            },
            7,
            TEMPO_CHAIN_ID,
            Address::repeat_byte(0x11),
        )
        .unwrap()
    }

    /// Serves `status` and `body` from a local webhook and records every request body.
    async fn webhook(status: StatusCode, body: Value) -> (Url, Arc<Mutex<Vec<Value>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let app = Router::new().route(
            "/policy",
            post(move |Json(request): Json<Value>| {
                recorded.lock().push(request);
                let body = body.clone();
                async move { (status, Json(body)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/policy").parse().unwrap(), seen)
    }

    #[tokio::test]
    async fn signs_the_portal_digest_for_the_exact_deposit() {
        let authorizer = authorizer(None);
        let depositor = Address::repeat_byte(0x22);
        let request = request();

        let before = now_unix_seconds();
        let response = authorizer.authorize(depositor, &request, 5).await.unwrap();
        let after = now_unix_seconds();

        assert_eq!(response.authorizer, authorizer.address());
        assert_eq!(response.nonce, U64::from(5));
        let valid_before = response.valid_before.to::<u64>();
        assert!((before + 90..=after + 90).contains(&valid_before));

        let digest = DepositAuthorization {
            depositor,
            token: request.token,
            amount: 1_000_000,
            keyIndex: U256::from(2),
            payloadHash: request.encrypted.authorization_hash(),
            tempoRefundRecipient: request.tempo_refund_recipient,
            nonce: 5,
            validBefore: valid_before,
        }
        .signing_hash(TEMPO_CHAIN_ID, Address::repeat_byte(0x11));
        let signature = Signature::from_raw(&response.signature).unwrap();
        assert_eq!(response.signature.len(), 65);
        assert_eq!(
            signature.recover_address_from_prehash(&digest).unwrap(),
            authorizer.address()
        );
    }

    #[tokio::test]
    async fn webhook_approval_gates_signing_and_receives_credentials() {
        let depositor = Address::repeat_byte(0x22);

        let (url, seen) = webhook(StatusCode::OK, json!({ "approved": true })).await;
        authorizer(Some(url))
            .authorize(depositor, &request(), 0)
            .await
            .expect("approved deposit is signed");
        let body = seen.lock().pop().unwrap();
        assert_eq!(body["zoneId"], 7);
        assert_eq!(body["depositor"], json!(depositor));
        assert_eq!(body["amount"], "0xf4240");
        assert_eq!(body["credentials"]["idToken"], "header.payload.signature");

        for (status, body) in [
            (StatusCode::OK, json!({ "approved": false })),
            (StatusCode::OK, json!({})),
            (StatusCode::FORBIDDEN, json!({ "approved": true })),
        ] {
            let (url, _) = webhook(status, body.clone()).await;
            let err = authorizer(Some(url))
                .authorize(depositor, &request(), 0)
                .await
                .expect_err("refused deposit is not signed");
            assert_eq!(err.code, -32007, "{status} {body}");
        }
    }

    #[tokio::test]
    async fn unreachable_webhook_fails_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/policy", listener.local_addr().unwrap());
        drop(listener);

        let err = authorizer(Some(url.parse().unwrap()))
            .authorize(Address::repeat_byte(0x22), &request(), 0)
            .await
            .expect_err("unavailable policy is not an approval");
        assert_eq!(err.code, -32603);
    }

    #[test]
    fn rejects_ttl_outside_portal_bound() {
        for ttl in [
            Duration::ZERO,
            MAX_DEPOSIT_AUTHORIZATION_TTL + Duration::from_secs(1),
        ] {
            let config = DepositAuthorizerConfig {
                signer: PrivateKeySigner::random(),
                ttl,
                policy_url: None,
            };
            assert!(DepositAuthorizer::new(config, 7, TEMPO_CHAIN_ID, Address::ZERO).is_err());
        }
    }
}
