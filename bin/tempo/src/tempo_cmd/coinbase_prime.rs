use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::eip2718::Encodable2718,
};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
use alloy_provider::{Provider, ProviderBuilder};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use eyre::{WrapErr as _, bail};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tempo_alloy::TempoNetwork;

const API_ORIGIN: &str = "https://api.prime.coinbase.com";

#[derive(Debug)]
struct Credentials {
    access_key: String,
    passphrase: String,
    signing_key: String,
    portfolio_id: String,
    wallet_id: String,
}

impl Credentials {
    fn from_env() -> eyre::Result<Self> {
        Ok(Self {
            access_key: super::get_env("COINBASE_PRIME_ACCESS_KEY")?,
            passphrase: super::get_env("COINBASE_PRIME_PASSPHRASE")?,
            signing_key: super::get_env("COINBASE_PRIME_SIGNING_KEY")?,
            portfolio_id: super::get_env("COINBASE_PRIME_PORTFOLIO_ID")?,
            wallet_id: super::get_env("COINBASE_PRIME_WALLET_ID")?,
        })
    }
}

#[derive(Debug, Serialize)]
struct CreateTransactionRequest<'a> {
    raw_unsigned_txn: String,
    rpc: RpcParams<'a>,
    evm_params: EvmParams,
}

#[derive(Debug, Serialize)]
struct RpcParams<'a> {
    skip_broadcast: bool,
    url: &'a str,
}

#[derive(Debug, Serialize)]
struct EvmParams {
    disable_dynamic_gas: bool,
    disable_dynamic_nonce: bool,
    chain_id: String,
}

#[derive(Debug, Deserialize)]
struct CreateTransactionResponse {
    transaction_id: String,
}

pub(super) async fn submit_transaction(
    rpc_url: &str,
    to: Address,
    input: Bytes,
) -> eyre::Result<String> {
    let credentials = Credentials::from_env()?;
    validate_path_segment("portfolio ID", &credentials.portfolio_id)?;
    validate_path_segment("wallet ID", &credentials.wallet_id)?;

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(rpc_url)
        .await
        .wrap_err("failed to connect to RPC")?;
    let chain_id = provider
        .get_chain_id()
        .await
        .wrap_err("failed to get chain id")?;

    // Prime fills the nonce and gas fields when the corresponding dynamic options are enabled.
    // It expects an EIP-2718 transaction with empty signature fields, not a signing payload.
    let unsigned = TxEip1559 {
        chain_id,
        nonce: 0,
        gas_limit: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(to),
        value: U256::ZERO,
        access_list: Default::default(),
        input,
    }
    .into_signed(Signature::new(U256::ZERO, U256::ZERO, false))
    .encoded_2718();

    let payload = CreateTransactionRequest {
        raw_unsigned_txn: alloy_primitives::hex::encode(unsigned),
        rpc: RpcParams {
            skip_broadcast: false,
            url: rpc_url,
        },
        evm_params: EvmParams {
            disable_dynamic_gas: false,
            disable_dynamic_nonce: false,
            chain_id: chain_id.to_string(),
        },
    };

    let body = serde_json::to_string(&payload)?;
    let path = format!(
        "/v1/portfolios/{}/wallets/{}/onchain_transaction",
        credentials.portfolio_id, credentials.wallet_id
    );

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before the Unix epoch")?
        .as_secs()
        .to_string();

    let signature = sign_request(&credentials.signing_key, &timestamp, &path, &body)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .wrap_err("failed building Coinbase Prime HTTP client")?;

    let response = client
        .post(format!("{API_ORIGIN}{path}"))
        .header("Content-Type", "application/json")
        .header("X-CB-ACCESS-KEY", credentials.access_key)
        .header("X-CB-ACCESS-PASSPHRASE", credentials.passphrase)
        .header("X-CB-ACCESS-SIGNATURE", signature)
        .header("X-CB-ACCESS-TIMESTAMP", timestamp)
        .body(body)
        .send()
        .await
        .wrap_err("Coinbase Prime request failed")?;

    let status = response.status();
    let response_body = response
        .text()
        .await
        .wrap_err("failed reading Coinbase Prime response")?;

    if !status.is_success() {
        bail!("Coinbase Prime returned {status}: {response_body}");
    }

    let response: CreateTransactionResponse =
        serde_json::from_str(&response_body).wrap_err("failed parsing Coinbase Prime response")?;

    Ok(response.transaction_id)
}

fn validate_path_segment(name: &str, value: &str) -> eyre::Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("Coinbase Prime {name} contains invalid characters");
    }
    Ok(())
}

fn sign_request(
    signing_key: &str,
    timestamp: &str,
    path: &str,
    body: &str,
) -> eyre::Result<String> {
    let message = format!("{timestamp}POST{path}{body}");
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes())
        .map_err(|error| eyre::eyre!("invalid Coinbase Prime signing key: {error}"))?;
    mac.update(message.as_bytes());
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_signature_matches_known_hmac() {
        let signature = sign_request(
            "secret",
            "1700000000",
            "/v1/portfolios/portfolio/wallets/wallet/onchain_transaction",
            r#"{"raw_unsigned_txn":"02c0"}"#,
        )
        .unwrap();

        assert_eq!(signature, "QFumTYjKzpNUnVAIj1qOCKm6/ZtJky0DBL8tL8T7gKA=");
    }

    #[test]
    fn rejects_path_delimiters_in_ids() {
        assert!(validate_path_segment("wallet ID", "wallet-id").is_ok());
        assert!(validate_path_segment("wallet ID", "../wallet").is_err());
        assert!(validate_path_segment("wallet ID", "wallet?id=other").is_err());
    }
}
