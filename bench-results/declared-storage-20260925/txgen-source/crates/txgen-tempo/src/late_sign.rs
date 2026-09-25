//! Deferred signing for Tempo expiring-nonce transactions.

use alloy_consensus::SignableTransaction;
use alloy_eips::eip2718::Encodable2718;
use alloy_network::{NetworkTransactionBuilder, TxSignerSync};
use alloy_primitives::Bytes;
use alloy_signer::SignerSync;
use eyre::{bail, Result, WrapErr};
use serde::{Deserialize, Serialize};
use std::{
    num::NonZeroU64,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_primitives::{transaction::TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS, TempoTxEnvelope};
use txgen_core::{AccountManager, LateSignSpec, WorkloadSpec};

/// Discriminator for relative Tempo expiring-nonce signing.
pub const FORMAT_TEMPO_EXPIRING_RELATIVE: &str = "tempo_expiring_relative";

/// Stable reference to an account in a workload account pool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerLocator {
    /// Account pool name.
    pub pool: String,
    /// Index within the pool.
    pub index: usize,
}

/// Payload for a Tempo transaction whose `valid_before` is assigned at send time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoExpiringPayload {
    /// Sender account.
    pub signer: SignerLocator,
    /// Optional fee payer account.
    #[serde(default)]
    pub sponsor: Option<SignerLocator>,
    /// Relative validity window in seconds.
    pub valid_for_secs: u64,
    /// Fully resolved request, excluding the final validity timestamp and signatures.
    pub request: TempoTransactionRequest,
}

impl TempoExpiringPayload {
    /// Wrap this payload for transport through the generic output format.
    pub fn into_spec(self) -> Result<LateSignSpec> {
        Ok(LateSignSpec {
            format: FORMAT_TEMPO_EXPIRING_RELATIVE.to_string(),
            payload: serde_json::to_value(self)?,
        })
    }

    /// Decode a Tempo payload from the generic envelope.
    pub fn from_spec(spec: &LateSignSpec) -> Result<Self> {
        if spec.format != FORMAT_TEMPO_EXPIRING_RELATIVE {
            bail!(
                "expected late-sign format `{FORMAT_TEMPO_EXPIRING_RELATIVE}`, got `{}`",
                spec.format
            );
        }
        Ok(serde_json::from_value(spec.payload.clone())?)
    }
}

/// Signer used by bench for deferred Tempo transactions.
pub struct TempoLateSigner {
    accounts: Arc<AccountManager>,
}

impl TempoLateSigner {
    /// Build a signer from a loaded workload specification.
    pub fn from_spec(spec: &WorkloadSpec) -> Result<Self> {
        Ok(Self { accounts: Arc::new(AccountManager::from_spec(&spec.accounts)?) })
    }

    /// Build a signer from a workload YAML file.
    pub fn from_workload_file(path: &Path) -> Result<Self> {
        let spec = WorkloadSpec::load(path)
            .wrap_err_with(|| format!("failed to load workload spec: {}", path.display()))?;
        Self::from_spec(&spec)
    }
}

impl bench_core::LateSigner for TempoLateSigner {
    fn sign(&self, spec: &LateSignSpec) -> Result<Bytes> {
        sign_tempo_expiring(&TempoExpiringPayload::from_spec(spec)?, &self.accounts)
    }
}

/// Materialize and sign a Tempo expiring-nonce transaction.
pub fn sign_tempo_expiring(
    payload: &TempoExpiringPayload,
    accounts: &AccountManager,
) -> Result<Bytes> {
    if payload.valid_for_secs == 0 || payload.valid_for_secs > TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS
    {
        bail!(
            "Tempo expiring transactions require `valid_for_secs` in the range 1..={TEMPO_EXPIRING_NONCE_MAX_EXPIRY_SECS}"
        );
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before the Unix epoch")?
        .as_secs();
    let valid_before = now
        .checked_add(payload.valid_for_secs)
        .ok_or_else(|| eyre::eyre!("Tempo expiring `valid_before` overflowed Unix time"))?;
    let valid_before = NonZeroU64::new(valid_before)
        .ok_or_else(|| eyre::eyre!("Tempo expiring `valid_before` must be greater than zero"))?;

    let mut request = payload.request.clone();
    request.set_valid_before(valid_before);

    let signer = accounts.get_by_index(&payload.signer.pool, payload.signer.index)?;
    let sender = signer.address();
    if let Some(sponsor) = &payload.sponsor {
        let transaction = request
            .clone()
            .build_aa()
            .map_err(|error| eyre::eyre!("failed to build Tempo tx for sponsorship: {error}"))?;
        let sponsor = accounts.get_by_index(&sponsor.pool, sponsor.index)?;
        request.set_fee_payer_signature(
            sponsor.sign_hash_sync(&transaction.fee_payer_signature_hash(sender))?,
        );
    }

    let mut unsigned = request
        .build_unsigned()
        .map_err(|error| eyre::eyre!("failed to build Tempo unsigned tx: {error}"))?;
    let signature = signer
        .sign_transaction_sync(&mut unsigned)
        .map_err(|error| eyre::eyre!("failed to sign Tempo tx: {error}"))?;
    let envelope = TempoTxEnvelope::from(unsigned.into_signed(signature));
    Ok(Bytes::from(envelope.encoded_2718()))
}
