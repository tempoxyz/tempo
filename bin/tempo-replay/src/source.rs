//! Typed Tempo RPC access and certificate-authenticated finalized block retrieval.

use crate::state::BlockCursor;
use alloy::{
    consensus::{
        BlockHeader, Transaction,
        transaction::{SignerRecoverable, TxHashRef},
    },
    eips::eip2718::Encodable2718,
    primitives::{Address, B256, U256},
    providers::{Provider, RootProvider, builder},
};
use anyhow::{Context, Result, ensure};
use reth_primitives_traits::SealedHeader;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::chainspec_from_chain_id;
use tempo_consensus::finalized_header_stream::{Config, FinalizedHeaderStream};
use tempo_primitives::{TempoHeader, TempoTxEnvelope};

/// Typed Alloy provider for Tempo RPC responses.
pub type TempoProvider = RootProvider<TempoNetwork>;

/// Typed full block matched to a certificate-authenticated finalized header.
#[derive(Clone, Debug)]
pub struct FinalizedBlock {
    pub cursor: BlockCursor,
    pub timestamp_ms: u64,
    pub transactions: Vec<TempoTxEnvelope>,
}

/// Shared classification and fields used by mirror, audit, and profile.
#[derive(Clone, Copy, Debug)]
pub enum TxMetadata {
    System,
    Subblock(ReplayMetadata),
    Replayable(ReplayMetadata),
}

impl TxMetadata {
    pub fn from_envelope(transaction: &TempoTxEnvelope) -> Result<Self> {
        if transaction.is_system_tx() {
            return Ok(Self::System);
        }
        let metadata = ReplayMetadata::from_envelope(transaction)?;
        if transaction.has_sub_block_nonce_key_prefix() {
            Ok(Self::Subblock(metadata))
        } else {
            Ok(Self::Replayable(metadata))
        }
    }
}

/// Shared fields for a non-system transaction.
#[derive(Clone, Copy, Debug)]
pub struct ReplayMetadata {
    pub hash: B256,
    pub transaction_type: u8,
    pub sender: Address,
    pub nonce: u64,
    pub nonce_key: U256,
    pub expiring: bool,
    pub encoded_length: u64,
    pub gas_limit: u64,
    pub valid_before: Option<u64>,
}

impl ReplayMetadata {
    fn from_envelope(transaction: &TempoTxEnvelope) -> Result<Self> {
        Ok(Self {
            hash: *transaction.tx_hash(),
            transaction_type: transaction.tx_type() as u8,
            sender: transaction
                .recover_signer()
                .context("recover source transaction signer")?,
            nonce: transaction.nonce(),
            nonce_key: transaction.nonce_key().unwrap_or_default(),
            expiring: transaction.is_expiring_nonce(),
            encoded_length: transaction.encode_2718_len() as u64,
            gas_limit: transaction.gas_limit(),
            valid_before: transaction.valid_before(),
        })
    }
}

pub fn connect(
    url: &str,
    bearer_token: Option<&str>,
    ca_pem: Option<&[u8]>,
) -> Result<TempoProvider> {
    let url = url.parse().context("invalid RPC URL")?;
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = bearer_token {
        ensure!(!token.is_empty(), "RPC bearer token is empty");
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid RPC bearer token")?;
        value.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    let mut client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers);
    if let Some(pem) = ca_pem {
        client = client.add_root_certificate(
            reqwest::Certificate::from_pem(pem).context("invalid RPC CA certificate")?,
        );
    }
    Ok(builder::<TempoNetwork>().connect_reqwest(client.build()?, url))
}

pub async fn chain_id(provider: &TempoProvider) -> Result<u64> {
    provider.get_chain_id().await.context("fetch chain id")
}

pub async fn block_hash(provider: &TempoProvider, number: u64) -> Result<B256> {
    Ok(provider
        .get_block_by_number(number.into())
        .await
        .context("fetch checkpoint block")?
        .with_context(|| format!("block {number} is unavailable"))?
        .header
        .hash)
}

pub async fn finalized_stream(
    provider: TempoProvider,
    chain_id: u64,
    start_after: B256,
) -> Result<FinalizedHeaderStream> {
    let chainspec = chainspec_from_chain_id(chain_id)
        .with_context(|| format!("unsupported Tempo chain id {chain_id}"))?;
    let epoch_length = chainspec
        .info
        .epoch_length()
        .context("Tempo chainspec has no consensus epoch length")?;
    FinalizedHeaderStream::init(
        provider,
        Config::new(
            start_after,
            chainspec.network_identity.clone(),
            epoch_length,
        ),
    )
    .await
    .context("initialize authenticated finalized stream")
}

pub async fn fetch_finalized_block(
    provider: &TempoProvider,
    header: &SealedHeader<TempoHeader>,
) -> Result<FinalizedBlock> {
    let number = header.number();
    let block = provider
        .get_block_by_number(number.into())
        .full()
        .await
        .context("fetch full finalized block")?
        .with_context(|| format!("finalized block {number} is unavailable"))?;
    ensure!(
        block.header.hash == header.hash(),
        "RPC block hash disagrees with authenticated finalized header at {number}"
    );
    ensure!(
        block.header.inner.inner == **header,
        "RPC block header disagrees with authenticated finalized header at {number}"
    );
    Ok(FinalizedBlock {
        cursor: BlockCursor {
            height: number,
            hash: header.hash(),
        },
        timestamp_ms: block.header.timestamp_millis,
        transactions: block
            .transactions
            .into_transactions()
            .map(|transaction| transaction.into_inner())
            .collect(),
    })
}

pub fn replayable(transaction: &TempoTxEnvelope) -> bool {
    !transaction.is_system_tx() && !transaction.has_sub_block_nonce_key_prefix()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        consensus::{SignableTransaction, TxLegacy},
        eips::eip2718::Encodable2718,
        primitives::{Signature, U256},
    };
    use tempo_primitives::{TempoSignature, TempoTransaction, transaction::PrimitiveSignature};

    #[test]
    fn replay_filter_uses_native_system_and_subblock_classification() {
        let system = TempoTxEnvelope::Legacy(TxLegacy::default().into_signed(Signature::new(
            U256::ZERO,
            U256::ZERO,
            false,
        )));
        assert!(!replayable(&system));

        let regular = TempoTxEnvelope::Legacy(TxLegacy::default().into_signed(Signature::new(
            U256::from(1),
            U256::from(2),
            false,
        )));
        let encoded = regular.encoded_2718();
        assert!(replayable(&regular));
        assert_eq!(regular.encoded_2718(), encoded);

        let nonce_key = U256::from_be_bytes::<32>({
            let mut key = [0; 32];
            key[0] = 0x5b;
            key
        });
        let subblock = TempoTxEnvelope::AA(
            TempoTransaction {
                nonce_key,
                ..Default::default()
            }
            .into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                Signature::new(U256::from(1), U256::from(2), false),
            ))),
        );
        assert!(!replayable(&subblock));
    }
}
