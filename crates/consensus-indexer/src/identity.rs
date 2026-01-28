use alloy_primitives::{B256, hex};
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::{
        ops::verify_message,
        variant::{MinSig, Variant},
    },
    ed25519::PublicKey,
};
use eyre::WrapErr;
use jsonrpsee::http_client::HttpClient;
use std::{error::Error as StdError, fmt};
use tempo_commonware_node::consensus::Digest;
use tempo_node::rpc::consensus::{CertifiedBlock, IdentityTransition, TempoConsensusApiClient};

use crate::db::ConsensusDb;

pub async fn refresh_identity_transitions(
    db: &ConsensusDb,
    client: &HttpClient,
) -> eyre::Result<()> {
    let response = client
        .get_identity_transition_proof(None, Some(true))
        .await?;
    for transition in &response.transitions {
        db.upsert_identity_transition(transition).await?;
    }
    Ok(())
}

pub fn derive_identity(start_epoch: u64, transitions: &[IdentityTransition]) -> String {
    if start_epoch == 0 {
        transitions
            .last()
            .map(|t| t.old_identity.clone())
            .unwrap_or_default()
    } else {
        transitions
            .first()
            .map(|t| t.new_identity.clone())
            .unwrap_or_default()
    }
}

pub fn verify_finalization(
    block: &CertifiedBlock,
    identity_hex: &str,
) -> Result<(), VerificationError> {
    let identity_bytes =
        hex::decode(identity_hex).map_err(|err| VerificationError::new(block, err))?;
    let pubkey = <MinSig as Variant>::Public::read(&mut identity_bytes.as_slice())
        .map_err(|err| VerificationError::new(block, err))?;
    let finalization = decode_finalization(&block.certificate)
        .map_err(|err| VerificationError::new(block, err))?;
    let message = finalization.proposal.encode();
    verify_message::<MinSig>(
        &pubkey,
        b"TEMPO_FINALIZE",
        &message,
        &finalization.certificate.vote_signature,
    )
    .map_err(|err| VerificationError::new(block, err))?;
    Ok(())
}

fn decode_finalization(
    certificate_hex: &str,
) -> eyre::Result<Finalization<Scheme<PublicKey, MinSig>, Digest>> {
    let certificate_bytes = hex::decode(certificate_hex)?;
    let finalization =
        Finalization::<Scheme<PublicKey, MinSig>, Digest>::read(&mut certificate_bytes.as_slice())
            .wrap_err("decode finalization")?;
    Ok(finalization)
}

#[derive(Debug)]
pub struct VerificationError {
    epoch: u64,
    digest: B256,
    source: String,
}

impl VerificationError {
    pub fn new(block: &CertifiedBlock, source: impl fmt::Display) -> Self {
        Self {
            epoch: block.epoch,
            digest: block.digest,
            source: source.to_string(),
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to verify finalization (epoch {}, digest {}): {}",
            self.epoch,
            hex::encode(self.digest.as_slice()),
            self.source
        )
    }
}

impl StdError for VerificationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        None
    }
}
