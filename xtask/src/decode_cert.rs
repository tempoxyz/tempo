//! Decode a hex-encoded consensus certificate and print its JSON representation to stdout.
//!
//! Certificates are assumed to be encoded via [`commonware_codec::Encode`] and hex-encoded. This tool decodes
//! them back into structured JSON for inspection.

use alloy_primitives::B256;
use commonware_codec::{DecodeExt as _, Encode as _, FixedSize, Read, ReadExt as _, Write};
use commonware_consensus::simplex::{
    scheme::bls12381_threshold::vrf::Scheme,
    types::Finalization,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_utils::{Array, Span};
use eyre::Context;
use serde::Serialize;

/// Minimal re-implementation of `tempo-commonware-node`'s `Digest` to avoid pulling in the full
/// crate. A 32-byte wrapper around [`B256`] implementing the commonware codec + crypto traits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
struct Digest(B256);

impl Array for Digest {}
impl Span for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::ops::Deref for Digest {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl commonware_math::algebra::Random for Digest {
    fn random(mut rng: impl rand_core::CryptoRngCore) -> Self {
        let mut array = B256::ZERO;
        rng.fill_bytes(&mut *array);
        Self(array)
    }
}

impl commonware_cryptography::Digest for Digest {
    const EMPTY: Self = Self(B256::ZERO);
}

impl FixedSize for Digest {
    const SIZE: usize = 32;
}

impl Read for Digest {
    type Cfg = ();
    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let array = <[u8; 32]>::read(buf)?;
        Ok(Self(B256::new(array)))
    }
}

impl Write for Digest {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf)
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct DecodeCert {
    /// Hex-encoded certificate bytes (with or without 0x prefix).
    hex: String,
}

/// JSON-serializable representation of the proposal inside a certificate.
#[derive(Serialize)]
struct ProposalJson {
    epoch: u64,
    view: u64,
    parent_view: u64,
    payload: String,
}

/// JSON-serializable representation of a decoded certificate.
#[derive(Serialize)]
struct CertJson {
    proposal: ProposalJson,
    recovered_certificate: String,
}

impl DecodeCert {
    pub(crate) async fn run(self) -> eyre::Result<()> {
        let bytes = const_hex::decode(&self.hex).wrap_err("invalid hex input")?;

        let f = Finalization::<Scheme<PublicKey, MinSig>, Digest>::decode(&bytes[..])
            .wrap_err("failed to decode certificate")?;

        let json = CertJson {
            proposal: ProposalJson {
                epoch: f.proposal.round.epoch().get(),
                view: f.proposal.round.view().get(),
                parent_view: f.proposal.parent.get(),
                payload: const_hex::encode_prefixed(f.proposal.payload.0),
            },
            recovered_certificate: const_hex::encode_prefixed(f.certificate.encode()),
        };

        println!(
            "{}",
            serde_json::to_string_pretty(&json).wrap_err("failed to encode certificate as json")?
        );

        Ok(())
    }
}
