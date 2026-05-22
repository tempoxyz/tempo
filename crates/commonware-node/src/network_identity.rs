use alloy_primitives::{FixedBytes, hex};
use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub(crate) struct NetworkIdentity(pub <MinSig as Variant>::Public);

impl NetworkIdentity {
    pub(crate) fn public_key(&self) -> <MinSig as Variant>::Public {
        self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseNetworkIdentityError {
    #[error("invalid hex string: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("must be a valid BLS public key: {0}")]
    InvalidPublicKey(#[from] commonware_codec::Error),
}

impl FromStr for NetworkIdentity {
    type Err = ParseNetworkIdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.parse::<FixedBytes<96>>()?;

        let mut bytes = bytes.as_slice();
        let key = <MinSig as Variant>::Public::read(&mut bytes)?;

        Ok(Self(key))
    }
}
