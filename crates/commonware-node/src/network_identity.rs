use alloy_primitives::FixedBytes;
use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};
use eyre::Context;
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
pub(crate) struct NetworkIdentity(pub <MinSig as Variant>::Public);

impl NetworkIdentity {
    pub(crate) fn public_key(&self) -> <MinSig as Variant>::Public {
        return self.0;
    }
}

impl FromStr for NetworkIdentity {
    type Err = Box<dyn std::error::Error + Send + Sync + 'static>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.parse::<FixedBytes<96>>()?;

        let mut bytes = bytes.as_slice();
        let key = <MinSig as Variant>::Public::read(&mut bytes)
            .wrap_err("must be a valid BLS public key")?;

        Ok(Self(key))
    }
}
