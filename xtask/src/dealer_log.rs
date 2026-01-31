//! Custom DealerLog decoder that exposes acks and reveals.
//!
//! The upstream `commonware_cryptography::bls12381::dkg::DealerLog` does not expose
//! getters for the acks and reveals. This module provides a custom decoder that
//! re-encodes the original DealerLog and decodes it into our own struct with public access.

use std::num::NonZeroU32;

use bytes::Buf;
use commonware_codec::{Error, RangeCfg, Read, ReadExt};
use commonware_cryptography::{PublicKey, bls12381::primitives::variant::Variant};
use commonware_math::poly::Poly;
use commonware_utils::NZU32;
use serde::Serialize;

/// A player's acknowledgement (signature over the dealer's commitment).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct PlayerAck<P: PublicKey> {
    pub sig: P::Signature,
}

impl<P: PublicKey> Read for PlayerAck<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            sig: ReadExt::read(buf)?,
        })
    }
}

/// A dealer's private message (share) revealed for a misbehaving player.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct DealerPrivMsg {
    pub share_bytes: [u8; 32],
}

impl Read for DealerPrivMsg {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let mut share_bytes = [0u8; 32];
        if buf.remaining() < 32 {
            return Err(Error::Invalid(
                "insufficient buffer for scalar",
                "DealerPrivMsg",
            ));
        }
        buf.copy_to_slice(&mut share_bytes);
        Ok(Self { share_bytes })
    }
}

/// Either an acknowledgement or a reveal from/for a player.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) enum AckOrReveal<P: PublicKey> {
    Ack(PlayerAck<P>),
    Reveal(DealerPrivMsg),
}

impl<P: PublicKey> Read for AckOrReveal<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag: u8 = ReadExt::read(buf)?;
        match tag {
            0 => Ok(Self::Ack(Read::read_cfg(buf, &())?)),
            1 => Ok(Self::Reveal(Read::read_cfg(buf, &())?)),
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// The result of a dealer's DKG round - either a map of acks/reveals or too many reveals.
#[derive(Clone, Debug)]
pub(crate) enum DealerResult<P: PublicKey> {
    Ok { keys: Vec<P>, values: Vec<AckOrReveal<P>> },
    TooManyReveals,
}

impl<P: PublicKey> Read for DealerResult<P> {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag: u8 = ReadExt::read(buf)?;
        match tag {
            0 => {
                // Map encodes keys (as Set) first, then values (as Vec)
                let range_cfg = RangeCfg::from(0..=cfg.get() as usize);
                let keys: Vec<P> = Read::read_cfg(buf, &(range_cfg, ()))?;
                let values: Vec<AckOrReveal<P>> =
                    Read::read_cfg(buf, &(RangeCfg::exact(keys.len()), ()))?;
                Ok(Self::Ok { keys, values })
            }
            1 => Ok(Self::TooManyReveals),
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// The dealer's public message (commitment polynomial).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct DealerPubMsg<V: Variant> {
    pub commitment: Poly<V::Public>,
}

impl<V: Variant> Read for DealerPubMsg<V> {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let range_cfg = RangeCfg::from(NZU32!(1)..=*cfg);
        Ok(Self {
            commitment: Read::read_cfg(buf, &(range_cfg, ()))?,
        })
    }
}

/// A custom DealerLog that exposes acks and reveals.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct InspectableDealerLog<V: Variant, P: PublicKey> {
    pub pub_msg: DealerPubMsg<V>,
    pub results: DealerResult<P>,
}

impl<V: Variant, P: PublicKey> Read for InspectableDealerLog<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            pub_msg: Read::read_cfg(buf, cfg)?,
            results: Read::read_cfg(buf, cfg)?,
        })
    }
}

impl<V: Variant, P: PublicKey> InspectableDealerLog<V, P> {
    /// Decode directly from bytes.
    pub(crate) fn from_bytes(bytes: &[u8], num_players: NonZeroU32) -> Result<Self, Error> {
        Self::read_cfg(&mut &bytes[..], &num_players)
    }

    /// Returns the number of acks in this dealer log.
    pub(crate) fn ack_count(&self) -> usize {
        match &self.results {
            DealerResult::Ok { values, .. } => values
                .iter()
                .filter(|aor| matches!(aor, AckOrReveal::Ack(_)))
                .count(),
            DealerResult::TooManyReveals => 0,
        }
    }

    /// Returns the number of reveals in this dealer log.
    pub(crate) fn reveal_count(&self) -> usize {
        match &self.results {
            DealerResult::Ok { values, .. } => values
                .iter()
                .filter(|aor| matches!(aor, AckOrReveal::Reveal(_)))
                .count(),
            DealerResult::TooManyReveals => 0,
        }
    }

    /// Returns true if this log indicates too many reveals.
    pub(crate) fn has_too_many_reveals(&self) -> bool {
        matches!(&self.results, DealerResult::TooManyReveals)
    }

    /// Returns an iterator over (player, is_ack) pairs.
    pub(crate) fn player_results(&self) -> Vec<PlayerResult<P>> {
        match &self.results {
            DealerResult::Ok { keys, values } => keys
                .iter()
                .zip(values.iter())
                .map(|(player, aor)| {
                    let result_type = match aor {
                        AckOrReveal::Ack(_) => PlayerResultType::Ack,
                        AckOrReveal::Reveal(_) => PlayerResultType::Reveal,
                    };
                    PlayerResult {
                        player: player.clone(),
                        result_type,
                    }
                })
                .collect(),
            DealerResult::TooManyReveals => vec![],
        }
    }
}

/// The type of result for a player in a dealer log.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PlayerResultType {
    Ack,
    Reveal,
}

/// A player's result in a dealer log.
#[derive(Clone, Debug)]
pub(crate) struct PlayerResult<P: PublicKey> {
    pub player: P,
    pub result_type: PlayerResultType,
}
