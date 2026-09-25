//! Items that are written to chain.

use std::num::NonZeroU32;

use bytes::{Buf, BufMut};
use commonware_codec::{Decode as _, EncodeSize, RangeCfg, Read, ReadExt, Write, varint::UInt};
#[cfg(feature = "commonware-consensus")]
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{
            sharing::{ModeVersion, Sharing},
            variant::{MinSig, Variant},
        },
    },
    ed25519::PublicKey,
};
use commonware_utils::{NZU32, ordered};
use tempo_hardfork::TempoHardfork;

const MAX_VALIDATORS: NonZeroU32 = NZU32!(u16::MAX as u32);

/// The outcome of a DKG ceremony as it is written to the chain.
///
/// This DKG outcome can encode up to [`u16::MAX`] validators. Note that in
/// practice this far exceeds the maximum size permitted header size and so
/// is likely out of reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnchainDkgOutcome {
    /// The epoch for which this outcome is used, encoded as an unsigned varint.
    pub epoch: u64,

    /// The output of the DKG ceremony. Contains the shared public polynomial,
    /// and the players in the ceremony (which will be the dealers for the
    /// epoch encoded with this output).
    pub output: Output<MinSig, PublicKey>,

    /// Configuration suffix present only before TIP-1123. After activation the
    /// artifact contains exactly `epoch` and `output`, without an option tag.
    pub legacy_config: Option<LegacyDkgConfig>,
}

impl OnchainDkgOutcome {
    /// Returns the epoch for which this outcome is used.
    #[cfg(feature = "commonware-consensus")]
    pub fn epoch(&self) -> Epoch {
        Epoch::new(self.epoch)
    }

    pub fn dealers(&self) -> &ordered::Set<PublicKey> {
        self.output.dealers()
    }

    pub fn players(&self) -> &ordered::Set<PublicKey> {
        self.output.players()
    }

    pub fn sharing(&self) -> &Sharing<MinSig> {
        self.output.public()
    }

    pub fn network_identity(&self) -> &<MinSig as Variant>::Public {
        self.sharing().public()
    }

    /// Decode a boundary using its hardfork's historical acceptance rules.
    /// Legacy boundaries allowed trailing bytes; TIP-1123 artifacts must contain
    /// exactly the epoch and output, so even a legacy configuration suffix is rejected.
    pub fn decode_boundary(
        mut bytes: &[u8],
        fork: &TempoHardfork,
    ) -> Result<Self, commonware_codec::Error> {
        if fork.is_tip1123() {
            Self::decode_cfg(bytes, fork)
        } else {
            Self::read_cfg(&mut bytes, fork)
        }
    }
}

impl Write for OnchainDkgOutcome {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.epoch).write(buf);
        self.output.write(buf);
        if let Some(config) = &self.legacy_config {
            config.next_players.write(buf);
            config.is_next_full_dkg.write(buf);
        }
    }
}

impl Read for OnchainDkgOutcome {
    type Cfg = TempoHardfork;

    fn read_cfg(buf: &mut impl Buf, fork: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let epoch = UInt::<u64>::read(buf)?.into();
        let output = Read::read_cfg(buf, &(MAX_VALIDATORS, ModeVersion::v0()))?;
        let legacy_config = if fork.is_tip1123() {
            None
        } else {
            Some(LegacyDkgConfig {
                next_players: Read::read_cfg(
                    buf,
                    &(RangeCfg::from(1..=(MAX_VALIDATORS.get() as usize)), ()),
                )?,
                is_next_full_dkg: ReadExt::read(buf)?,
            })
        };
        Ok(Self {
            epoch,
            output,
            legacy_config,
        })
    }
}

impl EncodeSize for OnchainDkgOutcome {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size()
            + self.output.encode_size()
            + self.legacy_config.as_ref().map_or(0, |config| {
                config.next_players.encode_size() + config.is_next_full_dkg.encode_size()
            })
    }
}

/// The configuration encoded after the DKG output in pre-TIP-1123 boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyDkgConfig {
    /// Players in the ceremony running during the outcome's epoch.
    pub next_players: ordered::Set<PublicKey>,
    /// Whether that ceremony creates a new polynomial instead of resharing.
    pub is_next_full_dkg: bool,
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use commonware_codec::Encode as _;
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::{
        Signer as _,
        bls12381::{dkg::feldman_desmedt as dkg, primitives::sharing::Mode},
        ed25519::PrivateKey,
    };
    use commonware_math::algebra::Random as _;
    use commonware_utils::{N3f1, TryFromIterator as _, ordered};
    use rand::SeedableRng as _;

    use super::*;

    #[test]
    fn onchain_dkg_outcome_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let mut player_keys = repeat_with(|| PrivateKey::random(&mut rng))
            .take(10)
            .collect::<Vec<_>>();
        player_keys.sort_by_key(|key| key.public_key());
        let (output, _shares) = dkg::deal::<_, _, N3f1>(
            &mut rng,
            Mode::NonZeroCounter,
            ordered::Set::try_from_iter(player_keys.iter().map(|key| key.public_key())).unwrap(),
        )
        .unwrap();

        let mut on_chain = OnchainDkgOutcome {
            epoch: 42,
            output,
            legacy_config: Some(LegacyDkgConfig {
                next_players: ordered::Set::try_from_iter(
                    player_keys.iter().map(|key| key.public_key()),
                )
                .unwrap(),
                is_next_full_dkg: false,
            }),
        };
        // Preserve Commonware Epoch's wire encoding, including varint boundaries.
        let payload = on_chain.encode()[Epoch::new(on_chain.epoch).encode_size()..].to_vec();
        for epoch in [0, 127, 128, 16383, 16384, u64::MAX] {
            let prefix = Epoch::new(epoch).encode();
            on_chain.epoch = epoch;
            #[cfg(feature = "commonware-consensus")]
            assert_eq!(on_chain.epoch(), Epoch::new(epoch));
            let bytes = on_chain.encode();
            assert_eq!(&bytes[..prefix.len()], prefix.as_ref());
            assert_eq!(&bytes[prefix.len()..], payload);
            assert_eq!(bytes.len(), on_chain.encode_size());
            assert_eq!(
                OnchainDkgOutcome::decode_boundary(bytes.as_ref(), &TempoHardfork::T12).unwrap(),
                on_chain
            );
            let mut compact = on_chain.clone();
            compact.legacy_config = None;
            let compact_bytes = compact.encode();
            assert_eq!(&bytes[..compact_bytes.len()], compact_bytes.as_ref());
            assert_eq!(compact_bytes.len(), compact.encode_size());
            assert_eq!(
                OnchainDkgOutcome::decode_boundary(compact_bytes.as_ref(), &TempoHardfork::Tip1123)
                    .unwrap(),
                compact,
            );
            assert!(
                OnchainDkgOutcome::decode_boundary(bytes.as_ref(), &TempoHardfork::Tip1123)
                    .is_err()
            );
            assert!(
                OnchainDkgOutcome::decode_boundary(compact_bytes.as_ref(), &TempoHardfork::T12)
                    .is_err()
            );
            let mut legacy_with_trailing_bytes = bytes.to_vec();
            legacy_with_trailing_bytes.push(0xff);
            assert_eq!(
                OnchainDkgOutcome::decode_boundary(
                    &legacy_with_trailing_bytes,
                    &TempoHardfork::T13,
                )
                .unwrap(),
                on_chain,
            );
            let mut compact_with_trailing_bytes = compact_bytes.to_vec();
            compact_with_trailing_bytes.push(0xff);
            assert!(
                OnchainDkgOutcome::decode_boundary(
                    &compact_with_trailing_bytes,
                    &TempoHardfork::Tip1123,
                )
                .is_err()
            );
            for length in 0..compact_bytes.len() {
                assert!(
                    OnchainDkgOutcome::decode_boundary(
                        &compact_bytes[..length],
                        &TempoHardfork::Tip1123
                    )
                    .is_err()
                );
            }
        }
    }
}
