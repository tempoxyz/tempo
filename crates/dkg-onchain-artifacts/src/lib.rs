//! Items that are written to chain.

use std::num::NonZeroU32;

use bytes::BufMut;
use commonware_codec::{Buf, DecodeExt, EncodeSize, RangeCfg, Read, ReadExt, Write, varint::UInt};
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

const MAX_VALIDATORS: NonZeroU32 = NZU32!(u16::MAX as u32);

/// Selects how a boundary block's `extra_data` encodes its [`OnchainDkgOutcome`].
///
/// The boundary block's own timestamp selects the encoding (TIP-1123).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeEncoding {
    /// Before TIP-1123: the outcome also carries the players and mode of the
    /// ceremony running during its epoch.
    Legacy,
    /// From TIP-1123: the outcome carries only its epoch and output. The
    /// players and mode of the ceremony live in the `CurrentCommittee`
    /// precompile.
    CeremonyInState,
}

/// The players and mode of a DKG ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgCeremony {
    /// The players of the ceremony, who receive shares for the epoch after it.
    pub players: ordered::Set<PublicKey>,

    /// Whether the ceremony is a full DKG (new polynomial) instead of a reshare.
    pub is_full_dkg: bool,
}

/// The outcome of a DKG ceremony as it is written to a boundary block's `extra_data`.
///
/// The boundary block's timestamp selects the variant (TIP-1123): see [`OutcomeEncoding`]. This DKG
/// outcome can encode up to [`u16::MAX`] validators. Note that in practice this far exceeds the
/// maximum size permitted header size and so is likely out of reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OnchainDkgOutcome {
    /// Before TIP-1123: the outcome also carries the ceremony running during its epoch.
    V1(OnchainDkgOutcomeV1),
    /// From TIP-1123: the ceremony running during its epoch lives in the `CurrentCommittee`
    /// precompile.
    V2(OnchainDkgOutcomeV2),
}

/// A DKG outcome written before TIP-1123.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnchainDkgOutcomeV1 {
    /// The epoch for which this outcome is used, encoded as an unsigned varint.
    pub epoch: u64,

    /// The output of the DKG ceremony. Contains the shared public polynomial,
    /// and the players in the ceremony (which will be the dealers for the
    /// epoch encoded with this output).
    pub output: Output<MinSig, PublicKey>,

    /// The players and mode of the DKG ceremony running during `epoch`.
    pub next_ceremony: DkgCeremony,
}

/// A DKG outcome written from TIP-1123: [`OnchainDkgOutcomeV1`] without its ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnchainDkgOutcomeV2 {
    /// The epoch for which this outcome is used, encoded as an unsigned varint.
    pub epoch: u64,

    /// The output of the DKG ceremony, as in [`OnchainDkgOutcomeV1::output`].
    pub output: Output<MinSig, PublicKey>,
}

impl OnchainDkgOutcome {
    /// Returns the epoch for which this outcome is used.
    #[cfg(feature = "commonware-consensus")]
    pub fn epoch(&self) -> Epoch {
        Epoch::new(self.raw_epoch())
    }

    /// Returns the epoch for which this outcome is used, as written to the chain.
    pub const fn raw_epoch(&self) -> u64 {
        match self {
            Self::V1(outcome) => outcome.epoch,
            Self::V2(outcome) => outcome.epoch,
        }
    }

    /// Returns the output of the DKG ceremony.
    pub const fn output(&self) -> &Output<MinSig, PublicKey> {
        match self {
            Self::V1(outcome) => &outcome.output,
            Self::V2(outcome) => &outcome.output,
        }
    }

    /// Returns the output of the DKG ceremony, consuming the outcome.
    pub fn into_output(self) -> Output<MinSig, PublicKey> {
        match self {
            Self::V1(outcome) => outcome.output,
            Self::V2(outcome) => outcome.output,
        }
    }

    pub fn dealers(&self) -> &ordered::Set<PublicKey> {
        self.output().dealers()
    }

    pub fn players(&self) -> &ordered::Set<PublicKey> {
        self.output().players()
    }

    /// Returns the ceremony running during this outcome's epoch if the outcome carries it (V1).
    /// A V2 outcome returns `None`: its ceremony is in the `CurrentCommittee` precompile.
    pub const fn next_ceremony(&self) -> Option<&DkgCeremony> {
        match self {
            Self::V1(outcome) => Some(&outcome.next_ceremony),
            Self::V2(_) => None,
        }
    }

    /// Returns how this outcome is encoded.
    pub const fn encoding(&self) -> OutcomeEncoding {
        match self {
            Self::V1(_) => OutcomeEncoding::Legacy,
            Self::V2(_) => OutcomeEncoding::CeremonyInState,
        }
    }

    /// Decodes the outcome in a boundary block's `extra_data`.
    ///
    /// [`OutcomeEncoding::CeremonyInState`] is a prefix of the legacy
    /// encoding, so it rejects trailing bytes. [`OutcomeEncoding::Legacy`]
    /// keeps ignoring them, as it always has.
    pub fn decode_extra_data(
        extra_data: &[u8],
        encoding: OutcomeEncoding,
    ) -> Result<Self, commonware_codec::Error> {
        let mut extra_data = commonware_codec::Copying(extra_data);
        Ok(match encoding {
            OutcomeEncoding::Legacy => Self::V1(OnchainDkgOutcomeV1::read(&mut extra_data)?),
            OutcomeEncoding::CeremonyInState => Self::V2(OnchainDkgOutcomeV2::decode(extra_data)?),
        })
    }

    pub fn sharing(&self) -> &Sharing<MinSig> {
        self.output().public()
    }

    pub fn network_identity(&self) -> &<MinSig as Variant>::Public {
        self.sharing().public()
    }
}

impl Write for OnchainDkgOutcome {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::V1(outcome) => outcome.write(buf),
            Self::V2(outcome) => outcome.write(buf),
        }
    }
}

impl EncodeSize for OnchainDkgOutcome {
    fn encode_size(&self) -> usize {
        match self {
            Self::V1(outcome) => outcome.encode_size(),
            Self::V2(outcome) => outcome.encode_size(),
        }
    }
}

impl From<OnchainDkgOutcomeV1> for OnchainDkgOutcome {
    fn from(outcome: OnchainDkgOutcomeV1) -> Self {
        Self::V1(outcome)
    }
}

impl From<OnchainDkgOutcomeV2> for OnchainDkgOutcome {
    fn from(outcome: OnchainDkgOutcomeV2) -> Self {
        Self::V2(outcome)
    }
}

impl OnchainDkgOutcomeV1 {
    /// This outcome without its ceremony, as a TIP-1123 boundary block writes it.
    pub fn without_ceremony(self) -> OnchainDkgOutcomeV2 {
        OnchainDkgOutcomeV2 {
            epoch: self.epoch,
            output: self.output,
        }
    }

    /// This outcome as a boundary block with `encoding` writes it: whole, or without its
    /// ceremony.
    pub fn into_encoding(self, encoding: OutcomeEncoding) -> OnchainDkgOutcome {
        match encoding {
            OutcomeEncoding::Legacy => OnchainDkgOutcome::V1(self),
            OutcomeEncoding::CeremonyInState => OnchainDkgOutcome::V2(self.without_ceremony()),
        }
    }
}

impl Write for OnchainDkgOutcomeV1 {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.epoch).write(buf);
        self.output.write(buf);
        self.next_ceremony.players.write(buf);
        self.next_ceremony.is_full_dkg.write(buf);
    }
}

impl Read for OnchainDkgOutcomeV1 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            epoch: UInt::<u64>::read(buf)?.into(),
            output: Read::read_cfg(buf, &(MAX_VALIDATORS, ModeVersion::v0()))?,
            next_ceremony: DkgCeremony {
                players: Read::read_cfg(
                    buf,
                    &(RangeCfg::from(1..=(MAX_VALIDATORS.get() as usize)), ()),
                )?,
                is_full_dkg: ReadExt::read(buf)?,
            },
        })
    }
}

impl EncodeSize for OnchainDkgOutcomeV1 {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size()
            + self.output.encode_size()
            + self.next_ceremony.players.encode_size()
            + self.next_ceremony.is_full_dkg.encode_size()
    }
}

impl Write for OnchainDkgOutcomeV2 {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.epoch).write(buf);
        self.output.write(buf);
    }
}

impl Read for OnchainDkgOutcomeV2 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            epoch: UInt::<u64>::read(buf)?.into(),
            output: Read::read_cfg(buf, &(MAX_VALIDATORS, ModeVersion::v0()))?,
        })
    }
}

impl EncodeSize for OnchainDkgOutcomeV2 {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size() + self.output.encode_size()
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl OnchainDkgOutcome {
    /// [`OnchainDkgOutcomeV1::dealt`] as a legacy outcome.
    pub fn dealt(epoch: u64, players: usize) -> Self {
        Self::V1(OnchainDkgOutcomeV1::dealt(epoch, players))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl OnchainDkgOutcomeV1 {
    /// The outcome of a DKG dealt to new `players` for `epoch`, who are also the next
    /// players of a reshare. The dealing is seeded with `epoch`, so the same arguments give the
    /// same outcome.
    pub fn dealt(epoch: u64, players: usize) -> Self {
        use commonware_cryptography::{
            Signer as _,
            bls12381::{dkg::feldman_desmedt as dkg, primitives::sharing::Mode},
            ed25519::PrivateKey,
        };
        use commonware_math::algebra::Random as _;
        use commonware_utils::{N3f1, TryFromIterator as _};
        use rand::SeedableRng as _;

        let mut rng = rand::rngs::StdRng::seed_from_u64(epoch);
        let keys =
            std::iter::repeat_with(|| PrivateKey::random(&mut rng).public_key()).take(players);
        let players = ordered::Set::try_from_iter(keys).expect("random keys are distinct");
        let (output, shares) = dkg::deal::<_, _, N3f1>(&mut rng, Mode::NonZeroCounter, players)
            .expect("a DKG deals to distinct players");
        Self {
            epoch,
            output,
            next_ceremony: DkgCeremony {
                players: shares.keys().clone(),
                is_full_dkg: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OnchainDkgOutcome, OnchainDkgOutcomeV1, OutcomeEncoding};
    use commonware_codec::{Encode as _, EncodeSize as _};
    use commonware_consensus::types::Epoch;

    #[test]
    fn onchain_dkg_outcome_roundtrip() {
        let mut on_chain = OnchainDkgOutcomeV1::dealt(42, 10);
        // Preserve Commonware Epoch's wire encoding, including varint boundaries.
        let payload = on_chain.encode()[Epoch::new(on_chain.epoch).encode_size()..].to_vec();
        for epoch in [0, 127, 128, 16383, 16384, u64::MAX] {
            let prefix = Epoch::new(epoch).encode();
            on_chain.epoch = epoch;
            let outcome = OnchainDkgOutcome::V1(on_chain.clone());
            #[cfg(feature = "commonware-consensus")]
            assert_eq!(outcome.epoch(), Epoch::new(epoch));
            let bytes = outcome.encode();
            assert_eq!(&bytes[..prefix.len()], prefix.as_ref());
            assert_eq!(&bytes[prefix.len()..], payload);
            assert_eq!(bytes.len(), outcome.encode_size());
            assert_eq!(
                OnchainDkgOutcome::decode_extra_data(&bytes, OutcomeEncoding::Legacy).unwrap(),
                outcome
            );
        }
    }

    #[test]
    fn ceremony_in_state_outcome_is_a_prefix_of_the_legacy_outcome() {
        let legacy = OnchainDkgOutcome::V1(OnchainDkgOutcomeV1::dealt(42, 10));
        let outcome = OnchainDkgOutcome::V2(OnchainDkgOutcomeV1::dealt(42, 10).without_ceremony());
        assert_eq!(outcome.encoding(), OutcomeEncoding::CeremonyInState);
        assert_eq!(legacy.encoding(), OutcomeEncoding::Legacy);

        let bytes = outcome.encode();
        assert_eq!(bytes.len(), outcome.encode_size());
        assert!(legacy.encode().starts_with(&bytes));
        assert_eq!(
            OnchainDkgOutcome::decode_extra_data(&bytes, OutcomeEncoding::CeremonyInState).unwrap(),
            outcome
        );
    }

    #[test]
    fn ceremony_in_state_outcome_rejects_trailing_bytes() {
        let legacy = OnchainDkgOutcomeV1::dealt(42, 10).encode();
        assert!(matches!(
            OnchainDkgOutcome::decode_extra_data(&legacy, OutcomeEncoding::CeremonyInState),
            Err(commonware_codec::Error::ExtraData(_))
        ));

        // Legacy outcomes keep ignoring trailing bytes, as before TIP-1123.
        let mut padded = legacy.to_vec();
        padded.push(0);
        assert_eq!(
            OnchainDkgOutcome::decode_extra_data(&padded, OutcomeEncoding::Legacy).unwrap(),
            OnchainDkgOutcome::V1(OnchainDkgOutcomeV1::dealt(42, 10))
        );
    }

    #[test]
    fn legacy_decoding_needs_the_next_ceremony() {
        let outcome = OnchainDkgOutcomeV1::dealt(42, 10).without_ceremony();
        assert!(matches!(
            OnchainDkgOutcome::decode_extra_data(&outcome.encode(), OutcomeEncoding::Legacy),
            Err(commonware_codec::Error::EndOfBuffer)
        ));
    }
}
