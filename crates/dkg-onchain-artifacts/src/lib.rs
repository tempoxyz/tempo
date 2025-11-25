//! Items that are written to chain.

use alloy_primitives::Address;
use alloy_rlp::{Decodable, Encodable};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, FixedSize as _, RangeCfg, Read, ReadExt as _, Write, varint::UInt,
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer as _, Verifier as _,
    bls12381::primitives::{group, poly::Public, variant::MinSig},
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_utils::{
    quorum,
    set::{Ordered, OrderedAssociated},
};

/// A message from a player to a dealer, confirming the receipt of share.
///
/// Contains the player's public key, as well as its signature over the
/// ceremony's epoch, dealear public key, and commitment contained in the
/// share message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// The public key identifier of the player sending the acknowledgment.
    player: PublicKey,
    /// A signature covering the DKG round, dealer ID, and the dealer's commitment.
    /// This confirms the player received and validated the correct share.
    signature: Signature,
}

impl Ack {
    /// Create a new acknowledgment signed by `signer`.
    pub fn new(
        namespace: &[u8],
        signer: PrivateKey,
        player: PublicKey,
        epoch: Epoch,
        dealer: &PublicKey,
        commitment: &Public<MinSig>,
    ) -> Self {
        let payload = Self::construct_signature_payload(epoch, dealer, commitment);
        let signature = signer.sign(Some(namespace), &payload);
        Self { player, signature }
    }

    fn construct_signature_payload(
        epoch: Epoch,
        dealer: &PublicKey,
        commitment: &Public<MinSig>,
    ) -> Vec<u8> {
        let mut payload =
            Vec::with_capacity(Epoch::SIZE + PublicKey::SIZE + commitment.encode_size());
        epoch.write(&mut payload);
        dealer.write(&mut payload);
        commitment.write(&mut payload);
        payload
    }

    pub fn verify(
        &self,
        namespace: &[u8],
        public_key: &PublicKey,
        epoch: Epoch,
        dealer: &PublicKey,
        commitment: &Public<MinSig>,
    ) -> bool {
        let payload = Self::construct_signature_payload(epoch, dealer, commitment);
        public_key.verify(Some(namespace), &payload, &self.signature)
    }

    pub fn player(&self) -> &PublicKey {
        &self.player
    }
}

impl Write for Ack {
    fn write(&self, buf: &mut impl BufMut) {
        self.player.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for Ack {
    fn encode_size(&self) -> usize {
        self.player.encode_size() + self.signature.encode_size()
    }
}

impl Read for Ack {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            player: PublicKey::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

/// The outcome of a dkg ceremony round.
///
/// Called public because it only contains the public polynomial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicOutcome {
    pub epoch: Epoch,
    pub validator_state: ValidatorState,
    pub public: Public<MinSig>,
}

impl Write for PublicOutcome {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.epoch).write(buf);
        self.validator_state.write(buf);
        self.public.write(buf);
    }
}

impl Read for PublicOutcome {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let epoch = UInt::read(buf)?.into();
        let validator_state = ValidatorState::read_cfg(buf, &())?;
        let public = Public::<MinSig>::read_cfg(
            buf,
            &(quorum(validator_state.dealers().len() as u32) as usize),
        )?;
        Ok(Self {
            epoch,
            validator_state,
            public,
        })
    }
}

impl EncodeSize for PublicOutcome {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size()
            + self.validator_state.encode_size()
            + self.public.encode_size()
    }
}

impl Encodable for PublicOutcome {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        use commonware_codec::Encode as _;

        let public_bytes = self.public.encode();
        let payload_len = Encodable::length(&self.epoch)
            + Encodable::length(&self.validator_state)
            + Encodable::length(&public_bytes.as_ref());

        alloy_rlp::Header {
            list: true,
            payload_length: payload_len,
        }
        .encode(out);
        Encodable::encode(&self.epoch, out);
        Encodable::encode(&self.validator_state, out);
        Encodable::encode(&public_bytes.as_ref(), out);
    }

    fn length(&self) -> usize {
        use commonware_codec::Encode as _;

        let public_bytes = self.public.encode();
        let payload_len = Encodable::length(&self.epoch)
            + Encodable::length(&self.validator_state)
            + Encodable::length(&public_bytes.as_ref());

        alloy_rlp::length_of_length(payload_len) + payload_len
    }
}

impl Decodable for PublicOutcome {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        use commonware_codec::Read as _;

        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let epoch: u64 = Decodable::decode(buf)?;
        let validator_state: ValidatorState = Decodable::decode(buf)?;

        let public_bytes: bytes::Bytes = Decodable::decode(buf)?;
        let quorum_size = quorum(validator_state.dealers().len() as u32) as usize;
        let mut public_buf = public_bytes.as_ref();
        let public = Public::<MinSig>::read_cfg(&mut public_buf, &quorum_size)
            .map_err(|_| alloy_rlp::Error::Custom("invalid public polynomial"))?;

        Ok(Self {
            epoch,
            validator_state,
            public,
        })
    }
}

/// The local outcome of a dealer's dealings.
///
/// This is the intermediate outcome of a ceremony, which contains a dealer's
/// generated commitment, all acks for the shares it sent to the ceremony's
/// players, and finally the revealed shares, for which it did not receive acks.
///
/// This object is persisted on-chain. Every player collects the intermediate
/// outcomes of the other dealers to create the overall outcome of the ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntermediateOutcome {
    /// The number of players in this epoch.
    n_players: u16,

    /// The public key of the dealer.
    dealer: PublicKey,

    /// The dealer's signature over the resharing round, commitment, acks, and reveals.
    dealer_signature: Signature,

    /// The epoch of the resharing operation.
    epoch: Epoch,

    /// The new group public key polynomial.
    commitment: Public<MinSig>,

    /// All signed acknowledgements from participants.
    acks: Vec<Ack>,

    /// Any revealed secret shares.
    reveals: Vec<group::Share>,
}

impl IntermediateOutcome {
    /// Creates a new intermediate ceremony outcome.
    ///
    /// This object contains, the number of players, the epoch of the ceremony,
    /// the dealer's commitment (public polynomial), the acks received by the
    /// players and the revealed shares for which no acks are received.
    ///
    /// Finally, it also includes a signature over
    /// `(namespace, epoch, commitment, acks, reveals)` signed by the dealer.
    pub fn new(
        n_players: u16,
        dealer_signer: &PrivateKey,
        namespace: &[u8],
        epoch: Epoch,
        commitment: Public<MinSig>,
        acks: Vec<Ack>,
        reveals: Vec<group::Share>,
    ) -> Self {
        // Sign the resharing outcome
        let payload =
            Self::signature_payload_from_parts(n_players, epoch, &commitment, &acks, &reveals);
        let dealer_signature = dealer_signer.sign(Some(namespace), payload.as_ref());

        Self {
            n_players,
            dealer: dealer_signer.public_key(),
            dealer_signature,
            epoch,
            commitment,
            acks,
            reveals,
        }
    }

    /// Verifies the intermediate outcome's signature.
    pub fn verify(&self, namespace: &[u8]) -> bool {
        let payload = Self::signature_payload_from_parts(
            self.n_players,
            self.epoch,
            &self.commitment,
            &self.acks,
            &self.reveals,
        );
        self.dealer
            .verify(Some(namespace), &payload, &self.dealer_signature)
    }

    /// Returns the payload that was signed by the dealer, formed from raw parts.
    fn signature_payload_from_parts(
        n_players: u16,
        epoch: Epoch,
        commitment: &Public<MinSig>,
        acks: &Vec<Ack>,
        reveals: &Vec<group::Share>,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            UInt(n_players).encode_size()
                + UInt(epoch).encode_size()
                + commitment.encode_size()
                + acks.encode_size()
                + reveals.encode_size(),
        );
        UInt(n_players).write(&mut buf);
        UInt(epoch).write(&mut buf);
        commitment.write(&mut buf);
        acks.write(&mut buf);
        reveals.write(&mut buf);
        buf
    }

    pub fn acks(&self) -> &[Ack] {
        &self.acks
    }

    pub fn dealer(&self) -> &PublicKey {
        &self.dealer
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn commitment(&self) -> &Public<MinSig> {
        &self.commitment
    }

    pub fn reveals(&self) -> &[group::Share] {
        &self.reveals
    }
}

impl Write for IntermediateOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        UInt(self.n_players).write(buf);
        self.dealer.write(buf);
        self.dealer_signature.write(buf);
        UInt(self.epoch).write(buf);
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl EncodeSize for IntermediateOutcome {
    fn encode_size(&self) -> usize {
        UInt(self.n_players).encode_size()
            + self.dealer.encode_size()
            + self.dealer_signature.encode_size()
            + UInt(self.epoch).encode_size()
            + self.commitment.encode_size()
            + self.acks.encode_size()
            + self.reveals.encode_size()
    }
}

impl Read for IntermediateOutcome {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let n_players: u16 = UInt::read(buf)?.into();
        let dealer = PublicKey::read(buf)?;
        let dealer_signature = Signature::read(buf)?;
        let epoch = UInt::read(buf)?.into();
        let commitment = Public::<MinSig>::read_cfg(buf, &(quorum(n_players as u32) as usize))?;

        let acks = Vec::read_cfg(buf, &(RangeCfg::from(0..=n_players as usize), ()))?;
        let reveals =
            Vec::<group::Share>::read_cfg(buf, &(RangeCfg::from(0..=n_players as usize), ()))?;

        Ok(Self {
            n_players,
            dealer,
            dealer_signature,
            epoch,
            commitment,
            acks,
            reveals,
        })
    }
}

/// A validator decoded from the ValidatorConfig contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedValidator {
    pub public_key: PublicKey,
    pub inbound: String,
    pub outbound: String,
    pub index: u64,
    pub address: Address,
}

impl Write for DecodedValidator {
    fn write(&self, buf: &mut impl BufMut) {
        self.public_key.write(buf);
        self.inbound.as_bytes().write(buf);
        self.outbound.as_bytes().write(buf);
        UInt(self.index).write(buf);
        self.address.0.write(buf);
    }
}

impl EncodeSize for DecodedValidator {
    fn encode_size(&self) -> usize {
        self.public_key.encode_size()
            + self.inbound.as_bytes().encode_size()
            + self.outbound.as_bytes().encode_size()
            + UInt(self.index).encode_size()
            + self.address.0.encode_size()
    }
}

impl Read for DecodedValidator {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let public_key = PublicKey::read_cfg(buf, &())?;
        let inbound = {
            let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=253usize), ()))?;
            String::from_utf8(bytes).map_err(|_| {
                commonware_codec::Error::Invalid("decode inbound address", "not utf8")
            })?
        };
        let outbound = {
            let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=253usize), ()))?;
            String::from_utf8(bytes).map_err(|_| {
                commonware_codec::Error::Invalid("decode outbound address", "not utf8")
            })?
        };
        let index = UInt::read_cfg(buf, &())?.into();
        let address = Address::new(<[u8; 20]>::read_cfg(buf, &())?);
        Ok(Self {
            public_key,
            inbound,
            outbound,
            index,
            address,
        })
    }
}

impl std::fmt::Display for DecodedValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "public key = `{}`, inbound = `{}`, outbound = `{}`, index = `{}`, address = `{}`",
            self.public_key, self.inbound, self.outbound, self.index, self.address
        )
    }
}

impl Encodable for DecodedValidator {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_payload_length(),
        }
        .encode(out);
        self.public_key.as_ref().encode(out);
        self.inbound.as_bytes().encode(out);
        self.outbound.as_bytes().encode(out);
        self.index.encode(out);
        self.address.encode(out);
    }

    fn length(&self) -> usize {
        alloy_rlp::length_of_length(self.rlp_payload_length()) + self.rlp_payload_length()
    }
}

impl DecodedValidator {
    fn rlp_payload_length(&self) -> usize {
        self.public_key.as_ref().length()
            + self.inbound.as_bytes().length()
            + self.outbound.as_bytes().length()
            + self.index.length()
            + self.address.length()
    }
}

impl Decodable for DecodedValidator {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        use commonware_codec::DecodeExt as _;

        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let public_key_bytes: bytes::Bytes = Decodable::decode(buf)?;
        let public_key = PublicKey::decode(public_key_bytes.as_ref())
            .map_err(|_| alloy_rlp::Error::Custom("invalid public key"))?;

        let inbound_bytes: bytes::Bytes = Decodable::decode(buf)?;
        let inbound = String::from_utf8(inbound_bytes.to_vec())
            .map_err(|_| alloy_rlp::Error::Custom("invalid utf8 for inbound"))?;

        let outbound_bytes: bytes::Bytes = Decodable::decode(buf)?;
        let outbound = String::from_utf8(outbound_bytes.to_vec())
            .map_err(|_| alloy_rlp::Error::Custom("invalid utf8 for outbound"))?;

        let index: u64 = Decodable::decode(buf)?;
        let address_bytes: [u8; 20] = Decodable::decode(buf)?;
        let address = Address::from(address_bytes);

        Ok(Self {
            public_key,
            inbound,
            outbound,
            index,
            address,
        })
    }
}

/// Tracks the participants of each DKG ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorState {
    dealers: OrderedAssociated<PublicKey, DecodedValidator>,
    players: OrderedAssociated<PublicKey, DecodedValidator>,
    syncing_players: OrderedAssociated<PublicKey, DecodedValidator>,
}

impl ValidatorState {
    pub fn new(validators: OrderedAssociated<PublicKey, DecodedValidator>) -> Self {
        Self {
            dealers: validators.clone(),
            players: validators.clone(),
            syncing_players: validators,
        }
    }

    pub fn dealers(&self) -> &OrderedAssociated<PublicKey, DecodedValidator> {
        &self.dealers
    }

    pub fn players(&self) -> &OrderedAssociated<PublicKey, DecodedValidator> {
        &self.players
    }

    pub fn syncing_players(&self) -> &OrderedAssociated<PublicKey, DecodedValidator> {
        &self.syncing_players
    }

    pub fn dealer_pubkeys(&self) -> Ordered<PublicKey> {
        self.dealers.keys().clone()
    }

    pub fn player_pubkeys(&self) -> Ordered<PublicKey> {
        self.players.keys().clone()
    }

    /// Constructs a peerset to register on the peer manager.
    ///
    /// The peerset is constructed by merging the participants of all the
    /// validator sets tracked in this queue, and resolving each of their
    /// addresses (parsing socket address or looking up domain name).
    ///
    /// If a validator has entries across the tracked sets, then then its entry
    /// for the latest pushed set is taken. For those cases where looking up
    /// domain names failed, the last successfully looked up name is taken.
    pub fn resolve_addresses_and_merge_peers(
        &self,
    ) -> OrderedAssociated<PublicKey, std::net::SocketAddr> {
        use std::net::ToSocketAddrs as _;

        // IMPORTANT: Starting with the syncing players to ensure that the
        // latest address for a validator with a given pubkey is used.
        // OrderedAssociated takes the first instance of a key it sees and
        // drops the later instances.
        self.syncing_players()
            .iter_pairs()
            .chain(self.players().iter_pairs())
            .chain(self.dealers().iter_pairs())
            .filter_map(|(pubkey, validator)| {
                let addr = validator.inbound.to_socket_addrs().ok()?.last()?;
                Some((pubkey.clone(), addr))
            })
            .collect()
    }

    /// Pushes `syncing_players` into the participants queue.
    ///
    /// This method is called on successful DKG ceremonies: the current players
    /// will become the next dealers, and the current syncing players will become
    /// the next regular players.
    ///
    /// Removes and returns the old dealers.
    pub fn push_on_success(
        &mut self,
        syncing_players: OrderedAssociated<PublicKey, DecodedValidator>,
    ) -> OrderedAssociated<PublicKey, DecodedValidator> {
        let players = std::mem::replace(&mut self.syncing_players, syncing_players);
        let dealers = std::mem::replace(&mut self.players, players);
        std::mem::replace(&mut self.dealers, dealers)
    }

    /// Pushes `syncing_players` into the participants queue.
    ///
    /// This method is called on failed DKG ceremonies: the current dealers
    /// will remain dealers for the next epoch, the current players are dropped
    /// (since for them, the ceremony failed), and the current syncing players
    /// will become the next regular players.
    pub fn push_on_failure(
        &mut self,
        syncing_players: OrderedAssociated<PublicKey, DecodedValidator>,
    ) -> OrderedAssociated<PublicKey, DecodedValidator> {
        let players = std::mem::replace(&mut self.syncing_players, syncing_players);
        std::mem::replace(&mut self.players, players)
    }
}

impl Write for ValidatorState {
    fn write(&self, buf: &mut impl BufMut) {
        self.dealers.write(buf);
        self.players.write(buf);
        self.syncing_players.write(buf);
    }
}

impl EncodeSize for ValidatorState {
    fn encode_size(&self) -> usize {
        self.dealers.encode_size() + self.players.encode_size() + self.syncing_players.encode_size()
    }
}

impl Read for ValidatorState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let dealers = OrderedAssociated::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), (), ()))?;
        let players = OrderedAssociated::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), (), ()))?;
        let syncing_players =
            OrderedAssociated::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), (), ()))?;
        Ok(Self {
            dealers,
            players,
            syncing_players,
        })
    }
}

/// Helper to encode an OrderedAssociated as RLP list of validators
fn encode_validators(
    validators: &OrderedAssociated<PublicKey, DecodedValidator>,
    out: &mut dyn bytes::BufMut,
) {
    let payload_len: usize = validators.values().iter().map(Encodable::length).sum();
    alloy_rlp::Header {
        list: true,
        payload_length: payload_len,
    }
    .encode(out);
    for v in validators.values() {
        v.encode(out);
    }
}

fn validators_length(validators: &OrderedAssociated<PublicKey, DecodedValidator>) -> usize {
    let payload_len: usize = validators.values().iter().map(Encodable::length).sum();
    alloy_rlp::length_of_length(payload_len) + payload_len
}

fn decode_validators(
    buf: &mut &[u8],
) -> alloy_rlp::Result<OrderedAssociated<PublicKey, DecodedValidator>> {
    let header = alloy_rlp::Header::decode(buf)?;
    if !header.list {
        return Err(alloy_rlp::Error::UnexpectedString);
    }

    let mut validators = Vec::new();
    let payload_view = &mut &buf[..header.payload_length];
    while !payload_view.is_empty() {
        let v: DecodedValidator = Decodable::decode(payload_view)?;
        validators.push((v.public_key.clone(), v));
    }
    *buf = &buf[header.payload_length..];
    Ok(validators.into())
}

impl Encodable for ValidatorState {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        alloy_rlp::Header {
            list: true,
            payload_length: self.rlp_payload_length(),
        }
        .encode(out);
        encode_validators(&self.dealers, out);
        encode_validators(&self.players, out);
        encode_validators(&self.syncing_players, out);
    }

    fn length(&self) -> usize {
        alloy_rlp::length_of_length(self.rlp_payload_length()) + self.rlp_payload_length()
    }
}

impl ValidatorState {
    fn rlp_payload_length(&self) -> usize {
        validators_length(&self.dealers)
            + validators_length(&self.players)
            + validators_length(&self.syncing_players)
    }
}

impl Decodable for ValidatorState {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let dealers = decode_validators(buf)?;
        let players = decode_validators(buf)?;
        let syncing_players = decode_validators(buf)?;

        Ok(Self {
            dealers,
            players,
            syncing_players,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{
        PrivateKeyExt as _, Signer as _,
        bls12381::{dkg, primitives::variant::MinSig},
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::{set::Ordered, union};
    use rand::{SeedableRng as _, rngs::StdRng};

    const ACK_NAMESPACE: &[u8] = b"_DKG_ACK";
    const OUTCOME_NAMESPACE: &[u8] = b"_DKG_OUTCOME";

    use crate::{Ack, DecodedValidator, PublicOutcome, ValidatorState};

    use super::IntermediateOutcome;

    fn four_private_keys() -> Ordered<PrivateKey> {
        vec![
            PrivateKey::from_seed(0),
            PrivateKey::from_seed(1),
            PrivateKey::from_seed(2),
            PrivateKey::from_seed(3),
        ]
        .into()
    }

    fn four_public_keys() -> Ordered<PublicKey> {
        vec![
            PrivateKey::from_seed(0).public_key(),
            PrivateKey::from_seed(1).public_key(),
            PrivateKey::from_seed(2).public_key(),
            PrivateKey::from_seed(3).public_key(),
        ]
        .into()
    }

    #[test]
    fn dealing_outcome_roundtrip() {
        let (_, commitment, shares) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([0; 32]),
            None,
            four_public_keys(),
        );

        let acks = vec![
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[0].clone(),
                four_public_keys()[0].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[1].clone(),
                four_public_keys()[1].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[2].clone(),
                four_public_keys()[2].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
        ];
        let reveals = vec![shares[3].clone()];
        let dealing_outcome = IntermediateOutcome::new(
            4,
            &four_private_keys()[0],
            &union(b"test", OUTCOME_NAMESPACE),
            42,
            commitment,
            acks,
            reveals,
        );

        let bytes = dealing_outcome.encode();
        assert_eq!(
            IntermediateOutcome::decode(&mut bytes.as_ref()).unwrap(),
            dealing_outcome,
        );
    }

    #[test]
    fn dealing_outcome_roundtrip_without_reveals() {
        let (_, commitment, _) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([0; 32]),
            None,
            four_public_keys(),
        );

        let acks = vec![
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[0].clone(),
                four_public_keys()[0].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[1].clone(),
                four_public_keys()[1].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[2].clone(),
                four_public_keys()[2].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
            Ack::new(
                &union(b"test", ACK_NAMESPACE),
                four_private_keys()[3].clone(),
                four_public_keys()[3].clone(),
                42,
                &four_public_keys()[0],
                &commitment,
            ),
        ];
        let reveals = vec![];
        let dealing_outcome = IntermediateOutcome::new(
            4,
            &four_private_keys()[0],
            &union(b"test", OUTCOME_NAMESPACE),
            42,
            commitment,
            acks,
            reveals,
        );

        let bytes = dealing_outcome.encode();
        assert_eq!(
            IntermediateOutcome::decode(&mut bytes.as_ref()).unwrap(),
            dealing_outcome,
        );
    }

    fn four_validator_state() -> ValidatorState {
        let validators = four_public_keys()
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                (
                    pk.clone(),
                    DecodedValidator {
                        public_key: pk.clone(),
                        inbound: format!("localhost:{}", 9000 + i),
                        outbound: format!("127.0.0.1:{}", 9000 + i),
                        index: i as u64,
                        address: Address::ZERO,
                    },
                )
            })
            .collect();
        ValidatorState::new(validators)
    }

    #[test]
    fn public_outcome_roundtrip() {
        let (_, commitment, _) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([0; 32]),
            None,
            four_public_keys(),
        );
        let public_outcome = PublicOutcome {
            epoch: 42,
            validator_state: four_validator_state(),
            public: commitment,
        };
        let bytes = public_outcome.encode();
        assert_eq!(
            PublicOutcome::decode(&mut bytes.as_ref()).unwrap(),
            public_outcome,
        );
    }

    #[test]
    fn validator_state_roundtrip() {
        let validator = DecodedValidator {
            public_key: PrivateKey::from_seed(0).public_key(),
            inbound: "localhost:9000".to_string(),
            outbound: "127.0.0.1:9000".to_string(),
            index: 0,
            address: Address::ZERO,
        };

        let validators = vec![(validator.public_key.clone(), validator)].into();
        let state = ValidatorState::new(validators);

        let encoded = state.encode();
        let decoded = ValidatorState::decode(&mut encoded.as_ref()).unwrap();

        assert_eq!(state.dealers().len(), decoded.dealers().len());
    }

    #[test]
    fn decoded_validator_rlp_roundtrip() {
        use alloy_rlp::{Decodable, Encodable};

        let validator = DecodedValidator {
            public_key: PrivateKey::from_seed(0).public_key(),
            inbound: "localhost:9000".to_string(),
            outbound: "127.0.0.1:9000".to_string(),
            index: 42,
            address: Address::ZERO,
        };

        let mut buf = Vec::new();
        Encodable::encode(&validator, &mut buf);

        let decoded = <DecodedValidator as Decodable>::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(validator, decoded);
    }

    #[test]
    fn validator_state_rlp_roundtrip() {
        use alloy_rlp::{Decodable, Encodable};

        let state = four_validator_state();

        let mut buf = Vec::new();
        Encodable::encode(&state, &mut buf);

        let decoded = <ValidatorState as Decodable>::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn public_outcome_rlp_roundtrip() {
        use alloy_rlp::{Decodable, Encodable};

        let (_, commitment, _) = dkg::Dealer::<_, MinSig>::new(
            &mut StdRng::from_seed([0; 32]),
            None,
            four_public_keys(),
        );
        let public_outcome = PublicOutcome {
            epoch: 42,
            validator_state: four_validator_state(),
            public: commitment,
        };

        let mut buf = Vec::new();
        Encodable::encode(&public_outcome, &mut buf);

        let decoded = <PublicOutcome as Decodable>::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(public_outcome, decoded);
    }
}
