use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs as _},
};

use alloy_evm::EvmInternals;
use alloy_primitives::Address;
use commonware_codec::{DecodeExt as _, EncodeSize, RangeCfg, Read, Write, varint::UInt};
use commonware_consensus::{types::Epoch, utils};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::set::{Ordered, OrderedAssociated};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use reth_ethereum::evm::revm::{State, database::StateProviderDatabase};
use reth_node_builder::{Block as _, ConfigureEvm as _};
use reth_provider::{BlockReader as _, StateProviderFactory as _};
use tempo_commonware_node_config::SocketAddrOrFqdnPort;
use tempo_node::TempoFullNode;
use tempo_precompiles::{
    storage::evm::EvmPrecompileStorageProvider,
    validator_config::{
        IValidatorConfig, ValidatorConfig, ensure_inbound_is_host_port, ensure_outbound_is_ip_port,
    },
};

use tracing::{Level, info, instrument, warn};

/// Reads the validator config of `epoch`.
///
/// The validator config for `epoch` is always read from the last height of
/// `epoch-1`.
#[instrument(
    skip_all,
    fields(
        attempt = _attempt,
        for_epoch,
        from_block = last_height_before_epoch(for_epoch, epoch_length),
    ),
    err
)]
pub(super) async fn read_from_contract(
    _attempt: u32,
    node: &TempoFullNode,
    for_epoch: Epoch,
    epoch_length: u64,
) -> eyre::Result<OrderedAssociated<PublicKey, DecodedValidator>> {
    let last_height = last_height_before_epoch(for_epoch, epoch_length);
    let block = node
        .provider
        .block_by_number(last_height)
        .map_err(Into::<eyre::Report>::into)
        .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty block"))
        .wrap_err_with(|| format!("failed reading block at height `{last_height}`"))?;

    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.provider
                .state_by_block_id(last_height.into())
                .wrap_err_with(|| {
                    format!("failed to get state from node provider for height `{last_height}`")
                })?,
        ))
        .build();

    // XXX: Ensure that evm and internals go out of scope before the await point
    // below.
    let raw_validators = {
        let mut evm = node
            .evm_config
            .evm_for_block(db, block.header())
            .wrap_err("failed instantiating evm for genesis block")?;

        let ctx = evm.ctx_mut();
        let internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut provider = EvmPrecompileStorageProvider::new_max_gas(internals, &ctx.cfg);

        let mut validator_config = ValidatorConfig::new(&mut provider);
        validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .wrap_err("failed to query contract for validator config")?
    };

    info!(?raw_validators, "read validators from contract",);

    Ok(decode_from_contract(raw_validators).await)
}

#[instrument(skip_all, fields(validators_to_decode = contract_vals.len()))]
async fn decode_from_contract(
    contract_vals: Vec<IValidatorConfig::Validator>,
) -> OrderedAssociated<PublicKey, DecodedValidator> {
    let mut decoded = HashMap::new();
    for val in contract_vals.into_iter().filter(|val| val.active) {
        // NOTE: not reporting errors because `decode_from_contract` emits
        // events on success and error
        if let Ok(val) = DecodedValidator::decode_from_contract(val)
            && let Some(old) = decoded.insert(val.public_key.clone(), val)
        {
            warn!(
                %old,
                new = %decoded.get(&old.public_key).expect("just inserted it"),
                "replaced peer because public keys were duplicated",
            );
        }
    }
    decoded.into_iter().collect::<_>()
}

/// Tracks the participants of each DKG ceremony, and, by extension, the p2p network.
///
/// The participants tracked here are in order:
///
/// 1. the dealers, that will drop out of the next ceremony
/// 2. the player, that will become dealers in the next ceremony
/// 3. the syncing players, that will become players in the next ceremony
#[derive(Clone, Debug)]
pub(super) struct ValidatorState {
    dealers: OrderedAssociated<PublicKey, DecodedValidator>,
    players: OrderedAssociated<PublicKey, DecodedValidator>,
    syncing_players: OrderedAssociated<PublicKey, DecodedValidator>,
}

impl ValidatorState {
    pub(super) fn new(validators: OrderedAssociated<PublicKey, DecodedValidator>) -> Self {
        Self {
            dealers: validators.clone(),
            players: validators.clone(),
            syncing_players: validators,
        }
    }

    /// Returns a validator state with the on-chain addresses and on-chain index set to 0.
    ///
    /// The contract inbound and outbound addresses are set to the values of the
    /// validators.
    pub(super) fn with_unknown_contract_state(
        validators: OrderedAssociated<PublicKey, SocketAddrOrFqdnPort>,
    ) -> Self {
        let validators = validators
            .iter_pairs()
            .map(|(key, addr)| {
                let key = key.clone();
                let validator = DecodedValidator {
                    public_key: key.clone(),
                    inbound: addr.to_string(),
                    outbound: addr.to_string(),
                    index: 0,
                    address: Address::ZERO,
                };
                (key, validator)
            })
            .collect();
        Self::new(validators)
    }

    pub(super) fn dealers(&self) -> &OrderedAssociated<PublicKey, DecodedValidator> {
        &self.dealers
    }

    pub(super) fn players(&self) -> &OrderedAssociated<PublicKey, DecodedValidator> {
        &self.players
    }

    pub(super) fn syncing_players(&self) -> &OrderedAssociated<PublicKey, DecodedValidator> {
        &self.syncing_players
    }

    pub(super) fn dealer_pubkeys(&self) -> Ordered<PublicKey> {
        self.dealers.keys().clone()
    }

    pub(super) fn player_pubkeys(&self) -> Ordered<PublicKey> {
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
    pub(super) fn resolve_addresses_and_merge_peers(
        &self,
    ) -> OrderedAssociated<PublicKey, SocketAddr> {
        // IMPORTANT: Starting with the syncing players to ensure that the
        // latest address for a validator with a given pubkey is used.
        // OrderedAssociated takes the first instance of a key it sees and
        // drops the later instances.
        self.syncing_players()
            .iter_pairs()
            .chain(self.players().iter_pairs())
            .chain(self.dealers().iter_pairs())
            .filter_map(|(pubkey, validator)| {
                let addr = validator.inbound_to_socket_addr().ok()?;
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
    pub(super) fn push_on_success(
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
    pub(super) fn push_on_failure(
        &mut self,
        syncing_players: OrderedAssociated<PublicKey, DecodedValidator>,
    ) -> OrderedAssociated<PublicKey, DecodedValidator> {
        let players = std::mem::replace(&mut self.syncing_players, syncing_players);
        let dropped = std::mem::replace(&mut self.players, players);
        dropped
    }
}

impl Write for ValidatorState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealers().write(buf);
        self.players().write(buf);
        self.syncing_players().write(buf);
    }
}

impl EncodeSize for ValidatorState {
    fn encode_size(&self) -> usize {
        self.dealers().encode_size()
            + self.players().encode_size()
            + self.syncing_players().encode_size()
    }
}

impl Read for ValidatorState {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        // The range 0..=usize::MAX here is ok: what we are writing to disk
        // is completely under our control and there is no danger of DoS.
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

/// A ContractValidator is a peer read from the validator config smart const.
///
/// The inbound and outbound addresses stored herein are guaranteed to be of the
/// form `<host>:<port>` for inbound, and `<ip>:<port>` for outbound. Here,
/// `<host>` is either an IPv4 or IPV6 address, or a fully qualified domain name.
/// `<ip>` is an IPv4 or IPv6 address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DecodedValidator {
    pub(super) public_key: PublicKey,
    pub(super) inbound: String,
    pub(super) outbound: String,
    pub(super) index: u64,
    pub(super) address: Address,
}

impl DecodedValidator {
    /// Attempts to decode a single validator from the values read in the smart contract.
    ///
    /// This function does not perform hostname lookup on either of the addresses.
    /// Instead, only the shape of the addresses are checked for whether they are
    /// socket addresses (IP:PORT pairs), or fully qualified domain names.
    #[instrument(ret(Display, level = Level::INFO), err(level = Level::WARN))]
    pub(super) fn decode_from_contract(
        IValidatorConfig::Validator {
            publicKey,
            active,
            index,
            validatorAddress,
            inboundAddress,
            outboundAddress,
            ..
        }: IValidatorConfig::Validator,
    ) -> eyre::Result<Self> {
        ensure!(
            active,
            "field `active` is set to false; this method should only be called \
            for active validators"
        );
        let public_key = PublicKey::decode(publicKey.as_ref())
            .wrap_err("failed decoding publicKey field as ed25519 public key")?;
        ensure_inbound_is_host_port(&inboundAddress).wrap_err("inboundAddress was not valid")?;
        ensure_outbound_is_ip_port(&outboundAddress).wrap_err("outboundAddress was not valid")?;
        Ok(Self {
            public_key,
            inbound: inboundAddress,
            outbound: outboundAddress,
            index,
            address: validatorAddress,
        })
    }

    /// Converts a decoded validator to a (pubkey, socket addr) pair.
    ///
    /// At the moment, only the inbound address is considered (constraint of
    /// [`commonware_p2p::authenticated::lookup`]). If the inbound value is a
    /// socket address, then the conversion is immediate. If is a domain name,
    /// the domain name is resolved. If DNS resolution returns more than 1 value,
    /// the last one is taken.
    #[instrument(skip_all, fields(public_key = %self.public_key, inbound = self.inbound), err)]
    fn inbound_to_socket_addr(&self) -> eyre::Result<SocketAddr> {
        let all_addrs = self
            .inbound
            .to_socket_addrs()
            .wrap_err_with(|| format!("failed resolving inbound address `{}`", self.inbound))?
            .collect::<Vec<_>>();
        let addr = match &all_addrs[..] {
            [] => return Err(eyre::eyre!("found no addresses for `{}`", self.inbound)),
            [addr] => *addr,
            [dropped @ .., addr] => {
                info!(
                    ?dropped,
                    "resolved to more than one; dropping all except the last"
                );
                *addr
            }
        };
        info!(%addr, "using address");
        Ok(addr)
    }
}

impl std::fmt::Display for DecodedValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "public key = `{}`, inbound = `{}`, outbound = `{}`, index = `{}`, address = `{}`",
            self.public_key, self.inbound, self.outbound, self.index, self.address
        ))
    }
}

impl Write for DecodedValidator {
    fn write(&self, buf: &mut impl bytes::BufMut) {
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

    fn read_cfg(
        mut buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let public_key = PublicKey::read_cfg(buf, &())?;
        let inbound = {
            // 253 is the maximum length of a fqdn.
            let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=253usize), ()))?;
            String::from_utf8(bytes).map_err(|_| {
                commonware_codec::Error::Invalid("decode inbound address", "not utf8")
            })?
        };
        let outbound = {
            // 253 is the maximum length of a fqdn.
            let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=253usize), ()))?;
            String::from_utf8(bytes).map_err(|_| {
                commonware_codec::Error::Invalid("decode outbound address", "not utf8")
            })?
        };
        let index = UInt::read_cfg(&mut buf, &())?.into();
        let address = Address::new(<[u8; 20]>::read_cfg(&mut buf, &())?);
        Ok(Self {
            public_key,
            inbound,
            outbound,
            index,
            address,
        })
    }
}

fn last_height_before_epoch(epoch: Epoch, epoch_length: u64) -> u64 {
    epoch
        .checked_sub(1)
        .map_or(0, |epoch| utils::last_block_in_epoch(epoch_length, epoch))
}

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{PrivateKeyExt, Signer, ed25519::PrivateKey};

    use crate::dkg::manager::DecodedValidator;

    #[test]
    fn roundtrip_decoded_validator() {
        let private_key = PrivateKey::from_seed(42);
        let decoded_validator = DecodedValidator {
            public_key: private_key.public_key(),
            inbound: "localhost:1234".into(),
            outbound: "localhost:4321".into(),
            index: 42,
            address: alloy_primitives::Address::ZERO,
        };
        assert_eq!(
            decoded_validator,
            DecodedValidator::decode(&mut decoded_validator.encode().freeze()).unwrap()
        );
    }
}
