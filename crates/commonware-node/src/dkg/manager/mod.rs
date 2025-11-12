use std::net::{SocketAddr, ToSocketAddrs};

use alloy_primitives::Address;
use commonware_codec::DecodeExt as _;
use commonware_cryptography::{
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_utils::set::OrderedAssociated;
use eyre::{WrapErr as _, ensure};
use futures::channel::mpsc;
use rand_core::CryptoRngCore;
use tempo_node::TempoFullNode;

mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

use ingress::{Command, Message};
use tempo_precompiles::validator_config::IValidatorConfig;
use tracing::{Level, info, instrument};

use crate::epoch;

pub(crate) async fn init<TContext, TPeerManager>(
    context: TContext,
    config: Config<TPeerManager>,
) -> eyre::Result<(Actor<TContext, TPeerManager>, Mailbox)>
where
    TContext: Clock + CryptoRngCore + Metrics + Spawner + Storage,
    TPeerManager: commonware_p2p::Manager<
            PublicKey = PublicKey,
            Peers = OrderedAssociated<PublicKey, SocketAddr>,
        >,
{
    let (tx, rx) = mpsc::unbounded();

    let actor = Actor::init(config, context, rx)
        .await
        .wrap_err("failed initializing actor")?;
    let mailbox = Mailbox { inner: tx };
    Ok((actor, mailbox))
}

pub(crate) struct Config<TPeerManager> {
    pub(crate) epoch_manager: epoch::manager::Mailbox,

    /// The namespace the dkg manager will use when sending messages during
    /// a dkg ceremony.
    pub(crate) namespace: Vec<u8>,

    pub(crate) me: PrivateKey,

    /// The number of heights per epoch.
    pub(crate) epoch_length: u64,

    pub(crate) mailbox_size: usize,

    /// The partition prefix to use when persisting ceremony metadata during
    /// rounds.
    pub(crate) partition_prefix: String,

    /// The full execution layer node. Used to read the initial set of peers
    /// from chainspec.
    pub(crate) execution_node: TempoFullNode,

    /// This node's initial share of the bls12381 private key.
    pub(crate) initial_share: Option<Share>,

    /// The peer manager on which the dkg actor will register new peers for a
    /// given epoch after reading them from the smart contract.
    pub(crate) peer_manager: TPeerManager,
}

/// A ContractValidator is a peer read from the validator config smart const.
///
/// The inbound and outbound addresses stored herein are guaranteed to be of the
/// form `<host>:<port>` for inbound, and `<ip>:<port>` for outbound. Here,
/// `<host>` is either an IPv4 or IPV6 address, or a fully qualified domain name.
/// `<ip>` is an IPv4 or IPv6 address.
#[derive(Debug)]
struct DecodedValidator {
    public_key: PublicKey,
    inbound: String,
    outbound: String,
    index: u64,
    address: Address,
}

impl DecodedValidator {
    /// Attempts to decode a single validator from the values read in the smart contract.
    ///
    /// This function does not perform hostname lookup on either of the addresses.
    /// Instead, only the shape of the addresses are checked for whether they are
    /// socket addresses (IP:PORT pairs), or fully qualified domain names.
    #[instrument(ret(Display, level = Level::INFO), err(level = Level::WARN))]
    fn decode_from_contract(
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
        tempo_precompiles::validator_config::ensure_inbound_is_host_port(&inboundAddress)
            .wrap_err("inboundAddress was not valid")?;
        tempo_precompiles::validator_config::ensure_outbound_is_ip_port(&outboundAddress)
            .wrap_err("outboundAddress was not valid")?;
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
