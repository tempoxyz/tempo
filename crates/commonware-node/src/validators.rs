use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, B256};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::Ingress;
use commonware_utils::{TryFromIterator, ordered};
use eyre::{OptionExt as _, WrapErr as _};
use reth_ethereum::evm::revm::{State, database::StateProviderDatabase};
use reth_node_builder::ConfigureEvm as _;
use reth_provider::{HeaderProvider as _, StateProviderBox, StateProviderFactory as _};
use tempo_node::{TempoFullNode, evm::evm::TempoEvm};
use tempo_precompiles::{
    storage::StorageCtx,
    validator_config_v2::{IValidatorConfigV2, ValidatorConfigV2},
};
use tempo_primitives::TempoHeader;

use tracing::{Level, debug, instrument, warn};

use crate::utils::public_key_to_b256;

/// Minimal execution-node interface needed to read validator config state.
///
/// Production code uses [`TempoFullNode`]. This trait exists so unit tests can
/// use a mock that only provides a historical state provider and an EVM
/// configured for the corresponding block, while still exercising the same
/// validator config reader used in production.
pub(crate) trait ExecutionNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader>;

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox>;

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<StateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<StateProviderBox>>>>;
}

impl ExecutionNode for TempoFullNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
        self.provider
            .header(block_hash)
            .map_err(eyre::Report::new)
            .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty header"))
    }

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox> {
        self.provider
            .state_by_block_hash(block_hash)
            .map_err(eyre::Report::new)
    }

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<StateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<StateProviderBox>>>> {
        self.evm_config
            .evm_for_block(db, header)
            .map_err(eyre::Report::new)
    }
}

impl<N> ExecutionNode for &N
where
    N: ExecutionNode,
{
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
        (*self).header(block_hash)
    }

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<StateProviderBox> {
        (*self).state_by_block_hash(block_hash)
    }

    fn evm_for_block(
        &self,
        db: State<StateProviderDatabase<StateProviderBox>>,
        header: &TempoHeader,
    ) -> eyre::Result<TempoEvm<State<StateProviderDatabase<StateProviderBox>>>> {
        (*self).evm_for_block(db, header)
    }
}

/// Returns active validator config v2 entries at block `hash`.
///
/// This returns both the validators that are `active` as per the contract, and
/// those that are `known`.
pub(crate) fn read_active_and_known_peers_at_block_hash(
    node: impl ExecutionNode,
    known: &ordered::Set<PublicKey>,
    hash: B256,
) -> eyre::Result<ordered::Map<PublicKey, commonware_p2p::Address>> {
    read_validator_config_at_block_hash(node, hash, |config: &ValidatorConfigV2| {
        let mut all = HashMap::new();
        for raw in config
            .get_active_validators()
            .wrap_err("failed getting active validator set")?
        {
            if let Ok(decoded) = DecodedValidatorV2::decode_from_contract(raw)
                && all
                    .insert(decoded.public_key.clone(), decoded.to_p2p_address())
                    .is_some()
            {
                warn!(
                    duplicate = %decoded.public_key,
                    "found duplicate public keys",
                );
            }
        }
        debug!(
            active_validators = ?all,
            "read active validators from contract, now extending with historic \
            peers that are still in the peer set but no longer marked active",
        );
        for member in known {
            if !all.contains_key(member) {
                let decoded = config
                    .validator_by_public_key(public_key_to_b256(member))
                    .map_err(eyre::Report::new)
                    .and_then(DecodedValidatorV2::decode_from_contract)
                    .wrap_err_with(|| format!("failed to read peer `{member}` from contract"))
                    .expect(
                        "invariant: known peers must have an entry in the \
                        smart contract and be well formed",
                    );
                all.insert(decoded.public_key.clone(), decoded.to_p2p_address());
            }
        }
        Ok(ordered::Map::try_from_iter(all).expect("hashmaps don't contain duplicates"))
    })
    .map(|(_height, _hash, value)| value)
}

/// Reads the validator state at the given block hash.
#[instrument(skip_all, fields(%block_hash), err(Display))]
pub(crate) fn read_validator_config_at_block_hash<C, T>(
    node: impl ExecutionNode,
    block_hash: B256,
    read_fn: impl FnOnce(&C) -> eyre::Result<T>,
) -> eyre::Result<(u64, B256, T)>
where
    C: Default,
{
    let header = node
        .header(block_hash)
        .wrap_err_with(|| format!("failed reading block with hash `{block_hash}`"))?;

    debug!(height = header.number(), "header found");

    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.state_by_block_hash(block_hash).wrap_err_with(|| {
                format!("failed to get state from node provider for hash `{block_hash}`")
            })?,
        ))
        .build();

    let mut evm = node
        .evm_for_block(db, &header)
        .wrap_err("failed instantiating evm for block")?;

    let ctx = evm.ctx_mut();
    let res = StorageCtx::enter_evm(
        &mut ctx.journaled_state,
        &ctx.block,
        &ctx.cfg,
        &ctx.tx,
        || read_fn(&C::default()),
    )?;
    Ok((header.number(), block_hash, res))
}

/// An entry in the validator config v2 contract with all its fields decoded
/// into Rust types.
pub(crate) struct DecodedValidatorV2 {
    public_key: PublicKey,
    ingress: SocketAddr,
    egress: IpAddr,
    added_at_height: u64,
    deleted_at_height: u64,
    index: u64,
    address: Address,
}

impl DecodedValidatorV2 {
    #[instrument(ret(Display, level = Level::DEBUG), err(level = Level::WARN))]
    pub(crate) fn decode_from_contract(
        IValidatorConfigV2::Validator {
            publicKey,
            validatorAddress: address,
            ingress,
            egress,
            index,
            addedAtHeight: added_at_height,
            deactivatedAtHeight: deleted_at_height,
            ..
        }: IValidatorConfigV2::Validator,
    ) -> eyre::Result<Self> {
        let public_key = PublicKey::decode(publicKey.as_ref())
            .wrap_err("failed decoding publicKey field as ed25519 public key")?;
        let ingress = ingress.parse().wrap_err("ingress was not valid")?;
        let egress = egress.parse().wrap_err("egress was not valid")?;
        Ok(Self {
            public_key,
            ingress,
            egress,
            added_at_height,
            deleted_at_height,
            index,
            address,
        })
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub(crate) fn to_p2p_address(&self) -> commonware_p2p::Address {
        // NOTE: commonware takes egress as socket address but only uses the IP part.
        // So setting port to 0 is ok.
        commonware_p2p::Address::Asymmetric {
            ingress: Ingress::Socket(self.ingress),
            egress: SocketAddr::from((self.egress, 0)),
        }
    }
}
impl std::fmt::Display for DecodedValidatorV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "public key = `{}`, ingress = `{}`, egress = `{}`, added_at_height: `{}`, deleted_at_height = `{}`, index = `{}`, address = `{}`",
            self.public_key,
            self.ingress,
            self.egress,
            self.added_at_height,
            self.deleted_at_height,
            self.index,
            self.address
        ))
    }
}
