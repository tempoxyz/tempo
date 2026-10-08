use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    num::NonZeroU64,
};

use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, B256, U256};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::Ingress;
use commonware_utils::{TryFromIterator, ordered};
use eyre::{OptionExt as _, WrapErr as _};
use reth_ethereum::{
    chainspec::EthChainSpec as _,
    evm::revm::{
        Journal,
        context::{BlockEnv, CfgEnv, JournalTr as _, TxEnv},
        database::StateProviderDatabase,
    },
};
use reth_provider::{
    EvmStateProviderBox, HeaderProvider as _, StateProvider as _, StateProviderFactory as _,
};
use tempo_chainspec::{TempoChainSpec, TempoHardforks as _};
use tempo_node::TempoFullNode;
use tempo_precompiles::{
    storage::{StorageActions, StorageCtx},
    validator_config_v2::{IValidatorConfigV2, ValidatorConfigV2},
};
use tempo_primitives::{TempoBlockEnv, TempoHeader};

use tracing::{Level, debug, instrument, warn};

/// Minimal execution-node interface needed to read validator config state.
///
/// Production code uses [`TempoFullNode`]. This trait exists so unit tests can
/// use a mock that only provides historical state and its chain schedule.
/// Reading storage does not require the node to support execution of the block.
pub(crate) trait ExecutionNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader>;

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<EvmStateProviderBox>;

    fn chain_spec(&self) -> &TempoChainSpec;
}

impl ExecutionNode for TempoFullNode {
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
        self.provider
            .header(block_hash)
            .map_err(eyre::Report::new)
            .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty header"))
    }

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<EvmStateProviderBox> {
        let provider = self
            .provider
            .state_by_block_hash(block_hash)
            .map_err(eyre::Report::new)?;
        Ok(Box::new(provider.into_evm_state_provider()))
    }

    fn chain_spec(&self) -> &TempoChainSpec {
        self.evm_config.chain_spec()
    }
}

impl<N> ExecutionNode for &N
where
    N: ExecutionNode,
{
    fn header(&self, block_hash: B256) -> eyre::Result<TempoHeader> {
        (*self).header(block_hash)
    }

    fn state_by_block_hash(&self, block_hash: B256) -> eyre::Result<EvmStateProviderBox> {
        (*self).state_by_block_hash(block_hash)
    }

    fn chain_spec(&self) -> &TempoChainSpec {
        (*self).chain_spec()
    }
}

/// Returns the validators that are `active` in the validator config v2
/// contract, with their p2p addresses. Entries that fail to decode are
/// skipped.
pub(crate) fn read_active_peers(
    config: &ValidatorConfigV2,
) -> eyre::Result<ordered::Map<PublicKey, commonware_p2p::Address>> {
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
    debug!(active_validators = ?all, "read active validators from contract");
    Ok(ordered::Map::try_from_iter(all).expect("hashmaps don't contain duplicates"))
}

/// Reads the validator state at the given block hash.
///
/// Note that `block_hash` must be a block hash of a canonical block.
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

    let state = node.state_by_block_hash(block_hash).wrap_err_with(|| {
        format!("failed to get state from node provider for hash `{block_hash}`")
    })?;
    let res = read_validator_config_with_state(node, state, &header, read_fn)?;
    Ok((header.number(), block_hash, res))
}

/// Reads the validator state from `state`, which must be the post-state of
/// the block with `header`.
pub(crate) fn read_validator_config_with_state<C, T>(
    node: impl ExecutionNode,
    state: EvmStateProviderBox,
    header: &TempoHeader,
    read_fn: impl FnOnce(&C) -> eyre::Result<T>,
) -> eyre::Result<T>
where
    C: Default,
{
    let chain_spec = node.chain_spec();
    let cfg = CfgEnv::new_with_spec(chain_spec.tempo_hardfork_at(header.timestamp()))
        .with_chain_id(chain_spec.chain_id());
    let block = TempoBlockEnv {
        inner: BlockEnv {
            number: U256::from(header.number()),
            timestamp: U256::from(header.timestamp()),
            ..Default::default()
        },
        timestamp_millis_part: header.timestamp_millis_part,
        epoch_length: chain_spec.info.epoch_length().unwrap_or(NonZeroU64::MIN),
        proposer_public_key: header.consensus_context.map(|ctx| ctx.proposer),
    };
    let mut journal = Journal::<_>::new(StateProviderDatabase::new(state));
    journal.set_spec_id(cfg.spec.into());
    // Install a storage context without creating an executor or invoking any
    // EVM/precompile dispatch. Historical state remains readable even when the
    // binary no longer executes the hardfork that produced it.
    let res = StorageCtx::enter_evm(
        &mut journal,
        &block,
        &cfg,
        &TxEnv::default(),
        StorageActions::disabled(),
        || read_fn(&C::default()),
    )?;
    Ok(res)
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

#[cfg(test)]
mod tests {
    use alloy_consensus::{Header, Sealable as _};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use tempo_chainspec::{
        TempoHardfork, constants::moderato::MODERATO_T11_TIMESTAMP, spec::MODERATO,
    };
    use tempo_precompiles::storage::hashmap::HashMapStorageProvider;

    use super::*;

    struct HistoricalState {
        header: TempoHeader,
        provider: MockEthProvider,
    }

    impl ExecutionNode for HistoricalState {
        fn header(&self, hash: B256) -> eyre::Result<TempoHeader> {
            assert_eq!(hash, self.header.hash_slow());
            Ok(self.header.clone())
        }

        fn state_by_block_hash(&self, hash: B256) -> eyre::Result<EvmStateProviderBox> {
            assert_eq!(hash, self.header.hash_slow());
            Ok(Box::new(self.provider.clone().into_evm_state_provider()))
        }

        fn chain_spec(&self) -> &TempoChainSpec {
            &MODERATO
        }
    }

    #[test]
    fn reads_historical_validator_state_without_an_executor() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(42431, TempoHardfork::T10);
        let owner = Address::repeat_byte(0xAA);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut config = ValidatorConfigV2::new();
            config.initialize(owner)?;
            config.set_network_identity_rotation_epoch(
                owner,
                IValidatorConfigV2::setNetworkIdentityRotationEpochCall { epoch: 42 },
            )?;
            Ok(())
        })?;

        let mut accounts = HashMap::<Address, Vec<(B256, U256)>>::new();
        for (address, slot, value) in storage.into_storage() {
            accounts
                .entry(address)
                .or_default()
                .push((B256::from(slot), value));
        }
        let provider = MockEthProvider::new();
        for (address, storage) in accounts {
            provider.add_account(
                address,
                ExtendedAccount::new(0, U256::ZERO).extend_storage(storage),
            );
        }
        let node = HistoricalState {
            header: TempoHeader {
                inner: Header {
                    number: 123,
                    timestamp: MODERATO_T11_TIMESTAMP - 1,
                    ..Default::default()
                },
                ..Default::default()
            },
            provider,
        };
        let hash = node.header.hash_slow();
        let (height, returned_hash, rotation_epoch) =
            read_validator_config_at_block_hash(&node, hash, |config: &ValidatorConfigV2| {
                let storage = StorageCtx::default();
                assert_eq!(storage.spec(), TempoHardfork::T10);
                assert_eq!(storage.chain_id(), 42431);
                assert_eq!(storage.block_number(), 123);
                Ok(config.get_next_network_identity_rotation_epoch()?)
            })?;
        assert_eq!((height, returned_hash, rotation_epoch), (123, hash, 42));
        Ok(())
    }
}
