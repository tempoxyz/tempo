//! Restarts consensus after an epoch lost its threshold signing key.
//!
//! The chainspec's [`tempo_chainspec::Recovery`] pins the last finalized block of the halted
//! epoch and the hash of the boundary block that ends it. Every node builds the same empty blocks
//! up to that boundary, writes the recovery DKG outcome into the boundary, and finalizes it in the
//! execution layer. The next epoch starts from that outcome. Marshal finalizes the filled blocks
//! later, as ancestors of the next epoch's first finalized block.

use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, B256, Bytes};
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_codec::{DecodeExt as _, Encode as _, ReadExt as _};
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{self, Output},
        primitives::{group::Share, sharing::Mode, variant::MinSig},
    },
    ed25519::PublicKey,
};
use commonware_utils::{N3f1, TryFromIterator as _, ordered};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use rand_core::CryptoRng;
use reth_chain_state::ExecutedBlock;
use reth_evm::{
    ConfigureEvm as _, NextBlockEnvAttributes,
    database::StateProviderDatabase,
    execute::{BlockBuilder as _, BlockBuilderOutcome},
};
use reth_execution_types::BlockExecutionOutput;
use reth_primitives_traits::{RecoveredBlock, SealedHeader, SealedOrRecoveredBlock};
use reth_provider::{
    BlockHashReader as _, BlockNumReader, ChainStateBlockReader, ChangeSetReader,
    DatabaseProviderFactory, HeaderProvider, HistoryReader, PruneCheckpointReader,
    StageCheckpointReader, StorageChangeSetReader, StorageSettingsCache,
};
use reth_storage_api::{DatabaseProviderROFactory as _, StateProvider as _};
use reth_storage_overlay::{OverlayManager, OverlayStateProviderFactory};
use reth_trie_common::SortedTrieData;
use tempo_chainspec::{NetworkIdentity, TempoChainSpec};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes, TempoStateAccess};
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_primitives::{Block, TempoConsensusContext, TempoHeader, TempoPrimitives};
use tracing::{info, instrument};

use crate::consensus::Digest;

/// A validated [`tempo_chainspec::Recovery`].
#[derive(Clone, Debug)]
pub(crate) struct Recovery {
    /// The last block finalized before consensus halted.
    last_finalized: (Height, Digest),
    /// The last block of the halted epoch, carrying `outcome`.
    boundary: (Height, Digest),
    /// The DKG outcome for the epoch after the halted one: a single member's 1-of-1 output,
    /// whose ceremony reshares to the halted epoch's next players.
    outcome: OnchainDkgOutcome,
}

impl Recovery {
    /// Reads and validates the chainspec's recovery. Returns `None` if the chainspec has none.
    pub(crate) fn from_chainspec(
        chain_spec: &TempoChainSpec,
        epoch_strategy: &FixedEpocher,
    ) -> eyre::Result<Option<Self>> {
        let Some(recovery) = chain_spec.info.recovery() else {
            return Ok(None);
        };

        let finalized_height = Height::new(recovery.finalized_height);
        let epoch_info = epoch_strategy
            .containing(finalized_height)
            .expect("epoch strategy is valid for all heights");
        let boundary = epoch_info.last();
        ensure!(
            finalized_height < boundary,
            "recovery finalized height `{finalized_height}` is the boundary of epoch `{}`; \
            there is nothing to fill",
            epoch_info.epoch(),
        );

        let outcome =
            OnchainDkgOutcome::decode(commonware_codec::Copying(recovery.outcome.as_ref()))
                .wrap_err("recovery outcome is not a valid DKG outcome")?;
        ensure!(
            outcome.epoch() == epoch_info.epoch().next(),
            "recovery outcome is for epoch `{}`, but the boundary at height `{boundary}` must \
            carry the outcome for epoch `{}`",
            outcome.epoch,
            epoch_info.epoch().next(),
        );

        let validated = Self {
            last_finalized: (finalized_height, Digest(recovery.finalized_hash)),
            boundary: (boundary, Digest(recovery.boundary_hash)),
            outcome,
        };
        Ok(Some(validated))
    }

    /// The identity that verifies finalizations from the epoch after the halted one.
    pub(crate) fn network_identity(&self) -> NetworkIdentity {
        NetworkIdentity {
            from_epoch: self.outcome.epoch,
            identity: *self.outcome.network_identity(),
        }
    }

    /// The boundary block that ends the halted epoch.
    pub(crate) fn boundary(&self) -> (Height, Digest) {
        self.boundary
    }

    /// Builds and imports the empty blocks after the last finalized block up to the boundary,
    /// then finalizes the boundary in the execution layer.
    ///
    /// Does nothing if the execution layer already finalized the boundary. Fails if the boundary
    /// this node builds does not match the pinned hash, or if the execution layer lacks the
    /// recovery's finalized block or finalized past it without reaching the boundary.
    #[instrument(skip_all, fields(last_finalized = %self.last_finalized.0, boundary = %self.boundary.0), err)]
    pub(crate) async fn fill_to_boundary(&self, node: &TempoFullNode) -> eyre::Result<()> {
        let ((finalized_height, Digest(finalized_hash)), (boundary, Digest(boundary_hash))) =
            (self.last_finalized, self.boundary);
        let finalized = node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .ok_or_eyre("execution layer has not finalized any block")?;

        if finalized.number >= boundary.get() {
            let hash = node
                .provider
                .block_hash(boundary.get())
                .wrap_err("failed reading the boundary hash")?
                .ok_or_eyre("execution layer finalized past the boundary but does not have it")?;
            ensure!(
                hash == boundary_hash,
                "execution layer finalized boundary `{hash}`, but the recovery pins `{}`",
                boundary_hash,
            );
            info!("execution layer already finalized the recovery boundary");
            return Ok(());
        }

        // Nodes can lag the network's last finalized block, but must have it.
        ensure!(
            finalized.number <= finalized_height.get(),
            "recovery starts at height `{finalized_height}`, but the execution layer finalized \
            `{}` at height `{}` past it",
            finalized.hash,
            finalized.number,
        );
        let parent = node
            .provider
            .sealed_header(finalized_height.get())
            .wrap_err("failed reading the recovery's finalized header")?
            .filter(|header| header.hash() == finalized_hash)
            .ok_or_else(|| {
                eyre::eyre!(
                    "execution layer does not have the recovery's finalized block \
                    `{finalized_hash}` at height `{finalized_height}`; sync it first"
                )
            })?;

        info!("filling the halted epoch with empty blocks");
        // Nothing can proceed until the boundary exists, so block on the build.
        let blocks = build_fill_blocks(
            node.provider.clone(),
            &node.evm_config,
            &node.chain_spec(),
            parent,
            boundary,
            &self.outcome,
        )?;
        let built = blocks
            .last()
            .expect("a recovery fills at least one block")
            .hash();
        ensure!(
            built == boundary_hash,
            "this node built boundary `{built}`, but the recovery pins `{}`",
            boundary_hash,
        );

        let engine = node.add_ons_handle.beacon_engine_handle.clone();
        for block in blocks {
            let number = block.number();
            let status = engine
                .new_payload(TempoExecutionData {
                    block: SealedOrRecoveredBlock::recovered_arc(Arc::new(block)),
                })
                .await
                .wrap_err_with(|| format!("failed submitting fill block `{number}`"))?;
            ensure!(
                status.is_valid(),
                "execution layer rejected fill block `{number}`: {status:?}",
            );
        }

        let response = engine
            .fork_choice_updated(
                ForkchoiceState {
                    head_block_hash: boundary_hash,
                    safe_block_hash: boundary_hash,
                    finalized_block_hash: boundary_hash,
                },
                None,
            )
            .await
            .wrap_err("failed finalizing the recovery boundary")?;
        ensure!(
            response.is_valid(),
            "execution layer refused to finalize the recovery boundary: {:?}",
            response.payload_status,
        );
        info!(boundary_hash = %boundary_hash, "finalized the recovery boundary");
        Ok(())
    }
}

/// Prepares the recovery of a chain halted inside an epoch whose threshold signing key was lost.
///
/// `factory` must have the halted chain up to its last finalized block. Returns the chainspec
/// `recovery` entry and `member`'s 1-of-1 share for the epoch after the halted one; that epoch's
/// ceremony then reshares to the halted epoch's next players.
pub fn prepare<TFactory>(
    factory: TFactory,
    chain_spec: &Arc<TempoChainSpec>,
    member: PublicKey,
    rng: impl CryptoRng,
) -> eyre::Result<(tempo_chainspec::Recovery, Share)>
where
    TFactory: DatabaseProviderFactory + HeaderProvider<Header = TempoHeader> + Clone,
    TFactory::Provider: HistoryReader
        + StorageSettingsCache
        + StageCheckpointReader
        + PruneCheckpointReader
        + ChangeSetReader
        + StorageChangeSetReader
        + BlockNumReader
        + ChainStateBlockReader,
{
    let epocher = FixedEpocher::new(
        chain_spec
            .info
            .epoch_length()
            .ok_or_eyre("epochLength not found in chainspec")?,
    );

    let finalized = last_finalized_header(&factory)?;
    let finalized_height = Height::new(finalized.number());
    let epoch_info = epocher
        .containing(finalized_height)
        .expect("fixed epocher is valid for all heights");
    ensure!(
        epoch_info.last() != finalized_height,
        "the finalized block `{finalized_height}` is the boundary of epoch `{}`; the next \
        epoch can start from it without recovery",
        epoch_info.epoch(),
    );

    let halted = halted_outcome(&factory, &epocher, epoch_info.epoch())?;
    ensure!(
        halted.next_players().position(&member).is_some(),
        "member `{member}` is not among the halted epoch's next players",
    );

    let (output, share) = deal_to(member, rng)?;
    let outcome = OnchainDkgOutcome {
        epoch: epoch_info.epoch().next().get(),
        output,
        next_players: halted.next_players,
        is_next_full_dkg: false,
    };

    let blocks = build_fill_blocks(
        factory,
        &TempoEvmConfig::new(chain_spec.clone()),
        chain_spec,
        finalized.clone(),
        epoch_info.last(),
        &outcome,
    )
    .wrap_err("failed building the fill blocks")?;
    let boundary = blocks.last().expect("a recovery fills at least one block");

    let recovery = tempo_chainspec::Recovery {
        finalized_height: finalized_height.get(),
        finalized_hash: finalized.hash(),
        boundary_hash: boundary.hash(),
        outcome: Bytes::from(outcome.encode().to_vec()),
    };
    Ok((recovery, share))
}

/// Reads the last block the execution layer finalized.
fn last_finalized_header<TFactory>(factory: &TFactory) -> eyre::Result<SealedHeader<TempoHeader>>
where
    TFactory: DatabaseProviderFactory + HeaderProvider<Header = TempoHeader>,
    TFactory::Provider: ChainStateBlockReader,
{
    let height = factory
        .database_provider_ro()
        .wrap_err("failed opening the database")?
        .last_finalized_block_number()
        .wrap_err("failed reading the finalized block number")?
        .ok_or_eyre("datadir has no finalized block")?;
    factory
        .sealed_header(height)
        .wrap_err("failed reading the finalized header")?
        .ok_or_eyre("datadir does not have the finalized header")
}

/// Reads the DKG outcome that started `halted_epoch`, which names the players its ceremony would
/// have dealt to.
fn halted_outcome<TFactory>(
    factory: &TFactory,
    epocher: &FixedEpocher,
    halted_epoch: Epoch,
) -> eyre::Result<OnchainDkgOutcome>
where
    TFactory: HeaderProvider<Header = TempoHeader>,
{
    let boundary = halted_epoch.previous().map_or(0, |previous| {
        epocher
            .last(previous)
            .expect("fixed epocher is valid for all epochs")
            .get()
    });
    let header = factory
        .header_by_number(boundary)
        .wrap_err_with(|| format!("failed reading boundary block `{boundary}`"))?
        .ok_or_eyre("datadir does not have the halted epoch's boundary block")?;
    OnchainDkgOutcome::read(&mut commonware_codec::Copying(header.extra_data().as_ref()))
        .wrap_err("halted epoch's boundary block has no DKG outcome")
}

/// Deals a fresh 1-of-1 threshold key to `member`.
fn deal_to(
    member: PublicKey,
    rng: impl CryptoRng,
) -> eyre::Result<(Output<MinSig, PublicKey>, Share)> {
    let players = ordered::Set::try_from_iter([member]).expect("a single player is unique");
    let (output, shares) = feldman_desmedt::deal::<_, _, N3f1>(rng, Mode::NonZeroCounter, players)
        .wrap_err("failed dealing the recovery share")?;
    let (_, share) = shares
        .into_iter()
        .next()
        .expect("dealing to one player yields one share");
    Ok((output, share))
}

/// Builds the empty blocks after `parent` up to `boundary`, writing `outcome` into the boundary.
///
/// `factory` must have the state after `parent`. Every node and `xtask recover` call this to get
/// the same blocks: each block advances the timestamp by one millisecond, continues the parent's
/// views and keeps its gas limit. Each pays the fee recipient of the proposer it inherits.
pub fn build_fill_blocks<TFactory>(
    factory: TFactory,
    evm_config: &TempoEvmConfig,
    chain_spec: &TempoChainSpec,
    mut parent: SealedHeader<TempoHeader>,
    boundary: Height,
    outcome: &OnchainDkgOutcome,
) -> eyre::Result<Vec<RecoveredBlock<Block>>>
where
    TFactory: DatabaseProviderFactory + Clone,
    TFactory::Provider: HistoryReader
        + StorageSettingsCache
        + StageCheckpointReader
        + PruneCheckpointReader
        + ChangeSetReader
        + StorageChangeSetReader
        + BlockNumReader,
{
    let mut overlay = OverlayManager::<TempoPrimitives>::default().overlay_builder(parent.hash());
    let outcome = Bytes::from(outcome.encode().to_vec());
    let mut blocks = Vec::new();
    while parent.number() < boundary.get() {
        let number = parent.number() + 1;
        let state = OverlayStateProviderFactory::new(factory.clone(), overlay.clone())
            .database_provider_ro()
            .wrap_err_with(|| format!("failed opening the state before fill block `{number}`"))?;

        let extra_data = if number == boundary.get() {
            outcome.clone()
        } else {
            Bytes::new()
        };
        let mut attributes = fill_attributes(chain_spec, &parent, extra_data);
        let mut db = StateProviderDatabase::new((&state).into_evm_state_provider());
        attributes.inner.suggested_fee_recipient =
            proposer_fee_recipient(evm_config, &mut db, &parent, &attributes).wrap_err_with(
                || format!("failed resolving the beneficiary of block `{number}`"),
            )?;

        let mut builder = evm_config
            .builder_for_next_block(db, &parent, attributes)
            .wrap_err_with(|| format!("failed configuring fill block `{number}`"))?;
        builder.apply_pre_execution_changes().wrap_err_with(|| {
            format!("failed applying pre-execution changes of block `{number}`")
        })?;
        let BlockBuilderOutcome {
            execution_result,
            execution_state,
            hashed_state,
            trie_updates,
            block,
            ..
        } = builder
            .finish(&state, None)
            .wrap_err_with(|| format!("failed building fill block `{number}`"))?;

        parent = block.sealed_header().clone();
        let executed = ExecutedBlock::new(
            Arc::new(block.clone()),
            Arc::new(BlockExecutionOutput {
                result: execution_result,
                state: execution_state,
            }),
            SortedTrieData::new(
                Arc::new(hashed_state.into_sorted()),
                Arc::new(trie_updates.into_sorted()),
            ),
        );
        overlay = overlay.with_appended_block(executed);
        blocks.push(block);
    }
    Ok(blocks)
}

/// The beneficiary a fill block must pay: the fee recipient the inherited proposer registered in
/// `ValidatorConfigV2`, which executors check from T14 on, or nobody before it is registered.
fn proposer_fee_recipient(
    evm_config: &TempoEvmConfig,
    db: &mut impl TempoStateAccess,
    parent: &SealedHeader<TempoHeader>,
    attributes: &TempoNextBlockEnvAttributes,
) -> eyre::Result<Address> {
    let Some(context) = attributes.consensus_context else {
        return Ok(Address::ZERO);
    };
    let env = evm_config
        .next_evm_env(parent, attributes)
        .wrap_err("failed configuring the block environment")?;
    let fee_recipient = db
        .proposer_fee_recipient(env.spec, env.block.number, B256::from(context.proposer))
        .wrap_err("failed reading the proposer's fee recipient")?;
    Ok(fee_recipient.unwrap_or(Address::ZERO))
}

/// The attributes of the empty block after `parent`: one millisecond later, the parent's gas
/// limit and next view. The beneficiary is left for [`proposer_fee_recipient`] to resolve.
fn fill_attributes(
    chain_spec: &TempoChainSpec,
    parent: &SealedHeader<TempoHeader>,
    extra_data: Bytes,
) -> TempoNextBlockEnvAttributes {
    let timestamp_millis = parent.timestamp_millis() + 1;
    let timestamp = timestamp_millis / 1000;
    let gas_limit = parent.gas_limit();
    let consensus_context = parent
        .consensus_context
        .map(|context| TempoConsensusContext {
            view: context.view + 1,
            parent_view: context.view,
            ..context
        });

    TempoNextBlockEnvAttributes {
        inner: NextBlockEnvAttributes {
            timestamp,
            suggested_fee_recipient: Address::ZERO,
            prev_randao: B256::ZERO,
            gas_limit,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals: Some(Default::default()),
            extra_data,
            slot_number: None,
        },
        general_gas_limit: chain_spec.general_gas_limit_at(timestamp, gas_limit, 0),
        shared_gas_limit: 0,
        timestamp_millis_part: timestamp_millis % 1000,
        consensus_context,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use alloy_genesis::Genesis;
    use commonware_runtime::{Runner as _, deterministic};

    use crate::test_utils::dkg_fixture;

    fn chain_spec(finalized_height: u64, outcome: &OnchainDkgOutcome) -> TempoChainSpec {
        let genesis: Genesis = serde_json::from_value(serde_json::json!({
            "config": {
                "chainId": 1234,
                "epochLength": 10,
                "recovery": {
                    "finalizedHeight": finalized_height,
                    "finalizedHash": B256::repeat_byte(1),
                    "boundaryHash": B256::repeat_byte(2),
                    "outcome": Bytes::from(outcome.encode().to_vec()),
                },
            },
            "alloc": {}
        }))
        .unwrap();
        TempoChainSpec::from_genesis(genesis)
    }

    fn epoch_strategy() -> FixedEpocher {
        FixedEpocher::new(NonZeroU64::new(10).unwrap())
    }

    #[test]
    fn recovery_fills_to_the_boundary_of_the_halted_epoch() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = dkg_fixture(&mut context, commonware_consensus::types::Epoch::new(2));
            let recovery =
                Recovery::from_chainspec(&chain_spec(13, &fixture.outcome), &epoch_strategy())
                    .unwrap()
                    .unwrap();
            assert_eq!(
                recovery.boundary(),
                (Height::new(19), Digest(B256::repeat_byte(2)))
            );
            assert_eq!(recovery.network_identity().from_epoch, 2);
        });
    }

    #[test]
    fn recovery_rejects_an_outcome_for_another_epoch() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = dkg_fixture(&mut context, commonware_consensus::types::Epoch::new(3));
            let error =
                Recovery::from_chainspec(&chain_spec(13, &fixture.outcome), &epoch_strategy())
                    .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("recovery outcome is for epoch `3`"),
                "{error}"
            );
        });
    }

    #[test]
    fn recovery_rejects_a_finalized_boundary() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = dkg_fixture(&mut context, commonware_consensus::types::Epoch::new(2));
            let error =
                Recovery::from_chainspec(&chain_spec(19, &fixture.outcome), &epoch_strategy())
                    .unwrap_err();
            assert!(
                error.to_string().contains("there is nothing to fill"),
                "{error}"
            );
        });
    }

    #[test]
    fn fill_blocks_are_deterministic_and_end_with_the_outcome() {
        let chain = tempo_chainspec::spec::DEV.clone();
        let factory = reth_provider::test_utils::create_test_provider_factory_with_node_types::<
            tempo_node::TempoNode,
        >(chain.clone());
        reth_db_common::init::init_genesis(&factory).unwrap();
        let genesis = factory.sealed_header(0).unwrap().unwrap();
        let evm_config = TempoEvmConfig::new(chain.clone());
        let outcome =
            dkg_fixture(&mut rand::rng(), commonware_consensus::types::Epoch::new(1)).outcome;

        let build = || {
            build_fill_blocks(
                factory.clone(),
                &evm_config,
                &chain,
                genesis.clone(),
                Height::new(3),
                &outcome,
            )
            .unwrap()
        };
        let blocks = build();

        assert_eq!(
            blocks
                .iter()
                .map(|block| block.number())
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(
            blocks[..2]
                .iter()
                .all(|block| block.extra_data().is_empty())
        );
        assert_eq!(blocks[2].extra_data().as_ref(), outcome.encode().as_ref());
        for (parent, child) in std::iter::once(genesis.hash())
            .chain(blocks.iter().map(|block| block.hash()))
            .zip(&blocks)
        {
            assert_eq!(child.parent_hash(), parent);
        }
        assert_eq!(
            build().iter().map(|block| block.hash()).collect::<Vec<_>>(),
            blocks.iter().map(|block| block.hash()).collect::<Vec<_>>(),
        );
    }
}
