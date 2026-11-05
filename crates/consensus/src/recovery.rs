//! Restarts consensus after an epoch lost its threshold signing key.
//!
//! The chainspec's [`tempo_chainspec::Recovery`] pins the last finalized block of the halted
//! epoch and the hash of the boundary block that ends it. Every node builds the same empty blocks
//! up to that boundary, writes the recovery DKG outcome into the boundary, and finalizes it in the
//! execution layer. The next epoch starts from that outcome. Marshal finalizes the filled blocks
//! later, as ancestors of the next epoch's first finalized block.

use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_engine::{ForkchoiceState, PayloadId};
use commonware_codec::DecodeExt as _;
use commonware_consensus::types::{Epocher as _, FixedEpocher, Height};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use reth_basic_payload_builder::{PayloadBuilder as _, PayloadConfig};
use reth_node_builder::BuiltPayload as _;
use reth_primitives_traits::SealedHeader;
use reth_provider::{BlockHashReader as _, HeaderProvider as _};
use tempo_chainspec::{NetworkIdentity, TempoChainSpec};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::TempoFullNode;
use tempo_payload_builder::{TempoPayloadBuilder, TempoPayloadBuilderConfig};
use tempo_payload_types::{Estimator, EstimatorConfig, TempoPayloadAttributes};
use tempo_primitives::{TempoConsensusContext, TempoHeader};
use tracing::{info, instrument};

use crate::consensus::Digest;

/// A validated [`tempo_chainspec::Recovery`].
#[derive(Clone, Debug)]
pub(crate) struct Recovery {
    /// The last block finalized before consensus halted.
    finalized_height: Height,
    finalized_hash: B256,
    /// The last block of the halted epoch, carrying `outcome`.
    boundary: Height,
    boundary_hash: B256,
    outcome: OnchainDkgOutcome,
    encoded_outcome: Bytes,
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

        Ok(Some(Self {
            finalized_height,
            finalized_hash: recovery.finalized_hash,
            boundary,
            boundary_hash: recovery.boundary_hash,
            outcome,
            encoded_outcome: recovery.outcome.clone(),
        }))
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
        (self.boundary, Digest(self.boundary_hash))
    }

    /// Builds and imports the empty blocks after the last finalized block up to the boundary,
    /// then finalizes the boundary in the execution layer.
    ///
    /// Does nothing if the execution layer already finalized the boundary. Fails if the boundary
    /// this node builds does not match the pinned hash, or if the execution layer finalized
    /// neither the boundary nor the recovery's finalized block.
    #[instrument(skip_all, fields(finalized_height = %self.finalized_height, boundary = %self.boundary), err)]
    pub(crate) async fn fill_to_boundary(&self, node: &TempoFullNode) -> eyre::Result<()> {
        let finalized = node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .ok_or_eyre("execution layer has not finalized any block")?;

        if finalized.number >= self.boundary.get() {
            let hash = node
                .provider
                .block_hash(self.boundary.get())
                .wrap_err("failed reading the boundary hash")?
                .ok_or_eyre("execution layer finalized past the boundary but does not have it")?;
            ensure!(
                hash == self.boundary_hash,
                "execution layer finalized boundary `{hash}`, but the recovery pins `{}`",
                self.boundary_hash,
            );
            info!("execution layer already finalized the recovery boundary");
            return Ok(());
        }

        ensure!(
            finalized.number == self.finalized_height.get()
                && finalized.hash == self.finalized_hash,
            "recovery starts at block `{}` at height `{}`, but the execution layer finalized \
            `{}` at height `{}`; sync the execution layer to the recovery block first",
            self.finalized_hash,
            self.finalized_height,
            finalized.hash,
            finalized.number,
        );

        let mut parent = node
            .provider
            .sealed_header(self.finalized_height.get())
            .wrap_err("failed reading the recovery's finalized header")?
            .ok_or_eyre("execution layer does not have the recovery's finalized header")?;

        let builder = TempoPayloadBuilder::new(
            node.pool.clone(),
            node.provider.clone(),
            node.task_executor.clone(),
            node.evm_config.clone(),
            // Node-local settings must not change the blocks: keep the parent's gas limit and
            // always compute the state root.
            TempoPayloadBuilderConfig {
                desired_gas_limit: None,
                is_dev: false,
                state_provider_metrics: false,
                enable_prewarming: false,
                skip_state_root: false,
                enable_parallel: false,
            },
            Estimator::new(EstimatorConfig::default()),
        );
        let engine = node.add_ons_handle.beacon_engine_handle.clone();

        info!("filling the halted epoch with empty blocks");
        while parent.number() < self.boundary.get() {
            let extra_data = if parent.number() + 1 == self.boundary.get() {
                self.encoded_outcome.clone()
            } else {
                Bytes::new()
            };
            let attributes = fill_attributes(&parent, extra_data);

            let builder = builder.clone();
            let config = PayloadConfig {
                parent_header: Arc::new(parent),
                parent_block_info: None,
                attributes,
                payload_id: PayloadId::default(),
            };
            // The builder blocks on its state-root task.
            let payload = tokio::task::spawn_blocking(move || builder.build_empty_payload(config))
                .await
                .wrap_err("fill block build task panicked")?
                .wrap_err("failed building fill block")?;
            parent = payload.block().sealed_header().clone();

            let status = engine
                .new_payload(payload.into_execution_data())
                .await
                .wrap_err_with(|| format!("failed submitting fill block `{}`", parent.number()))?;
            ensure!(
                status.is_valid(),
                "execution layer rejected fill block `{}`: {status:?}",
                parent.number(),
            );
            // Zero leaves the safe and finalized blocks unchanged.
            engine
                .fork_choice_updated(
                    ForkchoiceState {
                        head_block_hash: parent.hash(),
                        safe_block_hash: B256::ZERO,
                        finalized_block_hash: B256::ZERO,
                    },
                    None,
                )
                .await
                .wrap_err_with(|| {
                    format!("failed making fill block `{}` canonical", parent.number())
                })?;
        }

        ensure!(
            parent.hash() == self.boundary_hash,
            "this node built boundary `{}`, but the recovery pins `{}`",
            parent.hash(),
            self.boundary_hash,
        );

        let response = engine
            .fork_choice_updated(
                ForkchoiceState {
                    head_block_hash: self.boundary_hash,
                    safe_block_hash: self.boundary_hash,
                    finalized_block_hash: self.boundary_hash,
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
        info!(boundary_hash = %self.boundary_hash, "finalized the recovery boundary");
        Ok(())
    }
}

/// Attributes of the empty block after `parent`, identical on every node.
///
/// Each block advances the timestamp by one millisecond so the epoch's next block does not wait
/// for a timestamp in the future, and continues the parent's views with no proposer reward.
fn fill_attributes(
    parent: &SealedHeader<TempoHeader>,
    extra_data: Bytes,
) -> TempoPayloadAttributes {
    let timestamp_millis = parent.timestamp_millis() + 1;
    let consensus_context = parent
        .consensus_context
        .map(|context| TempoConsensusContext {
            view: context.view + 1,
            parent_view: context.view,
            ..context
        });
    let mut attributes = TempoPayloadAttributes::new(
        None,
        timestamp_millis / 1000,
        timestamp_millis % 1000,
        extra_data,
        consensus_context,
    );
    attributes.target_gas_limit = Some(parent.gas_limit());
    attributes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use alloy_genesis::Genesis;
    use commonware_codec::Encode as _;
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
}
