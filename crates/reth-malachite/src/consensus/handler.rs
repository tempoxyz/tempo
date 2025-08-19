//! Consensus message handler that bridges Malachite consensus to the Reth application

use std::time::Duration;

use crate::{app::State, context::MalachiteContext};
use alloy_rpc_types_engine::ExecutionData;
use eyre::{WrapErr, bail, eyre};
use malachitebft_app_channel::{AppMsg, Channels, NetworkMsg, Reply, app::engine::host::Next};
use malachitebft_core_consensus::LocallyProposedValue;
use malachitebft_core_types::{Context, Height as _, Round, Validity};
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_builder::{NodeTypes, PayloadTypes};
use tempo_telemetry_util::{display_duration, error_field};
use tracing::{error, info, instrument};

/// Run the consensus message handler loop
///
/// This function receives messages from the Malachite consensus engine and
/// delegates them to the appropriate methods on the application state.
pub async fn run_consensus_handler<N: NodeTypes>(
    state: &State<N>,
    channels: &mut Channels<MalachiteContext>,
) -> eyre::Result<()>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    info!("Starting consensus handler loop");
    while let Some(msg) = channels.consensus.recv().await {
        info!(
            "Received consensus message: {:?}",
            std::any::type_name_of_val(&msg)
        );
        match msg {
            // Consensus is ready to start
            AppMsg::ConsensusReady { reply, .. } => {
                info!("Handling ConsensusReady message");

                // Determine the starting height
                let start_height = state.current_height()?;
                let validator_set = state.get_validator_set(start_height);

                info!(
                    "Sending ConsensusReady reply with height={:?}",
                    start_height
                );
                if reply.send((start_height, validator_set)).is_err() {
                    error!("Failed to send ConsensusReady reply");
                }
                info!("ConsensusReady reply sent successfully");
            }

            // New round has started
            AppMsg::StartedRound {
                height,
                round,
                proposer,
                role,
                reply_value,
            } => {
                info!(%height, %round, %proposer, ?role, "Started new round");

                // Update state with current round info
                state.set_current_height(height)?;
                state.set_current_round(round)?;
                state.set_current_proposer(Some(proposer))?;
                // Convert malachitebft_app::consensus::Role to our app::Role
                let app_role = match role {
                    malachitebft_app::consensus::Role::Proposer => crate::app::Role::Proposer,
                    malachitebft_app::consensus::Role::Validator => crate::app::Role::Validator,
                    malachitebft_app::consensus::Role::None => crate::app::Role::None,
                };
                state.set_current_role(app_role)?;

                // Check if we have any pending proposals for this height/round
                let proposals = vec![]; // TODO: Query from state storage

                if reply_value.send(proposals).is_err() {
                    error!("Failed to send StartedRound reply");
                }
            }

            // Consensus requests a value to propose
            AppMsg::GetValue {
                height,
                round,
                timeout,
                reply,
            } => handle_get_value(state, channels, height, round, timeout, reply).await?,

            // Vote extension handling (not used for now)
            AppMsg::ExtendVote { reply, .. } => {
                if reply.send(None).is_err() {
                    error!("Failed to send ExtendVote reply");
                }
            }

            AppMsg::VerifyVoteExtension { reply, .. } => {
                if reply.send(Ok(())).is_err() {
                    error!("Failed to send VerifyVoteExtension reply");
                }
            }

            // Received a proposal part from another validator
            AppMsg::ReceivedProposalPart { from, part, reply } => {
                info!(%from, "Received proposal part");

                match state.received_proposal_part(from, part).await {
                    Ok(proposed_value) => {
                        if reply.send(proposed_value).is_err() {
                            error!("Failed to send ReceivedProposalPart reply");
                        }
                    }
                    Err(e) => {
                        error!(%e, "Failed to process proposal part");
                        if reply.send(None).is_err() {
                            error!("Failed to send ReceivedProposalPart reply");
                        }
                    }
                }
            }

            // Request for validator set at a specific height
            AppMsg::GetValidatorSet { height, reply } => {
                let validator_set = state.get_validator_set(height);
                if reply.send(Some(validator_set)).is_err() {
                    error!("Failed to send GetValidatorSet reply");
                }
            }

            // Consensus has decided on a value
            AppMsg::Decided {
                certificate,
                extensions,
                reply,
            } => {
                info!(
                    height = %certificate.height,
                    round = %certificate.round,
                    value = %certificate.value_id,
                    "Consensus decided on value"
                );

                // Commit the decided value
                match state.commit(certificate.clone(), extensions).await {
                    Ok(_) => {
                        // Move to next height
                        let current = state.current_height()?;
                        let next_height = current.increment();
                        state.set_current_height(next_height)?;

                        if reply
                            .send(Next::Start(
                                next_height,
                                state.get_validator_set(next_height),
                            ))
                            .is_err()
                        {
                            error!("Failed to send StartHeight reply");
                        }
                    }
                    Err(e) => {
                        error!(%e, "Failed to commit decided value");
                        // Restart the current height
                        let current = state.current_height()?;
                        if reply
                            .send(Next::Restart(current, state.get_validator_set(current)))
                            .is_err()
                        {
                            error!("Failed to send RestartHeight reply");
                        }
                    }
                }
            }

            // Process a synced value from another node
            AppMsg::ProcessSyncedValue {
                height,
                round,
                proposer,
                value_bytes,
                reply,
            } => {
                info!(%height, %round, "Processing synced value");

                if let Some((value, block)) = crate::app::decode_value_with_block(value_bytes) {
                    // First validate the block through the engine
                    match state.validate_synced_block(&block).await {
                        Ok(true) => {
                            // Block is valid, create and store the proposal
                            let proposed_value =
                                malachitebft_app_channel::app::types::ProposedValue {
                                    height,
                                    round,
                                    valid_round: Round::Nil,
                                    proposer,
                                    value,
                                    validity: Validity::Valid,
                                };

                            // Store the synced value with its block
                            if let Err(e) = state
                                .store_synced_proposal(proposed_value.clone(), block)
                                .await
                            {
                                error!(error = error_field(&e), "Failed to store synced proposal");
                            }

                            if reply.send(Some(proposed_value)).is_err() {
                                error!("Failed to send ProcessSyncedValue reply");
                            }
                        }
                        Ok(false) => {
                            info!("Synced value failed validation");
                            if reply.send(None).is_err() {
                                error!("Failed to send ProcessSyncedValue reply");
                            }
                        }
                        Err(e) => {
                            error!(error = error_field(&e), "Failed to validate synced value");
                            if reply.send(None).is_err() {
                                error!("Failed to send ProcessSyncedValue reply");
                            }
                        }
                    }
                } else if reply.send(None).is_err() {
                    error!("Failed to send ProcessSyncedValue reply");
                }
            }

            // Request for a decided value at a specific height
            AppMsg::GetDecidedValue { height, reply } => {
                info!(%height, "Request for decided value");

                let decided_value = state.get_decided_value(height).await;
                let raw_value = decided_value.map(|dv| {
                    malachitebft_app_channel::app::types::sync::RawDecidedValue {
                        certificate: dv.certificate,
                        value_bytes: crate::app::encode_value(&dv.value),
                    }
                });

                if reply.send(raw_value).is_err() {
                    error!("Failed to send GetDecidedValue reply");
                }
            }

            // Request for the earliest available height
            AppMsg::GetHistoryMinHeight { reply } => {
                let min_height = state.get_earliest_height().await;
                if reply.send(min_height).is_err() {
                    error!("Failed to send GetHistoryMinHeight reply");
                }
            }

            // Request to restream a proposal
            AppMsg::RestreamProposal {
                height,
                round,
                valid_round,
                address: _,
                value_id,
            } => {
                info!(%height, %round, %valid_round, "Restreaming proposal");

                // Look for the proposal at valid_round or round
                let proposal_round = if valid_round == Round::Nil {
                    round
                } else {
                    valid_round
                };

                match state
                    .get_proposal_for_restreaming(height, proposal_round, value_id)
                    .await
                {
                    Ok(Some(proposal)) => {
                        let locally_proposed: malachitebft_app_channel::app::types::LocallyProposedValue<
                            MalachiteContext,
                        > = malachitebft_app_channel::app::types::LocallyProposedValue {
                                height,
                                round,
                                value: proposal.value,
                            };

                        // Retrieve the block for restreaming
                        match state.get_block(&proposal.value.hash()).await {
                            Ok(Some(block)) => {
                                // Stream the proposal parts
                                for part in
                                    state.stream_proposal(locally_proposed, block, valid_round)
                                {
                                    channels
                                        .network
                                        .send(NetworkMsg::PublishProposalPart(part))
                                        .await?;
                                }
                            }
                            Ok(None) => {
                                error!(
                                    "Block not found for restreaming: {}",
                                    proposal.value.hash()
                                );
                            }
                            Err(e) => {
                                error!(
                                    error = error_field(&e),
                                    "Failed to retrieve block for restreaming",
                                );
                            }
                        }
                    }
                    Ok(None) => {
                        info!("Proposal not found for restreaming");
                    }
                    Err(e) => {
                        error!(
                            error = error_field(&e),
                            "Failed to get proposal for restreaming"
                        );
                    }
                }
            }
        }
    }

    // Channel closed, consensus has stopped
    Err(eyre!("Consensus channel closed unexpectedly"))
}

#[instrument(
    skip_all,
    fields(
        %height,
        %round,
        timeout = %display_duration(timeout),
    ),
    ret
    // FIXME: Return the full error; this sucks because in tracing, but there is currently no way
    // to have errors emitted in instrument attributes that use dyn Stderr: Value
    err(Debug),
)]
async fn handle_get_value<N: NodeTypes>(
    state: &State<N>,
    channels: &mut Channels<MalachiteContext>,
    height: <MalachiteContext as Context>::Height,
    round: Round,
    timeout: Duration,
    reply: Reply<LocallyProposedValue<MalachiteContext>>,
) -> eyre::Result<()>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    let (proposal, block) =
        match tokio::time::timeout(timeout, get_or_propose_block(state, height, round)).await {
            Ok(ret) => ret.wrap_err("failed to construct a proposal")?,
            Err(elapsed) => {
                return Err(elapsed)
                    .wrap_err("exceeded the timeout window to construct a proposal permitted");
            }
        };
    if reply.send(proposal.clone()).is_err() {
        bail!("failed to send proposal to consensus layer; channel was already dropped");
    }

    // FIXME: this likely should always propagate the proposal, not only in the case of newly
    // constructed proposals.
    if let Some(block) = block {
        for part in state.stream_proposal(proposal, block, Round::Nil) {
            channels
                .network
                .send(NetworkMsg::PublishProposalPart(part))
                .await?;
        }
    }
    Ok(())
}

/// Utility to get a new proposal.
///
/// Mainly used to to apply a timeout to the procedure.
// FIXME: Returns `Option<Block>` only on a fully new proposal to be in line with
// the previous implementation. But very likely this is wrong a block should always be returned.
async fn get_or_propose_block<N: NodeTypes>(
    state: &State<N>,
    height: <MalachiteContext as Context>::Height,
    round: Round,
) -> eyre::Result<(
    LocallyProposedValue<MalachiteContext>,
    Option<reth_ethereum_primitives::Block>,
)>
where
    N::Payload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    match state.get_previously_built_value(height, round).await {
        Some(proposal) => {
            info!(value_id = %proposal.value.id(), "reusing previously built proposal");
            Ok((proposal, None))
        }
        None => {
            let (proposal, block) = state
                .propose_value(height, round)
                .await
                .wrap_err("failed to propose new value")?;
            info!(value_id = %proposal.value.id(), "constructed new proposal");
            Ok((proposal, Some(block)))
        }
    }
}
