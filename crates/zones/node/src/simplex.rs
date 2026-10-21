//! Simplex-sequenced Zone node services.
//!
//! Every quorum node runs the same long-lived task set for the whole process lifetime: Simplex
//! consensus on a dedicated Commonware runtime, transaction forwarding to every other quorum
//! member, and settlement with a rotating duty. There is no role switching: leadership changes
//! every view inside consensus.

use std::{path::Path, sync::Arc, time::Duration};

use alloy_eips::NumHash;
use alloy_primitives::{Address, U256};
use alloy_provider::{DynProvider, Provider as _};
use eyre::WrapErr as _;
use reth_chain_state::PersistedBlockSubscriptions;
use reth_node_api::ConsensusEngineHandle;
use reth_payload_builder::PayloadBuilderHandle;
use reth_storage_api::{BlockNumReader, StateProviderFactory};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::TransactionPool;
use tempo_alloy::TempoNetwork;
use tempo_contracts::zones::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, ZonePortal};
use tempo_transaction_pool::transaction::TempoPooledTransaction;
use tracing::{info, warn};
use zone_chainspec::ZoneChainSpec;
use zone_l1::{DepositQueue, EncryptionKeyRing, L1BlockTracker, TempoStateExt as _};
use zone_p2p::{ManifestNode, P2pConfig, P2pNetworkId, SimplexHandle, ZoneManifest};
use zone_payload::ZonePayloadTypes;
use zone_sequencer::{
    ProofCollectorHandle, SettlementDuty, SettlementProver, ZoneSequencerConfig,
    ZoneSequencerProvider, spawn_zone_sequencer,
};

use crate::{
    ZoneSequencerAddOnsConfig,
    tx_forwarding::{forward_new_transactions, insert_forwarded_transactions},
};

/// Worker threads of the dedicated Commonware runtime, as on Tempo L1.
const CONSENSUS_WORKER_THREADS: usize = 3;

/// Inputs for [`launch`].
pub(crate) struct Services<P, Pool> {
    pub(crate) p2p: P2pConfig,
    pub(crate) sequencer: ZoneSequencerAddOnsConfig,
    pub(crate) provider: P,
    pub(crate) pool: Pool,
    pub(crate) engine: ConsensusEngineHandle<ZonePayloadTypes>,
    pub(crate) payload_builder: PayloadBuilderHandle<ZonePayloadTypes>,
    pub(crate) chain_spec: Arc<ZoneChainSpec>,
    pub(crate) deposit_queue: DepositQueue,
    pub(crate) l1_block_tracker: L1BlockTracker,
    pub(crate) encryption_keys: EncryptionKeyRing,
    pub(crate) portal_address: Address,
    pub(crate) l1_chain_id: u64,
    pub(crate) l1_rpc_url: String,
    pub(crate) retry_connection_interval: Duration,
    pub(crate) proof_collector: Option<ProofCollectorHandle>,
    pub(crate) settlement_prover: Option<SettlementProver>,
}

/// The finalized Zone block a Simplex node resumes from.
///
/// Reth's canonical head may be an unfinalized block that consensus later replaces, so L1
/// ingestion and the deposit queue restart from the finalized block. Reth's finalized marker can
/// briefly name a block that was not persisted before an unclean stop.
pub(crate) fn checkpoint_block<P>(provider: &P) -> eyre::Result<u64>
where
    P: BlockNumReader + StateProviderFactory,
{
    let finalized = provider.finalized_block_number()?.unwrap_or_default();
    Ok(finalized.min(provider.best_block_number()?))
}

/// Seed the deposit queue with the Tempo checkpoint of `zone_block`.
///
/// `deferred_work` says the L1 subscriber restores portal work crossed by checkpoint-only blocks
/// before following new blocks.
pub(crate) fn seed_deposit_queue<P>(
    provider: &P,
    deposit_queue: &DepositQueue,
    zone_block: u64,
    deferred_work: bool,
) -> eyre::Result<NumHash>
where
    P: StateProviderFactory,
{
    let checkpoint = provider
        .history_by_block_number(zone_block)?
        .tempo_num_hash()?;
    deposit_queue.seed_consumed_through(checkpoint, deferred_work)?;
    Ok(checkpoint)
}

/// Check the manifest's participants against `ZonePortal` before consensus starts.
///
/// Every participant settles with one self-signed attestation, so each individual address must be
/// a registered sequencer and the portal threshold must be one. Both would otherwise surface as a
/// mysterious stall at the next batch boundary. Extra registered signers only warn: deregistering
/// is a cleanup task, and failing on it would make every membership change a window in which no
/// node can start.
///
/// A configured portal must already be deployed at the current L1 tip. The persisted Zone genesis
/// anchor may still predate portal deployment so the creation block can be replayed; this live-tip
/// check is deliberately independent of that historical anchor.
///
/// TODO: replace threshold-one settlement with quorum attestations of Simplex-finalized batches
/// (simplex.md review §1) before production use.
pub(crate) async fn validate_portal_sequencer_set(
    manifest: &ZoneManifest,
    portal_address: Address,
    l1_provider: &DynProvider<TempoNetwork>,
) -> eyre::Result<()> {
    // Programmatic synthetic test harnesses use zero to mean no Portal; the production CLI
    // rejects a zero address before node launch.
    if portal_address.is_zero() {
        info!(target: "zone::simplex", "No ZonePortal configured; skipping the manifest sequencer check");
        return Ok(());
    }
    let portal_code = l1_provider
        .get_code_at(portal_address)
        .await
        .map_err(|err| eyre::eyre!("failed to check portal {portal_address} deployment: {err}"))?;
    eyre::ensure!(
        !portal_code.is_empty(),
        "ZonePortal {portal_address} is not deployed at the current L1 tip; refusing to start consensus before its sequencer set can be validated"
    );

    // Read at the chain tip rather than the finalized head: a fresh or local L1 may have no
    // finalized block at all, and an unfinalized registration satisfying this check early is
    // harmless for a startup sanity check.
    let portal = ZonePortal::new(portal_address, l1_provider);
    let (sequencer_set_version, threshold, registered_count) = l1_provider
        .multicall()
        .add(portal.sequencerSetVersion())
        .add(portal.sequencerThreshold())
        .add(portal.sequencerCount())
        .aggregate()
        .await
        .wrap_err("failed reading the registered sequencer set from ZonePortal")?;
    let mut registration_calls = l1_provider.multicall().dynamic();
    for node in manifest.nodes() {
        registration_calls =
            registration_calls.add_dynamic(portal.isSequencer(node.secp256k1_address()));
    }
    let registered = registration_calls
        .aggregate()
        .await
        .wrap_err("failed reading the registered sequencers from ZonePortal")?;
    let validated_version = portal
        .sequencerSetVersion()
        .call()
        .await
        .wrap_err("failed re-reading the ZonePortal sequencer-set version")?;
    eyre::ensure!(
        validated_version == sequencer_set_version,
        "ZonePortal sequencer set changed during startup validation ({sequencer_set_version} -> {validated_version})"
    );

    for (node, is_registered) in manifest.nodes().iter().zip(registered) {
        eyre::ensure!(
            is_registered,
            "manifest node `{}` ({}) is not a registered ZonePortal sequencer",
            node.name(),
            node.secp256k1_address()
        );
    }
    eyre::ensure!(
        threshold == 1,
        "Simplex sequencers settle with one self-signed attestation, but ZonePortal \
         {portal_address} requires {threshold} signatures; set the sequencer threshold to 1"
    );
    if registered_count > U256::from(manifest.nodes().len()) {
        warn!(
            target: "zone::simplex",
            %registered_count,
            manifest_nodes = manifest.nodes().len(),
            "ZonePortal has registered sequencers the manifest does not list; any of them can settle this zone"
        );
    }

    info!(target: "zone::simplex", sequencer_set_version, participants = manifest.nodes().len(), "Checked the manifest against ZonePortal");
    Ok(())
}

/// Start consensus, transaction forwarding, and settlement for the process lifetime.
pub(crate) async fn launch<P, Pool>(
    services: Services<P, Pool>,
    datadir: &Path,
    task_executor: &TaskExecutor,
) -> eyre::Result<()>
where
    P: zone_consensus::ConsensusProvider + ZoneSequencerProvider + PersistedBlockSubscriptions,
    Pool: TransactionPool<Transaction = TempoPooledTransaction> + Clone + 'static,
{
    let Services {
        p2p,
        sequencer,
        provider,
        pool,
        engine,
        payload_builder,
        chain_spec,
        deposit_queue,
        l1_block_tracker,
        encryption_keys,
        portal_address,
        l1_chain_id,
        l1_rpc_url,
        retry_connection_interval,
        proof_collector,
        settlement_prover,
    } = services;
    let manifest = p2p.manifest().clone();
    let l1_transaction_signer = p2p.l1_transaction_signer();
    let settlement_duty = SettlementDuty::new(
        manifest.nodes().iter().map(ManifestNode::secp256k1_address),
        l1_transaction_signer.address(),
        manifest.consensus().settlement_failover,
    )?;

    let consensus_config = zone_consensus::Config {
        provider: provider.clone(),
        engine,
        payload_builder,
        chain_spec: chain_spec.clone(),
        deposit_queue,
        l1_block_tracker,
        encryption_keys,
        portal_address,
        fee_recipient: sequencer.sequencer_signer.address(),
        proof_collector,
        manifest,
    };
    let SimplexHandle {
        shutdown: shutdown_token,
        mut stopped,
        thread,
        commands,
        events,
    } = zone_p2p::spawn_simplex(
        p2p.with_storage_directory(datadir.join("consensus")),
        P2pNetworkId::new(l1_chain_id, portal_address),
        CONSENSUS_WORKER_THREADS,
        move |context, network| zone_consensus::run(context, network, consensus_config),
    )?;

    task_executor.spawn_critical_with_graceful_shutdown_signal(
        "zone-simplex",
        |shutdown| async move {
            let unexpected_exit = tokio::select! {
                guard = shutdown => {
                    let _guard = guard;
                    shutdown_token.cancel();
                    match stopped.await {
                        Ok(Ok(())) => info!(target: "reth::cli", "Simplex runtime stopped"),
                        Ok(Err(err)) => tracing::error!(target: "reth::cli", %err, "Simplex runtime failed during shutdown"),
                        Err(err) => tracing::error!(target: "reth::cli", %err, "Simplex runtime completion channel closed during shutdown"),
                    }
                    None
                }
                result = &mut stopped => Some(match result {
                    Ok(Ok(())) => "Simplex runtime stopped unexpectedly".to_string(),
                    Ok(Err(err)) => format!("Simplex runtime failed: {err}"),
                    Err(err) => format!("Simplex runtime completion channel closed unexpectedly: {err}"),
                }),
            };
            match tokio::task::spawn_blocking(move || thread.join()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => panic!("Simplex runtime thread panicked"),
                Err(err) => panic!("Failed joining Simplex runtime thread: {err}"),
            }
            if let Some(reason) = unexpected_exit {
                panic!("{reason}");
            }
        },
    );

    let forward_pool = pool.clone();
    let listener = forward_pool.new_transactions_listener();
    task_executor.spawn_critical_task(
        "zone-transaction-forwarding",
        forward_new_transactions(forward_pool, listener, commands),
    );
    task_executor.spawn_critical_task(
        "zone-transaction-import",
        insert_forwarded_transactions(pool, events),
    );

    let sequencer_config = ZoneSequencerConfig {
        chain_spec,
        portal_address,
        l1_rpc_url,
        retry_connection_interval,
        zone_poll_interval: sequencer.zone_poll_interval,
        withdrawal_poll_interval: sequencer.withdrawal_poll_interval,
        withdrawal_batch_limits: sequencer.withdrawal_batch_limits,
        outbox_address: ZONE_OUTBOX_ADDRESS,
        inbox_address: ZONE_INBOX_ADDRESS,
        batch_anchor_config: sequencer.batch_anchor_config,
        settlement_duty: Some(settlement_duty),
    };
    let handle = spawn_zone_sequencer(
        sequencer_config,
        l1_transaction_signer,
        provider,
        settlement_prover,
        tokio_util::sync::CancellationToken::new(),
    )
    .await;
    task_executor.spawn_critical_task("zone-settlement", async move {
        tokio::select! {
            res = handle.withdrawal_handle => {
                tracing::error!(target: "reth::cli", ?res, "Withdrawal processor task exited");
            }
            res = handle.monitor_handle => {
                tracing::error!(target: "reth::cli", ?res, "Zone monitor task exited");
            }
        }
    });
    info!(target: "reth::cli", "Started Simplex consensus, transaction forwarding, and settlement");
    Ok(())
}
